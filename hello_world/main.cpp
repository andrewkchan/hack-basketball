#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include <iostream>

// int main() {
//   std::cout << "Hello world!!!" << std::endl;
//   std::string str = "Hi from the tool's print function";
//   myPrint(str);
//   return 0;
// }

#include <errno.h>
#include <pthread.h>
#include <fcntl.h>

// For ptrace ops
#include <unistd.h>
#include <sys/wait.h> // For waitpid()
#include <sys/types.h>
#include <sys/ptrace.h> // For ptrace()

#include <dirent.h> //For POSIX directory functions


#define REGION_ITERATOR_DONE    (1UL << 0)
#define REGION_ITERATOR_READ    (1UL << 1)
#define REGION_ITERATOR_WRITE   (1UL << 2)
#define REGION_ITERATOR_EXECUTE (1UL << 3)

struct watch_addr {
  uintptr_t addr;
  int prev;
};

struct watchlist {
  size_t count;
  size_t size;
  struct watch_addr *list;
};

struct region_iterator {
  uintptr_t base; // current position in remote proc's address space
  size_t size; // size of contiguous region in remote memory
  unsigned long flags;
  pid_t pid; // PID of attached process
  FILE *maps; // file pointer for /proc/pid/maps file
  int mem; // file descriptor for /proc/pid/mem file
  char *buf; // buffer to read remote region into
  size_t bufsize; // size of allocated buffer
};

static int region_iterator_next(struct region_iterator *i) {
  // read the next contiguous region's permissions string into perms
  // and the start and end  pointers of the region into start, end
  char perms[8];
  uintptr_t start, end;
  int r = fscanf(i->maps, "%" SCNxPTR "-%" SCNxPTR " %7s", &start, &end, perms);
  // check if read 3 values or at EOF
  if (r != 3) {
    i->flags = REGION_ITERATOR_DONE;
    return 0;
  }
  // skip to the end of the line in /proc/pid/maps
  int c;
  do {c = fgetc(i->maps);} while (c != '\n' && c != EOF);
  // set the iterator's current position to the position in maps
  // and the size of the region being read
  i->base = start;
  i->size = end - start;
  // set iterator's flags according to the current line's permissions
  i->flags = 0;
  if (perms[0] == 'r')
    i->flags |= REGION_ITERATOR_READ;
  if (perms[1] == 'w')
    i->flags |= REGION_ITERATOR_WRITE;
  if (perms[2] == 'x')
    i->flags |= REGION_ITERATOR_EXECUTE;
  return 1;
}

static int region_iterator_init(struct region_iterator *i, pid_t pid) {
  // get a pointer to the PID's maps filestream and init iterator accordingly
  i->flags = REGION_ITERATOR_DONE;
  char file[256];

  // open /proc/pid/maps
  sprintf(file, "/proc/%ld/maps", (long)pid);
  FILE *maps = fopen(file, "r");
  if (!maps)
    return 0;
  // open /proc/pid/mem
  sprintf(file, "/proc/%ld/mem", (long)pid);
  int mem = open(file, O_RDONLY);
  if (mem == -1) {
    fclose(maps);
    return 0;
  }
  *i = (struct region_iterator) {
    .pid = pid,
    .maps = maps,
    .mem = mem,
  };
  return region_iterator_next(i);
}

static const void *region_iterator_readmem(struct region_iterator *i) {
  // make sure to allocate enough memory to view the remote's heap-allocated memory
  if (i->bufsize < i->size) {
    free(i->buf);
    i->bufsize = i->size;
    i->buf = (char *)malloc(i->bufsize);
  }
  // attach to the process and read the region
  if (ptrace(PTRACE_ATTACH, i->pid, 0, 0) == -1)
    return NULL;
  waitpid(i->pid, NULL, 0);
  int result = pread(i->mem, i->buf, i->size, i->base) == (ssize_t)i->size;
  ptrace(PTRACE_DETACH, i->pid, 0, 0);
  // return the local buffer's address if successful, else NULL
  return result ? i->buf : NULL;
}

static void region_iterator_destroy(struct region_iterator *i) {
  free(i->buf);
  i->buf = NULL;
  i->bufsize = 0;
  fclose(i->maps);
  close(i->mem);
}

static int region_iterator_done(struct region_iterator *i) {
  return !!(i->flags & REGION_ITERATOR_DONE);
}

static int write_memory(pid_t pid, uintptr_t addr, void *buf, size_t bufsize) {
  // write the values in the buffer to the address of the process of given PID
  // return a nonzero val iff writes were successful
  char file[256];
  sprintf(file, "/proc/%ld/mem", (long)pid);
  int fd = open(file, O_WRONLY);
  if (fd == -1)
    return 0;
  if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
    close(fd);
    return 0;
  }
  waitpid(pid, NULL, 0);
  int result = pwrite(fd, buf, bufsize, addr) == (ssize_t)bufsize;
  ptrace(PTRACE_DETACH, pid, 0, 0);
  close(fd);
  return result;
}

static void watchlist_push(struct watchlist *wl, uintptr_t addr, int val) {
  // pushes the given address onto the watchlist and marks its previous value as val
  if (wl->count == wl->size) {
    wl->size *= 2;
    wl->list = (struct watch_addr *)realloc(wl->list, wl->size * sizeof(int));
  }
  wl->list[wl->count].addr = addr;
  wl->list[wl->count].prev = val;
  wl->count++;
}

static void watchlist_init(struct watchlist *wl) {
  wl->size = 4096;
  wl->count = 0;
  wl->list = (struct watch_addr *)malloc(wl->size * sizeof(int));
}

static void watchlist_clear(struct watchlist *wl) {
  wl->count = 0;
}

static void watchlist_free(struct watchlist *wl) {
  free(wl->list);
  wl->list = NULL;
}

static int scan(struct watchlist *wl, pid_t pid, int val) {
  size_t INT_SIZE = sizeof(int);
  // clear the watchlist
  watchlist_clear(wl);
  struct region_iterator it[1];
  // begin reading off process maps
  region_iterator_init(it, pid);
  for (; !region_iterator_done(it); region_iterator_next(it)) {
    // read the next contiguous region of memory into buf
    const char *buf = (const char *)region_iterator_readmem(it);
    if (buf) {
      // check every value-aligned block of buffer
      size_t count = it->size / INT_SIZE;
      int *read = (int *)buf;
      for (size_t i= 0; i < count; i++) {
        // does this particular block == desired value?
        if (*read == val) {
          // if it matches, add the block address (in remote addr space) to watchlist
          uintptr_t addr = it->base + i*INT_SIZE;
          watchlist_push(wl, addr, val);
        }
        read++; // next block
      }
    } else {
      std::cout << "memory read failed at "
        << it->base << " with error "
        << strerror(errno) << std::endl;
    }
  }
  region_iterator_destroy(it);
  return 1;
}

int main() {
  pid_t pid     = 10580; //The process id you wish to attach to
  struct watchlist wl;
  watchlist_init(&wl);

  char cmd[4096];
  const char *delim = " \n\t";
  std::cout << "Enter a command (s [VAL] - search for VAL, f [VAL] - filter for VAL):";
  while (fgets(cmd, sizeof(cmd), stdin)) {
    char *verb = strtok(cmd, delim);
    if (verb) {
      char *val_str = strtok(NULL, delim);
      if (strcmp(verb, "q") == 0)
        break;
      int val = (int) strtoimax(val_str, NULL, 10);

      std::cout << "Scanning for value " << val << std::endl;
      scan(&wl, pid, val);
      std::cout << wl.count << " addresses found with value " << val << std::endl;
      std::cout << "Enter a command (s [VAL] - search for VAL, f [VAL] - filter for VAL):";
    }
  }

  return 0;
}
