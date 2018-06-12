#include <iostream>
#include "tools.h"

// int main() {
//   std::cout << "Hello world!!!" << std::endl;
//   std::string str = "Hi from the tool's print function";
//   myPrint(str);
//   return 0;
// }

#include <errno.h>
#include <sys/ptrace.h> //For ptrace()
#include <sys/wait.h>   //For waitpid()

int main () {
    int pid     = 5136; //The process id you wish to attach to
    int addr = 0x13371337; //The address you wish to read in the process


    std::cout << "Attaching to process 5136" << std::endl;
    //First, attach to the process
    //All ptrace() operations that fail return -1, the exceptions are
    //PTRACE_PEEK* operations
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        //Read the value of errno for details.
        //To get a human readable, call strerror()
        //strerror(errno) <-- Returns a human readable version of the
        //error that occurred
        std::cout << "Error running ptrace()" << std::endl;
        std::cout << strerror(errno) << std::endl;
        return 0;
    }

    //Now, attaching doesn't mean we can read the value straight away
    //We have to wait for the process to stop
    int status;
    //waitpid() returns -1 on failure
    //W.I.F, not W.T.F
    //WIFSTOPPED() returns true if the process was stopped when we attached to it
    if (waitpid(pid, &status, 0) == -1 || !WIFSTOPPED(status)) {
        //Failed, read the value of errno or strerror(errno)
        std::cout << "waitpid failed or process is not stopped" << std::endl;
        std::cout << strerror(errno) << std::endl;
        return 0;
    }

    errno = 0; //Set errno to zero
    //We are about to perform a PTRACE_PEEK* operation, it is possible that the value
    //we read at the address is -1, if so, ptrace() will return -1 EVEN THOUGH it succeeded!
    //This is why we need to 'clear' the value of errno.
    int value = ptrace(PTRACE_PEEKDATA, pid, (void*)addr, NULL);
    if (value == -1 && errno != 0) {
        //Failed, read the value of errno or strerror(errno)
        return 0;
    } else {
        //Success! Read the value
        std::cout << "Success!" << std::endl;
        std::cout << value << std::endl;
    }

    //Now, we have to detach from the process
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;
}
