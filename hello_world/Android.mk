LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := main.out
LOCAL_C_INCLUDES += \
	../tools/
LOCAL_SRC_FILES := \
	main.cpp \
	../tools/tools.cpp
include $(BUILD_EXECUTABLE)
