# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.13

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/bin/cmake

# The command to remove a file.
RM = /usr/local/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/lyc/Desktop/nd/libsnark_sample-master

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/lyc/Desktop/nd/libsnark_sample-master/build

# Utility rule file for ContinuousSubmit.

# Include the progress variables for this target.
include libsnark/libsnark/CMakeFiles/ContinuousSubmit.dir/progress.make

libsnark/libsnark/CMakeFiles/ContinuousSubmit:
	cd /home/lyc/Desktop/nd/libsnark_sample-master/build/libsnark/libsnark && /usr/local/bin/ctest -D ContinuousSubmit

ContinuousSubmit: libsnark/libsnark/CMakeFiles/ContinuousSubmit
ContinuousSubmit: libsnark/libsnark/CMakeFiles/ContinuousSubmit.dir/build.make

.PHONY : ContinuousSubmit

# Rule to build all files generated by this target.
libsnark/libsnark/CMakeFiles/ContinuousSubmit.dir/build: ContinuousSubmit

.PHONY : libsnark/libsnark/CMakeFiles/ContinuousSubmit.dir/build

libsnark/libsnark/CMakeFiles/ContinuousSubmit.dir/clean:
	cd /home/lyc/Desktop/nd/libsnark_sample-master/build/libsnark/libsnark && $(CMAKE_COMMAND) -P CMakeFiles/ContinuousSubmit.dir/cmake_clean.cmake
.PHONY : libsnark/libsnark/CMakeFiles/ContinuousSubmit.dir/clean

libsnark/libsnark/CMakeFiles/ContinuousSubmit.dir/depend:
	cd /home/lyc/Desktop/nd/libsnark_sample-master/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/lyc/Desktop/nd/libsnark_sample-master /home/lyc/Desktop/nd/libsnark_sample-master/libsnark/libsnark /home/lyc/Desktop/nd/libsnark_sample-master/build /home/lyc/Desktop/nd/libsnark_sample-master/build/libsnark/libsnark /home/lyc/Desktop/nd/libsnark_sample-master/build/libsnark/libsnark/CMakeFiles/ContinuousSubmit.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : libsnark/libsnark/CMakeFiles/ContinuousSubmit.dir/depend

