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

# Include any dependencies generated for this target.
include libsnark/depends/CMakeFiles/zm.dir/depend.make

# Include the progress variables for this target.
include libsnark/depends/CMakeFiles/zm.dir/progress.make

# Include the compile flags for this target's objects.
include libsnark/depends/CMakeFiles/zm.dir/flags.make

libsnark/depends/CMakeFiles/zm.dir/ate-pairing/src/zm.cpp.o: libsnark/depends/CMakeFiles/zm.dir/flags.make
libsnark/depends/CMakeFiles/zm.dir/ate-pairing/src/zm.cpp.o: ../libsnark/depends/ate-pairing/src/zm.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lyc/Desktop/nd/libsnark_sample-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object libsnark/depends/CMakeFiles/zm.dir/ate-pairing/src/zm.cpp.o"
	cd /home/lyc/Desktop/nd/libsnark_sample-master/build/libsnark/depends && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/zm.dir/ate-pairing/src/zm.cpp.o -c /home/lyc/Desktop/nd/libsnark_sample-master/libsnark/depends/ate-pairing/src/zm.cpp

libsnark/depends/CMakeFiles/zm.dir/ate-pairing/src/zm.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/zm.dir/ate-pairing/src/zm.cpp.i"
	cd /home/lyc/Desktop/nd/libsnark_sample-master/build/libsnark/depends && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/lyc/Desktop/nd/libsnark_sample-master/libsnark/depends/ate-pairing/src/zm.cpp > CMakeFiles/zm.dir/ate-pairing/src/zm.cpp.i

libsnark/depends/CMakeFiles/zm.dir/ate-pairing/src/zm.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/zm.dir/ate-pairing/src/zm.cpp.s"
	cd /home/lyc/Desktop/nd/libsnark_sample-master/build/libsnark/depends && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/lyc/Desktop/nd/libsnark_sample-master/libsnark/depends/ate-pairing/src/zm.cpp -o CMakeFiles/zm.dir/ate-pairing/src/zm.cpp.s

libsnark/depends/CMakeFiles/zm.dir/ate-pairing/src/zm2.cpp.o: libsnark/depends/CMakeFiles/zm.dir/flags.make
libsnark/depends/CMakeFiles/zm.dir/ate-pairing/src/zm2.cpp.o: ../libsnark/depends/ate-pairing/src/zm2.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lyc/Desktop/nd/libsnark_sample-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object libsnark/depends/CMakeFiles/zm.dir/ate-pairing/src/zm2.cpp.o"
	cd /home/lyc/Desktop/nd/libsnark_sample-master/build/libsnark/depends && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/zm.dir/ate-pairing/src/zm2.cpp.o -c /home/lyc/Desktop/nd/libsnark_sample-master/libsnark/depends/ate-pairing/src/zm2.cpp

libsnark/depends/CMakeFiles/zm.dir/ate-pairing/src/zm2.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/zm.dir/ate-pairing/src/zm2.cpp.i"
	cd /home/lyc/Desktop/nd/libsnark_sample-master/build/libsnark/depends && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/lyc/Desktop/nd/libsnark_sample-master/libsnark/depends/ate-pairing/src/zm2.cpp > CMakeFiles/zm.dir/ate-pairing/src/zm2.cpp.i

libsnark/depends/CMakeFiles/zm.dir/ate-pairing/src/zm2.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/zm.dir/ate-pairing/src/zm2.cpp.s"
	cd /home/lyc/Desktop/nd/libsnark_sample-master/build/libsnark/depends && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/lyc/Desktop/nd/libsnark_sample-master/libsnark/depends/ate-pairing/src/zm2.cpp -o CMakeFiles/zm.dir/ate-pairing/src/zm2.cpp.s

# Object files for target zm
zm_OBJECTS = \
"CMakeFiles/zm.dir/ate-pairing/src/zm.cpp.o" \
"CMakeFiles/zm.dir/ate-pairing/src/zm2.cpp.o"

# External object files for target zm
zm_EXTERNAL_OBJECTS =

libsnark/depends/libzm.a: libsnark/depends/CMakeFiles/zm.dir/ate-pairing/src/zm.cpp.o
libsnark/depends/libzm.a: libsnark/depends/CMakeFiles/zm.dir/ate-pairing/src/zm2.cpp.o
libsnark/depends/libzm.a: libsnark/depends/CMakeFiles/zm.dir/build.make
libsnark/depends/libzm.a: libsnark/depends/CMakeFiles/zm.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/lyc/Desktop/nd/libsnark_sample-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX static library libzm.a"
	cd /home/lyc/Desktop/nd/libsnark_sample-master/build/libsnark/depends && $(CMAKE_COMMAND) -P CMakeFiles/zm.dir/cmake_clean_target.cmake
	cd /home/lyc/Desktop/nd/libsnark_sample-master/build/libsnark/depends && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/zm.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
libsnark/depends/CMakeFiles/zm.dir/build: libsnark/depends/libzm.a

.PHONY : libsnark/depends/CMakeFiles/zm.dir/build

libsnark/depends/CMakeFiles/zm.dir/clean:
	cd /home/lyc/Desktop/nd/libsnark_sample-master/build/libsnark/depends && $(CMAKE_COMMAND) -P CMakeFiles/zm.dir/cmake_clean.cmake
.PHONY : libsnark/depends/CMakeFiles/zm.dir/clean

libsnark/depends/CMakeFiles/zm.dir/depend:
	cd /home/lyc/Desktop/nd/libsnark_sample-master/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/lyc/Desktop/nd/libsnark_sample-master /home/lyc/Desktop/nd/libsnark_sample-master/libsnark/depends /home/lyc/Desktop/nd/libsnark_sample-master/build /home/lyc/Desktop/nd/libsnark_sample-master/build/libsnark/depends /home/lyc/Desktop/nd/libsnark_sample-master/build/libsnark/depends/CMakeFiles/zm.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : libsnark/depends/CMakeFiles/zm.dir/depend

