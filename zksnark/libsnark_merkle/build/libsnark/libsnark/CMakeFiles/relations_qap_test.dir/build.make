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
include libsnark/libsnark/CMakeFiles/relations_qap_test.dir/depend.make

# Include the progress variables for this target.
include libsnark/libsnark/CMakeFiles/relations_qap_test.dir/progress.make

# Include the compile flags for this target's objects.
include libsnark/libsnark/CMakeFiles/relations_qap_test.dir/flags.make

libsnark/libsnark/CMakeFiles/relations_qap_test.dir/relations/arithmetic_programs/qap/tests/test_qap.cpp.o: libsnark/libsnark/CMakeFiles/relations_qap_test.dir/flags.make
libsnark/libsnark/CMakeFiles/relations_qap_test.dir/relations/arithmetic_programs/qap/tests/test_qap.cpp.o: ../libsnark/libsnark/relations/arithmetic_programs/qap/tests/test_qap.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lyc/Desktop/nd/libsnark_sample-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object libsnark/libsnark/CMakeFiles/relations_qap_test.dir/relations/arithmetic_programs/qap/tests/test_qap.cpp.o"
	cd /home/lyc/Desktop/nd/libsnark_sample-master/build/libsnark/libsnark && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/relations_qap_test.dir/relations/arithmetic_programs/qap/tests/test_qap.cpp.o -c /home/lyc/Desktop/nd/libsnark_sample-master/libsnark/libsnark/relations/arithmetic_programs/qap/tests/test_qap.cpp

libsnark/libsnark/CMakeFiles/relations_qap_test.dir/relations/arithmetic_programs/qap/tests/test_qap.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/relations_qap_test.dir/relations/arithmetic_programs/qap/tests/test_qap.cpp.i"
	cd /home/lyc/Desktop/nd/libsnark_sample-master/build/libsnark/libsnark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/lyc/Desktop/nd/libsnark_sample-master/libsnark/libsnark/relations/arithmetic_programs/qap/tests/test_qap.cpp > CMakeFiles/relations_qap_test.dir/relations/arithmetic_programs/qap/tests/test_qap.cpp.i

libsnark/libsnark/CMakeFiles/relations_qap_test.dir/relations/arithmetic_programs/qap/tests/test_qap.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/relations_qap_test.dir/relations/arithmetic_programs/qap/tests/test_qap.cpp.s"
	cd /home/lyc/Desktop/nd/libsnark_sample-master/build/libsnark/libsnark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/lyc/Desktop/nd/libsnark_sample-master/libsnark/libsnark/relations/arithmetic_programs/qap/tests/test_qap.cpp -o CMakeFiles/relations_qap_test.dir/relations/arithmetic_programs/qap/tests/test_qap.cpp.s

# Object files for target relations_qap_test
relations_qap_test_OBJECTS = \
"CMakeFiles/relations_qap_test.dir/relations/arithmetic_programs/qap/tests/test_qap.cpp.o"

# External object files for target relations_qap_test
relations_qap_test_EXTERNAL_OBJECTS =

libsnark/libsnark/relations_qap_test: libsnark/libsnark/CMakeFiles/relations_qap_test.dir/relations/arithmetic_programs/qap/tests/test_qap.cpp.o
libsnark/libsnark/relations_qap_test: libsnark/libsnark/CMakeFiles/relations_qap_test.dir/build.make
libsnark/libsnark/relations_qap_test: libsnark/libsnark/libsnark.a
libsnark/libsnark/relations_qap_test: libsnark/depends/libff/libff/libff.a
libsnark/libsnark/relations_qap_test: /usr/lib/x86_64-linux-gnu/libgmp.so
libsnark/libsnark/relations_qap_test: /usr/lib/x86_64-linux-gnu/libgmp.so
libsnark/libsnark/relations_qap_test: /usr/lib/x86_64-linux-gnu/libgmpxx.so
libsnark/libsnark/relations_qap_test: libsnark/depends/libzm.a
libsnark/libsnark/relations_qap_test: libsnark/libsnark/CMakeFiles/relations_qap_test.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/lyc/Desktop/nd/libsnark_sample-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable relations_qap_test"
	cd /home/lyc/Desktop/nd/libsnark_sample-master/build/libsnark/libsnark && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/relations_qap_test.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
libsnark/libsnark/CMakeFiles/relations_qap_test.dir/build: libsnark/libsnark/relations_qap_test

.PHONY : libsnark/libsnark/CMakeFiles/relations_qap_test.dir/build

libsnark/libsnark/CMakeFiles/relations_qap_test.dir/clean:
	cd /home/lyc/Desktop/nd/libsnark_sample-master/build/libsnark/libsnark && $(CMAKE_COMMAND) -P CMakeFiles/relations_qap_test.dir/cmake_clean.cmake
.PHONY : libsnark/libsnark/CMakeFiles/relations_qap_test.dir/clean

libsnark/libsnark/CMakeFiles/relations_qap_test.dir/depend:
	cd /home/lyc/Desktop/nd/libsnark_sample-master/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/lyc/Desktop/nd/libsnark_sample-master /home/lyc/Desktop/nd/libsnark_sample-master/libsnark/libsnark /home/lyc/Desktop/nd/libsnark_sample-master/build /home/lyc/Desktop/nd/libsnark_sample-master/build/libsnark/libsnark /home/lyc/Desktop/nd/libsnark_sample-master/build/libsnark/libsnark/CMakeFiles/relations_qap_test.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : libsnark/libsnark/CMakeFiles/relations_qap_test.dir/depend

