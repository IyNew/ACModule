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
include libsnark/libsnark/CMakeFiles/demo_arithmetization.dir/depend.make

# Include the progress variables for this target.
include libsnark/libsnark/CMakeFiles/demo_arithmetization.dir/progress.make

# Include the compile flags for this target's objects.
include libsnark/libsnark/CMakeFiles/demo_arithmetization.dir/flags.make

libsnark/libsnark/CMakeFiles/demo_arithmetization.dir/reductions/ram_to_r1cs/examples/demo_arithmetization.cpp.o: libsnark/libsnark/CMakeFiles/demo_arithmetization.dir/flags.make
libsnark/libsnark/CMakeFiles/demo_arithmetization.dir/reductions/ram_to_r1cs/examples/demo_arithmetization.cpp.o: ../libsnark/libsnark/reductions/ram_to_r1cs/examples/demo_arithmetization.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lyc/Desktop/nd/libsnark_sample-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object libsnark/libsnark/CMakeFiles/demo_arithmetization.dir/reductions/ram_to_r1cs/examples/demo_arithmetization.cpp.o"
	cd /home/lyc/Desktop/nd/libsnark_sample-master/build/libsnark/libsnark && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/demo_arithmetization.dir/reductions/ram_to_r1cs/examples/demo_arithmetization.cpp.o -c /home/lyc/Desktop/nd/libsnark_sample-master/libsnark/libsnark/reductions/ram_to_r1cs/examples/demo_arithmetization.cpp

libsnark/libsnark/CMakeFiles/demo_arithmetization.dir/reductions/ram_to_r1cs/examples/demo_arithmetization.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/demo_arithmetization.dir/reductions/ram_to_r1cs/examples/demo_arithmetization.cpp.i"
	cd /home/lyc/Desktop/nd/libsnark_sample-master/build/libsnark/libsnark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/lyc/Desktop/nd/libsnark_sample-master/libsnark/libsnark/reductions/ram_to_r1cs/examples/demo_arithmetization.cpp > CMakeFiles/demo_arithmetization.dir/reductions/ram_to_r1cs/examples/demo_arithmetization.cpp.i

libsnark/libsnark/CMakeFiles/demo_arithmetization.dir/reductions/ram_to_r1cs/examples/demo_arithmetization.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/demo_arithmetization.dir/reductions/ram_to_r1cs/examples/demo_arithmetization.cpp.s"
	cd /home/lyc/Desktop/nd/libsnark_sample-master/build/libsnark/libsnark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/lyc/Desktop/nd/libsnark_sample-master/libsnark/libsnark/reductions/ram_to_r1cs/examples/demo_arithmetization.cpp -o CMakeFiles/demo_arithmetization.dir/reductions/ram_to_r1cs/examples/demo_arithmetization.cpp.s

# Object files for target demo_arithmetization
demo_arithmetization_OBJECTS = \
"CMakeFiles/demo_arithmetization.dir/reductions/ram_to_r1cs/examples/demo_arithmetization.cpp.o"

# External object files for target demo_arithmetization
demo_arithmetization_EXTERNAL_OBJECTS =

libsnark/libsnark/demo_arithmetization: libsnark/libsnark/CMakeFiles/demo_arithmetization.dir/reductions/ram_to_r1cs/examples/demo_arithmetization.cpp.o
libsnark/libsnark/demo_arithmetization: libsnark/libsnark/CMakeFiles/demo_arithmetization.dir/build.make
libsnark/libsnark/demo_arithmetization: libsnark/libsnark/libsnark.a
libsnark/libsnark/demo_arithmetization: /usr/lib/x86_64-linux-gnu/libboost_program_options.so
libsnark/libsnark/demo_arithmetization: libsnark/depends/libff/libff/libff.a
libsnark/libsnark/demo_arithmetization: /usr/lib/x86_64-linux-gnu/libgmp.so
libsnark/libsnark/demo_arithmetization: /usr/lib/x86_64-linux-gnu/libgmp.so
libsnark/libsnark/demo_arithmetization: /usr/lib/x86_64-linux-gnu/libgmpxx.so
libsnark/libsnark/demo_arithmetization: libsnark/depends/libzm.a
libsnark/libsnark/demo_arithmetization: libsnark/libsnark/CMakeFiles/demo_arithmetization.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/lyc/Desktop/nd/libsnark_sample-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable demo_arithmetization"
	cd /home/lyc/Desktop/nd/libsnark_sample-master/build/libsnark/libsnark && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/demo_arithmetization.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
libsnark/libsnark/CMakeFiles/demo_arithmetization.dir/build: libsnark/libsnark/demo_arithmetization

.PHONY : libsnark/libsnark/CMakeFiles/demo_arithmetization.dir/build

libsnark/libsnark/CMakeFiles/demo_arithmetization.dir/clean:
	cd /home/lyc/Desktop/nd/libsnark_sample-master/build/libsnark/libsnark && $(CMAKE_COMMAND) -P CMakeFiles/demo_arithmetization.dir/cmake_clean.cmake
.PHONY : libsnark/libsnark/CMakeFiles/demo_arithmetization.dir/clean

libsnark/libsnark/CMakeFiles/demo_arithmetization.dir/depend:
	cd /home/lyc/Desktop/nd/libsnark_sample-master/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/lyc/Desktop/nd/libsnark_sample-master /home/lyc/Desktop/nd/libsnark_sample-master/libsnark/libsnark /home/lyc/Desktop/nd/libsnark_sample-master/build /home/lyc/Desktop/nd/libsnark_sample-master/build/libsnark/libsnark /home/lyc/Desktop/nd/libsnark_sample-master/build/libsnark/libsnark/CMakeFiles/demo_arithmetization.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : libsnark/libsnark/CMakeFiles/demo_arithmetization.dir/depend

