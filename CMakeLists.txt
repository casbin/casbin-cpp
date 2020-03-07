	# CMakeList.txt : CMake project for CMakeProject1, include source and define
	# project specific logic here.
	#
	cmake_minimum_required (VERSION 3.8)

	project ("casbin")

	# Add source to this project's executable.
	add_executable (casbin "casbin.cpp" "casbin.h" "include/CSVManager.cc" "include/CSVManager.h")

	# TODO: Add tests and install targets if needed.