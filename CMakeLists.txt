project(PeProtected)

set(CMAKE_CXX_STANDARD 20)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

cmake_minimum_required(VERSION 3.17)

IF (CMAKE_SYSTEM_NAME MATCHES "Windows")
	add_compile_options("/Zi")
	add_link_options("/DEBUG")
ENDIF(CMAKE_SYSTEM_NAME MATCHES "Windows")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/Bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/Bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/Bin)
set(CMAKE_PDB_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/Bin)

add_subdirectory(./LoadPe/)
add_subdirectory(./Test/)
add_subdirectory(./TestDll/)