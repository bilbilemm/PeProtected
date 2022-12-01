#include <Windows.h>
#include <winnt.h>
#include <fstream>
#include <filesystem>

int main()
{
	_IMAGE_DOS_HEADER;
	_IMAGE_NT_HEADERS;
	
	std::filesystem::path file_name = kProjectSourceDir"build_windows/bin/Debug/Test.exe";
	auto file_size = std::filesystem::file_size(file_name);
	char* buffer = new char[file_size] {};

	std::ifstream is(file_name, std::ios::binary);
	is.read(buffer, file_size);
	is.close();

	auto dos = (_IMAGE_DOS_HEADER*)buffer;

	return 0;
}