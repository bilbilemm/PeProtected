#include <Windows.h>
#include <winnt.h>
#include <fstream>
#include <filesystem>

/*
	https://thunderjie.github.io/2019/03/27/PE%E7%BB%93%E6%9E%84%E8%AF%A6%E8%A7%A3/
	https://blog.csdn.net/zhyulo/article/details/85717711
*/

int main()
{
	_IMAGE_DOS_HEADER;
	_IMAGE_NT_HEADERS64;
	
	std::filesystem::path file_name = kProjectSourceDir"build_windows/bin/Debug/Test.exe";
	auto file_size = std::filesystem::file_size(file_name);
	char* buffer = new char[file_size] {};

	std::ifstream is(file_name, std::ios::binary);
	is.read(buffer, file_size);
	is.close();

	constexpr auto pe_size = sizeof(_IMAGE_NT_HEADERS64);

	auto dos = (_IMAGE_DOS_HEADER*)buffer;
	auto pe = (_IMAGE_NT_HEADERS64*)(buffer + dos->e_lfanew);
	auto sec_heard = (_IMAGE_SECTION_HEADER*)(buffer + dos->e_lfanew + pe_size);

	return 0;
}