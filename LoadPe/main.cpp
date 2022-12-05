#include <Windows.h>
#include <winnt.h>
#include <fstream>
#include <filesystem>
#include <unordered_map>

/*
* 
*	pe struct 
	https://thunderjie.github.io/2019/03/27/PE%E7%BB%93%E6%9E%84%E8%AF%A6%E8%A7%A3/
	https://blog.csdn.net/zhyulo/article/details/85717711
	https://bidouillesecurity.com/tutorial-writing-a-pe-packer-part-1/

	cff vii tools
	https://soft.3dmgame.com/down/204551.html

	memory load dll
	https://www.joachim-bauch.de/tutorials/loading-a-dll-from-memory/
*/

DWORD old_protect = {};

char* AllocVirtual(_IMAGE_NT_HEADERS64* pe) {
	/*
		https://baike.baidu.com/item/VirtualAlloc/1606859
	*/
	return (char*)VirtualAlloc(nullptr, pe->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
}

/*
	pe 头写入内存,仅可读
*/
void WritePeHeard(char* virtual_address, char* file_buffer, _IMAGE_NT_HEADERS64* pe) {
	std::memmove(virtual_address, file_buffer, pe->OptionalHeader.SizeOfHeaders);
	VirtualProtect(virtual_address, pe->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &old_protect);
}


/*
	段权限转换
*/
DWORD ConvertSectionRole(_IMAGE_SECTION_HEADER* section) {
	DWORD convert_res = {};
	if (section->Characteristics & IMAGE_SCN_MEM_WRITE) {
		convert_res &= PAGE_READWRITE;
	}
	if (section->Characteristics & IMAGE_SCN_MEM_READ) {
		convert_res &= PAGE_READONLY;
	}
	if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
		convert_res &= PAGE_EXECUTE;
	}
	return convert_res;
}


/*
	写入段.根据段描述编辑权限
*/
void WriteSections(char* virtual_address, char* file_buffer, _IMAGE_NT_HEADERS64* pe) {

	_IMAGE_SECTION_HEADER* section_ary = (_IMAGE_SECTION_HEADER*)(pe + 1);

	for (auto i = 0; i < pe->FileHeader.NumberOfSections; ++i) {

		auto cur_section = section_ary[i];

		std::memmove(
			virtual_address + cur_section.VirtualAddress
			, file_buffer + cur_section.PointerToRawData
			, cur_section.SizeOfRawData
		);

		VirtualProtect(
			virtual_address + cur_section.VirtualAddress
			, cur_section.SizeOfRawData
			, ConvertSectionRole(&cur_section)
			, &old_protect
		);
	}
}

/*
	查找导出函数. 
		序号
		名称
		地址
*/
template<typename _Ty,typename _OffsetTy = DWORD>
_Ty ReadExportAddressData(char* virtual_address, DWORD rva, int idx,bool ret_target_val = false) {
	_OffsetTy* address_ary = (_OffsetTy*)(virtual_address + rva);
	auto target_address = address_ary[idx];
	if (ret_target_val) {
		return (_Ty)target_address;
	}
	return (_Ty)(virtual_address + target_address);
}

struct ExportFunPack {
	int idx = {};
	std::string name = {};
	size_t virtual_address = {};
};
std::unordered_map<std::string, ExportFunPack> 
GetExportList(char* virtual_address, char* file_buffer, _IMAGE_NT_HEADERS64* pe) {

	std::unordered_map<std::string, ExportFunPack> res_list = {};

	auto virtual_range = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	
	IMAGE_EXPORT_DIRECTORY* export_directory = (IMAGE_EXPORT_DIRECTORY*)(virtual_address + virtual_range.VirtualAddress);

	for (auto i = 0u; i < export_directory->NumberOfNames; ++i) {

		/*读取导出*/
		auto name = ReadExportAddressData<char*>(virtual_address, export_directory->AddressOfNames, i);
		auto id = ReadExportAddressData<WORD, WORD>(virtual_address, export_directory->AddressOfNameOrdinals, i, true);
		auto fun_rva = ReadExportAddressData<size_t>(virtual_address, export_directory->AddressOfFunctions, id);

		res_list.emplace(
			name,
			ExportFunPack{
				id
				,name
				,fun_rva
			}
		);
	}

	return res_list;
}


int main()
{
	std::filesystem::path file_name = kProjectSourceDir"build_windows/bin/Debug/TestDll.dll";
	auto file_size = std::filesystem::file_size(file_name);
	char* buffer = new char[file_size] {};

	std::ifstream is(file_name, std::ios::binary);
	is.read(buffer, file_size);
	is.close();

	constexpr auto pe_size = sizeof(_IMAGE_NT_HEADERS64);

	auto dos = (_IMAGE_DOS_HEADER*)buffer;
	auto pe = (_IMAGE_NT_HEADERS64*)(buffer + dos->e_lfanew);
	auto sec_heard = (_IMAGE_SECTION_HEADER*)(buffer + dos->e_lfanew + pe_size);

	auto virtual_address = AllocVirtual(pe);
	WritePeHeard(virtual_address, buffer, pe);
	WriteSections(virtual_address, buffer, pe);

	auto export_list = GetExportList(virtual_address, buffer, pe);

	return 0;
}