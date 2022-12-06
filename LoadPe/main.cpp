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
bool MainIs64 = {};

bool IsPe64(std::string name) {
	if (std::filesystem::exists("C:/Windows/System32/" + name) and MainIs64) {
		name = "C:/Windows/System32/" + name;
	}
	else if (std::filesystem::exists("C:/Windows/SysWOW64/" + name) and not MainIs64) {
		name = "C:/Windows/SysWOW64/" + name;
	}
	 
	if (not std::filesystem::exists(name)) {
		return false;;
	}

	auto file_size = std::filesystem::file_size(name);
	char* buffer = new char[file_size] {};

	std::ifstream is(name, std::ios::binary);
	is.read(buffer, file_size);
	is.close();

	auto dos = (_IMAGE_DOS_HEADER*)buffer;
	auto pe = (_IMAGE_NT_HEADERS64*)(buffer + dos->e_lfanew);

	return pe->OptionalHeader.Magic == 0x20b;
}

template<typename _Ty>
char* AllocVirtual(_Ty* pe) {
	/*
		https://baike.baidu.com/item/VirtualAlloc/1606859
	*/
	return (char*)VirtualAlloc(nullptr, pe->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
}

/*
	pe 头写入内存,仅可读
*/
template<typename _Ty>
void WritePeHeard(char* virtual_address, char* file_buffer, _Ty* pe) {
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
template<typename _Ty>
void WriteSections(char* virtual_address, char* file_buffer, _Ty* pe) {

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
template<typename _Ty>
std::vector<ExportFunPack> 
GetExportList(char* virtual_address, _Ty* pe) {

	std::vector<ExportFunPack>  res_list = {};

	auto virtual_range = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	
	IMAGE_EXPORT_DIRECTORY* export_directory = (IMAGE_EXPORT_DIRECTORY*)(virtual_address + virtual_range.VirtualAddress);

	for (auto i = 0u; i < export_directory->NumberOfNames; ++i) {

		/*读取导出*/
		auto name = ReadExportAddressData<char*>(virtual_address, export_directory->AddressOfNames, i);
		auto id = ReadExportAddressData<WORD, WORD>(virtual_address, export_directory->AddressOfNameOrdinals, i, true);
		auto fun_rva = ReadExportAddressData<size_t>(virtual_address, export_directory->AddressOfFunctions, id);

		res_list.push_back(
			ExportFunPack{
				id
				,name
				,fun_rva
			}
		);
	}

	return res_list;
}

template<typename _Ty>
char* LoadModle(std::string name) {

	if (std::filesystem::exists("C:/Windows/System32/" + name) and MainIs64) {
		name = "C:/Windows/System32/" + name;
	}
	else if (std::filesystem::exists("C:/Windows/SysWOW64/" + name) and not MainIs64) {
		name = "C:/Windows/SysWOW64/" + name;
	}

	if (not std::filesystem::exists(name)) {
		return nullptr;;
	}

	auto file_size = std::filesystem::file_size(name);
	char* buffer = new char[file_size] {};

	std::ifstream is(name, std::ios::binary);
	is.read(buffer, file_size);
	is.close();

	auto dos = (_IMAGE_DOS_HEADER*)buffer;
	auto pe = (_Ty*)(buffer + dos->e_lfanew);
	auto virtual_address = AllocVirtual(pe);
	WritePeHeard(virtual_address, buffer, pe);
	WriteSections(virtual_address, buffer, pe);

	delete[] buffer;

	return virtual_address;
}

template<typename _ModuleTy,typename _SelfPeType>
void FixImportModuleImpl(char* virtual_address, IMAGE_IMPORT_DESCRIPTOR& import_descriptor) {
	auto module_vir_address = LoadModle<_ModuleTy>((char*)(virtual_address + import_descriptor.Name));
	auto module_dos = (_IMAGE_DOS_HEADER*)module_vir_address;
	auto module_pe = (_ModuleTy*)(module_vir_address + module_dos->e_lfanew);

	auto module_export = GetExportList(module_vir_address, module_pe);

	using IMAGE_THUNK_DATA_TYPE = std::conditional_t<std::is_same_v<_SelfPeType, _IMAGE_NT_HEADERS64>, IMAGE_THUNK_DATA64, IMAGE_THUNK_DATA32 >;

	IMAGE_THUNK_DATA_TYPE* lookup_table = (IMAGE_THUNK_DATA_TYPE*)(virtual_address + import_descriptor.OriginalFirstThunk);
	IMAGE_THUNK_DATA_TYPE* address_table = (IMAGE_THUNK_DATA_TYPE*)(virtual_address + import_descriptor.FirstThunk);

	for (int i = 0; lookup_table[i].u1.AddressOfData != 0; ++i) {
		auto lookup_addr = lookup_table[i].u1.AddressOfData;
		size_t use_ordinal_role = (lookup_addr & (std::is_same_v<_ModuleTy, _IMAGE_NT_HEADERS64> ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32));
		size_t func_addr = {};
		if (use_ordinal_role == 0) {
			/*使用位置查找name*/
			IMAGE_IMPORT_BY_NAME* image_import = (IMAGE_IMPORT_BY_NAME*)(virtual_address + lookup_addr);
			auto iter = std::find_if(module_export.begin(), module_export.end(), [&](const ExportFunPack & pack) {
				return pack.name == (char*)image_import->Name;
				});
			if (iter not_eq module_export.end()) {
				func_addr = iter->virtual_address;
			}
			else {
				throw "can't find import symbol";
			}
		}
		else {
			/*数据是索引*/
			auto iter = std::find_if(module_export.begin(), module_export.end(), [&](const ExportFunPack& pack) {
				return pack.idx == lookup_addr;
				});
			if (iter not_eq module_export.end()) {
				func_addr = iter->virtual_address;
			}
			else {
				throw "can't find import ordinal";
			}
		}
		address_table[i].u1.Function = (decltype(address_table[i].u1.Function))func_addr;
	}

}

template<typename _Ty>
void FixImportModule(char* virtual_address, _Ty* pe) {
	auto virtual_range = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	IMAGE_IMPORT_DESCRIPTOR * import_descriptor = (IMAGE_IMPORT_DESCRIPTOR*)(virtual_address + virtual_range.VirtualAddress);

	for (int i = 0; import_descriptor[i].OriginalFirstThunk != 0; ++i) {

		if (IsPe64((char*)(virtual_address + import_descriptor[i].Name))) {
			FixImportModuleImpl<_IMAGE_NT_HEADERS64, _Ty>(
				virtual_address
				, import_descriptor[i]
				);
		}
		else {
			FixImportModuleImpl<_IMAGE_NT_HEADERS, _Ty>(
				virtual_address
				, import_descriptor[i]
				);
		}                 
	}
}

void FixImageBaseOffset(char* virtual_address, _IMAGE_NT_HEADERS64* pe) {

	using BitDataType = decltype(pe->OptionalHeader.ImageBase);

	BitDataType delta_va_reloc = (BitDataType)virtual_address - pe->OptionalHeader.ImageBase;

	auto virtual_range = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	
	IMAGE_BASE_RELOCATION* relocation = (IMAGE_BASE_RELOCATION*)(virtual_address + virtual_range.VirtualAddress);

	while (relocation->VirtualAddress not_eq 0) {
		
		auto size = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
		WORD* reloc = (WORD*)(relocation + 1);

		for (auto i = 0; i < size; ++i) {
			auto type = reloc[i] >> 12;
			auto offset = reloc[i] & 0x0FFF;
			BitDataType* change_addr = (BitDataType*)(virtual_address + virtual_range.VirtualAddress + offset);

			switch (type)
			{
			case IMAGE_REL_BASED_HIGHLOW:
			case IMAGE_REL_BASED_DIR64:
				{
					*change_addr += delta_va_reloc;
				}
				break;
			default:
				throw "re loaction type not find process";
				break;
			}
		}

		/* go next block */
		relocation = (IMAGE_BASE_RELOCATION*)(((char*)relocation) + relocation->SizeOfBlock);
	}
}

int main()
{
	MainIs64 = true;

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
	FixImportModule(virtual_address, pe);
	FixImageBaseOffset(virtual_address, pe);

	auto export_list = GetExportList(virtual_address, pe);

	return 0;
}