#include <Windows.h>
#include <winnt.h>
#include <fstream>
#include <filesystem>
#include <unordered_map>
#include <iostream>

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

	转发函数
	http://www.pnpon.com/article/detail-37.html
	https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets

	api set
	https://chromium.googlesource.com/external/github.com/DynamoRIO/dynamorio/+/cronbuild-7.0.17744/core/win32/loader.c
*/

DWORD old_protect = {};
bool MainIs64 = {};

char* RunPe(const std::string& file);

const char* FindPathAry[] = {
	"C:/Windows/System32/"
	,"C:/Windows/SysWOW64/"
	,"C:/Windows/System32/downlevel/"
	,"C:/Windows/SysWOW64/downlevel/"
	,kProjectSourceDir"build_windows/bin/Debug/"
	,"C:/Windows Kits/10/Redist/10.0.18362.0/ucrt/DLLs/x64/"
};

bool IsPe64Impl(std::string name) {
	auto file_size = std::filesystem::file_size(name);
	char* buffer = new char[file_size] {};

	std::ifstream is(name, std::ios::binary);
	is.read(buffer, file_size);
	is.close();

	auto dos = (_IMAGE_DOS_HEADER*)buffer;
	auto pe = (_IMAGE_NT_HEADERS64*)(buffer + dos->e_lfanew);

	bool res = pe->OptionalHeader.Magic == 0x20b;
	delete[] buffer;

	return res;
}
std::string MakePath(std::string name)
{
	for (auto path : FindPathAry) {
		if(std::filesystem::exists(path + name)) {
			if (IsPe64Impl(path + name) == MainIs64) {
				name = path + name;
			}
		}
	}

	return name;
}
bool IsPe64(std::string name) {

	name = MakePath(name);
	 
	if (not std::filesystem::exists(name)) {
		std::cout << "********** IsPe64 not find name: " << name << std::endl;
		return false;
	}

	return IsPe64Impl(name);
}
bool IsForwardApi(std::string name) {
	const char* cmp_str = "api-ms-win";
	return std::memcmp(name.c_str(), cmp_str, std::strlen(cmp_str)) == 0;
}

bool
str_case_prefix(const char* str, const char* pfx)
{
	while (true) {
		if (*pfx == '\0')
			return true;
		if (*str == '\0')
			return false;
		if (tolower(*str) != tolower(*pfx))
			return false;
		str++;
		pfx++;
	}
	return false;
}

static const char*
map_api_set_dll(const char* name, std::string dependent)
{
	/* Ideally we would read apisetschema.dll ourselves.
	 * It seems to be mapped in at 0x00040000.
	 * But this is simpler than trying to parse that dll's table.
	 * We ignore the version suffix ("-1-0", e.g.).
	 */
	if (str_case_prefix(name, "API-MS-Win-Core-APIQuery-L1"))
		return "ntdll.dll";
	else if (str_case_prefix(name, "API-MS-Win-Core-Console-L1"))
		return "kernel32.dll";
	else if (str_case_prefix(name, "API-MS-Win-Core-DateTime-L1"))
		return "kernel32.dll";
	else if (str_case_prefix(name, "API-MS-Win-Core-DelayLoad-L1"))
		return "kernel32.dll";
	else if (str_case_prefix(name, "API-MS-Win-Core-Debug-L1"))
		return "kernelbase.dll";
	else if (str_case_prefix(name, "API-MS-Win-Core-ErrorHandling-L1")) {
		/* This one includes {,Set}UnhandledExceptionFilter which are only in
		 * kernel32, but kernel32 itself imports GetLastError, etc.  which must come
		 * from kernelbase to avoid infinite loop.  XXX: what does apisetschema say?
		 * dependent on what's imported?
		 */
		if (str_case_prefix(dependent.c_str(), "kernel32.dll"))
			return "kernelbase.dll";
		else
			return "kernel32.dll";
	}
	else if (str_case_prefix(name, "API-MS-Win-Core-Fibers-L1"))
		return "kernelbase.dll";
	else if (str_case_prefix(name, "API-MS-Win-Core-File-L1"))
		return "kernelbase.dll";
	else if (str_case_prefix(name, "API-MS-Win-Core-Handle-L1"))
		return "kernelbase.dll";
	else if (str_case_prefix(name, "API-MS-Win-Core-Heap-L1"))
		return "kernelbase.dll";
	else if (str_case_prefix(name, "API-MS-Win-Core-Interlocked-L1"))
		return "kernelbase.dll";
	else if (str_case_prefix(name, "API-MS-Win-Core-IO-L1"))
		return "kernelbase.dll";
	else if (str_case_prefix(name, "API-MS-Win-Core-Localization-L1"))
		return "kernelbase.dll";
	else if (str_case_prefix(name, "API-MS-Win-Core-LocalRegistry-L1"))
		return "kernel32.dll";
	else if (str_case_prefix(name, "API-MS-Win-Core-LibraryLoader-L1"))
		return "kernelbase.dll";
	else if (str_case_prefix(name, "API-MS-Win-Core-Memory-L1"))
		return "kernelbase.dll";
	else if (str_case_prefix(name, "API-MS-Win-Core-Misc-L1"))
		return "kernelbase.dll";
	else if (str_case_prefix(name, "API-MS-Win-Core-NamedPipe-L1"))
		return "kernelbase.dll";
	else if (str_case_prefix(name, "API-MS-Win-Core-ProcessEnvironment-L1"))
		return "kernelbase.dll";
	else if (str_case_prefix(name, "API-MS-Win-Core-ProcessThreads-L1")) {
		/* This one includes CreateProcessAsUserW which is only in
		 * kernel32, but kernel32 itself imports from here and its must come
		 * from kernelbase to avoid infinite loop.  XXX: see above: seeming
		 * more and more like it depends on what's imported.
		 */
		if (str_case_prefix(dependent.c_str(), "kernel32.dll"))
			return "kernelbase.dll";
		else
			return "kernel32.dll";
	}
	else if (str_case_prefix(name, "API-MS-Win-Core-Profile-L1"))
		return "kernelbase.dll";
	else if (str_case_prefix(name, "API-MS-Win-Core-RTLSupport-L1")) {
		if (true ||
			(str_case_prefix(dependent.c_str(), "kernel.dll")))
			return "ntdll.dll";
		else
			return "kernel32.dll";
	}
	else if (str_case_prefix(name, "API-MS-Win-Core-String-L1"))
		return "kernelbase.dll";
	else if (str_case_prefix(name, "API-MS-Win-Core-Synch-L1"))
		return "kernelbase.dll";
	else if (str_case_prefix(name, "API-MS-Win-Core-SysInfo-L1"))
		return "kernelbase.dll";
	else if (str_case_prefix(name, "API-MS-Win-Core-ThreadPool-L1"))
		return "kernelbase.dll";
	else if (str_case_prefix(name, "API-MS-Win-Core-XState-L1"))
		return "ntdll.dll";
	else if (str_case_prefix(name, "API-MS-Win-Core-Util-L1"))
		return "kernelbase.dll";
	else if (str_case_prefix(name, "API-MS-Win-Security-Base-L1"))
		return "kernelbase.dll";
	else if (str_case_prefix(name, "API-MS-Win-Security-LSALookup-L1"))
		return "sechost.dll";
	else if (str_case_prefix(name, "API-MS-Win-Security-SDDL-L1"))
		return "sechost.dll";
	else if (str_case_prefix(name, "API-MS-Win-Service-Core-L1"))
		return "sechost.dll";
	else if (str_case_prefix(name, "API-MS-Win-Service-Management-L1"))
		return "sechost.dll";
	else if (str_case_prefix(name, "API-MS-Win-Service-Management-L2"))
		return "sechost.dll";
	else if (str_case_prefix(name, "API-MS-Win-Service-Winsvc-L1"))
		return "sechost.dll";
	/**************************************************/
	/* Added in Win8 */
	else if (str_case_prefix(name, "API-MS-Win-Core-Kernel32-Legacy-L1"))
		return "kernel32.dll";
	else if (str_case_prefix(name, "API-MS-Win-Core-Appcompat-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-BEM-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-Comm-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-Console-L2-1") ||
		str_case_prefix(name, "API-MS-Win-Core-File-L2-1") ||
		str_case_prefix(name, "API-MS-Win-Core-Job-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-Localization-L2-1") ||
		str_case_prefix(name, "API-MS-Win-Core-Localization-Private-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-Namespace-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-Normalization-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-ProcessTopology-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-Psapi-Ansi-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-Psapi-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-Psapi-Obsolete-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-Realtime-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-Registry-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-SideBySide-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-String-Obsolete-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-SystemTopology-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-Threadpool-Legacy-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-Threadpool-Private-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-Timezone-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-WOW64-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-WindowsErrorReporting-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Security-Appcontainer-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Security-Base-Private-L1-1"))
		return "kernelbase.dll";
	else if (str_case_prefix(name, "API-MS-Win-Core-Heap-Obsolete-L1-1"))
		return "kernel32.dll";
	else if (str_case_prefix(name, "API-MS-Win-Core-CRT-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-CRT-L2-1"))
		return "msvcrt.dll";
	else if (str_case_prefix(name, "API-MS-Win-Service-Private-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Security-Audit-L1-1"))
		return "sechost.dll";
	else if (str_case_prefix(name, "API-MS-Win-Eventing-Controller-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Eventing-Consumer-L1-1")) {
		/* i#1528: moved to sechost.dll on win8.1 */
		if (true)
			return "sechost.dll";
		else
			return "kernelbase.dll";
	}
	/**************************************************/
	/* Added in Win8.1 */
	else if (str_case_prefix(name, "API-MS-Win-Core-ProcessTopology-L1-2") ||
		str_case_prefix(name, "API-MS-Win-Core-XState-L2-1"))
		return "kernelbase.dll";
	else if (str_case_prefix(name, "API-MS-WIN-SECURITY-LSAPOLICY-L1"))
		return "advapi32.dll";
	/**************************************************/
	/* Added in Win10 (some may be 8.1 too) */
	else if (str_case_prefix(name, "API-MS-Win-Core-Console-L2-2") ||
		str_case_prefix(name, "API-MS-Win-Core-Console-L3-1") ||
		str_case_prefix(name, "API-MS-Win-Core-Console-L3-2") ||
		str_case_prefix(name, "API-MS-Win-Core-Enclave-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-Fibers-L2-1") ||
		str_case_prefix(name, "API-MS-Win-Core-Heap-L2-1") ||
		str_case_prefix(name, "API-MS-Win-Core-LargeInteger-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-LibraryLoader-L2-1") ||
		str_case_prefix(name, "API-MS-Win-Core-Localization-Obsolete-L1-2") ||
		str_case_prefix(name, "API-MS-Win-Core-Localization-Obsolete-L1-3") ||
		str_case_prefix(name, "API-MS-Win-Core-Path-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-PerfCounters-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-ProcessSnapshot-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-Psm-Key-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-Quirks-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-RegistryUserSpecific-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-SHLWAPI-Legacy-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-SHLWAPI-Obsolete-L1-2") ||
		str_case_prefix(name, "API-MS-Win-Core-String-L2-1") ||
		str_case_prefix(name, "API-MS-Win-Core-StringAnsi-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-URL-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-Version-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-VersionAnsi-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Eventing-Provider-L1-1"))
		return "kernelbase.dll";
	else if (str_case_prefix(name, "API-MS-Win-Core-PrivateProfile-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-Atoms-L1-1"))
		return "kernel32.dll";
	else if (str_case_prefix(name, "API-MS-Win-Core-WinRT-Error-L1-1"))
		return "combase.dll";
	else if (str_case_prefix(name, "API-MS-Win-Appmodel-Runtime-L1-1"))
		return "kernel.appcore.dll";
	else if (str_case_prefix(name, "API-MS-Win-GDI-")) {
		/* We've seen many different GDI-* */
		return "gdi32full.dll";
	}
	else if (str_case_prefix(name, "API-MS-Win-CRT-")) {
		/* We've seen CRT-{String,Runtime,Private} */
		return "ucrtbase.dll";
	}
	else if (str_case_prefix(name, "API-MS-Win-Core-COM-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-COM-Private-L1-1") ||
		str_case_prefix(name, "API-MS-Win-Core-WinRT-String-L1-1")) {
		return "combase.dll";
	}
	else if (str_case_prefix(name, "API-MS-Win-Core-Kernel32-Private-L1-1")) {
		return "kernel32.dll";
	}
	else {
		throw "unknown API-MS-Win pseudo-dll";
		/* good guess */
		return "kernelbase.dll";
	}
}


struct ForwardInfo {
	std::string mode_name = {};
	std::string func_name = {};
};
ForwardInfo AnalysisForwardStr(std::string str, std::string origin_module_name) {
	ForwardInfo ret = {};
	std::string* cur_str = &ret.mode_name;
	for (auto c : str) {
		if (c == '.') {
			cur_str = &ret.func_name;
			continue;
		}
		cur_str->push_back(c);
	}

	if (origin_module_name == ret.func_name 
		and  origin_module_name == "kernel32.dll"
	) {
		ret.mode_name = "kernelbase.dll";
	}
	else if(origin_module_name == ret.func_name){
		throw "import module == orgin module";
	}
	else {
		ret.mode_name += ".dll";
	}

	return ret;
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
	
	convert_res = section->Characteristics & IMAGE_SCN_MEM_WRITE ?
		section->Characteristics & IMAGE_SCN_MEM_EXECUTE ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE
		: section->Characteristics & IMAGE_SCN_MEM_EXECUTE ? PAGE_EXECUTE_READ : PAGE_READONLY;
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

	if (virtual_range.VirtualAddress == 0) {
		return res_list;
	}
	
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
std::vector<ExportFunPack>
GetExportListEx(const char* name) {
	auto module_vir_address = RunPe(name);
	if (module_vir_address == nullptr) {
		return {};
	}
	auto module_dos = (_IMAGE_DOS_HEADER*)module_vir_address;
	auto module_pe = (_Ty*)(module_vir_address + module_dos->e_lfanew);

	return GetExportList<_Ty>(module_vir_address, module_pe);
}

template<typename _Ty>
ExportFunPack GetExportInfoEx1(const char* name, const char* symbol_name) {
	auto module_export = GetExportListEx<_Ty>(name);
	auto iter = std::find_if(module_export.begin(), module_export.end(), [&](const ExportFunPack& pack) {
		return pack.name == symbol_name;
		});
	if (iter not_eq module_export.end()) {
		return *iter;
	}
	else {
		throw "not find symbol";
		return {};
	}
	
}

template<typename _Ty>
char* LoadModle(std::string name) {

	name = MakePath(name);

	if (not std::filesystem::exists(name)) {
		std::cout << "********** LoadModle not find name: " << name << std::endl;
		return nullptr;
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
void FixImportModuleImpl(char* virtual_address, IMAGE_IMPORT_DESCRIPTOR& import_descriptor, const std::string& origin_mode_name) {

	auto module_export = GetExportListEx<_SelfPeType>((char*)(virtual_address + import_descriptor.Name));
	if (IsForwardApi((char*)(virtual_address + import_descriptor.Name))) {
		module_export = GetExportListEx<_SelfPeType>(map_api_set_dll((char*)(virtual_address + import_descriptor.Name), origin_mode_name));
	}

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

			if ((char*)image_import->Name == std::string("GetSystemTimeAsFileTime")) {
				int number = 10;
			}

			/*转发api*/
			/*if (IsForwardApi((char*)(virtual_address + import_descriptor.Name))) {
				auto forward_info = AnalysisForwardStr((char*)iter->virtual_address, origin_mode_name); 
				auto froward_export_info = GetExportInfoEx1<_SelfPeType>(forward_info.mode_name.c_str(), forward_info.func_name.c_str());
				func_addr = froward_export_info.virtual_address;
			}
			else*/ if (iter not_eq module_export.end()) {
				func_addr = iter->virtual_address;
			}
			else {
				throw "can't find import symbol";
			}
		}
		else {
			/*数据是索引*/
			auto iter = std::find_if(module_export.begin(), module_export.end(), [&](const ExportFunPack& pack) {
				return pack.idx == (char)lookup_addr;
				});
			if (iter not_eq module_export.end()) {
				func_addr = iter->virtual_address;
			}
			else {
				throw "can't find import ordinal";
			}
		}
		DWORD back_protect;
		VirtualProtect(&address_table[i], sizeof(IMAGE_THUNK_DATA_TYPE), PAGE_READWRITE, &back_protect);

		address_table[i].u1.Function = (decltype(address_table[i].u1.Function))func_addr;

		VirtualProtect(&address_table[i], sizeof(IMAGE_THUNK_DATA_TYPE), back_protect, &back_protect);
	}

}

template<typename _Ty>
void FixImportModule(char* virtual_address, _Ty* pe, const std::string& origin_mode_name) {
	auto virtual_range = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	
	if (virtual_range.VirtualAddress == 0) {
		return;
	}

	IMAGE_IMPORT_DESCRIPTOR * import_descriptor = (IMAGE_IMPORT_DESCRIPTOR*)(virtual_address + virtual_range.VirtualAddress);

	for (int i = 0; import_descriptor[i].OriginalFirstThunk != 0; ++i) {

		if (IsPe64((char*)(virtual_address + import_descriptor[i].Name))) {
			FixImportModuleImpl<_IMAGE_NT_HEADERS64, _Ty>(
				virtual_address
				, import_descriptor[i]
				, origin_mode_name
				);
		}
		else {
			FixImportModuleImpl<_IMAGE_NT_HEADERS, _Ty>(
				virtual_address
				, import_descriptor[i]
				, origin_mode_name
				);
		}                 
	}
}

template<typename _Ty>
void FixImageBaseOffset(char* virtual_address, _Ty* pe) {

	using BitDataType = decltype(pe->OptionalHeader.ImageBase);

	BitDataType delta_va_reloc = (BitDataType)virtual_address - pe->OptionalHeader.ImageBase;

	auto virtual_range = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	if (virtual_range.VirtualAddress == 0) {
		return;
	}
	
	IMAGE_BASE_RELOCATION* relocation = (IMAGE_BASE_RELOCATION*)(virtual_address + virtual_range.VirtualAddress);

	while (relocation->VirtualAddress not_eq 0) {
		
		auto size = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
		WORD* reloc = (WORD*)(relocation + 1);

		for (auto i = 0; i < size; ++i) {
			auto type = reloc[i] >> 12;
			auto offset = reloc[i] & 0x0FFF;
			BitDataType* change_addr = (BitDataType*)(virtual_address + relocation->VirtualAddress + offset);

			switch (type)
			{
			case IMAGE_REL_BASED_HIGHLOW:
			case IMAGE_REL_BASED_DIR64:
				{
					DWORD back_protect;
					VirtualProtect(change_addr, sizeof(BitDataType), PAGE_READWRITE, &back_protect);

					*change_addr += delta_va_reloc;

					VirtualProtect(change_addr, sizeof(BitDataType), back_protect, &back_protect);
				}
				break;
			case IMAGE_REL_BASED_ABSOLUTE:
				/*文件内存对齐*/
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

char* RunPe(const std::string& file) {

	static std::unordered_map<std::string, char*> cache = {};

	if (cache.contains(file)) {
		return cache[file];
	}

	char* virtual_addr = nullptr;
	void(*enter_point)() = nullptr;

	if (MainIs64) {
		virtual_addr = LoadModle<_IMAGE_NT_HEADERS64>(file);
		if (virtual_addr == nullptr) {
			cache[file] = virtual_addr;
			return virtual_addr;
		}

		cache[file] = virtual_addr;

		auto dos = (_IMAGE_DOS_HEADER*)virtual_addr;
		auto pe = (_IMAGE_NT_HEADERS64*)(virtual_addr + dos->e_lfanew);

		FixImportModule(virtual_addr, pe, file);


		if (file == kProjectSourceDir"build_windows/bin/Debug/Test.exe") {
			int number = 10;
		}

		FixImageBaseOffset(virtual_addr, pe);

		enter_point = (void(*)())(virtual_addr + pe->OptionalHeader.AddressOfEntryPoint);
	}
	else {
		virtual_addr = LoadModle<_IMAGE_NT_HEADERS>(file);
		if (virtual_addr == nullptr) {
			cache[file] = virtual_addr;
			return virtual_addr;
		}

		cache[file] = virtual_addr;

		auto dos = (_IMAGE_DOS_HEADER*)virtual_addr;
		auto pe = (_IMAGE_NT_HEADERS*)(virtual_addr + dos->e_lfanew);

		FixImportModule(virtual_addr, pe, file);
		FixImageBaseOffset(virtual_addr, pe);

		enter_point = (void(*)())(virtual_addr + pe->OptionalHeader.AddressOfEntryPoint);
	}

	std::cout << "load pe: " << file <<" call enter_point: " << (void*)((size_t)enter_point - (size_t)virtual_addr) << std::endl;

	if ((char*)enter_point not_eq virtual_addr) {
		if (file == kProjectSourceDir"build_windows/bin/Debug/Test.exe") {
			enter_point();
		}
		else {
			enter_point();
		}
		
	}

	return virtual_addr;
}

int main()
{
	std::filesystem::path file_name = kProjectSourceDir"build_windows/bin/Debug/Test.exe";
	MainIs64 = IsPe64(file_name.string());
	RunPe(file_name.string());

	return 0;
}