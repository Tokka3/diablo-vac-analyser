#include "hooks.h"
#include "utility.h"
#include "gvars.h"
#include <iomanip>
#include "colour.hpp"
#include <time.h>

typedef int(__stdcall* t_originalRunFunc)(int scanId, DWORD* vacRequest, int vacRequestSize, PVOID returnBuffer, int* returnBufferSize);
typedef int(__cdecl* t_originalMainScan)(PVOID a1, PVOID a2, DWORD* a3);
t_originalRunFunc origRunFunc;

t_originalMainScan o_MainScan;
t_originalLoadModule o_LoadModule;


std::string folder;
std::string module_folder;
std::string request_folder;
std::string procid_dump_folder;
std::string scan_dump_folder;

// Function that references MainScan 1
std::map<UINT64, std::string> scanhashMap =
{
	//invalid modules
	std::make_pair(0xc0590d2ae24ec3d3, "crash"),

	std::make_pair(0xe7eaaddc6cd05213, "eventlog"), // scans all drivers
	std::make_pair(0x213b2aeb9407873e, "driver_scan"), // scans a specific driver more in depth
	//fully bypassed modules
	std::make_pair(0x807ee56c2128dc2d, "hwid"),
	std::make_pair(0xea2af2e2bce3220a, "handle"),
	std::make_pair(0xaab5578e266c1b61, "window"),
	std::make_pair(0x68a58bb36a53a7a4, "filemapping"),

	//unneeded modules
	std::make_pair(0x84b281f10dcac7f0, "processInfo1"),
	std::make_pair(0x2b8b9289eb65fced, "processInfo2"),
	std::make_pair(0xb154c9c7bf1070ff, "processInfo3"),

	std::make_pair(0xf0f0251921dfd9fa, "modsAndThreads1"),
	std::make_pair(0x6b6eec243d579bae, "modsAndThreads2"),
	std::make_pair(0xb67a7bf5058c3df9, "memScan"),
	std::make_pair(0x248314d144e9bbb0, "moreProcessInfo"),
	std::make_pair(0x4ff1f6019b33fd5f, "queryAndReadMem"),
	std::make_pair(0xfdc2028fa3b8286f, "readMem"),

	//low priority
	std::make_pair(0xb34c2e74f57f4d0a, "SCQUERY"),
	std::make_pair(0xa612337c5223f13a, "SNMP"),
	std::make_pair(0x2153e378b10e88f5, "BOOTREGKEYS"),
	std::make_pair(0x7ed519a82f6eda98, "SERVICEDEVICESTUFF"),
	std::make_pair(0x2fedf1d053df1095, "SCManager"),
	std::make_pair(0xfc3fc1debaf63c31, "SCManager2"),
	std::make_pair(0xe3dd26051927a54c, "CPUSTUFF"),


		std::make_pair(0x11fb8eef7be0370d, "ENUMERATETHREADS"),

		std::make_pair(0xe19485b2c8387cc4, "HUGESCAN"),
	std::make_pair(0xce10bf36fc2a548b, "ADVANCEDPROCINFO"),
		std::make_pair(0x32ccb640a26e7d68, "ENUMPROCHANDLE"),
		//wip
		std::make_pair(0xeee57d9442e9d36f, "USN"),
		std::make_pair(0x463a5b2296ae616b, "SYSCALLSTUFF")
};

std::map<PVOID, int> moduleCounter{

};
std::map<int, bool> moduleLoaded{

};

std::map<PVOID, ModuleInfo*> module_data{

};

ModuleInfo* clone;

static int hashId = 0;

PVOID originaltemp;
PVOID main_scan_offset_c;
PVOID main_scan_original;
PVOID scan_add;

struct _MAIN_SCAN {
	PVOID main_scan_address;
	int main_scan_count;
};

struct VAC_FUNCTION {
	std::vector<_MAIN_SCAN> mainscan_fns;
	std::vector<PVOID> mainscan_ref_fns;
	std::vector<PVOID> sorted_addresses;

};
std::map<UINT64, int> scanRepeatCount{

};

VAC_FUNCTION vac_fncs;

struct _MAIN_SCAN_INFO {
	PVOID original_address;
	std::string identifier;
};
int __cdecl MainScan(_MAIN_SCAN_INFO* test, PVOID a1, PVOID a2, DWORD* a3) {
	
	std::cout << "test: " << test->identifier << std::endl;
	std::cout << "a1: " << a1 << std::endl;
	std::cout << "a2: " << a2 << std::endl;
	std::cout << "a3: " << *a3 << std::endl;

	std::cout << "mainscan hook called: " <<  test << std::endl;
	Sleep(2000);
	o_MainScan = (t_originalMainScan)test->original_address;
	DWORD returnVal = o_MainScan(a1, a2, a3);
	std::cout << "main scan hook called: " << std::hex << a2 << " | " << std::hex << &a2 << " | " << std::hex << (PVOID)a2 << std::endl;

	utility::DumpDataToDisk(a2, *a3, scan_dump_folder + "\\scandump_" + test->identifier  + ".txt");
	utility::DumpDataToDisk(a1, 176, scan_dump_folder + "\\scanreq_" + test->identifier + ".txt");


	return returnVal;
}



int __stdcall HkRunFunc(int scanId, DWORD* vacRequest, int vacRequestSize, PVOID returnBuffer, int* returnBufferSize)
{
	moduleCounter[originaltemp]++;

	std::cout << "path runfunc: " << request_folder << std::endl;
	//std::cout << "hkfunc for original: " << originaltemp << " called " << std::endl;

	clone->runfunc = originaltemp;

	//   std::cout << "hkfunc reset \n \n" << std::endl;

	utility::DumpDataToDisk(vacRequest, vacRequestSize, request_folder + "\\req_" + std::to_string(module_data[originaltemp]->crc32) + "." + std::to_string(moduleCounter[originaltemp]) + ".txt");
	utility::DumpWindowsInfo(procid_dump_folder + "\\procdump_" + std::to_string(module_data[originaltemp]->crc32) + "." + std::to_string(moduleCounter[originaltemp]) + ".txt");
	return origRunFunc(scanId, vacRequest, vacRequestSize, returnBuffer, returnBufferSize);
}

#include <winternl.h>

int module_count = 0;

void log_error(std::string str) {
	std::cout << dye::red(str) << " " << std::hex << GetLastError() << std::endl;
	Sleep(1000);
	//exit(0);

}
// steamservice.dll


DWORD __stdcall LoadModuleHk(ModuleInfo* ModuleStruct, char flags) {
	time_t _tm = time(NULL);

	struct tm* curtime = localtime(&_tm);

	std::cout << "load module hook called: " << ModuleStruct->crc32   << " | " <<asctime(curtime) << std::endl;
	std::cout << "path: " << module_folder << std::endl;


	if (!moduleLoaded[ModuleStruct->crc32]) {
		std::string modCounterString = module_folder + "\\VAC_" + std::to_string(ModuleStruct->crc32) + ".dll";
		HANDLE hFile = CreateFileA((LPCSTR)modCounterString.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile) {
			DWORD BytesWritten = 0;
			WriteFile(hFile, ModuleStruct->origImage, ModuleStruct->size, &BytesWritten, 0);
			std::cout << "wrote " << BytesWritten << " bytes. \n";
			CloseHandle(hFile);
		}
		else {
			std::cout << "failed to create file handle: " << GetLastError() << std::endl;
		}

		moduleLoaded[ModuleStruct->crc32] = true;

	}
	// identify unmapped module mainscan

	DWORD text_add = get_section_address(ModuleStruct->origImage, ".text");

	if (!text_add) {
		log_error("failed to get text address");
	}
	else {
		PDWORD function_list = (PDWORD)((DWORD)ModuleStruct->origImage + text_add + 0x4);

		if (!function_list) {
			log_error("failed to get function list");
		}
		else {
			int main_scan_count = 0;

			for (int i = 0; i < 100000000; i++) { // looping through function list



				PBYTE function_address = (PBYTE)(function_list[i]);
				//	std::cout << "loop " << std::endl;

				if (!function_address) break;

				//std::cout << "function address: " << std::hex << DWORD(function_address) << std::endl;
				function_address = (PBYTE)resolve_relative_address(ModuleStruct->origImage, (DWORD)function_address);
				if (*(BYTE*)(function_address) != 0xA1) break;
				

				//	PrintData(function_address, 8);

				if (!function_address) break;

				PVOID scan_add{};
				module_count++;
				for (function_address;; function_address += sizeof(byte)) { // looping through the bytes in each function to check for return

					BYTE curr_byte = *function_address;


					if (curr_byte == 0xC3) {

						break; // return opcode
					}
					if (curr_byte == 0xA1) {
					
						//function_address += 5;
						continue;
					}

					if (curr_byte == 0xA3) {

						DWORD* addr = *(DWORD**)(function_address + 1);

						addr = (DWORD*)resolve_relative_address(ModuleStruct->origImage, (DWORD)addr);

						if (addr[0] == 0 && addr[2] == 1) {
				

							DWORD* curr_ref = addr;
							DWORD scan_fn_virt = curr_ref[3];

							scan_add = (PVOID)resolve_relative_address(ModuleStruct->origImage, (DWORD)(scan_fn_virt));
							main_scan_count++;
							// std::cout << "scan_add found " << std::hex << (DWORD)scan_add << std::endl;
							PVOID mainscan_fnc_add = scan_add;

							//  PrintData((PBYTE)mainscan_fnc_add, 40);
							_MAIN_SCAN add;

							add.main_scan_address = mainscan_fnc_add;

							add.main_scan_count = main_scan_count;


							vac_fncs.mainscan_fns.emplace_back(add);
							vac_fncs.mainscan_ref_fns.emplace_back(function_address);
							//PrintData((PBYTE)mainscan_fnc_add, 8);
						}
					}



				}



			}
			for (_MAIN_SCAN add : vac_fncs.mainscan_fns) {
				vac_fncs.sorted_addresses.emplace_back(add.main_scan_address);
			}
			for (PVOID main_scan_ref : vac_fncs.mainscan_ref_fns) {
				vac_fncs.sorted_addresses.emplace_back(main_scan_ref);
			}
			std::sort(vac_fncs.sorted_addresses.begin(), vac_fncs.sorted_addresses.end());

			auto next_add = [](PVOID add) -> DWORD { // gets the next address because mainscan function is always followed by the reference func or another mainscan  
				bool ready = false;
				for (PVOID address : vac_fncs.sorted_addresses) {
					//	std::cout <<"sort add: " <<  address << std::endl;
					if (ready && add != address) return (DWORD)address; // add != address because some module has two ref funcs for the same mainscan
					if (address == add) ready = true;

				}
			};

		
			std::cout << std::setw(10) << dye::light_green("count unmapped");
			std::cout << std::setw(15) << dye::light_green("address");
			std::cout << std::setw(15) << dye::light_green("ref address");
			std::cout << std::setw(15) << dye::light_green("size");
			std::cout << std::setw(25) << dye::light_green("repeat count");
			std::cout << std::setw(25) << dye::light_green("hash");
			std::cout << std::setw(15) << dye::light_green("identifier") << std::endl; ;

			for (int i = 0; i < main_scan_count; i++) {
				DWORD size = next_add(vac_fncs.mainscan_fns[i].main_scan_address) - DWORD(vac_fncs.mainscan_fns[i].main_scan_address);

				UINT64 hash = 0;
				UINT64* fnAddr = (UINT64*)vac_fncs.mainscan_fns[i].main_scan_address;
				for (size_t i = 0; i < size / sizeof(UINT64); i++)
				{
					hash += fnAddr[i];
				}

				
				std::cout << std::setw(10) << vac_fncs.mainscan_fns[i].main_scan_count;
				std::cout << std::setw(15) << std::hex << vac_fncs.mainscan_fns[i].main_scan_address;
				std::cout << std::setw(15) << std::hex << vac_fncs.mainscan_ref_fns[i];
				std::cout << std::setw(15) << std::hex << size;
				std::cout << std::setw(25) << scanRepeatCount[hash];
				std::cout << std::setw(25) << std::hex << hash;
				if (scanhashMap[hash].empty()) {
					std::cout << std::setw(15) << dye::yellow("unknown") << std::endl;
				}
				else {
					std::cout << std::setw(15) << dye::yellow(scanhashMap[hash]) << std::endl;
				

					if (scanhashMap[hash] == "crash"){
						std::cout << "returning from crash module" << std::endl;
						return o_LoadModule(ModuleStruct, flags);
				}

				}

				scanRepeatCount[hash]++;

			}

			vac_fncs.mainscan_fns.clear();
			vac_fncs.mainscan_ref_fns.clear();
			vac_fncs.sorted_addresses.clear();
		}

		}

		





	DWORD returnVal = o_LoadModule(ModuleStruct, flags);



	DWORD text_section_add = (DWORD)ModuleStruct->mappedMod->moduleBase + utility::GetSectionVa(ModuleStruct->mappedMod->moduleBase, ".text");

	PDWORD function_list = (PDWORD)((DWORD)text_section_add + 0x4);

	int main_scan_count = 0; // this is used to identify the next function in order to calculate size


	for (int i = 0; i < 100000000; i++) { // looping through function list



		PBYTE function_address = (PBYTE)(function_list[i]);
		if (*(BYTE*)(function_address) != 0xA1) break;


		if (!function_address) break;

		//std::cout << "function address: " << std::hex << DWORD(function_address) << std::endl;

		//	PrintData(function_address, 20);


		PVOID scan_add{};
		int byte_count = 0;
		for (function_address;; function_address += sizeof(byte)) { // looping through the bytes in each function to check for return
			BYTE curr_byte = *function_address;


			if (curr_byte == 0xC3) {
			
				break; // return opcode
			}
			if (curr_byte == 0xA1) {
			
				//function_address += 5;
				continue;
			}

			if (curr_byte == 0xA3) {

				DWORD* addr = *(DWORD**)(function_address + 1);

			

				if (addr[0] == 0 && addr[2] == 1) {
				

					DWORD* curr_ref = addr;
					DWORD scan_fn_virt = curr_ref[3];
					
				
					main_scan_count++;
					// std::cout << "scan_add found " << std::hex << (DWORD)scan_add << std::endl;
					PVOID mainscan_fnc_add = (PVOID)scan_fn_virt;
					
					

					BYTE main_scan_hk[] =
					
						{
					/*0*/	0x8B, 0x4C, 0x24, 0x0C, // mov ecx , [esp + 12]
					/*4*/	0x51, // push ecx
					/*5*/	0x8B, 0x4C, 0x24, 0x0C,  // mov ecx , [esp + 12]
					/*9*/	0x51,// push ecx
					/*10*/	0x8B, 0x4C, 0x24, 0x0C,  // mov ecx , [esp + 12]
					/*14*/	0x51,// push ecx
					/*15*/	0x68, 0x11, 0x11, 0x11, 0x11, // push our arg
					/*20*/	0x68, 0x33, 0x33, 0x33, 0x33, // push address to return, virtualalloc add + offset (31) (add esp 16) 
					/*25*/	0x68, 0x22, 0x22, 0x22, 0x22, // push hook address
					/*30*/	0xC3, // ret (jump to hook address)
					/*31*/	0x83, 0xC4, 0x10, // add esp 16 (clean stack)
					/*34*/	0xC3  // ret
					}
					;
					_MAIN_SCAN_INFO scan_info;
					scan_info.original_address = mainscan_fnc_add;
					scan_info.identifier = "get_fucked";

					PVOID scan_info_str = VirtualAlloc(0, sizeof(_MAIN_SCAN_INFO), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
					memcpy(scan_info_str, &scan_info, sizeof(_MAIN_SCAN_INFO));

					PVOID hook_add = VirtualAlloc(0, sizeof(main_scan_hk), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

					*((DWORD*)&main_scan_hk[26]) = (DWORD)MainScan;

					*((DWORD*)&main_scan_hk[21]) = (DWORD)((DWORD)hook_add + 31);

					*((DWORD*)&main_scan_hk[16]) = (DWORD)scan_info_str;
					
					std::cout << "hook add " << hook_add << std::endl;

					DWORD oldProt = 0;

					VirtualProtect(hook_add, sizeof(main_scan_hk), PAGE_EXECUTE_READWRITE, &oldProt);

					memcpy(hook_add, main_scan_hk, sizeof(main_scan_hk));

					VirtualProtect(hook_add, sizeof(main_scan_hk), oldProt, &oldProt);

					curr_ref[3] = (DWORD)hook_add;


					//  PrintData((PBYTE)mainscan_fnc_add, 40);
					_MAIN_SCAN add;

					add.main_scan_address = mainscan_fnc_add;

					add.main_scan_count = main_scan_count;


					vac_fncs.mainscan_fns.emplace_back(add);
					vac_fncs.mainscan_ref_fns.emplace_back(function_address);
					//PrintData((PBYTE)mainscan_fnc_add, 8);
				}
			}



		}



	}

	//std::cout << function_count << " scan(s) found. " << std::endl;


	// ------ this section adds all the addresses of the reference func and the actual mainscan's them selves to a list ------
	for (_MAIN_SCAN add : vac_fncs.mainscan_fns) {
		vac_fncs.sorted_addresses.emplace_back(add.main_scan_address);
	}
	for (PVOID main_scan_ref : vac_fncs.mainscan_ref_fns) {
		vac_fncs.sorted_addresses.emplace_back(main_scan_ref);
	}
	std::sort(vac_fncs.sorted_addresses.begin(), vac_fncs.sorted_addresses.end());

	// ---------------- and then sorts -----------------------------------------------------------------------------


	auto next_add = [](PVOID add) -> DWORD { // gets the next address because mainscan function is always followed by the reference func or another mainscan  
		bool ready = false;
		for (PVOID address : vac_fncs.sorted_addresses) {
			//	std::cout <<"sort add: " <<  address << std::endl;
			if (ready && add != address) return (DWORD)address; // add != address because some module has two ref funcs for the same mainscan
			if (address == add) ready = true;

		}
	};



	std::cout << std::setw(10) << dye::light_green("count");
	std::cout << std::setw(15) << dye::light_green("address");
	std::cout << std::setw(15) << dye::light_green("ref address");
	std::cout << std::setw(15) << dye::light_green("size") << std::endl;

	for (int i = 0; i < main_scan_count; i++) {
		DWORD size = next_add(vac_fncs.mainscan_fns[i].main_scan_address) - DWORD(vac_fncs.mainscan_fns[i].main_scan_address);

		std::cout << std::setw(10) << vac_fncs.mainscan_fns[i].main_scan_count;
		std::cout << std::setw(15) << std::hex << vac_fncs.mainscan_fns[i].main_scan_address;
		std::cout << std::setw(15) << std::hex << vac_fncs.mainscan_ref_fns[i];
		std::cout << std::setw(4) << std::hex << size;


		UINT64 hash = 0;
		UINT64* fnAddr = (UINT64*)vac_fncs.mainscan_fns[i].main_scan_address;
		for (size_t i = 0; i < size / sizeof(UINT64); i++)
		{
			hash += fnAddr[i]; //read access violation: fnAddr was 0x50F1112

		}
		

	
		
		//VirtualProtect(vac_fncs.mainscan_fns[i].main_scan_address, sizeof(main_scan_hk), curProtection, &temp);
		if (scanhashMap[hash].empty()) {
			std::cout << dye::yellow("unknooeuwn") <<  " " << hash <<  std::endl;
		}
		else {
			std::cout << dye::yellow(scanhashMap[hash]) << std::endl;
		
			
		}

	}
	vac_fncs.mainscan_fns.clear();
	vac_fncs.sorted_addresses.clear();
	vac_fncs.mainscan_ref_fns.clear();



	//// exists within each and every ac module
	//origRunFunc = (t_originalRunFunc)ModuleStruct->runfunc;



	//clone = &(*ModuleStruct);
	//originaltemp = ModuleStruct->runfunc;
	//module_data[originaltemp] = ModuleStruct;
	//ModuleStruct->runfunc = &HkRunFunc;



	//std::cout << "changed: " << (PVOID)origRunFunc << " to " << ModuleStruct->runfunc << std::endl;

	return returnVal;


}