#include "hooks.h"
#include "utility.h"
#include "gvars.h"
#include <iomanip>
#include "colour.hpp"

typedef int(__stdcall* t_originalRunFunc)(int scanId, DWORD* vacRequest, int vacRequestSize, PVOID returnBuffer, int* returnBufferSize);
typedef int ( __cdecl* t_originalMainScan)(PVOID a1, PVOID a2, DWORD* a3);
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

     //fully bypassed modules
     std::make_pair(0xa00dbf237edd5a2f, "hwid"),
     std::make_pair(0xea2af2e2bce3220a, "handle"),
     std::make_pair(0xaab5578e266c1b61, "window"),
     std::make_pair(0x68a58bb36a53a7a4, "filemapping"),

     //unneeded modules
     std::make_pair(0x2f28f009f9674643, "processInfo1"),
     std::make_pair(0xb219318b5e3a74c3, "processInfo2"),
     std::make_pair(0xda4778bb56d2989, "processInfo3"),
     std::make_pair(0xf0f0251921dfd9fa, "modsAndThreads1"),
     std::make_pair(0x6b6eec243d579bae, "modsAndThreads2"),
     std::make_pair(0xb59a2f53422e586e, "memScan"),
     std::make_pair(0x8bded48bbea11906, "moreProcessInfo"),
     std::make_pair(0x4ff1f6019b33fd5f, "queryAndReadMem"),
     std::make_pair(0xfdc2028fa3b8286f, "readMem"),

     //low priority
     std::make_pair(0xb34c2e74f57f4d0a, "SCQUERY"),
     std::make_pair(0xa612337c5223f13a, "SNMP"),
     std::make_pair(0x2153e378b10e88f5, "BOOTREGKEYS"),
     std::make_pair(0x7e14cd062f6edb31, "SERVICEDEVICESTUFF"),
     std::make_pair(0xd3dc7554776447f1, "CPUSTUFF"),

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


VAC_FUNCTION vac_fncs;

int __cdecl MainScan(PVOID a1, PVOID a2, DWORD* a3) {

    DWORD returnVal = o_MainScan(a1, a2, a3);
    std::cout << "main scan hook called: " <<  std::hex << a2  << " | " << std::hex <<  &a2 << " | " << std::hex << (PVOID)a2 << std::endl;

    utility::DumpDataToDisk(a2, *a3, scan_dump_folder + "\\scandump_" + std::to_string(module_data[originaltemp]->crc32) + "." + std::to_string(moduleCounter[originaltemp]) + ".txt");
    utility::DumpDataToDisk(a1, 176, scan_dump_folder + "\\scanreq_" + std::to_string(module_data[originaltemp]->crc32) + "." + std::to_string(moduleCounter[originaltemp]) + ".txt");
 
   
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


char mov_addr_rax[] = "\xA3\x00\x00\x00\x00";

// steamservice.dll
DWORD __stdcall LoadModuleHk(ModuleInfo* ModuleStruct, char flags) {

    
    std::cout << "load module hook called: " << ModuleStruct->crc32 << std::endl;
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

			for (function_address;; function_address += sizeof(byte)) { // looping through the bytes in each function to check for return

				BYTE curr_byte = *(BYTE*)(function_address);

				if (curr_byte == 0xC7) { // 0xc7 is byte for return address 

					function_address -= 5;

					scan_add = *(PVOID*)(function_address + 1);

					
					//PrintData(function_address, 20);


					if (scan_add) {

						main_scan_count++;
						// std::cout << "scan_add found " << std::hex << (DWORD)scan_add << std::endl;
						PVOID mainscan_fnc_add = *(PVOID*)((DWORD)scan_add + 0xC);
						
						//  PrintData((PBYTE)mainscan_fnc_add, 40);
						_MAIN_SCAN add;

						add.main_scan_address = mainscan_fnc_add;

						add.main_scan_count = main_scan_count;


						vac_fncs.mainscan_fns.emplace_back(add);
						vac_fncs.mainscan_ref_fns.emplace_back(function_address);
						//PrintData((PBYTE)mainscan_fnc_add, 8);
					}
					break;
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
				hash += fnAddr[i];
			}
			if (scanhashMap[hash].empty()) {
				std::cout << dye::yellow("unknown") << std::endl;
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
