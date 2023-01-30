#include "hooks.h"
#include "utility.h"
#include "gvars.h"

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
     
      //  system("pause");
        PVOID func_address = PVOID(text_section_add + 0x4);
     
        //system("pause");
        PVOID new_add = *(PVOID*)func_address;

        DWORD add = (DWORD)new_add;

        for (add;; add += sizeof(byte)) {

            BYTE curr_byte = *(BYTE*)(add);
            if (curr_byte == 0xC7) { // 0xc7 is byte for return address 
             
                     add -= 5;
                    scan_add = *(PVOID*)(add + 1);
                    std::cout << "mainscan add found: " << std::hex << scan_add << std::endl;
                    break;
            }
        }
      
        main_scan_offset_c = *(PVOID*)((DWORD)scan_add + 0xC);
        
        if (MH_CreateHook(main_scan_offset_c, &MainScan, (void**)&o_MainScan) == MH_OK) {
            std::cout << "main scan hook created" << std::endl;

            MH_EnableHook(MH_ALL_HOOKS);
        }

        std::cout << "main_scan_offset: " << main_scan_offset_c << std::endl;



    

        // main_scan_original = main_scan_add;
   

       

   


     
      


  
    // exists within each and every ac module
    origRunFunc = (t_originalRunFunc)ModuleStruct->runfunc;

   

    clone = &(*ModuleStruct);
    originaltemp = ModuleStruct->runfunc;
    module_data[originaltemp] = ModuleStruct;
    ModuleStruct->runfunc = &HkRunFunc;



    std::cout << "changed: " << (PVOID)origRunFunc << " to " << ModuleStruct->runfunc << std::endl;

    return returnVal;


}
