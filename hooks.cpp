#include "hooks.h"
#include "utility.h"
#include "gvars.h"

typedef int(__stdcall* t_originalRunFunc)(int scanId, DWORD* vacRequest, int vacRequestSize, PVOID returnBuffer, int* returnBufferSize);

t_originalRunFunc origRunFunc;


t_originalLoadModule o_LoadModule;


 std::string folder;
 std::string module_folder;
 std::string request_folder;
 std::string procid_dump_folder;



std::map<PVOID, int> moduleCounter{

};
std::map<int, bool> moduleLoaded{

};

std::map<PVOID, ModuleInfo*> module_data{

};

ModuleInfo* clone;

static int hashId = 0;

PVOID originaltemp;
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




// steamservice.dll
DWORD __stdcall LoadModuleHk(ModuleInfo* ModuleStruct, char flags) {


    



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
    std::cout << "load module hook called: " << ModuleStruct->crc32 << std::endl;
    std::cout << "path: " << module_folder << std::endl;
    DWORD returnVal = o_LoadModule(ModuleStruct, flags);

    std::cout << ModuleStruct->runfunc << std::endl;
    // exists within each and every ac module
    origRunFunc = (t_originalRunFunc)ModuleStruct->runfunc;


    clone = &(*ModuleStruct);
    originaltemp = ModuleStruct->runfunc;
    module_data[originaltemp] = ModuleStruct;
    ModuleStruct->runfunc = &HkRunFunc;

    std::cout << "changed: " << (PVOID)origRunFunc << " to " << ModuleStruct->runfunc << std::endl;

    return returnVal;


}
