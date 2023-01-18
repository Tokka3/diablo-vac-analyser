#include <windows.h>
#include <iostream>
#include <Psapi.h>
#include "include/MinHook.h"
#include <map>
#include <string>
struct MapModuleReturn
{
    PVOID unknown;
    PVOID moduleBase;
    PIMAGE_NT_HEADERS32 ntHeaders;
    HMODULE* hMod;
    PVOID unknown1;
};
struct ModuleInfo
{
    ULONG crc32;
    HMODULE hmod;
    MapModuleReturn* mappedMod;
    PVOID runfunc;
    ULONG lastStatus;
    ULONG size;
    PVOID origImage;
};


std::map<int, int> moduleCounter{

};
std::map<int, bool> moduleLoaded{

};
BOOL DumpDataToDisk(PVOID data, ULONG size, std::string path)
{
    HANDLE fileHandle = CreateFileA(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (!fileHandle)
    {
        printf("Failed to create dump file %X\n", GetLastError());
        return GetLastError();
    }

    BOOL writeStat = WriteFile(fileHandle, data, size, 0, 0);
    if (!writeStat)
    {
        printf("Failed to dump module %X\n", GetLastError());
        CloseHandle(fileHandle);
        return GetLastError();
    }


    CloseHandle(fileHandle);
    return writeStat;
}

typedef int(__stdcall* t_originalRunFunc)(int scanId, DWORD* vacRequest, int vacRequestSize, PVOID returnBuffer, int* returnBufferSize);

PVOID origRunFunc;

static int hashId = 0;

int __stdcall HkRunFunc(int scanId, DWORD* vacRequest, int vacRequestSize, PVOID returnBuffer, int* returnBufferSize)
{
    int scanRet = (*(int(__stdcall**)(int, PVOID, int, PVOID, int*))(&origRunFunc))(scanId, vacRequest, vacRequestSize, returnBuffer, returnBufferSize);

    printf("done with scan %i\n", scanRet);
    DumpDataToDisk(vacRequest, vacRequestSize, "C:\\Users\\admin\\Desktop\\csgo shit\\sploozemoduledumper\\dumpwithreq\\reqhashid_" + std::to_string(hashId) + ".txt");
    return scanRet;
}
typedef DWORD(__stdcall* t_originalLoadModule)(ModuleInfo* ModuleStruct, char flags);

t_originalLoadModule o_LoadModule;

DWORD __stdcall LoadModuleHk(ModuleInfo* ModuleStruct, char flags) {

    static int modCount = 0;
    //printf("size, %d", ModuleStruct->size);
    moduleCounter[ModuleStruct->crc32]++;
    if (!moduleLoaded[ModuleStruct->crc32]) {
        std::cout << "unique module loaded:  " << ModuleStruct->crc32 << std::endl;
        std::cout << ModuleStruct->crc32 << std::endl;
        moduleLoaded[ModuleStruct->crc32] = true;
        modCount++;

        std::string modCounterString = "C:\\Users\\admin\\Desktop\\csgo shit\\sploozemoduledumper\\dumpwithreq\\VAC_" + std::to_string(ModuleStruct->crc32) + ".dll";
        HANDLE hFile = CreateFileA((LPCSTR)modCounterString.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

        DWORD BytesWritten = 0;
        WriteFile(hFile, ModuleStruct->origImage, ModuleStruct->size, &BytesWritten, 0);

        CloseHandle(hFile);
        std::cout << "overwritten: " << BytesWritten << " bytes" << std::endl;
    }



    // std::cout << "hook called: " << ModuleStruct->crc32 << " counter " << moduleCounter[ModuleStruct->crc32] << std::endl;
    DWORD returnVal = o_LoadModule(ModuleStruct, flags);
    hashId = ModuleStruct->crc32;
    origRunFunc = ModuleStruct->runfunc;
    ModuleStruct->runfunc = &HkRunFunc;

    return returnVal;
}

PVOID Utils_findPattern(PCWSTR module, PCSTR pattern, SIZE_T offset)
{
    MODULEINFO moduleInfo;
    HMODULE moduleHandle = GetModuleHandleW(module);

    if (moduleHandle && GetModuleInformation(GetCurrentProcess(), moduleHandle, &moduleInfo, sizeof(moduleInfo))) {
        for (PCHAR c = (PCHAR)moduleInfo.lpBaseOfDll; (PBYTE)c != (PBYTE)moduleInfo.lpBaseOfDll + moduleInfo.SizeOfImage; c++) {
            bool matched = true;

            for (PCSTR patternIt = pattern, it = c; *patternIt; patternIt++, it++) {
                if (*patternIt != '?' && *it != *patternIt) {
                    matched = false;
                    break;
                }
            }
            if (matched)
                return c + offset;
        }
    }
    return NULL;
}
void main(HMODULE hModule) {
    
    FILE* f;

    AllocConsole();
    freopen_s(&f, "CONOUT$", "w", stdout);

    if (MH_Initialize() == MH_OK) {
        printf("Minhook Initialized \n");
    }
   

    PVOID load_module_address = (PVOID)((uintptr_t)GetModuleHandleA("steamservice.dll") + 0x58cf0);
   // PVOID run_func_address = (PVOID)((uintptr_t)GetModuleHandleA("steamservice.dll") + 0x2BBC);

    std::cout << load_module_address << std::endl;

  

   if (MH_CreateHook(load_module_address, &LoadModuleHk, (void**)&o_LoadModule) /*not too comfortable with the 3rd parameter */ == MH_OK) {
       printf("hook successful on LoadModule \n");
 }



 
   Sleep(100);
  

   while (true) {
       if (GetAsyncKeyState(VK_INSERT)) {
           if (MH_EnableHook(MH_ALL_HOOKS) == MH_OK) {
               printf("sucessfully enabled hook \n");
           }
           break;
       }
   }
    while (true) {


        if (GetAsyncKeyState(VK_DELETE)) {
            break;
        }
    }

    MH_RemoveHook(load_module_address);
    MH_Uninitialize();

   
    fclose(f);
    FreeConsole();

    FreeLibraryAndExitThread(hModule, 0);

}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpvReserved)  // reserved
{
    // Perform actions based on the reason for calling.
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        // Initialize once for each new process.
        // Return FALSE to fail DLL load.
        CreateThread(0, 0, (LPTHREAD_START_ROUTINE)main, hinstDLL, 0, 0);
        break;

    case DLL_THREAD_ATTACH:
        // Do thread-specific initialization.
        break;

    case DLL_THREAD_DETACH:
        // Do thread-specific cleanup.
        break;

    case DLL_PROCESS_DETACH:

        if (lpvReserved != nullptr)
        {
            break; // do not do cleanup if process termination scenario
        }

        // Perform any necessary cleanup.
        break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}