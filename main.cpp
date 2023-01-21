#include <windows.h>
#include <iostream>
#include <Psapi.h>
#include "include/MinHook.h"
#include <map>
#include <string>
#include <sysinfoapi.h>
#include <direct.h>
#include <string>
#include <algorithm>
#include <vector>
#include <fstream>
#include <tchar.h>

std::string folder;
std::string module_folder; 
std::string request_folder;
std::string procid_dump_folder;



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
    std::string buffer;
};


std::map<PVOID, int> moduleCounter{

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

t_originalRunFunc origRunFunc;

ModuleInfo* clone;



static int hashId = 0;

PVOID originaltemp;

static bool needs_to_reset = false;
std::vector<std::pair<DWORD, std::string>> windows;

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    DWORD pid;
    GetWindowThreadProcessId(hwnd, &pid);
    TCHAR windowTitle[255];
    GetWindowText(hwnd, windowTitle, sizeof(windowTitle));
    windows.push_back(std::make_pair(pid, windowTitle));
    return TRUE;
}
std::string GetExeName(DWORD pid) {
    TCHAR exeName[MAX_PATH];
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        return "";
    }
    HMODULE hMod;
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
        GetModuleBaseName(hProcess, hMod, exeName, sizeof(exeName) / sizeof(TCHAR));
    }
    CloseHandle(hProcess);
    return exeName;
}

void DumpWindowsInfo(std::string filepath) {
    EnumWindows(EnumWindowsProc, NULL);
    std::sort(windows.begin(), windows.end());
    HANDLE hFile = CreateFileA(filepath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return;
    }
    DWORD dwBytesWritten;
    std::string output = "PID | WINDOW NAME | EXE NAME\n";
    for (auto& i : windows) {
        output += std::to_string(i.first) + " | " + i.second + " | " + GetExeName(i.first) + "\n";
    }
    WriteFile(hFile, output.c_str(), output.size(), &dwBytesWritten, NULL);
    CloseHandle(hFile);
}
std::map<PVOID, ModuleInfo*> module_data{

};
int __stdcall HkRunFunc( int scanId, DWORD* vacRequest, int vacRequestSize, PVOID returnBuffer, int* returnBufferSize)
{
    moduleCounter[originaltemp]++;
    std::cout << "hkfunc for original: " << originaltemp << " called " <<  std::endl;

    clone->runfunc = originaltemp;

    std::cout << "hkfunc reset \n \n" << std::endl;

    DumpDataToDisk(vacRequest, vacRequestSize, request_folder + "\\req_" + std::to_string(module_data[originaltemp]->crc32) + "." + std::to_string(moduleCounter[originaltemp]) + ".txt");
    DumpWindowsInfo(procid_dump_folder + "\\procdump_" + std::to_string(module_data[originaltemp]->crc32) + "." + std::to_string(moduleCounter[originaltemp]) + ".txt");
    return origRunFunc(scanId, vacRequest, vacRequestSize, returnBuffer, returnBufferSize);
}
typedef DWORD(__stdcall* t_originalLoadModule)(ModuleInfo* ModuleStruct, char flags);

t_originalLoadModule o_LoadModule;
#include <winternl.h>




// steamservice.dll
DWORD __stdcall LoadModuleHk(ModuleInfo* ModuleStruct, char flags) {


  

    if (!moduleLoaded[ModuleStruct->crc32]) {
        std::string modCounterString = module_folder + "\\VAC_" + std::to_string(ModuleStruct->crc32) + ".dll";
        HANDLE hFile = CreateFileA((LPCSTR)modCounterString.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile) {
            DWORD BytesWritten = 0;
            WriteFile(hFile, ModuleStruct->origImage, ModuleStruct->size, &BytesWritten, 0);

            CloseHandle(hFile);
        }
        else {
            std::cout << "failed to create file handle: " << GetLastError() << std::endl;
        }
        moduleLoaded[ModuleStruct->crc32] = true;
    }
        std::cout << "load module hook called: " << ModuleStruct->crc32 << std::endl;

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


const std::string currentDateTime() {
    time_t     now = time(0);
    struct tm  tstruct;
    char       buf[80];
    tstruct = *localtime(&now);
    // Visit http://en.cppreference.com/w/cpp/chrono/c/strftime
    // for more information about date/time format
    strftime(buf, sizeof(buf), "%Y-%m-%d-%H-%M", &tstruct);

    return buf;
}


void main(HMODULE hModule) {
    
    FILE* f;

    AllocConsole();
    freopen_s(&f, "CONOUT$", "w", stdout);

    if (MH_Initialize() == MH_OK) {
        printf("Minhook Initialized \n");
    }
    folder = "C:\\Users\\admin\\Desktop\\csgo shit\\moduledump\\" + currentDateTime();

    module_folder = "C:\\Users\\admin\\Desktop\\csgo shit\\moduledump\\" + currentDateTime() + "\\modules";
    request_folder = "C:\\Users\\admin\\Desktop\\csgo shit\\moduledump\\" + currentDateTime() + "\\requests";
    procid_dump_folder = "C:\\Users\\admin\\Desktop\\csgo shit\\moduledump\\" + currentDateTime() + "\\procids";

    _mkdir(folder.c_str());
    _mkdir(module_folder.c_str());
    _mkdir(request_folder.c_str());
    _mkdir(procid_dump_folder.c_str());


    PVOID load_module_address = (PVOID)((uintptr_t)GetModuleHandleA("steamservice.dll") + 0x58cf0);
   // PVOID run_func_address = (PVOID)((uintptr_t)GetModuleHandleA("steamservice.dll") + 0x2BBC);

    std::cout << load_module_address << std::endl;

  

   if (MH_CreateHook(load_module_address, &LoadModuleHk, (void**)&o_LoadModule) /*not too comfortable with the 3rd parameter */ == MH_OK) {
       printf("hook successful on LoadModule \n");
 }



 
   Sleep(100);
  


           if (MH_EnableHook(MH_ALL_HOOKS) == MH_OK) {
               printf("sucessfully enabled hook \n");
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