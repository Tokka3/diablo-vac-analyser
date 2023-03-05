#include <windows.h>
#include <iostream>
#include <Psapi.h>
#include "hooks.h"
#include <map>
#include "utility.h"
#include <string>
#include <sysinfoapi.h>
#include <direct.h>
#include <string>
#include <algorithm>
#include <vector>
#include <fstream>
#include <tchar.h>
#include "gvars.h"

extern t_originalLoadModule o_LoadModule;

extern std::string folder;
extern std::string module_folder;
extern std::string request_folder;
extern std::string procid_dump_folder;
extern std::string scan_dump_folder;







void main(HMODULE hModule) {
    
    FILE* f;

    AllocConsole();
    freopen_s(&f, "CONOUT$", "w", stdout);

    if (MH_Initialize() == MH_OK) {
        printf("Minhook Initialized \n");
    }
   folder = "C:\\Users\\admin\\Desktop\\csgo shit\\moduledump\\" + utility::currentDateTime();

    module_folder = "C:\\Users\\admin\\Desktop\\csgo shit\\moduledump\\" + utility::currentDateTime() + "\\modules";
    request_folder = "C:\\Users\\admin\\Desktop\\csgo shit\\moduledump\\" + utility::currentDateTime() + "\\requests";
   procid_dump_folder = "C:\\Users\\admin\\Desktop\\csgo shit\\moduledump\\" + utility::currentDateTime() + "\\procids";
   scan_dump_folder = "C:\\Users\\admin\\Desktop\\csgo shit\\moduledump\\" + utility::currentDateTime() + "\\scans";
    _mkdir(folder.c_str());
    _mkdir(module_folder.c_str());
    _mkdir(request_folder.c_str());
    _mkdir(procid_dump_folder.c_str());
    _mkdir(scan_dump_folder.c_str());


    PVOID load_module_address = (PVOID)((uintptr_t)GetModuleHandleA("steamservice.dll") + 0x58D10);
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