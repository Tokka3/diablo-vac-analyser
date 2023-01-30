#include <Windows.h>
#include <iostream>
#include "include/MinHook.h"
#include <Psapi.h>
#include <map>
#include <string>
#include <sysinfoapi.h>
#include <direct.h>
#include <string>
#include <algorithm>
#include <vector>
#include <fstream>
#include <tchar.h>
#include "vac_structs.h"



typedef DWORD(__stdcall* t_originalLoadModule)(ModuleInfo* ModuleStruct, char flags);
int __stdcall HkRunFunc(int scanId, DWORD* vacRequest, int vacRequestSize, PVOID returnBuffer, int* returnBufferSize);
DWORD __stdcall LoadModuleHk(ModuleInfo* ModuleStruct, char flags);
