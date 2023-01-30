#pragma once
#include <Windows.h>
#include <iostream>
#include <Windows.h>
#include <iostream>

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

class utility
{
public:
	static PVOID Utils_findPattern(PCWSTR module, PCSTR pattern, SIZE_T offset);
	static void DumpWindowsInfo(std::string filepath);
	static std::string GetExeName(DWORD pid);
	static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);
	static BOOL DumpDataToDisk(PVOID data, ULONG size, std::string path);
	static const std::string currentDateTime();
	static DWORD GetSectionVa(PVOID base, const char* sectionName);
};

