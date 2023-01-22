#include "utility.h"
#include <Psapi.h>


const std::string utility::currentDateTime() {
    time_t     now = time(0);
    struct tm  tstruct;
    char       buf[80];
    tstruct = *localtime(&now);
    // Visit http://en.cppreference.com/w/cpp/chrono/c/strftime
    // for more information about date/time format
    strftime(buf, sizeof(buf), "%Y-%m-%d-%H-%M", &tstruct);

    return buf;
}
BOOL utility::DumpDataToDisk(PVOID data, ULONG size, std::string path)
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


std::vector<std::pair<DWORD, std::string>> windows;
BOOL CALLBACK utility::EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    DWORD pid;
    GetWindowThreadProcessId(hwnd, &pid);
    TCHAR windowTitle[255];
    GetWindowText(hwnd, windowTitle, sizeof(windowTitle));
    windows.push_back(std::make_pair(pid, windowTitle));
    return TRUE;
}
std::string utility::GetExeName(DWORD pid) {
    TCHAR exeName[MAX_PATH];
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

void utility::DumpWindowsInfo(std::string filepath) {
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
    windows.clear();
}


PVOID utility::Utils_findPattern(PCWSTR module, PCSTR pattern, SIZE_T offset)
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
