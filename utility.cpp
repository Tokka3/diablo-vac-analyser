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

DWORD utility::GetSectionVa(PVOID base, const char* sectionName)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS32 ntHeaders = PIMAGE_NT_HEADERS32((DWORD)base + dosHeader->e_lfanew);


    PIMAGE_SECTION_HEADER firstSection = IMAGE_FIRST_SECTION(ntHeaders);
    if (!firstSection)
    {
        printf("Failed to find first section\n");
        return 0;
    }


    for (size_t i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
    {
        if (!strcmp(sectionName, (char*)firstSection[i].Name))
        {
            return firstSection[i].VirtualAddress;
        }
    }

    printf("Failed to find %s section\n", sectionName);
    return 0;
}


PIMAGE_NT_HEADERS get_nt_headers(PVOID pImageBase)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;

    if (pDosHeader == nullptr) return NULL;

    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)pImageBase + pDosHeader->e_lfanew);
    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    return pNtHeader;
}

DWORD get_image_base(PVOID pImageBase) { // virtual base
    PIMAGE_NT_HEADERS nt_header = get_nt_headers(pImageBase);

    return nt_header->OptionalHeader.ImageBase;
}
DWORD get_section_address(PVOID base, const char* name) {


    PIMAGE_NT_HEADERS nt_header = get_nt_headers(base);

    if (!nt_header) return 0;

    WORD num_sections = nt_header->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_header);



    for (WORD i = 0; i < num_sections; i++) {

        if (!strcmp(name, (char*)section[i].Name))
        {

            return section[i].PointerToRawData;
        }
    }

    return 0;
}

DWORD resolve_relative_address(PVOID base, DWORD virtual_add) {

    PIMAGE_NT_HEADERS nt_headers = get_nt_headers(base);

    DWORD virtual_base = get_image_base(base);

    PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_headers);

    WORD num_sections = nt_headers->FileHeader.NumberOfSections;

    bool found = false;

    for (WORD i = 0; i < num_sections; i++, section_header++) {
        DWORD section_start = virtual_base + section_header->VirtualAddress;
        DWORD section_end = section_start + section_header->Misc.VirtualSize;
        /*std::cout << "start: " << section_start << std::endl;
        std::cout << "end: " << section_end << std::endl;*/
        /*std::cout << virtual_add << std::endl;*/
        if (virtual_add >= section_start && virtual_add < section_end) {
            found = true;
            break;
        }
    }
    if (!found) {
        //std::cout << "failed to find section" << std::endl;
        return NULL;
    }
    virtual_add -= virtual_base;
    virtual_add -= section_header->VirtualAddress;

    virtual_add += section_header->PointerToRawData;
    virtual_add += (DWORD)base;

    return virtual_add;
}