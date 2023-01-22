#include <Windows.h>
#include <string>
#include <map>

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

