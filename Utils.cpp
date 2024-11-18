#include "utils.h"
#include <tchar.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

void CharToWChar(const char* charArray, wchar_t* wcharArray, int wcharArraySize) {
    MultiByteToWideChar(CP_ACP, 0, charArray, -1, wcharArray, wcharArraySize);
}

void WCharToChar(const wchar_t* wcharArray, char* charArray, int charArraySize) {
    WideCharToMultiByte(CP_ACP, 0, wcharArray, -1, charArray, charArraySize, NULL, NULL);
}

void Utils::CharToTChar(const char* source, TCHAR* dest, int destSize) {
#ifdef UNICODE
    MultiByteToWideChar(CP_ACP, 0, source, -1, dest, destSize);
#else
    strncpy(dest, source, destSize - 1);
    dest[destSize - 1] = '\0';
#endif
}

bool isValidString(const wchar_t* str) {
    if (str == nullptr) return false;

    try {
        const wchar_t* temp = str;
        while (*temp != L'\0') {
            ++temp;
        }
        return true; 
    } catch (...) {
        return false; 
    }
}

bool Utils::wcscmp(const wchar_t *str, const wchar_t *text) {
    if (!isValidString(str) || !isValidString(text)) {
        return false; 
    }

    return ::wcscmp(str, text) == 0; 
}
bool Utils::compareStrings(const char* str, const char* text) {
    if (!str || !text) {
        return false; 
    }
    return strcmp(str, text) == 0; 
}

DWORD Utils::GetPID(const char* ProcessName) {
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(PROCESSENTRY32);

    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (processesSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    if (Process32First(processesSnapshot, &processInfo)) {
        do {
#ifdef UNICODE
            wchar_t wideProcessName[256];
            CharToWChar(ProcessName, wideProcessName, sizeof(wideProcessName) / sizeof(wchar_t));
            if (wcscmp(processInfo.szExeFile, wideProcessName) == 0)
#else
            if (compareStrings(processInfo.szExeFile, ProcessName))
#endif
            {
                DWORD pid = processInfo.th32ProcessID;
                CloseHandle(processesSnapshot);
                return pid;
            }
        } while (Process32Next(processesSnapshot, &processInfo));
    }

    CloseHandle(processesSnapshot);
    return 0;
}


MODULEENTRY32 Utils::GetModule(const char* moduleName, unsigned long ProcessID) {
    MODULEENTRY32 modEntry = { 0 };
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessID);

    if (hSnapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 curr = { 0 };
        curr.dwSize = sizeof(MODULEENTRY32);
        if (Module32First(hSnapshot, &curr)) {
            do {
#ifdef UNICODE
                wchar_t wideModuleName[256];
                CharToWChar(moduleName, wideModuleName, sizeof(wideModuleName) / sizeof(wideModuleName[0]));
                if (wcscmp(curr.szModule, wideModuleName) == 0)
#else
                if (compareStrings(curr.szModule, moduleName))
#endif
                {
                    modEntry = curr;
                    break;
                }
            } while (Module32Next(hSnapshot, &curr));
        }
        CloseHandle(hSnapshot);
    }
    return modEntry;
}


uintptr_t Utils::dwGetModuleBaseAddress(TCHAR* lpszModuleName, DWORD pID)
{
    uintptr_t dwModuleBaseAddress = 0;
    HANDLE hSnapshoot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pID);
    MODULEENTRY32 ModuleEntry32 = { 0 };
    ModuleEntry32.dwSize = sizeof(MODULEENTRY32);

    if (Module32First(hSnapshoot, &ModuleEntry32))
    {
        do {
            if (_tcscmp(ModuleEntry32.szModule, lpszModuleName) == 0)
            {
                dwModuleBaseAddress = (uintptr_t)ModuleEntry32.modBaseAddr;
                break;
            }
        } while (Module32Next(hSnapshoot, &ModuleEntry32));

    }
    CloseHandle(hSnapshoot);
    return dwModuleBaseAddress;
}


uintptr_t Utils::resolvePointer(HANDLE processHandle, uintptr_t baseAddress, std::vector<uintptr_t> offsets) {
    uintptr_t address = baseAddress;
    for (int i = 0; i < offsets.size(); i++) {
        address = readMemory<uintptr_t>(address);
        address += offsets[i];
    }
    return address;
}

std::vector<int> patternToByte(const char* pattern) {
    std::vector<int> bytes;
    const char* start = pattern;
    const char* end = pattern + strlen(pattern);

    for (const char* current = start; current < end; ++current) {
        if (*current == '?') {
            ++current;
            bytes.push_back(-1);
        } else {
            bytes.push_back(strtoul(current, nullptr, 16));
        }
    }
    return bytes;
}
uintptr_t scanSignature(HANDLE process, uintptr_t begin, uintptr_t end, const char* signature) {
    std::vector<int> patternBytes = patternToByte(signature);
    size_t patternSize = patternBytes.size();
    std::vector<BYTE> buffer(end - begin);

    SIZE_T bytesRead;
    if (!ReadProcessMemory(process, (LPCVOID)begin, &buffer[0], buffer.size(), &bytesRead)) {
        return 0;
    }

    for (size_t i = 0; i < bytesRead - patternSize; ++i) {
        bool found = true;
        for (size_t j = 0; j < patternSize; ++j) {
            if (patternBytes[j] != -1 && patternBytes[j] != buffer[i + j]) {
                found = false;
                break;
            }
        }
        if (found) {
            return begin + i;
        }
    }
    return 0;
}


#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <vector>
#include <conio.h>
#include <memory>
#include <mutex>
#include <atomic>

bool Utils::compareBytes(const BYTE* data, const BYTE* mask, const char* pattern) {
    for (; *pattern; ++pattern, ++data, ++mask) {
        if (*pattern == 'x' && *data != *mask) {
            return false;
        }
    }
    return true;
}

Utils::Pattern Utils::createPattern(const std::string& sig) {
    Pattern pattern;
    const char* str = sig.c_str();
    while (*str) {
        if (*str == ' ') {
            ++str;
            continue;
        }
        if (*str == '?') {
            pattern.bytes.push_back(0);
            pattern.mask.push_back('?');
            ++str;
            if (*str == '?') {
                ++str;
            }
        } else {
            pattern.bytes.push_back(static_cast<BYTE>(std::strtoul(str, nullptr, 16)));
            pattern.mask.push_back('x');
            while (*str && *str != ' ') {
                ++str;
            }
        }
    }
    return pattern;
}

void Utils::scanMemory(HANDLE handle, void* startAddress, SIZE_T regionSize, Pattern pattern, std::atomic<void*>& foundAddress) {
    std::unique_ptr<BYTE[]> pageData(new BYTE[regionSize]);
    SIZE_T bytesRead;
    if (ReadProcessMemory(handle, startAddress, pageData.get(), regionSize, &bytesRead)) {
        const BYTE* patBytes = pattern.bytes.data();
        const char* patMask = pattern.mask.c_str();

        for (size_t i = 0; i <= bytesRead - pattern.bytes.size(); ++i) {
            if (compareBytes(pageData.get() + i, patBytes, patMask)) {
                std::lock_guard<std::mutex> lock(resultsMutex);
                foundAddress = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(startAddress) + i);
                return;
            }
        }
    }
}
#include <thread>
void* Utils::scanSig(const std::string& sig) {
    Utils utils;
    Pattern pattern = createPattern(sig);
    std::atomic<void*> foundAddress(nullptr);
    DWORD oldprotect;
    unsigned long long pid = GetPID("Minecraft.Windows.exe");
    MODULEENTRY32 module = GetModule("Minecraft.Windows.exe", pid);
    HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    MEMORY_BASIC_INFORMATION memInfo;
    void* currentAddress = nullptr;

    std::vector<std::thread> threads;

    while (VirtualQueryEx(phandle, currentAddress, &memInfo, sizeof(memInfo)) != 0) {
        if (memInfo.State == MEM_COMMIT && memInfo.Protect != PAGE_NOACCESS) {
            threads.emplace_back(&Utils::scanMemory, this, phandle, currentAddress, memInfo.RegionSize, pattern, std::ref(foundAddress));

            if (foundAddress) {
                break;
            }
        }
        currentAddress = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(currentAddress) + memInfo.RegionSize);
    }


    for (auto& thread : threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }

    return foundAddress;
}

void Utils::alloc(LPVOID lpAddress, unsigned int size)
{
    DWORD oldprotect;
    unsigned long long pid = GetPID("Minecraft.Windows.exe");
    HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    VirtualAllocEx(phandle, lpAddress, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

void Utils::unalloc(LPVOID lpAddress)
{
    DWORD oldprotect;
    unsigned long long pid = GetPID("Minecraft.Windows.exe");
    HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    VirtualFreeEx(phandle, lpAddress, 0, MEM_RELEASE);
}

#include <string>

// Utility function to convert wide string to string
std::string WideToString(const std::wstring& wstr) {
    std::string str(wstr.begin(), wstr.end());
    return str;
}

uintptr_t Utils::FindSignature(std::vector<int> signature) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    PROCESSENTRY32 pEntry; 
    pEntry.dwSize = sizeof(pEntry);

    const char* target = "Minecraft.Windows.exe";
    DWORD processId{};

    if (Process32First(hSnapshot, &pEntry)) {
        do {
            if (strcmp(pEntry.szExeFile, target) == 0) {
                processId = pEntry.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pEntry)); 
    }

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);

    MODULEENTRY32 mEntry;
    mEntry.dwSize = sizeof(mEntry);

    if (Module32First(hSnapshot, &mEntry)) {
        do {
            if (strcmp(mEntry.szModule, target) == 0) break;
        } while (Module32Next(hSnapshot, &mEntry)); 
    }

    hSnapshot = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

    std::vector<BYTE> memBuffer(mEntry.modBaseSize);
    ReadProcessMemory(hSnapshot, (LPCVOID)mEntry.modBaseAddr, memBuffer.data(), mEntry.modBaseSize, NULL);

    for (size_t i = 0; i < mEntry.modBaseSize; i++) {
        for (size_t j = 0; j < signature.size(); j++) {
            if (signature[j] != -1 && signature[j] != memBuffer[i + j]) break;
            if (j + 1 == signature.size()) {
                CloseHandle(hSnapshot);
                return reinterpret_cast<uintptr_t>(mEntry.modBaseAddr) + i;
            }
        }
    }

    CloseHandle(hSnapshot);
    return 0;
}


void Utils::patchBytes(void* dst, void* src, size_t size) {
    DWORD oldprotect;
    unsigned long long pid = GetPID("Minecraft.Windows.exe");
    HANDLE phandle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_ALL_ACCESS, FALSE, pid);

    VirtualProtectEx(phandle, dst, size, PAGE_EXECUTE_READWRITE, &oldprotect);
    WriteProcessMemory(phandle, dst, src, size, nullptr);
    VirtualProtectEx(phandle, dst, size, oldprotect, &oldprotect);
};


uintptr_t Utils::AllocMem(uintptr_t addr)
{
    uintptr_t offset = 0;
    DWORD pID = GetPID("Minecraft.Windows.exe");
    HANDLE processHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pID);
    if (processHandle == nullptr) {
        std::cerr << "Failed to open process" << std::endl;
        return 0;
    }

    std::cout << "Hook addr: 0x" << std::hex << addr << std::endl;

    uintptr_t currentAddress = addr;
    bool memoryAllocated = false;

    while (!memoryAllocated)
    {
        MEMORY_BASIC_INFORMATION memInfo;
        if (VirtualQueryEx(processHandle, reinterpret_cast<LPVOID>(currentAddress), &memInfo, sizeof(memInfo)) == sizeof(memInfo))
        {
            if (memInfo.State == MEM_FREE)
            {
                LPVOID address = VirtualAllocEx(processHandle, reinterpret_cast<LPVOID>(currentAddress), sizeof(float), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (address != nullptr)
                {
                    memoryAllocated = true;
                    std::cout << "Memory allocated at address: 0x" << std::hex << currentAddress << std::endl;
                    break;
                }
            }
        }

        currentAddress += 0x10000;
        offset += 0x10000;
    }

    if (!memoryAllocated)
    {
        std::cerr << "Failed to allocate memory" << std::endl;
    }

    CloseHandle(processHandle);
    return offset;
}






