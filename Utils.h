#ifndef UTILS_H
#define UTILS_H
#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <string>
#include <atomic>
#include <iostream>
#include <mutex>
class Utils
{
public:
    static void CharToTChar(const char* source, TCHAR* dest, int destSize);

    bool wcscmp(const wchar_t* str, const wchar_t* text);

    bool compareStrings(const char *str, const char *text);

    DWORD GetPID(const char* ProcessName);
    MODULEENTRY32 GetModule(const char* moduleName, unsigned long ProcessID);
    uintptr_t dwGetModuleBaseAddress(TCHAR* lpszModuleName, DWORD pID);
    uintptr_t resolvePointer(HANDLE processHandle, uintptr_t baseAddress, std::vector<uintptr_t> offsets);



    uintptr_t FindSignature(std::vector<int> signature);
    void patchBytes(void* dst, void* src, size_t size);
    bool compareBytes(const BYTE* data, const BYTE* mask, const char* pattern);

    struct Pattern {
        std::vector<BYTE> bytes;
        std::string mask;
    };
    std::mutex resultsMutex;
    Pattern createPattern(const std::string& sig);
    void scanMemory(HANDLE handle, void* startAddress, SIZE_T regionSize, Pattern pattern, std::atomic<void*>& foundAddress);
    void* scanSig(const std::string& sig);
    void alloc(LPVOID lpAddress, unsigned int size);
    void unalloc(LPVOID lpAddress);
    template <typename T>
    T readMemory(uintptr_t address) {
        DWORD processID = GetPID("Minecraft.Windows.exe");
        HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
        T value = {};
        DWORD oldProtect = 0;

        if (VirtualProtectEx(processHandle, (LPVOID)address, sizeof(T), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            if (!ReadProcessMemory(processHandle, (LPCVOID)address, &value, sizeof(T), nullptr)) {
                std::cerr << "Failed to virtual protect memory (utils)" << std::endl;
            }
        } else {
            if (!ReadProcessMemory(processHandle, (LPCVOID)address, &value, sizeof(T), nullptr)) {
                std::cerr << "Failed to read memory (utils)" << std::endl;
            }
        }
        return value;
    }
    template <typename T>
void writeMemory(uintptr_t address, T value) {
        DWORD oldProtect = 0;
        DWORD processID = GetPID("Minecraft.Windows.exe");
        HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
        if (VirtualProtectEx(processHandle, (LPVOID)address, sizeof(T), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            if (!WriteProcessMemory(processHandle, (LPVOID)address, &value, sizeof(T), nullptr)) {
                std::cerr << "Failed to virtual protect memory (utils)" << std::endl;
            }
        } else {
            if (!WriteProcessMemory(processHandle, (LPVOID)address, &value, sizeof(T), nullptr)) {
                std::cerr << "Failed to write memory (utils)" << std::endl;
            }
        }
    }



     std::vector<BYTE> jmpTo(uintptr_t fromAddr, uintptr_t toAddr) {
        int32_t offset = static_cast<int32_t>(toAddr - (fromAddr + 5));

        std::vector<BYTE> jmpBytes = {
            0xE9,
            static_cast<BYTE>(offset & 0xFF),
            static_cast<BYTE>((offset >> 8) & 0xFF),
            static_cast<BYTE>((offset >> 16) & 0xFF),
            static_cast<BYTE>((offset >> 24) & 0xFF)
        };

        return jmpBytes;
    }
    std::vector<BYTE> movToRax(uintptr_t address) {
        std::vector<BYTE> dynamicBytes = {0x48, 0xA3};

        for (int i = 0; i < sizeof(address); ++i) {
            dynamicBytes.push_back(static_cast<BYTE>((address >> (8 * i)) & 0xFF));
        }

        return dynamicBytes;
    }

    uintptr_t AllocMem(uintptr_t addr);

};

#endif // UTILS_H
