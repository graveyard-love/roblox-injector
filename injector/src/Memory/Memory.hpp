#pragma once
#include <vector>
#include <Windows.h>
#include <TlHelp32.h>
#include "../../../shared/ioctls.h"

extern HANDLE g_Drv;
extern DWORD g_Pid;

HANDLE g_Proc = NULL;
DWORD g_Old = 0;

template<typename T>
T Read(uintptr_t adr) {
    T val{};
    READ_MEMORY_REQ req = { 0 };
    req.TargetPid = (HANDLE)(ULONG_PTR)g_Pid;
    req.RemoteBase = (PVOID)adr;
    req.Buffer = &val;
    req.Size = sizeof(T);
    DWORD br;
    DeviceIoControl(g_Drv, IOCTL_READ_MEMORY, &req, sizeof(req), &req, sizeof(req), &br, nullptr);
    return val;
}

bool Read(uintptr_t adr, void* buf, size_t sz) {
    READ_MEMORY_REQ req = { 0 };
    req.TargetPid = (HANDLE)(ULONG_PTR)g_Pid;
    req.RemoteBase = (PVOID)adr;
    req.Buffer = buf;
    req.Size = sz;
    DWORD br;
    return DeviceIoControl(g_Drv, IOCTL_READ_MEMORY, &req, sizeof(req), &req, sizeof(req), &br, nullptr);
}

template<typename T>
bool Write(uintptr_t adr, const T& val) {
    WRITE_MEMORY_REQ req = { 0 };
    req.TargetPid = (HANDLE)(ULONG_PTR)g_Pid;
    req.RemoteBase = (PVOID)adr;
    req.Buffer = (PVOID)&val;
    req.Size = sizeof(T);
    DWORD br;
    return DeviceIoControl(g_Drv, IOCTL_WRITE_MEMORY, &req, sizeof(req), &req, sizeof(req), &br, nullptr);
}

bool Write(uintptr_t adr, const void* buf, size_t sz) {
    WRITE_MEMORY_REQ req = { 0 };
    req.TargetPid = (HANDLE)(ULONG_PTR)g_Pid;
    req.RemoteBase = (PVOID)adr;
    req.Buffer = (PVOID)buf;
    req.Size = sz;
    DWORD br;
    return DeviceIoControl(g_Drv, IOCTL_WRITE_MEMORY, &req, sizeof(req), &req, sizeof(req), &br, nullptr);
}

bool Prot(uintptr_t adr, SIZE_T sz, DWORD nPr) {
    PROTECT_MEMORY_REQ req = { 0 };
    req.TargetPid = (HANDLE)(ULONG_PTR)g_Pid;
    req.RemoteBase = (PVOID)adr;
    req.Size = sz;
    req.NewProtect = nPr;
    DWORD br;
    bool ok = DeviceIoControl(g_Drv, IOCTL_PROTECT_MEMORY, &req, sizeof(req), &req, sizeof(req), &br, nullptr);
    if (ok) g_Old = req.OldProtect;
    return ok;
}

uintptr_t Alloc(SIZE_T sz, DWORD nPr) {
    ALLOCATE_MEMORY_REQ req = { 0 };
    req.TargetPid = (HANDLE)(ULONG_PTR)g_Pid;
    req.Size = sz;
    req.Protect = nPr;
    DWORD br;
    if (DeviceIoControl(g_Drv, IOCTL_ALLOCATE_MEMORY, &req, sizeof(req), &req, sizeof(req), &br, nullptr))
        return (uintptr_t)req.RemoteBase;
    return 0;
}

bool Unlink(uintptr_t adr, SIZE_T sz) {
    UNLINK_VAD_REQ req = { 0 };
    req.TargetPid = (HANDLE)(ULONG_PTR)g_Pid;
    req.RemoteBase = (PVOID)adr;
    req.RegionSize = sz;
    DWORD br;
    return DeviceIoControl(g_Drv, IOCTL_UNLINK_VAD, &req, sizeof(req), &req, sizeof(req), &br, nullptr);
}

DWORD GetPid(const char* n) {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (s == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = { 0 };
    pe.dwSize = sizeof(pe);
    for (BOOL ok = Process32First(s, &pe); ok; ok = Process32Next(s, &pe)) {
        if (!_stricmp(pe.szExeFile, n)) {
            CloseHandle(s);
            return pe.th32ProcessID;
        }
    }
    CloseHandle(s);
    return 0;
}

MODULEENTRY32 GetMod(DWORD p, const char* m) {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, p);
    if (s == INVALID_HANDLE_VALUE) return {};
    MODULEENTRY32 me = { 0 };
    me.dwSize = sizeof(me);
    for (BOOL ok = Module32First(s, &me); ok; ok = Module32Next(s, &me)) {
        if (!_stricmp(me.szModule, m)) {
            CloseHandle(s);
            return me;
        }
    }
    CloseHandle(s);
    return {};
}

uintptr_t GetProc(uintptr_t b, const char* n) {
    auto d = Read<IMAGE_DOS_HEADER>(b);
    auto nt = Read<IMAGE_NT_HEADERS>(b + d.e_lfanew);
    auto e = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!e.VirtualAddress || !e.Size) return 0;
    auto ex = Read<IMAGE_EXPORT_DIRECTORY>(b + e.VirtualAddress);
    std::vector<DWORD> v1(ex.NumberOfNames);
    std::vector<WORD> v2(ex.NumberOfNames);
    std::vector<DWORD> v3(ex.NumberOfFunctions);
    if (!Read(b + ex.AddressOfNames, v1.data(), 4 * v1.size()) || !Read(b + ex.AddressOfNameOrdinals, v2.data(), 2 * v2.size()) || !Read(b + ex.AddressOfFunctions, v3.data(), 4 * v3.size()))
        return 0;
    char buf[256];
    for (size_t i = 0; i < v1.size(); ++i) {
        if (!Read(b + v1[i], buf, 256)) continue;
        if (!strcmp(buf, n)) {
            WORD o = v2[i];
            if (o >= v3.size()) return 0;
            return b + v3[o];
        }
    }
    return 0;
}

uintptr_t GetHbk(uintptr_t j) {
    for (uintptr_t i = 0x0; i < 0x400; i += 0x10) {
        uintptr_t b = Read<uintptr_t>(j + i);
        if (!b) continue;
        if (Read<int>(b + 0x28) < 16) {
            if (Read<std::string>(b + 0x18) == "Heartbeat") return b;
        }
    }
    return 0;
}

std::vector<BYTE> ExtSc(uintptr_t f) {
    MEMORY_BASIC_INFORMATION m;
    VirtualQuery((void*)f, &m, sizeof(m));
    size_t s = m.RegionSize;
    std::vector<BYTE> sc;
    for (size_t i = 0; i < s; ++i) {
        BYTE v = *(BYTE*)(f + i);
        sc.push_back(v);
        if (v == 0xCC && *(BYTE*)(f + i + 1) == 0xCC && *(BYTE*)(f + i + 2) == 0xCC)
            break;
    }
    return sc;
}

void RepSc(std::vector<BYTE>& d, uint64_t s, uint64_t r) {
    for (size_t i = 0; i <= d.size() - 10; ++i) {
        if ((d[i] == 0x48 || d[i] == 0x49) && d[i + 1] >= 0xB8 && d[i + 1] <= 0xBF) {
            uint64_t m = *(uint64_t*)(&d[i + 2]), o = *(uint32_t*)(&d[i + 2]);
            if (m - o == s) {
                uintptr_t nr = (uintptr_t)(r + o);
                memcpy(&d[i + 2], &nr, 8);
            }
        }
        uint64_t q = *(uint64_t*)(&d[i + 1]), o2 = *(uint32_t*)(&d[i + 1]);
        if ((d[i] == 0xA1 || d[i] == 0xA2 || d[i] == 0xA3) && q - o2 == s) {
            uintptr_t nr2 = (uintptr_t)(r + o2);
            memcpy(&d[i + 1], &nr2, 8);
        }
    }
}