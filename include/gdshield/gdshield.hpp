#pragma once
#include <string>
#include <cstddef>
#include <cstdint>
#include <vector>

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#include <intrin.h>
#elif defined(__APPLE__)
#include <sys/types.h>
#include <sys/sysctl.h>
#include <unistd.h>
#elif defined(__ANDROID__) || defined(__linux__)
#include <sys/ptrace.h>
#include <unistd.h>
#include <fstream>
#endif

namespace gdshield {

// Compile-time XOR string obfuscation template
template<size_t N>
struct ObfString {
    char data[N];
    constexpr ObfString(const char(&str)[N], char key) : data{} {
        for (size_t i = 0; i < N; ++i) {
            data[i] = str[i] ^ key;
        }
    }
};

#define OBF_STR(str, key) ([]() -> std::string { \
    constexpr ::gdshield::ObfString<sizeof(str)> obf(str, key); \
    std::string s(obf.data, sizeof(str) - 1); \
    for (char& c : s) c ^= key; \
    return s; \
})()

// Dynamic non-literal offset derivation (derived in native binary, never literal in GDScript)
inline int derive_pack_offset(uint32_t project_salt = 0x5F3759DF) {
    volatile uint32_t a = project_salt;
    volatile uint32_t b = 0x1337BEEF;
    volatile uint32_t c = (a ^ b) & 0x3FF;
    // Guarantee minimum 384 bytes, maximum 1024 bytes, 64-byte struct alignment
    uint32_t offset = (c | 0x180) & ~0x3F;
    if (offset < 384) offset = 448;
    if (offset > 1024) offset = 512;
    return static_cast<int>(offset);
}

// Multi-point anti-injection check (Frida, DLL injection, memory hooking)
inline bool is_injection_detected() {
#if defined(_WIN32) || defined(_WIN64)
    const char* bad_modules[] = {
        "frida-gadget.dll", "frida-agent.dll", "frida-agent-64.dll",
        "frida-agent-32.dll", "cuckoomon.dll"
    };
    for (const char* mod : bad_modules) {
        if (GetModuleHandleA(mod) != nullptr) return true;
    }
#elif defined(__linux__) || defined(__ANDROID__)
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        if (line.find("frida") != std::string::npos || line.find("gadget") != std::string::npos) {
            return true;
        }
    }
#endif
    return false;
}

// Hardware breakpoint detection (DR0 - DR3 debug registers)
inline bool has_hardware_breakpoints() {
#if defined(_WIN32) || defined(_WIN64)
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hThread = GetCurrentThread();
    if (GetThreadContext(hThread, &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
            return true;
        }
    }
#endif
    return false;
}

// RDTSC execution timing delta check (catches single-stepping debuggers)
inline bool is_timing_tampered() {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    uint64_t start = __rdtsc();
    volatile int dummy = 0;
    for (int i = 0; i < 1000; ++i) dummy += i;
    uint64_t delta = __rdtsc() - start;
    if (delta > 250000) return true; // Single-stepping produces massive tick spikes
#endif
    return false;
}

// Layered anti-debugging tripwire
inline bool is_debugger_present() {
#if defined(_WIN32) || defined(_WIN64)
    // 1. Standard PEB BeingDebugged
    if (IsDebuggerPresent() != 0) return true;

    // 2. Remote debugger check
    BOOL remoteDebugger = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger) && remoteDebugger) {
        return true;
    }

    // 3. Hardware Breakpoints
    if (has_hardware_breakpoints()) return true;

    // 4. Timing delta
    if (is_timing_tampered()) return true;

    // 5. Native NtQueryInformationProcess (ProcessDebugPort = 7)
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        typedef LONG(NTAPI* pfnNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        auto pNtQuery = reinterpret_cast<pfnNtQueryInformationProcess>(GetProcAddress(hNtdll, "NtQueryInformationProcess"));
        if (pNtQuery) {
            DWORD_PTR debugPort = 0;
            if (pNtQuery(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), nullptr) == 0) {
                if (debugPort != 0) return true;
            }
        }
    }
    return false;
#elif defined(__APPLE__)
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    struct kinfo_proc info{};
    size_t size = sizeof(info);
    if (sysctl(mib, 4, &info, &size, nullptr, 0) == 0) {
        return (info.kp_proc.p_flag & P_TRACED) != 0;
    }
    return false;
#elif defined(__ANDROID__)
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
        return true;
    }
    std::ifstream statusFile("/proc/self/status");
    std::string line;
    while (std::getline(statusFile, line)) {
        if (line.rfind("TracerPid:", 0) == 0) {
            int tracerPid = std::stoi(line.substr(10));
            return tracerPid != 0;
        }
    }
    return false;
#elif defined(__linux__)
    std::ifstream statusFile("/proc/self/status");
    std::string line;
    while (std::getline(statusFile, line)) {
        if (line.rfind("TracerPid:", 0) == 0) {
            int tracerPid = std::stoi(line.substr(10));
            return tracerPid != 0;
        }
    }
    return false;
#else
    return false;
#endif
}

// Memory integrity checksum helper
inline uint32_t compute_fnv1a(const uint8_t* data, size_t length) {
    uint32_t hash = 0x811c9dc5;
    for (size_t i = 0; i < length; ++i) {
        hash ^= data[i];
        hash *= 0x01000193;
    }
    return hash;
}

// Command-line sanitizer (blocks unauthorized CEF devtools / remote debugging injection)
inline bool is_malicious_arg(const std::string& arg) {
    const char* bad_patterns[] = {
        "--remote-debugging-port",
        "--remote-debugging-pipe",
        "--auto-open-devtools-for-tabs",
        "--enable-devtools"
    };
    for (const char* pattern : bad_patterns) {
        if (arg.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

} // namespace gdshield
