#pragma once
#include <string>
#include <cstddef>
#include <cstdint>

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#elif defined(__linux__) || defined(__ANDROID__)
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

// Cross-platform anti-debugging tripwire
inline bool is_debugger_present() {
#if defined(_WIN32) || defined(_WIN64)
    return IsDebuggerPresent() != 0;
#elif defined(__linux__) || defined(__ANDROID__)
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

} // namespace gdshield
