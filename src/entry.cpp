#include <gdshield/gdshield.hpp>

#ifdef _WIN32
#define GDE_EXPORT __declspec(dllexport)
#else
#define GDE_EXPORT
#endif

extern "C" {

GDE_EXPORT int gdshield_get_pack_offset() {
    return gdshield::derive_pack_offset();
}

GDE_EXPORT int gdshield_is_debugger_present() {
    return gdshield::is_debugger_present() ? 1 : 0;
}

GDE_EXPORT int gdshield_is_injection_detected() {
    return gdshield::is_injection_detected() ? 1 : 0;
}

}
