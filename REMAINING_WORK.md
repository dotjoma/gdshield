# gdshield — Status & Remaining Work

## ✅ Shipped & Working (CI Green)

| Component | Status | Files |
|---|---|---|
| **PCK Hardening** (`harden`) | ✅ Done | `gdshield.py`, `gdshield_export_plugin.gd` |
| **Dynamic Build Seed** (`reseed`) | ✅ Done | `gdshield.py`, `build_seed.generated.h` |
| **Native Offset Derivation** | ✅ Done | `gdshield.hpp` → `derive_pack_offset()` |
| **Binary Stripping** (`strip-dll`) | ✅ Done | `gdshield.py` |
| **Web Minification** (`minify-web`) | ✅ Done | `gdshield.py` |
| **Security Audit** (`audit`) | ✅ Done | `gdshield.py` (zero-files-examined = FAIL) |
| **CI Audit Gate** | ✅ Green | `audit.yml` (bash shell, import pre-pass) |
| **Release Workflow** | ✅ Ready | `release.yml` (tag → ZIP → GitHub Release) |
| **Anti-Debug** (PEB, DR7, RDTSC, NtQuery) | ✅ Done | `gdshield.hpp` |
| **Anti-Injection** (Frida module scan) | ✅ Done | `gdshield.hpp` |
| **CEF DevTools Blocker** | ✅ Done | `gdshield.hpp` → `is_malicious_arg()` |
| **XOR String Obfuscation** | ✅ Done | `gdshield.hpp` → `OBF_STR()` |
| **Editor Export Plugin** | ✅ Done | `plugin.gd`, `gdshield_export_plugin.gd` |
| **Demo Scene** | ✅ Done | `scenes/main.tscn`, `scenes/main.gd` |

---

## 🔧 Remaining — Functional Gaps

### 1. GDExtension `.gdextension` Registration File — **Priority: HIGH**
`main.gd` calls `ClassDB.class_exists("GDShieldNative")` and `ClassDB.instantiate("GDShieldNative")`,
but there is **no `.gdextension` file** registering `libgame.dll` with Godot's GDExtension system,
and `entry.cpp` exports plain C functions — not a GDExtension class.

**What this means:** The native offset loader currently doesn't work at runtime. Godot never loads `libgame.dll` because nothing tells it to.

**Fix options:**
- **A) Minimal (recommended):** Skip GDExtension class registration. Instead, load the DLL via `GDNative`/`FFI` or just call the exports via `OS.execute()` or a small wrapper. Simplest: make `main.gd` read the offset from a file that `gdshield.py harden` writes, or call a python helper.
- **B) Full GDExtension:** Write proper `gdextension_init()` entry point using `godot-cpp`, register `GDShieldNative` class with `get_pack_offset()` method, add `bin/gdshield.gdextension` descriptor. This is the production path but requires `godot-cpp` headers (SCons build).

### 2. GDMaim Integration — **Priority: MEDIUM**
Phase 1 of the plan. Not integrated yet. GDMaim provides GDScript identifier obfuscation (variable/function name mangling, constant inlining).

**Options:**
- Add as git submodule or recommend manual install in README
- Add a `gdshield.py obfuscate` command that wraps GDMaim's CLI

### 3. `verify_memory_integrity()` — **Priority: LOW**
`compute_fnv1a()` exists in `gdshield.hpp` but no `verify_memory_integrity()` function uses it. No inline-hook detection.

**What's needed:** Checksum the first N bytes of critical functions at init, store expected values, periodically re-check.

### 4. Periodic Anti-Debug (Randomized Intervals) — **Priority: LOW**
Current anti-debug is call-once. Should run at randomized intervals during gameplay to catch debuggers that attach post-startup.

### 5. Stream Decryption (Per-Asset) — **Priority: LOW**
Current `harden` decrypts the whole pack at mount time. Streaming per-asset decryption would reduce the memory dump surface.

---

## 🧹 Remaining — Quality / Polish

### 6. README Accuracy — **Priority: MEDIUM**
- Step 4 references `GDShieldRuntime.PACK_OFFSET` which no longer exists (offset is native-derived now)
- CI example shows `ubuntu-latest` but actual workflow runs on `windows-latest`
- Should document `reseed` command
- Should document the `.gdextension` requirement (once fixed)

### 7. `repomix-output.xml` in Repo — **Priority: LOW**
43KB generated file committed. Should be in `.gitignore` or deleted.

### 8. `*.import` in `.gitignore` — **Priority: LOW**
Godot `.import` files are sometimes needed for CI exports. `icon.svg.import` is tracked but `.gitignore` excludes `*.import`. Inconsistent.

### 9. Cross-Platform CI — **Priority: LOW**
Only Windows tested. Linux/macOS export presets + CI matrix would validate the Linux `TracerPid` and macOS `P_TRACED` anti-debug paths.

### 10. Unit Tests — **Priority: LOW**
No test suite. At minimum:
- Python: test `get_derived_pack_offset()` matches C++ `derive_pack_offset()` for known seeds
- Audit: test zero-files = exit 1, test FAIL detection

---

## Recommended Next Step

**Item #1 (GDExtension registration)** is the only thing preventing the native offset loader from actually working at runtime. Everything else is defense-in-depth polish. Fix this first.

Two paths:
1. **Quick path:** Delete `ClassDB.instantiate("GDShieldNative")` from `main.gd`. Instead, have `gdshield.py harden` write the offset to a small file (e.g., `gdshield_meta.cfg`) that `main.gd` reads. Zero native dependency for the demo.
2. **Production path:** Add `godot-cpp` build, proper GDExtension init, `.gdextension` file. Required if you want `OBF_STR` and anti-debug checks running inside the game process.
