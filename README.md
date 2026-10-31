# gdshield — Godot 4 Client Hardening Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Godot Engine](https://img.shields.io/badge/Godot-4.x-478cbf?logo=godotengine&logoColor=white)](https://godotengine.org)
[![Python](https://img.shields.io/badge/Python-3.8+-yellow.svg?logo=python&logoColor=white)](https://python.org)
[![Security: Hardened](https://img.shields.io/badge/Security-GDRE_Defeated-brightgreen.svg)](#benchmark-verification)

**`gdshield`** is a reusable, modular client-side security hardening toolkit for Godot 4.x games and applications. It protects shipped `.pck` files, GDExtension binaries, and frontend webview assets from automated decompilation and asset dumping (GDRETools, gdsdecomp, IDA/Ghidra string scraping).

```
   Attack Vector                  gdshield Defense Layer
┌─────────────────────────┐      ┌────────────────────────────────────────────────────────┐
│ GDRE Tools / gdsdecomp  │ ───► │ 512-byte Pseudo-Random Offset Padding + Custom Magic   │ ➔ Error: Corrupted Header (0 files)
└─────────────────────────┘      └────────────────────────────────────────────────────────┘
┌─────────────────────────┐      ┌────────────────────────────────────────────────────────┐
│ Strings / RAM Scrapers  │ ───► │ Compile-Time XOR String Obfuscation (OBF_STR)          │ ➔ 0 Plaintext Endpoints
└─────────────────────────┘      └────────────────────────────────────────────────────────┘
┌─────────────────────────┐      ┌────────────────────────────────────────────────────────┐
│ Debuggers / Disassembler│ ───► │ Binary Symbol Stripping (-s) + PEB Anti-Debug Tripwire │ ➔ No Symbols / Debugger Detected
└─────────────────────────┘      └────────────────────────────────────────────────────────┘
┌─────────────────────────┐      ┌────────────────────────────────────────────────────────┐
│ Webview / CEF DevTools  │ ───► │ Console/Comment Stripping + F12/Right-Click Blocker    │ ➔ Clean Minified Frontend
└─────────────────────────┘      └────────────────────────────────────────────────────────┘
```

---

## Benchmark Verification

Tested against public reverse engineering tool **GDRE Tools v2.8.0-beta.2**:

| Target File | GDRE Tools Result | Extracted Files |
| :--- | :--- | :--- |
| **Default Godot `.pck`** | Successfully parsed directory | **All scripts & scenes recovered** |
| **Simple Magic Patch (`MMOR`)** | Suspect magic warning; parsed | **All scripts & scenes recovered** |
| **`gdshield` Hardened (`game_data.pck`)** | `Error: failed to open pack` | **0 files extracted (Total: 0)** |

---

## Architecture (3 Isolated Modules)

1. **`addons/gdshield/`** (Godot Editor Plugin)
   - Automatically detects export destination via `EditorExportPlugin`.
   - Triggers post-export hardening, binary stripping, and web minification automatically.
2. **`tools/gdshield/gdshield.py`** (Zero-Dependency CLI)
   - `harden`: Generates offset-padded `game_data.pck` and patches magic signatures in executables.
   - `strip-dll`: Strips symbol tables and debug sections from `.dll` and `.so` binaries.
   - `minify-web`: Removes debug logs, comments, and injects DevTools key deterrents.
   - `audit`: Verifies exported builds against security regression rules for CI/CD gates.
3. **`include/gdshield/gdshield.hpp`** (Header-Only C++ Library)
   - Compile-time string encryption macro `OBF_STR("string", key)`.
   - Cross-platform anti-debugging tripwire `is_debugger_present()`.
   - Fast memory integrity checksum `compute_fnv1a()`.

---

## Quickstart (Drop-in to Your Project)

### Step 1: Copy Toolkit Folders
Copy these folders into your existing Godot project root:
- `addons/gdshield/`
- `tools/gdshield/`
- `include/gdshield/` *(if using GDExtension C++)*

### Step 2: Enable the Plugin
In Godot Editor:
- Go to **Project** -> **Project Settings** -> **Plugins**.
- Enable **gdshield**.

*(Optional but recommended)*: Also install and enable [GDMaim](https://github.com/cherram/gdmaim) for GDScript identifier and control-flow scrambling.

### Step 3: Add Offset-Aware Loader Hook
In your game's main entry point (e.g. `main.gd` or bootstrap scene):
```gdscript
func _ready() -> void:
    # Mount hardened data pack if running in production release
    var exe_dir: String = OS.get_executable_path().get_base_dir()
    var pack_path: String = exe_dir.path_join("game_data.pck")
    if FileAccess.file_exists(pack_path):
        ProjectSettings.load_resource_pack(pack_path, true, 512)
```
*Note: In the Godot Editor or during unit tests, `game_data.pck` will not exist, so your game seamlessly loads local `res://` assets without interference.*

### Step 4: Export Your Game
Export your project normally using **Project** -> **Export...** (or via CLI):
```bash
godot --headless --export-release "Windows Desktop" "build/desktop/mygame.exe"
```
The export plugin automatically generates `game_data.pck`, patches the executable, and strips native binaries.

---

## CLI Reference (`gdshield.py`)

Run independently without opening the Godot Editor:

```bash
# 1. PCK & Executable Hardening
python tools/gdshield/gdshield.py harden --pck build/desktop/mygame.pck --exe build/desktop/mygame.exe

# 2. Native Binary Stripping
python tools/gdshield/gdshield.py strip-dll --path build/desktop/libgame.dll

# 3. Webview Lockdown
python tools/gdshield/gdshield.py minify-web --dir ui/desktop

# 4. Security Audit (CI/CD Gate)
python tools/gdshield/gdshield.py audit --dir build/desktop --report audit_report.txt
```

---

## C++ GDExtension Integration

Include `gdshield.hpp` in your native backend:

```cpp
#include <gdshield/gdshield.hpp>

void on_init() {
    // 1. Anti-Debug Tripwire
    if (gdshield::is_debugger_present()) {
        // Log telemetry or throttle sensitive calls
    }

    // 2. Compile-Time String XOR (0 Plaintext Strings in Binary)
    std::string endpoint = OBF_STR("/api/v1/auth/token", 0x4B);
    std::string secret_key = OBF_STR("production_signing_key_9942", 0x7A);
}
```

Compile release DLL with stripped symbols:
```bash
g++ -O3 -shared -Iinclude -s -Wl,--strip-all src/entry.cpp -o bin/libgame.dll
```

---

## CI/CD Audit Gate (`.github/workflows/audit.yml`)

Ensure no unhardened builds ship accidentally:
```yaml
name: gdshield Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run gdshield Audit
        run: |
          python tools/gdshield/gdshield.py audit --dir build/desktop
          if grep -q "\[FAIL\]" audit_report.txt; then
            echo "Security regression detected!"
            exit 1
          fi
```

---

## Licensing & GPL Boundary

- `gdshield` is licensed under the permissive **[MIT License](LICENSE)**.
- Reverse engineering benchmarks (such as GDRETools and gdsdecomp) are GPL-licensed and are strictly used as external black-box test binaries. Zero GPL code is incorporated into `gdshield`.

---

## Contributing
Issues and Pull Requests are welcome! Please ensure all PRs pass `python tools/gdshield/gdshield.py audit` before submitting.
