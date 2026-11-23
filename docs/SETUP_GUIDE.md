# RAA Setup & Prerequisites Guide: MCP Tools & Analysis Engines

This guide details the complete prerequisites, system environment variables, binary dependencies, hardware configurations, and verification procedures required before running full end-to-end testing across all **244 RAA Model Context Protocol (MCP) tools** and underlying reverse engineering engines.

---

## 1. Architecture & Execution Modes

RAA operates across two execution boundaries:

1. **Pure-Python Native Mode (`RAA_ENGINE_EXECUTION_ENABLED=false`)**:
   - Zero-external-dependency indexing, DEX/AXML/ARSC parsing, manifest extraction, code structure mapping, RFC 5652 PKCS#7 v1/v2/v3 APK signing, and string localization/patching.
   - Requires only Python 3.11+ and project dependencies.
2. **External Engine Mode (`RAA_ENGINE_EXECUTION_ENABLED=true`)**:
   - Spawns external decompilers, disassemblers, native binary analyzers, instrumentation bridges (Frida, ADB, Scrcpy), and security linters.
   - Requires external binaries in the system `PATH` and dedicated environment variables.

---

## 2. System Environment Variables Reference

Configure these environment variables in your operating system profile (`~/.bashrc`, `~/.zshrc`, or Windows System Properties -> Environment Variables):

| Environment Variable | Recommended Value | Description |
| :--- | :--- | :--- |
| `RAA_PROFILE` | `full` | Active tool profile (`minimal`, `core`, `full`, `dynamic`, `api`, `ui`, `admin`). |
| `RAA_ENGINE_EXECUTION_ENABLED` | `true` | Enables invocation of host binaries (JADX, Apktool, Frida, etc.). |
| `RAA_ALLOWED_INPUT_ROOTS` | `["/path/to/apks", "C:\\apks"]` | JSON list of trusted filesystem directories allowed for `artifact_ingest`. |
| `RAA_WORKSPACE` | `.raa-workspace` | Directory for SQLite databases, decompiled caches, and rebuilt APK artifacts. |
| `RAA_MAX_INPUT_BYTES` | `2147483648` (2 GB) | Maximum accepted upload file size. |
| `RAA_ANALYSIS_TIMEOUT_SECONDS`| `300.0` | Timeout for deep AST and decompilation routines. |
| `RAA_ENGINE_TIMEOUT_SECONDS`  | `180.0` | Process execution timeout for external CLI commands. |
| `ANDROID_HOME` / `ANDROID_SDK_ROOT` | `/path/to/android-sdk` | Base directory of the Android SDK. |
| `JAVA_HOME` | `/path/to/jdk-17` | Required by JADX, Apktool, and Gradle (JDK 17 or 21 recommended). |

---

## 3. Required System `PATH` Directories

Ensure the following directories are present in your system `PATH` variable:

### Linux / macOS
```bash
# Android SDK
export ANDROID_HOME="$HOME/Android/Sdk"
export PATH="$PATH:$ANDROID_HOME/platform-tools"
export PATH="$PATH:$ANDROID_HOME/build-tools/34.0.0"
export PATH="$PATH:$ANDROID_HOME/cmdline-tools/latest/bin"

# Java JDK 17+
export JAVA_HOME="/usr/lib/jvm/java-17-openjdk"
export PATH="$PATH:$JAVA_HOME/bin"

# Decompilers & Tools
export PATH="$PATH:/usr/local/bin"
export PATH="$PATH:$HOME/.local/bin"
```

### Windows (PowerShell)
Add the following folders to your User or System `Path`:
- `C:\Program Files\Java\jdk-17\bin`
- `%LOCALAPPDATA%\Android\Sdk\platform-tools` (contains `adb.exe`)
- `%LOCALAPPDATA%\Android\Sdk\build-tools\34.0.0` (contains `aapt2.exe`, `apksigner.bat`, `zipalign.exe`)
- `C:\Tools\jadx\bin` (contains `jadx.bat`)
- `C:\Tools\apktool` (contains `apktool.bat`)

---

## 4. Engine Installation Matrix

RAA integrates with 24 specialized reversing, decompilation, and security engines categorized by tier:

### Tier 1 — Core Mobile Reverse Engineering (High Priority)
| Engine ID | Binary / Command | Installation Command | Purpose |
| :--- | :--- | :--- | :--- |
| **`adb`** | `adb` | Android SDK `platform-tools` | Device communication, shell commands, and package management |
| **`jadx`** | `jadx`, `jadx-gui` | `brew install jadx` or download release | Java/Kotlin source code decompilation from DEX |
| **`apktool`** | `apktool` | `apt install apktool` or download JAR | Disassembling resources, decoding binary XML, and rebuilding Smali |
| **`aapt2`** | `aapt2` | Android SDK `build-tools` | Compiling, inspecting, and dumping Android resources |
| **`apksigner`**| `apksigner` | Android SDK `build-tools` | Validating APK v1/v2/v3/v4 signatures |
| **`frida`** | `frida`, `frida-ps` | `pip install frida-tools` | Dynamic instrumentation, hook tracing, and script injection |
| **`apkid`** | `apkid` | `pip install apkid` | Packer, protector, compiler, and anti-debug detector |
| **`androguard`** | `androguard` | `pip install androguard` | Pythonic DEX and manifest structure analysis |
| **`mitmproxy`** | `mitmproxy`, `mitmdump`| `pip install mitmproxy` | Traffic interception and TLS inspection proxy |

### Tier 2 — Native, Cross-Platform & Hybrid Frameworks
| Engine ID | Binary / Command | Installation Source | Purpose |
| :--- | :--- | :--- | :--- |
| **`ghidra`** | `analyzeHeadless` | [Ghidra Releases](https://ghidra-sre.org/) | Native `.so` binary decompilation and disassembly (NSA Ghidra) |
| **`rizin`** | `rizin` | [Rizin Releases](https://rizin.re/) | Fast CLI reverse engineering of ELF shared libraries |
| **`blutter`** | `blutter` | `git clone https://github.com/worawit/blutter` | Flutter Dart AOT snapshot reversing and class reconstruction |
| **`il2cppdumper`**| `Il2CppDumper` | [Il2CppDumper Releases](https://github.com/Perfare/Il2CppDumper) | Unity IL2CPP game binary and metadata unpacker |
| **`hbctool`** | `hbctool` | `pip install hbctool` | React Native Hermes bytecode disassembly and assembler |
| **`ilspycmd`** | `ilspycmd` | `dotnet tool install -g ilspycmd` | Xamarin/.NET decompilation for cross-platform Android apps |

### Tier 3 — AppSec, Vulnerabilities & SBOM Verification
| Engine ID | Binary / Command | Installation Source | Purpose |
| :--- | :--- | :--- | :--- |
| **`semgrep`** | `semgrep` | `pip install semgrep` | Static analysis security scans for injected scripts and source |
| **`syft`** | `syft` | `curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \| sh` | Software Bill of Materials (SBOM) generator |
| **`grype`** | `grype` | `curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \| sh` | Vulnerability scanning for third-party libraries |
| **`quark`** | `quark` | `pip install quark-engine` | Android malware behavioral heuristics and rule engine |
| **`schemathesis`**| `schemathesis` | `pip install schemathesis` | Autonomous API property-based contract testing |

---

## 5. Physical Mobile Device Testing Setup

When validating dynamic tools (`dynamic_instrument_frida`, `apk_install`, `runtime_screen_capture`, `rasp_bypass`):

1. **Enable Developer Options on Device**:
   - Navigate to `Settings` -> `About Device` -> Tap `Build Number` 7 times.
   - Enter `Developer Options` -> Toggle **USB Debugging** on.
   - Toggle **Install via USB** on (crucial for automated signing tests).
   - Toggle **Disable Permission Monitoring** on (if available on ColorOS/Oppo/Xiaomi).
2. **Authorize Host Machine**:
   ```bash
   adb devices
   # Accept the "Always allow from this computer" prompt on the device screen
   ```
3. **Root / Frida Server (For Dynamic Hooking)**:
   - For rooted devices: push `frida-server` matching device architecture (`adb shell getprop ro.product.cpu.abi`):
     ```bash
     adb push frida-server /data/local/tmp/
     adb shell "chmod 755 /data/local/tmp/frida-server"
     adb shell "/data/local/tmp/frida-server &"
     ```
   - For non-rooted devices: use RAA's built-in gadget injector tool:
     ```bash
     # RAA injects Frida gadget automatically into the target APK:
     apk_patch(operation="inject_frida_gadget", parameters={"gadget_version": "16.1.4"})
     ```

---

## 6. Pre-Flight Health Check

Before initiating automated MCP tests, run the RAA Doctor command to verify that all databases, workspace permissions, and installed engines are detected:

### Using the CLI
```bash
raa admin doctor
```

### Using the MCP Tool
Invoke the MCP tool:
```json
{
  "name": "raa.admin_doctor",
  "arguments": {}
}
```

**Expected Healthy Response**:
```json
{
  "ok": true,
  "profile": "full",
  "workspace_writable": true,
  "database_ok": true,
  "mcp_sdk": "1.3.0",
  "engines": {
    "catalogued": 24,
    "installed": 12
  },
  "implemented_tools": 244
}
```

---

## 7. Quick Smoke Test Sequence

Run this short sequence to confirm that workspace ingestion, static analysis, patching, RFC signing, and physical deployment operate without error:

```bash
# 1. Ingest sample APK
raa artifact ingest --path sample.apk

# 2. Inspect manifest and permissions
raa source search --query "android.permission.INTERNET"

# 3. Patch APK for network inspection and set debuggable
raa apk patch --operation network_security_bypass --input sample.apk

# 4. Sign rebuilt container (Applies pure-native v1, v2, and v3 RFC 5652 signatures)
raa apk sign --input patched_sample.apk

# 5. Install and verify on physical Android target
adb install -r signed_sample.apk
```
