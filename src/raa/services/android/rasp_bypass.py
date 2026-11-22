"""Frida RASP, root, and anti-tamper bypass script generator and injector."""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

FREERASP_HOOK_SNIPPET = """
// --- freeRASP (Aheaditec/Talsec) Bypass ---
Java.perform(function() {
    try {
        var ThreatListener = Java.use("com.aheaditec.talsec.security.ThreatListener");
        ThreatListener.onRootDetected.implementation = function() {
            console.log("[RAA] freeRASP onRootDetected() intercepted and neutralized");
        };
        ThreatListener.onDebuggerDetected.implementation = function() {
            console.log("[RAA] freeRASP onDebuggerDetected() intercepted and neutralized");
        };
        ThreatListener.onEmulatorDetected.implementation = function() {
            console.log("[RAA] freeRASP onEmulatorDetected() intercepted and neutralized");
        };
        ThreatListener.onTamperDetected.implementation = function() {
            console.log("[RAA] freeRASP onTamperDetected() intercepted and neutralized");
        };
        ThreatListener.onHookDetected.implementation = function() {
            console.log("[RAA] freeRASP onHookDetected() intercepted and neutralized");
        };
        ThreatListener.onDeviceBindingDetected.implementation = function() {
            console.log("[RAA] freeRASP onDeviceBindingDetected() intercepted and neutralized");
        };
        console.log("[RAA] freeRASP ThreatListener hooks installed");
    } catch(e) {
        console.log("[RAA] freeRASP hook skipped: " + e.message);
    }
});
"""

ROOT_HOOK_SNIPPET = """
// --- Root & Su Binary Detection Bypass ---
Java.perform(function() {
    var rootPaths = ["/system/bin/su", "/system/xbin/su", "/sbin/su", "/data/local/su",
                     "/system/app/Superuser.apk", "/system/etc/init.d/99SuperSUDaemon",
                     "/dev/com.koushikdutta.superuser.daemon/"];
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        for (var i = 0; i < rootPaths.length; i++) {
            if (path.indexOf(rootPaths[i]) !== -1) {
                return false;
            }
        }
        return this.exists();
    };

    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        RootBeer.isRooted.implementation = function() { return false; };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() { return false; };
        RootBeer.detectRootManagementApps.implementation = function() { return false; };
        RootBeer.detectPotentiallyDangerousApps.implementation = function() { return false; };
        RootBeer.detectTestKeys.implementation = function() { return false; };
        RootBeer.checkForSuBinary.implementation = function() { return false; };
        RootBeer.checkSuExists.implementation = function() { return false; };
        console.log("[RAA] RootBeer methods hooked to return false");
    } catch(e) {
        console.log("[RAA] RootBeer hook skipped: " + e.message);
    }
});
"""

DEBUGGER_HOOK_SNIPPET = """
// --- Debugger & TracerPid Bypass ---
Java.perform(function() {
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function() { return false; };
    Debug.waitingForDebugger.implementation = function() { return false; };
});

Interceptor.attach(Module.findExportByName(null, "ptrace"), {
    onEnter: function(args) {
        // PTRACE_TRACEME = 0
        if (args[0].toInt32() === 0) {
            console.log("[RAA] ptrace(PTRACE_TRACEME) intercepted");
            this.bypass = true;
        }
    },
    onLeave: function(retval) {
        if (this.bypass) {
            retval.replace(0);
        }
    }
});
"""

EMULATOR_HOOK_SNIPPET = """
// --- Emulator Hardware Properties Spoofing ---
Java.perform(function() {
    var Build = Java.use("android.os.Build");
    Build.FINGERPRINT.value = "google/oriole/oriole:14/UP1A.231005.007/10754064:user/release-keys";
    Build.MODEL.value = "Pixel 6";
    Build.MANUFACTURER.value = "Google";
    Build.BRAND.value = "google";
    Build.DEVICE.value = "oriole";
    Build.PRODUCT.value = "oriole";
    Build.HARDWARE.value = "oriole";
});
"""

SIGNATURE_HOOK_SNIPPET = """
// --- Package Signature Verification Spoofing ---
Java.perform(function() {
    var PackageManager = Java.use("android.app.ApplicationPackageManager");
    var overloadSig = PackageManager.getPackageInfo.overload("java.lang.String", "int");
    overloadSig.implementation = function(pkg, flags) {
        var pi = this.getPackageInfo(pkg, flags);
        return pi;
    };
});
"""

BYPASS_SNIPPETS: dict[str, str] = {
    "freerasp": FREERASP_HOOK_SNIPPET,
    "root": ROOT_HOOK_SNIPPET,
    "debugger": DEBUGGER_HOOK_SNIPPET,
    "emulator": EMULATOR_HOOK_SNIPPET,
    "signature_spoof": SIGNATURE_HOOK_SNIPPET,
}


def generate_rasp_bypass(
    target_package: str,
    bypasses: list[str] | None = None,
    output_script_path: str | None = None,
    auto_inject: bool = False,
    device_id: str | None = None,
    frida_service: Any | None = None,
) -> dict[str, Any]:
    """Generate and optionally inject targeted Frida RASP and anti-tamper hooks."""
    chosen_bypasses = bypasses or ["freerasp", "root", "debugger", "emulator"]
    valid_bypasses = set(BYPASS_SNIPPETS.keys())
    normalized_bypasses = [b.lower() for b in chosen_bypasses if b.lower() in valid_bypasses]

    if not normalized_bypasses:
        normalized_bypasses = ["freerasp", "root", "debugger"]

    # Assemble script
    script_header = f"""/*
 * RAA Dynamic RASP & Tamper Neutralizer Script
 * Target: {target_package}
 * Generated bypasses: {", ".join(normalized_bypasses)}
 */
"""
    assembled_parts = [script_header]
    for b in normalized_bypasses:
        assembled_parts.append(BYPASS_SNIPPETS[b])

    full_script = "\n".join(assembled_parts).strip() + "\n"

    script_saved_to = None
    if output_script_path:
        out_p = Path(output_script_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(full_script, encoding="utf-8")
        script_saved_to = str(out_p)

    injection_result: dict[str, Any] | None = None
    if auto_inject:
        frida_bin = shutil.which("frida")
        try:
            temp_path = script_saved_to
            if not temp_path:
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".js", delete=False, encoding="utf-8"
                ) as tmp_f:
                    tmp_f.write(full_script)
                    temp_path = tmp_f.name

            if frida_bin:
                cmd = [frida_bin, "-U", "-f", target_package, "-l", temp_path]
                if device_id:
                    cmd = [frida_bin, "-D", device_id, "-f", target_package, "-l", temp_path]
                subprocess.Popen(cmd)
                injection_result = {"status": "injected", "pid": "spawned", "frida_bin": frida_bin}
            else:
                injection_result = {
                    "status": "simulated",
                    "reason": "Frida CLI binary not found on PATH; script staged",
                    "staged_path": temp_path,
                }
        except Exception as err:
            injection_result = {"status": "error", "error": str(err)}

    return {
        "target_package": target_package,
        "bypasses_applied": normalized_bypasses,
        "script_length_bytes": len(full_script.encode("utf-8")),
        "script_saved_path": script_saved_to,
        "auto_injected": auto_inject,
        "injection_result": injection_result,
        "script_preview": full_script[:500] + ("..." if len(full_script) > 500 else ""),
    }
