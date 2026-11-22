"""Codeless Runtime Hook Generation & Dynamic Method Interceptor.

Inspired by m0bilesecurity/RMS-Runtime-Mobile-Security: automatically injects pre-configured
Frida monitors for javax.crypto.Cipher, Android KeyStore, and SharedPreferences, and provides
codeless on-the-fly method interception to inspect arguments and override return values without JS.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any

PRECONFIGURED_HOOKS: dict[str, dict[str, Any]] = {
    "crypto": {
        "classes": ["javax.crypto.Cipher", "javax.crypto.spec.SecretKeySpec"],
        "methods": ["init", "doFinal"],
        "description": "Monitor AES/RSA cipher modes, secret keys, IVs, plaintexts, ciphertexts.",
        "script": (
            "// RMS Pre-configured Crypto Interceptor\n"
            "Java.perform(function() {\n"
            "    var Cipher = Java.use('javax.crypto.Cipher');\n"
            "    Cipher.init.overload('int', 'java.security.Key')"
            ".implementation = function(op, k) {\n"
            "        console.log('[RMS:Crypto] Cipher.init op=' + op);\n"
            "        return this.init(op, k);\n"
            "    };\n"
            "    Cipher.doFinal.overload('[B').implementation = function(input) {\n"
            "        var inLen = input ? input.length : 0;\n"
            "        console.log('[RMS:Crypto] Cipher.doFinal len=' + inLen);\n"
            "        var res = this.doFinal(input);\n"
            "        console.log('[RMS:Crypto] Cipher.doFinal out=' + (res ? res.length : 0));\n"
            "        return res;\n"
            "    };\n"
            "});\n"
        ),
    },
    "keystore": {
        "classes": ["java.security.KeyStore"],
        "methods": ["getEntry", "getKey", "setKeyEntry"],
        "description": "Audit Android Keystore entry access, key aliases, and hardware keys.",
        "script": (
            "// RMS Pre-configured KeyStore Interceptor\n"
            "Java.perform(function() {\n"
            "    var KeyStore = Java.use('java.security.KeyStore');\n"
            "    KeyStore.getKey.overload('java.lang.String', '[C')"
            ".implementation = function(a, p) {\n"
            "        console.log('[RMS:KeyStore] KeyStore.getKey alias=' + a);\n"
            "        return this.getKey(a, p);\n"
            "    };\n"
            "});\n"
        ),
    },
    "shared_preferences": {
        "classes": [
            "android.app.SharedPreferencesImpl",
            "android.content.SharedPreferences$Editor",
        ],
        "methods": ["getString", "putString", "getInt", "putInt"],
        "description": "Track runtime SharedPreferences reads and writes for unencrypted values.",
        "script": (
            "// RMS Pre-configured SharedPreferences Interceptor\n"
            "Java.perform(function() {\n"
            "    var Editor = Java.use('android.content.SharedPreferences$Editor');\n"
            "    Editor.putString.implementation = function(k, v) {\n"
            "        console.log('[RMS:Prefs] putString key=' + k + ' val=' + v);\n"
            "        return this.putString(k, v);\n"
            "    };\n"
            "});\n"
        ),
    },
}


def generate_rms_runtime_hooks(
    category: str = "crypto",
    target_package: str | None = None,
) -> dict[str, Any]:
    """Generate pre-configured Frida hooks for Crypto, KeyStore, or SharedPreferences."""
    cat = category.lower()
    hook_meta = PRECONFIGURED_HOOKS.get(cat, PRECONFIGURED_HOOKS["crypto"])

    digest = hashlib.sha256(f"{cat}:{target_package}:{time.time()}".encode()).hexdigest()[:8]
    hook_id = f"rms-{cat}-{digest}"

    return {
        "hook_id": hook_id,
        "category": cat,
        "target_package": target_package or "default",
        "description": hook_meta["description"],
        "monitored_classes": hook_meta["classes"],
        "monitored_methods": hook_meta["methods"],
        "frida_script": hook_meta["script"],
        "status": "ready",
    }


def override_rms_method(
    target_class: str = "com.target.app.SecurityCheck",
    target_method: str = "isDeviceRooted",
    param_types: list[str] | None = None,
    return_value_override: Any = False,
    log_arguments: bool = True,
) -> dict[str, Any]:
    """Dynamically hook target class/method, logging arguments and overriding return value."""
    digest = hashlib.sha256(f"{target_class}:{target_method}".encode()).hexdigest()[:8]
    hook_id = f"rms-override-{digest}"

    # Build dynamic Frida script
    ret_js = (
        "true"
        if return_value_override is True
        else ("false" if return_value_override is False else f"'{return_value_override}'")
    )
    frida_script = (
        f"// RMS Codeless Method Interceptor for {target_class}.{target_method}\n"
        "Java.perform(function() {\n"
        f"    var targetClass = Java.use('{target_class}');\n"
        f"    targetClass.{target_method}.implementation = function() {{\n"
    )
    if log_arguments:
        frida_script += (
            f"        console.log('[RMS:Intercept] {target_class}.{target_method} called.');\n"
            "        for (var i = 0; i < arguments.length; i++) {\n"
            "            console.log('   arg[' + i + '] = ' + arguments[i]);\n"
            "        }\n"
        )
    if return_value_override is not None:
        frida_script += (
            f"        console.log('[RMS:Intercept] Overriding return value with: {ret_js}');\n"
            f"        return {ret_js};\n"
        )
    else:
        frida_script += "        return this." + target_method + ".apply(this, arguments);\n"

    frida_script += "    };\n});\n"

    return {
        "hook_id": hook_id,
        "target_class": target_class,
        "target_method": target_method,
        "param_types": param_types or [],
        "override_active": return_value_override is not None,
        "return_value_override": return_value_override,
        "frida_script": frida_script,
        "status": "ready",
    }
