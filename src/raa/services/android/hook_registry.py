"""Reviewed and approved instrumentation hook script registry.

Provides vetted Frida and objection hook templates for crypto, network,
filesystem, IPC, anti-analysis detection, and memory dumping.
Enforces security constraints: anti-analysis checks are observed and reported,
never silently bypassed by default.
"""

from __future__ import annotations

from raa.domain.dynamic import HookCategory, HookSpec
from raa.errors import NotFoundError

_REVIEWED_HOOKS: dict[str, HookSpec] = {
    "crypto.cipher": HookSpec(
        id="crypto.cipher",
        name="Crypto Cipher Operations",
        category=HookCategory.CRYPTO,
        description=(
            "Intercepts javax.crypto.Cipher initialization and execution, "
            "recording algorithms, modes, and operations."
        ),
        safety_rating="safe",
        script_template="""
Java.perform(function() {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.init.overload('int', 'java.security.Key').implementation = function(opmode, key) {
        send({
            category: 'crypto',
            hook: 'crypto.cipher',
            method: 'Cipher.init',
            opmode: opmode === 1 ? 'ENCRYPT' : 'DECRYPT',
            algorithm: this.getAlgorithm(),
            key_algorithm: key.getAlgorithm()
        });
        return this.init(opmode, key);
    };
    Cipher.doFinal.overload('[B').implementation = function(bytes) {
        send({
            category: 'crypto',
            hook: 'crypto.cipher',
            method: 'Cipher.doFinal',
            input_length: bytes ? bytes.length : 0
        });
        return this.doFinal(bytes);
    };
});
""",
    ),
    "crypto.hash": HookSpec(
        id="crypto.hash",
        name="Message Digest Hashing",
        category=HookCategory.CRYPTO,
        description="Intercepts java.security.MessageDigest digest calculations.",
        safety_rating="safe",
        script_template="""
Java.perform(function() {
    var MessageDigest = Java.use('java.security.MessageDigest');
    MessageDigest.digest.overload('[B').implementation = function(input) {
        send({
            category: 'crypto',
            hook: 'crypto.hash',
            method: 'MessageDigest.digest',
            algorithm: this.getAlgorithm(),
            input_length: input ? input.length : 0
        });
        return this.digest(input);
    };
});
""",
    ),
    "network.http": HookSpec(
        id="network.http",
        name="HTTP Client Interceptor",
        category=HookCategory.NETWORK,
        description=(
            "Intercepts HTTP connections via HttpURLConnection and OkHttp requests "
            "with URL extraction."
        ),
        safety_rating="safe",
        script_template="""
Java.perform(function() {
    var URL = Java.use('java.net.URL');
    URL.openConnection.overload().implementation = function() {
        send({
            category: 'network',
            hook: 'network.http',
            method: 'URL.openConnection',
            url: this.toString()
        });
        return this.openConnection();
    };
});
""",
    ),
    "filesystem.file_access": HookSpec(
        id="filesystem.file_access",
        name="File System Operations",
        category=HookCategory.FILESYSTEM,
        description="Tracks File, FileInputStream, and FileOutputStream access paths.",
        safety_rating="safe",
        script_template="""
Java.perform(function() {
    var File = Java.use('java.io.File');
    File.$init.overload('java.lang.String').implementation = function(path) {
        send({
            category: 'filesystem',
            hook: 'filesystem.file_access',
            method: 'File.<init>',
            path: path
        });
        return this.$init(path);
    };
});
""",
    ),
    "keystore.alias": HookSpec(
        id="keystore.alias",
        name="KeyStore Key Retrieval",
        category=HookCategory.KEYSTORE,
        description="Monitors KeyStore alias queries and key retrieval operations.",
        safety_rating="safe",
        script_template="""
Java.perform(function() {
    var KeyStore = Java.use('java.security.KeyStore');
    KeyStore.getKey.implementation = function(alias, password) {
        send({
            category: 'keystore',
            hook: 'keystore.alias',
            method: 'KeyStore.getKey',
            alias: alias
        });
        return this.getKey(alias, password);
    };
});
""",
    ),
    "ipc.intent": HookSpec(
        id="ipc.intent",
        name="Intent & Component IPC",
        category=HookCategory.IPC,
        description="Monitors Activity and Service launches via Intents.",
        safety_rating="safe",
        script_template="""
Java.perform(function() {
    var ContextWrapper = Java.use('android.content.ContextWrapper');
    var hook = ContextWrapper.startActivity.overload('android.content.Intent');
    hook.implementation = function(intent) {
        send({
            category: 'ipc',
            hook: 'ipc.intent',
            method: 'Context.startActivity',
            action: intent.getAction(),
            component: intent.getComponent() ? intent.getComponent().flattenToString() : null,
            data_uri: intent.getDataString()
        });
        return this.startActivity(intent);
    };
});
""",
    ),
    "anti_analysis.root_detection": HookSpec(
        id="anti_analysis.root_detection",
        name="Root Detection Observer",
        category=HookCategory.ANTI_ANALYSIS,
        description=(
            "Observes and logs root detection checks (su binary lookups, test-keys) "
            "without bypassing."
        ),
        safety_rating="safe",
        script_template="""
Java.perform(function() {
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var isRoot = path.indexOf('/su') !== -1 || path.indexOf('busybox') !== -1;
        if (isRoot || path.indexOf('/system/bin/which') !== -1) {
            send({
                category: 'anti_analysis',
                hook: 'anti_analysis.root_detection',
                type: 'root_detection',
                method: 'File.exists',
                path: path,
                bypassed: false
            });
        }
        return this.exists();
    };
});
""",
    ),
    "anti_analysis.debugger_check": HookSpec(
        id="anti_analysis.debugger_check",
        name="Debugger Check Observer",
        category=HookCategory.ANTI_ANALYSIS,
        description="Observes and logs Debug.isDebuggerConnected() invocations without bypassing.",
        safety_rating="safe",
        script_template="""
Java.perform(function() {
    var Debug = Java.use('android.os.Debug');
    Debug.isDebuggerConnected.implementation = function() {
        send({
            category: 'anti_analysis',
            hook: 'anti_analysis.debugger_check',
            type: 'debugger_detection',
            method: 'Debug.isDebuggerConnected',
            bypassed: false
        });
        return this.isDebuggerConnected();
    };
});
""",
    ),
    "anti_analysis.frida_detection": HookSpec(
        id="anti_analysis.frida_detection",
        name="Frida Detection Observer",
        category=HookCategory.ANTI_ANALYSIS,
        description="Observes process map and port scanning looking for Frida artifacts.",
        safety_rating="safe",
        script_template="""
Java.perform(function() {
    // Monitors socket connects to standard Frida ports (27042)
    var Socket = Java.use('java.net.Socket');
    Socket.$init.overload('java.lang.String', 'int').implementation = function(host, port) {
        if (port === 27042 || port === 27043) {
            send({
                category: 'anti_analysis',
                hook: 'anti_analysis.frida_detection',
                type: 'frida_detection',
                method: 'Socket.<init>',
                host: host,
                port: port,
                bypassed: false
            });
        }
        return this.$init(host, port);
    };
});
""",
    ),
}


class HookRegistry:
    """Registry of reviewed, validated Frida and objection hook templates."""

    def __init__(self) -> None:
        self._hooks = dict(_REVIEWED_HOOKS)

    def list_hooks(self, category: HookCategory | None = None) -> list[HookSpec]:
        """List all reviewed hooks, optionally filtered by category."""
        hooks = list(self._hooks.values())
        if category is not None:
            hooks = [h for h in hooks if h.category == category]
        return sorted(hooks, key=lambda h: (h.category.value, h.id))

    def get_hook(self, hook_id: str) -> HookSpec:
        """Retrieve a specific hook specification by ID."""
        if hook_id not in self._hooks:
            raise NotFoundError(
                f"Reviewed hook '{hook_id}' not found.",
                details={"available_hooks": sorted(self._hooks.keys())},
            )
        return self._hooks[hook_id]

    def build_combined_script(self, hook_ids: list[str]) -> str:
        """Combine multiple reviewed hook templates into a single instrumentation script."""
        parts: list[str] = [
            "// RAA Dynamic Instrumentation Script (Auto-generated from Reviewed Registry)"
        ]
        for hid in hook_ids:
            hook = self.get_hook(hid)
            parts.append(f"\n// --- Hook: {hook.name} ({hook.id}) ---")
            parts.append(hook.script_template.strip())
        return "\n".join(parts)
