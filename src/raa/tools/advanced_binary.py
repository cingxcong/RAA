"""Phase 17 Tools: Next-Gen Binary Decompilation, Advanced Apple Analysis & Hardware Controls.

Registers 18 tools:
- kuna_rust_decompile
- retdec_native_decompile
- malimite_macho_demangle
- macho_swift_section_parse
- objc_helper_macho_reconstruct
- native_gdb_mi_session
- native_objdump_dwarf_inspect
- engine_rizin_cutter_bridge
- engine_ghidra_headless_bridge
- iot_firmware_partition_extract
- device_lock_bypass_adb
- device_lock_bruteforce_adb
- device_hid_ducky_payload_gen
- device_gatekeeper_credential_clear
- xposed_unlock_hook_inject
- nanobot_daemon_ctl
- nanobot_notify_dispatch
- airgap_lastbook_query
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from raa.registry.models import (
    CapabilityRegistry,
    ToolAnnotations,
    ToolContext,
    ToolInput,
    ToolOutcome,
    ToolSpec,
)
from raa.registry.profiles import ADMIN, CORE, DYNAMIC

# --- Input Models ---


class KunaRustDecompileInput(ToolInput):
    library_name: str = Field(
        min_length=1, description="Native library filename (e.g. libcrypto.so)."
    )
    target_arch: str = Field(default="arm64-v8a", description="Target CPU architecture.")
    symbol_filter: str | None = Field(
        default=None, description="Optional symbol name to decompile."
    )


class RetdecNativeDecompileInput(ToolInput):
    library_name: str = Field(min_length=1, description="Native library filename.")
    target_arch: str = Field(default="arm64-v8a", description="Target architecture.")


class MalimiteMachoDemangleInput(ToolInput):
    binary_path: str = Field(min_length=1, description="Path to Mach-O binary in IPA Payload.")


class MachOSwiftSectionParseInput(ToolInput):
    binary_path: str = Field(min_length=1, description="Path to Mach-O binary.")


class ObjcHelperMachoReconstructInput(ToolInput):
    binary_path: str = Field(min_length=1, description="Path to Mach-O binary.")


class NativeGdbMiSessionInput(ToolInput):
    action: Literal["start", "command", "breakpoint", "registers", "stop"] = Field(
        description="GDB/MI session control action.",
    )
    target_binary: str = Field(min_length=1, description="Path to binary being debugged.")
    session_id: str | None = Field(default=None, description="Active session ID.")
    command_str: str | None = Field(default=None, description="GDB/MI command.")
    breakpoint_location: str | None = Field(default=None, description="Symbol or hex address.")


class NativeObjdumpDwarfInspectInput(ToolInput):
    target_file: str = Field(min_length=1, description="Path to native ELF or Mach-O library.")
    target_symbol: str | None = Field(default=None, description="Optional symbol to disassemble.")


class EngineRizinCutterBridgeInput(ToolInput):
    target_file: str = Field(min_length=1, description="Path to native library.")


class EngineGhidraHeadlessBridgeInput(ToolInput):
    target_file: str = Field(min_length=1, description="Path to native library.")
    analysis_script: str = Field(
        default="DecompileHeadless.java", description="Ghidra analysis script."
    )


class IoTFirmwarePartitionExtractInput(ToolInput):
    apk_path: str = Field(min_length=1, description="Path to mobile companion APK.")


class DeviceLockBypassAdbInput(ToolInput):
    device_id: str = Field(min_length=1, description="Target ADB device serial.")


class DeviceLockBruteforceAdbInput(ToolInput):
    device_id: str = Field(min_length=1, description="Target ADB device serial.")
    max_digits: int = Field(default=4, ge=4, le=6, description="PIN length to brute force.")


class DeviceHidDuckyPayloadGenInput(ToolInput):
    target_pin: str = Field(default="1234", description="PIN to inject.")


class DeviceGatekeeperCredentialClearInput(ToolInput):
    device_id: str = Field(min_length=1, description="Target ADB device serial.")


class XposedUnlockHookInjectInput(ToolInput):
    device_id: str = Field(min_length=1, description="Target ADB device serial.")


class NanobotDaemonCtlInput(ToolInput):
    action: Literal["start", "stop", "status", "schedule_cron"] = Field(
        description="Nanobot daemon action.",
    )
    cron_expression: str | None = Field(default=None, description="Cron expression.")
    job_name: str | None = Field(default=None, description="Job identifier.")


class NanobotNotifyDispatchInput(ToolInput):
    channel: Literal["telegram", "slack", "discord"] = Field(
        description="Target chat webhook channel."
    )
    title: str = Field(min_length=1, description="Alert title.")
    message: str = Field(min_length=1, description="Alert message.")
    severity: str = Field(default="HIGH", description="Severity level.")


class AirgapLastbookQueryInput(ToolInput):
    query: str = Field(min_length=1, description="Reversing query.")
    category: Literal["mastg", "permissions", "opcodes_arm64", "opcodes_dalvik", "cve_dict"] = (
        Field(
            default="mastg",
            description="Offline knowledge category.",
        )
    )


# --- Handlers ---


async def _kuna_rust_decompile(ctx: ToolContext, args: KunaRustDecompileInput) -> ToolOutcome:
    res = ctx.runtime.advanced_binary.decompile_native_binary(
        library_name=args.library_name,
        engine="kuna_rust",
        target_arch=args.target_arch,
        symbol_filter=args.symbol_filter,
    )
    return ToolOutcome(data=res.model_dump())


async def _retdec_native_decompile(
    ctx: ToolContext, args: RetdecNativeDecompileInput
) -> ToolOutcome:
    res = ctx.runtime.advanced_binary.decompile_native_binary(
        library_name=args.library_name,
        engine="retdec_llvm",
        target_arch=args.target_arch,
    )
    return ToolOutcome(data=res.model_dump())


async def _malimite_macho_demangle(
    ctx: ToolContext, args: MalimiteMachoDemangleInput
) -> ToolOutcome:
    res = ctx.runtime.advanced_binary.analyze_macho_apple(binary_path=args.binary_path)
    return ToolOutcome(data=res.model_dump())


async def _macho_swift_section_parse(
    ctx: ToolContext, args: MachOSwiftSectionParseInput
) -> ToolOutcome:
    res = ctx.runtime.advanced_binary.analyze_macho_apple(
        binary_path=args.binary_path, extract_objc=False
    )
    return ToolOutcome(data=res.model_dump())


async def _objc_helper_macho_reconstruct(
    ctx: ToolContext, args: ObjcHelperMachoReconstructInput
) -> ToolOutcome:
    res = ctx.runtime.advanced_binary.analyze_macho_apple(
        binary_path=args.binary_path, demangle_swift=False
    )
    return ToolOutcome(data=res.model_dump())


async def _native_gdb_mi_session(ctx: ToolContext, args: NativeGdbMiSessionInput) -> ToolOutcome:
    res = ctx.runtime.advanced_binary.manage_gdb_mi_session(
        action=args.action,
        target_binary=args.target_binary,
        session_id=args.session_id,
        command_str=args.command_str,
        breakpoint_location=args.breakpoint_location,
    )
    return ToolOutcome(data=res.model_dump())


async def _native_objdump_dwarf_inspect(
    ctx: ToolContext, args: NativeObjdumpDwarfInspectInput
) -> ToolOutcome:
    res = ctx.runtime.advanced_binary.analyze_disassembly_engine(
        target_file=args.target_file,
        engine="objdump_dwarf",
        target_symbol=args.target_symbol,
    )
    return ToolOutcome(data=res.model_dump())


async def _engine_rizin_cutter_bridge(
    ctx: ToolContext, args: EngineRizinCutterBridgeInput
) -> ToolOutcome:
    res = ctx.runtime.advanced_binary.analyze_disassembly_engine(
        target_file=args.target_file,
        engine="rizin_cutter",
    )
    return ToolOutcome(data=res.model_dump())


async def _engine_ghidra_headless_bridge(
    ctx: ToolContext, args: EngineGhidraHeadlessBridgeInput
) -> ToolOutcome:
    res = ctx.runtime.advanced_binary.analyze_disassembly_engine(
        target_file=args.target_file,
        engine="ghidra_headless",
    )
    return ToolOutcome(data=res.model_dump())


async def _iot_firmware_partition_extract(
    ctx: ToolContext, args: IoTFirmwarePartitionExtractInput
) -> ToolOutcome:
    res = ctx.runtime.advanced_binary.extract_iot_firmware(apk_path=args.apk_path)
    return ToolOutcome(data=res.model_dump())


async def _device_lock_bypass_adb(ctx: ToolContext, args: DeviceLockBypassAdbInput) -> ToolOutcome:
    res = ctx.runtime.advanced_binary.execute_lockscreen_operation(
        device_id=args.device_id, method="adb_keyguard_dismiss"
    )
    return ToolOutcome(data=res.model_dump())


async def _device_lock_bruteforce_adb(
    ctx: ToolContext, args: DeviceLockBruteforceAdbInput
) -> ToolOutcome:
    res = ctx.runtime.advanced_binary.execute_lockscreen_operation(
        device_id=args.device_id, method="pin_bruteforce"
    )
    return ToolOutcome(data=res.model_dump())


async def _device_hid_ducky_payload_gen(
    ctx: ToolContext, args: DeviceHidDuckyPayloadGenInput
) -> ToolOutcome:
    res = ctx.runtime.advanced_binary.execute_lockscreen_operation(
        device_id="hardware_otg",
        method="usb_hid_ducky",
        pin_code=args.target_pin,
    )
    return ToolOutcome(data=res.model_dump())


async def _device_gatekeeper_credential_clear(
    ctx: ToolContext, args: DeviceGatekeeperCredentialClearInput
) -> ToolOutcome:
    res = ctx.runtime.advanced_binary.execute_lockscreen_operation(
        device_id=args.device_id, method="gatekeeper_clear"
    )
    return ToolOutcome(data=res.model_dump())


async def _xposed_unlock_hook_inject(
    ctx: ToolContext, args: XposedUnlockHookInjectInput
) -> ToolOutcome:
    res = ctx.runtime.advanced_binary.execute_lockscreen_operation(
        device_id=args.device_id, method="xposed_hook"
    )
    return ToolOutcome(data=res.model_dump())


async def _nanobot_daemon_ctl(ctx: ToolContext, args: NanobotDaemonCtlInput) -> ToolOutcome:
    res = ctx.runtime.advanced_binary.control_nanobot_daemon(
        action=args.action,
        cron_expression=args.cron_expression,
        job_name=args.job_name,
    )
    return ToolOutcome(data=res.model_dump())


async def _nanobot_notify_dispatch(
    ctx: ToolContext, args: NanobotNotifyDispatchInput
) -> ToolOutcome:
    res = ctx.runtime.advanced_binary.dispatch_nanobot_notification(
        channel=args.channel,
        title=args.title,
        message=args.message,
        severity=args.severity,
    )
    return ToolOutcome(data=res)


async def _airgap_lastbook_query(ctx: ToolContext, args: AirgapLastbookQueryInput) -> ToolOutcome:
    res = ctx.runtime.advanced_binary.query_lastbook_airgap(
        query=args.query, category=args.category
    )
    return ToolOutcome(data=res.model_dump())


# --- Register Function ---


def register(registry: CapabilityRegistry) -> None:
    registry.register(
        ToolSpec(
            name="kuna_rust_decompile",
            title="Agent-First Kuna Rust Native Ghidra Decompiler",
            description="Decompiles native ARM64/x86_64 shared libraries into token-optimized C AST using native Rust.",
            input_model=KunaRustDecompileInput,
            handler=_kuna_rust_decompile,
            family="native",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="retdec_native_decompile",
            title="Retargetable RetDec LLVM Machine-Code Decompiler",
            description="Decompiles stripped native machine-code across CPU architectures using RetDec LLVM core.",
            input_model=RetdecNativeDecompileInput,
            handler=_retdec_native_decompile,
            family="native",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="malimite_macho_demangle",
            title="LaurieWired Malimite Apple Mach-O Reversing Engine",
            description="Demangles Swift/Objective-C runtime metadata and analyzes Mach-O binaries in iOS IPAs.",
            input_model=MalimiteMachoDemangleInput,
            handler=_malimite_macho_demangle,
            family="apple",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="macho_swift_section_parse",
            title="Deep Mach-O Swift Runtime Metadata Section Parser",
            description="Deeply parses Mach-O Swift 5 sections to extract Swift structs, classes, protocols, and fields.",
            input_model=MachOSwiftSectionParseInput,
            handler=_macho_swift_section_parse,
            family="apple",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="objc_helper_macho_reconstruct",
            title="Objective-C Class and Protocol Reconstructor",
            description="Reconstructs Objective-C classes, categories, methods, and cross-references from Mach-O metadata.",
            input_model=ObjcHelperMachoReconstructInput,
            handler=_objc_helper_macho_reconstruct,
            family="apple",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="native_gdb_mi_session",
            title="Persistent GDB/MI3 & LLDB Native Debugger Session",
            description="Manages persistent interactive native debugger sessions with breakpoints, registers, and stepping.",
            input_model=NativeGdbMiSessionInput,
            handler=_native_gdb_mi_session,
            family="native",
            profiles=DYNAMIC,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=False),
        )
    )
    registry.register(
        ToolSpec(
            name="native_objdump_dwarf_inspect",
            title="GNU/LLVM Objdump DWARF Link Inspector",
            description="Runs GNU/LLVM objdump with DWARF debug link resolution and selective symbol disassembly.",
            input_model=NativeObjdumpDwarfInspectInput,
            handler=_native_objdump_dwarf_inspect,
            family="native",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="engine_rizin_cutter_bridge",
            title="Headless Rizin Cutter CFG Analysis Bridge",
            description="Extracts control flow graphs (CFGs) and binary cyclomatic complexity metrics via headless Rizin.",
            input_model=EngineRizinCutterBridgeInput,
            handler=_engine_rizin_cutter_bridge,
            family="native",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="engine_ghidra_headless_bridge",
            title="Headless Ghidra Script Execution Bridge",
            description="Executes headless Ghidra scripts for automated C pseudocode decompilation and CFG extraction.",
            input_model=EngineGhidraHeadlessBridgeInput,
            handler=_engine_ghidra_headless_bridge,
            family="native",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="iot_firmware_partition_extract",
            title="Mobile Companion App IoT Firmware Extractor",
            description="Extracts embedded ESP32, UF2, and Nordic semiconductor firmware partitions from mobile companion APKs.",
            input_model=IoTFirmwarePartitionExtractInput,
            handler=_iot_firmware_partition_extract,
            family="iot",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="device_lock_bypass_adb",
            title="ADB Programmatic Lockscreen Keyguard Bypass",
            description="Programmatically neutralizes Android lockscreen keyguards and dismisses security prompts over ADB.",
            input_model=DeviceLockBypassAdbInput,
            handler=_device_lock_bypass_adb,
            family="device",
            profiles=DYNAMIC,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=False),
        )
    )
    registry.register(
        ToolSpec(
            name="device_lock_bruteforce_adb",
            title="Automated ADB Lockscreen PIN Brute-Forcer",
            description="Automates dictionary-guided 4/6-digit PIN and pattern brute-forcing over ADB with timer reset.",
            input_model=DeviceLockBruteforceAdbInput,
            handler=_device_lock_bruteforce_adb,
            family="device",
            profiles=DYNAMIC,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=False),
        )
    )
    registry.register(
        ToolSpec(
            name="device_hid_ducky_payload_gen",
            title="USB Rubber Ducky Keystroke Injection Generator",
            description="Generates USB Rubber Ducky and BadUSB keystroke injection scripts for hardware OTG lockscreen bypass.",
            input_model=DeviceHidDuckyPayloadGenInput,
            handler=_device_hid_ducky_payload_gen,
            family="device",
            profiles=DYNAMIC,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="device_gatekeeper_credential_clear",
            title="Forensic Locksettings and Gatekeeper Clear",
            description="Forensically clears locksettings database and Gatekeeper credential keys over ADB/Recovery.",
            input_model=DeviceGatekeeperCredentialClearInput,
            handler=_device_gatekeeper_credential_clear,
            family="device",
            profiles=DYNAMIC,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=False),
        )
    )
    registry.register(
        ToolSpec(
            name="xposed_unlock_hook_inject",
            title="Xposed Dynamic Unlock and Root Trigger Hook",
            description="Configures Xposed/LSPosed hooks for automated alternate unlock and root payload execution.",
            input_model=XposedUnlockHookInjectInput,
            handler=_xposed_unlock_hook_inject,
            family="device",
            profiles=DYNAMIC,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=False),
        )
    )
    registry.register(
        ToolSpec(
            name="nanobot_daemon_ctl",
            title="Headless Background Monitoring Nanobot Daemon",
            description="Manages background monitoring daemon, cron schedules, and heartbeat health checks.",
            input_model=NanobotDaemonCtlInput,
            handler=_nanobot_daemon_ctl,
            family="automation",
            profiles=ADMIN,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=False),
        )
    )
    registry.register(
        ToolSpec(
            name="nanobot_notify_dispatch",
            title="Multi-Channel Alert Dispatcher",
            description="Dispatches rich security alerts and test receipts to Telegram, Slack, and Discord webhooks.",
            input_model=NanobotNotifyDispatchInput,
            handler=_nanobot_notify_dispatch,
            family="automation",
            profiles=ADMIN,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="airgap_lastbook_query",
            title="Air-Gapped Offline Knowledge Vault Query",
            description="Queries local zero-network reversing knowledge base, MASTG guidelines, and opcode manuals.",
            input_model=AirgapLastbookQueryInput,
            handler=_airgap_lastbook_query,
            family="knowledge",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
