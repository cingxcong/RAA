"""Dynamic analysis, device lease, instrumentation, and memory dump MCP tools."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from raa.policy.scopes import (
    ANDROID_INSTALL,
    ANDROID_PATCH,
    DYNAMIC_DEVICE,
    DYNAMIC_INSTRUMENT,
    PROJECT_READ,
    PROJECT_WRITE,
)
from raa.registry.models import (
    CapabilityRegistry,
    ToolAnnotations,
    ToolContext,
    ToolOutcome,
    ToolSpec,
)
from raa.registry.profiles import API, DYNAMIC, UI
from raa.services.android.perfetto_analyzer import (
    analyze_perfetto_events,
    record_perfetto_trace,
)
from raa.services.android.webview_cdp import WebViewCDPSession

# --- Input models ---


class DeviceListInput(BaseModel):
    """Filter parameters for listing test devices."""

    device_type: str | None = Field(
        default=None,
        description="Filter by device platform: avd, redroid, physical, emulator, mock.",
    )
    available_only: bool = Field(
        default=False,
        description="Filter to only available (unleased) devices.",
    )


class DeviceLeaseInput(BaseModel):
    """Parameters to lease an isolated device."""

    project_id: str = Field(min_length=1, description="Target project ID.")
    device_id: str = Field(min_length=1, description="Device identifier to lease.")
    duration_seconds: int = Field(
        default=3600,
        ge=60,
        le=86400,
        description="Lease duration in seconds.",
    )


class DeviceReleaseInput(BaseModel):
    """Parameters to release a leased device and restore it to clean state."""

    project_id: str = Field(min_length=1, description="Target project ID.")
    device_id: str = Field(min_length=1, description="Leased device identifier to release.")


class DeviceSnapshotInput(BaseModel):
    """Parameters to create or restore a device snapshot."""

    project_id: str = Field(min_length=1, description="Target project ID.")
    device_id: str = Field(min_length=1, description="Leased device identifier.")
    name: str = Field(min_length=1, description="Snapshot name.")
    action: Literal["create", "restore"] = Field(
        default="create",
        description="Action to perform: 'create' or 'restore'.",
    )


class AppInstallInput(BaseModel):
    """Parameters to install an application APK onto a leased device."""

    project_id: str = Field(min_length=1, description="Target project ID.")
    device_id: str = Field(min_length=1, description="Leased device identifier.")
    artifact_id: str | None = Field(
        default=None,
        description="Ingested artifact ID containing APK.",
    )
    package_name: str | None = Field(
        default=None,
        description="Target package name if known.",
    )


class AppLaunchInput(BaseModel):
    """Parameters to launch an application activity on a leased device."""

    project_id: str = Field(min_length=1, description="Target project ID.")
    device_id: str = Field(min_length=1, description="Leased device identifier.")
    package_name: str = Field(min_length=1, description="Application package name.")
    activity: str | None = Field(
        default=None,
        description="Main or specific activity component to start.",
    )
    extra_args: list[str] | None = Field(
        default=None,
        description="Optional intent extras or CLI arguments.",
    )


class AppStopInput(BaseModel):
    """Parameters to stop an application on a leased device."""

    project_id: str = Field(min_length=1, description="Target project ID.")
    device_id: str = Field(min_length=1, description="Leased device identifier.")
    package_name: str = Field(min_length=1, description="Application package name.")


class InstrumentStartInput(BaseModel):
    """Parameters to start a reviewed instrumentation hook session."""

    project_id: str = Field(min_length=1, description="Target project ID.")
    device_id: str = Field(min_length=1, description="Leased device identifier.")
    package_name: str = Field(min_length=1, description="Application package name.")
    hook_ids: list[str] = Field(
        default_factory=list,
        description="List of reviewed hook IDs to attach (e.g., crypto, network, keystore).",
    )


class InstrumentStopInput(BaseModel):
    """Parameters to stop and finalize an instrumentation session."""

    project_id: str = Field(min_length=1, description="Target project ID.")
    session_id: str = Field(min_length=1, description="Active instrumentation session ID.")


class RuntimeGetEventsInput(BaseModel):
    """Parameters to query paginated, redacted runtime interception events."""

    project_id: str = Field(min_length=1, description="Target project ID.")
    session_id: str = Field(min_length=1, description="Instrumentation session ID.")
    category: str | None = Field(
        default=None,
        description="Filter by hook category (crypto, network, filesystem, ipc, keystore).",
    )
    limit: int = Field(default=50, ge=1, le=500, description="Page limit.")
    offset: int = Field(default=0, ge=0, description="Offset index.")


class RuntimeGetLogcatInput(BaseModel):
    """Parameters to query filtered, redacted logcat messages."""

    project_id: str = Field(min_length=1, description="Target project ID.")
    device_id: str = Field(min_length=1, description="Leased device identifier.")
    tag: str | None = Field(default=None, description="Filter log lines by tag.")
    package_name: str | None = Field(default=None, description="Filter log lines by package name.")
    limit: int = Field(default=100, ge=1, le=1000, description="Maximum lines to return.")
    offset: int = Field(default=0, ge=0, description="Offset index.")


class DumpDexInput(BaseModel):
    """Parameters to extract mapped runtime DEX bytecode from process memory."""

    project_id: str = Field(min_length=1, description="Target project ID.")
    device_id: str = Field(min_length=1, description="Leased device identifier.")
    package_name: str = Field(min_length=1, description="Target application package name.")


class DumpNativeInput(BaseModel):
    """Parameters to extract loaded native shared objects from process memory."""

    project_id: str = Field(min_length=1, description="Target project ID.")
    device_id: str = Field(min_length=1, description="Leased device identifier.")
    package_name: str = Field(min_length=1, description="Target application package name.")
    library_name: str | None = Field(
        default=None,
        description="Optional specific native library name to dump (e.g. libnative.so).",
    )


class DumpHeapInput(BaseModel):
    """Parameters to extract an HPROF memory dump from a running process."""

    project_id: str = Field(min_length=1, description="Target project ID.")
    device_id: str = Field(min_length=1, description="Leased device identifier.")
    package_name: str = Field(min_length=1, description="Target application package name.")
    max_bytes: int = Field(
        default=10_000_000,
        ge=1024,
        le=500_000_000,
        description="Maximum heap dump size in bytes.",
    )


class DynamicInjectGadgetInput(BaseModel):
    """Parameters to inject Frida Gadget into an APK native library directory."""

    project_id: str = Field(min_length=1, description="Target project ID.")
    artifact_id: str = Field(min_length=1, description="Source APK artifact ID.")
    target_arch: str = Field(
        default="arm64-v8a",
        description="Target CPU architecture (arm64-v8a, armeabi-v7a, x86, x86_64).",
    )


class DynamicDumpStorageInput(BaseModel):
    """Parameters to dump internal SQLite databases and SharedPreferences."""

    project_id: str = Field(min_length=1, description="Target project ID.")
    device_id: str | None = Field(
        default=None,
        description="Optional leased device identifier.",
    )
    target_type: Literal["all", "sqlite", "shared_prefs"] = Field(
        default="all",
        description="Type of storage to extract: all, sqlite, or shared_prefs.",
    )


class DynWebviewCdpAttachInput(BaseModel):
    """Parameters to attach to an in-app WebView via Chrome DevTools Protocol."""

    project_id: str = Field(min_length=1, description="Target project ID.")
    package_name: str = Field(
        default="com.example.app", description="Target application package name."
    )
    device_id: str | None = Field(default=None, description="Optional target device ID.")
    forwarded_port: int = Field(
        default=9222, ge=1024, le=65535, description="Local forwarded port."
    )
    local_port: int | None = Field(
        default=None, ge=1024, le=65535, description="Alias for local forwarded port."
    )
    eval_script: str | None = Field(
        default=None, description="Optional JavaScript code to evaluate."
    )


class DynPerfettoRecordInput(BaseModel):
    """Parameters to record a Perfetto dynamic system trace via ADB."""

    project_id: str = Field(min_length=1, description="Target project ID.")
    package_name: str = Field(
        default="com.example.app", description="Target application package name."
    )
    duration_ms: int = Field(default=5000, ge=500, le=60000, description="Trace duration in ms.")
    device_id: str | None = Field(default=None, description="Optional leased device identifier.")
    output_trace_path: str = Field(
        default="/data/misc/perfetto-traces/trace.perfetto-trace",
        description="Device output path.",
    )


class DynPerfettoQueryInput(BaseModel):
    """Parameters to analyze Perfetto trace events and detect Binder storms / ANR deadlocks."""

    project_id: str = Field(min_length=1, description="Target project ID.")
    target_package: str = Field(
        default="com.example.app", description="Target application package name."
    )
    events_log: str | None = Field(
        default=None, description="Raw ftrace / Perfetto events log text to analyze."
    )


class NetIotSnifferInput(BaseModel):
    """Parameters to dissect local multicast/broadcast IoT protocol packets."""

    project_id: str | None = Field(default=None, description="Optional target project ID.")
    traffic_input: str | list[dict[str, Any]] = Field(
        description="Raw packet captures, log lines, or list of event records."
    )
    subnet_filter: str | None = Field(
        default=None, description="Optional subnet filter (e.g. 192.168.1.0/24)."
    )


class DynWireguardTunnelStartInput(BaseModel):
    """Parameters to start a zero-trust WireGuard capture tunnel on device."""

    project_id: str | None = Field(default=None, description="Optional target project ID.")
    target_package: str = Field(
        default="com.example.app", description="Target application package name."
    )
    device_id: str | None = Field(default=None, description="Optional target device ID.")
    interface_name: str = Field(default="wg0", description="WireGuard interface name.")
    server_address: str = Field(default="10.0.0.1/24", description="Tunnel server CIDR.")
    client_address: str = Field(default="10.0.0.2/32", description="Tunnel client CIDR.")
    listen_port: int = Field(default=51820, description="WireGuard UDP listen port.")
    proxy_port: int = Field(default=8080, description="Local proxy port to redirect traffic to.")
    mtu: int = Field(default=1420, description="Tunnel MTU size.")


class DynWireguardTunnelStopInput(BaseModel):
    """Parameters to stop the active WireGuard tunnel on device."""

    project_id: str | None = Field(default=None, description="Optional target project ID.")
    target_package: str = Field(
        default="com.example.app", description="Target application package name."
    )
    device_id: str | None = Field(default=None, description="Optional target device ID.")
    interface_name: str = Field(default="wg0", description="WireGuard interface name.")


class DynAdbFleetDiscoverInput(BaseModel):
    """Parameters to scan and discover wireless ADB devices on local subnets."""

    project_id: str | None = Field(default=None, description="Optional target project ID.")
    subnet_cidr: str = Field(
        default="192.168.1.0/24", description="Subnet CIDR or comma-separated IPs."
    )
    target_ports: list[int] | None = Field(
        default=None, description="Optional list of ADB ports to scan."
    )
    timeout_ms: int = Field(
        default=500, ge=100, le=5000, description="Socket connect timeout in ms."
    )
    max_hosts: int = Field(default=32, ge=1, le=256, description="Maximum hosts to evaluate.")


class DynBurpMcpBridgeInput(BaseModel):
    """Parameters to configure bidirectional Burp Suite MCP bridge."""

    project_id: str | None = Field(default=None, description="Optional target project ID.")
    burp_api_url: str = Field(
        default="http://127.0.0.1:1337", description="Burp Suite REST API endpoint."
    )
    bridge_port: int = Field(
        default=8999, ge=1024, le=65535, description="Port for MCP bridge listener."
    )
    export_tools: list[str] | None = Field(
        default=None, description="Tool names to export to Burp Suite."
    )
    sync_scope: list[str] | None = Field(
        default=None, description="Domain/URL scope rules to sync with Burp."
    )
    enable_active_scan_hook: bool = Field(
        default=True, description="Enable active scan callback trigger."
    )


class DynTrafficPassiveAuditInput(BaseModel):
    """Parameters for passive HTTP traffic security inspection with PII redaction."""

    project_id: str | None = Field(default=None, description="Optional target project ID.")
    requests: list[dict[str, Any]] | None = Field(
        default=None, description="List of captured request/response dicts."
    )
    target_domain: str | None = Field(default=None, description="Filter audit to specific domain.")
    redact_pii: bool = Field(
        default=True, description="Redact PII, tokens, and passwords in output."
    )


class DynP2pDeviceTunnelInput(BaseModel):
    """Parameters to establish encrypted P2P tunnel to remote Android device."""

    project_id: str | None = Field(default=None, description="Optional target project ID.")
    device_id: str = Field(
        default="device-remote-01", description="Identifier of remote target device."
    )
    tunnel_type: str = Field(
        default="iroh_p2p", description="P2P protocol: iroh_p2p, wireguard_derp, tailscale."
    )
    relay_node: str | None = Field(
        default=None, description="Optional custom STUN/DERP relay node."
    )
    auth_key: str | None = Field(
        default=None, description="Optional authentication pre-shared key."
    )
    local_listen_port: int = Field(
        default=55555, ge=1024, le=65535, description="Local port for ADB forward."
    )


class DynVirtualDisplayStartInput(BaseModel):
    """Parameters to start a headless Android VirtualDisplay session."""

    project_id: str | None = Field(default=None, description="Optional target project ID.")
    display_name: str = Field(default="raa-headless-0", description="Virtual display name.")
    width: int = Field(default=1080, ge=320, le=4096, description="Virtual display width.")
    height: int = Field(default=2400, ge=480, le=4096, description="Virtual display height.")
    density_dpi: int = Field(default=420, ge=120, le=640, description="Virtual display density.")
    flags: list[str] | None = Field(default=None, description="DisplayManager flags.")
    target_package: str | None = Field(default=None, description="Auto-launch target package.")


class DynVirtualDisplayStopInput(BaseModel):
    """Parameters to tear down an active headless VirtualDisplay session."""

    project_id: str | None = Field(default=None, description="Optional target project ID.")
    session_id: str = Field(min_length=1, description="Active VirtualDisplay session ID.")
    display_id: int | None = Field(default=None, description="Optional integer display ID.")


class DynGuiAgentCrawlInput(BaseModel):
    """Parameters for autonomous multimodal GUI crawling on Flutter/Canvas apps."""

    project_id: str | None = Field(default=None, description="Optional target project ID.")
    target_package: str = Field(min_length=1, description="Target app package name.")
    max_steps: int = Field(default=5, ge=1, le=50, description="Maximum autonomous steps.")
    goal_prompt: str = Field(
        default="Explore main UI and trigger deep activities", description="Agent goal prompt."
    )
    allow_permission_bypass: bool = Field(
        default=True, description="Autonomously bypass permission dialogs."
    )


class TermuxWorkspaceHarnessInput(BaseModel):
    """Parameters to configure on-device PRoot mobile workspace harness in Termux."""

    project_id: str | None = Field(default=None, description="Optional target project ID.")
    workspace_dir: str = Field(
        default="/data/data/com.termux/files/home/raa-harness",
        description="PRoot workspace path on device.",
    )
    rootfs_type: str = Field(
        default="debian_arm64", description="Rootfs architecture & distribution."
    )
    enable_smali_patching: bool = Field(
        default=True, description="Enable unified diff smali patching."
    )
    installed_packages: list[str] | None = Field(
        default=None, description="Toolchain packages to pre-install."
    )


class DynScrcpyInjectFastInput(BaseModel):
    """Parameters for ultra-low-latency scrcpy input injection."""

    action_type: str = Field(
        default="touch",
        description="Action type: touch, keycode, or text.",
    )
    x: int = Field(default=540, ge=0, description="X coordinate.")
    y: int = Field(default=1200, ge=0, description="Y coordinate.")
    action: str = Field(default="down", description="Touch action: down, up, move.")
    keycode: int | None = Field(default=None, description="Android keycode for key injection.")
    text: str | None = Field(default=None, description="Text string for text injection.")
    device_id: str | None = Field(default=None, description="Target ADB device serial.")
    control_port: int = Field(default=27183, description="Scrcpy daemon control socket port.")


class DynScrcpyFrameCaptureInput(BaseModel):
    """Parameters for fast scrcpy frame capture."""

    device_id: str | None = Field(default=None, description="Target ADB device serial.")
    width: int = Field(default=1080, ge=320, le=4096, description="Frame width.")
    height: int = Field(default=2400, ge=480, le=4096, description="Frame height.")
    video_codec: str = Field(default="h264", description="Video stream codec (h264, h265).")


class DynGuiStateVerifyInput(BaseModel):
    """Parameters for deterministic GUI state transition verification."""

    current_state: dict[str, Any] | None = Field(
        default=None,
        description="Observed current screen state (activity, elements, title).",
    )
    expected_state: dict[str, Any] | None = Field(
        default=None,
        description="Target expected screen state to assert against.",
    )
    transition_action: str | None = Field(
        default=None,
        description="Action attempted (e.g. tap_login, fill_password).",
    )
    match_tolerance: float = Field(
        default=0.9,
        ge=0.0,
        le=1.0,
        description="Minimum similarity score required to pass verification.",
    )


class DynRmsHookGenerateInput(BaseModel):
    """Parameters for pre-configured RMS runtime hook generation."""

    category: str = Field(
        default="crypto",
        description="Target subsystem to monitor (crypto, keystore, shared_preferences).",
    )
    target_package: str | None = Field(
        default=None, description="Optional target application package name."
    )


class DynRmsMethodOverrideInput(BaseModel):
    """Parameters for codeless method interception and return value override."""

    target_class: str = Field(
        default="com.target.app.SecurityCheck",
        description="Full Java class name to target.",
    )
    target_method: str = Field(
        default="isDeviceRooted",
        description="Target method name on the class.",
    )
    param_types: list[str] | None = Field(
        default=None, description="Optional parameter type signature overloads."
    )
    return_value_override: Any = Field(
        default=False, description="Value to force return from the intercepted method."
    )
    log_arguments: bool = Field(
        default=True, description="Log invoked arguments in real time to console."
    )


class DynLamdaDaemonConnectInput(BaseModel):
    """Parameters to connect to on-device LAMDA agent daemon."""

    host: str = Field(default="127.0.0.1", description="LAMDA daemon host IP.")
    port: int = Field(default=65000, ge=1024, le=65535, description="LAMDA daemon port.")
    auth_token: str | None = Field(default=None, description="Optional authentication token.")


class DynLamdaTouchEventInput(BaseModel):
    """Parameters to dispatch kernel-level multi-touch events via LAMDA."""

    session_id: str | None = Field(default=None, description="Active LAMDA session ID.")
    event_type: str = Field(default="tap", description="Touch action (tap, swipe, hold).")
    x: int = Field(default=540, ge=0, description="X coordinate.")
    y: int = Field(default=1200, ge=0, description="Y coordinate.")
    points: list[dict[str, int]] | None = Field(
        default=None, description="Optional multi-touch coordinate points."
    )
    duration_ms: int = Field(default=50, ge=1, description="Gesture duration in ms.")


class DynDockerAndroidSpawnInput(BaseModel):
    """Parameters to spawn containerized Android emulator sandbox."""

    image: str = Field(
        default="budtmo/docker-android:emulator_11.0",
        description="Docker Android container image.",
    )
    device_name: str = Field(
        default="Samsung Galaxy S10",
        description="Emulated device profile name.",
    )
    kvm_enabled: bool = Field(
        default=True,
        description="Enable KVM hardware virtualization acceleration.",
    )
    adb_port: int = Field(default=5555, ge=1024, le=65535, description="Host ADB forward port.")
    novnc_port: int = Field(
        default=6080, ge=1024, le=65535, description="Host noVNC web streaming port."
    )


class DynDockerAndroidTeardownInput(BaseModel):
    """Parameters to tear down containerized Android sandbox."""

    container_id: str = Field(min_length=1, description="Target Docker Android container ID.")
    purge_volumes: bool = Field(
        default=True, description="Purge container attached storage volumes."
    )


class DynAgentDeviceControlInput(BaseModel):
    """Parameters for agent-native mobile device automation."""

    device_id: str | None = Field(default=None, description="Target ADB device ID.")
    action: str = Field(
        default="launch",
        description="Action to perform (launch, ax_tree, eval_js, logcat).",
    )
    target_package: str | None = Field(default=None, description="Target application package name.")
    script_js: str | None = Field(
        default=None, description="Optional JavaScript code snippet to evaluate."
    )
    log_filter: str | None = Field(
        default=None, description="Optional logcat tag or substring filter."
    )


class DynVisualDiffAuditInput(BaseModel):
    """Parameters for font- and layout-aware visual regression diff."""

    original_screenshot_path: str | None = Field(
        default=None, description="Path to original UI screen capture."
    )
    rebuilt_screenshot_path: str | None = Field(
        default=None, description="Path to rebuilt/migrated Compose screen capture."
    )
    tolerance: float = Field(
        default=0.95, ge=0.0, le=1.0, description="Minimum visual parity score."
    )


class DynEmulatorArmTranslationInjectInput(BaseModel):
    """Parameters to flash ARM/ARM64 translation libraries into x86 emulator."""

    device_id: str | None = Field(default=None, description="Target emulator serial.")
    emulator_abi: str = Field(default="x86_64", description="Host emulator ABI (x86_64, x86).")
    android_api: int = Field(default=30, ge=21, le=35, description="Target Android API level.")
    translation_package: str | None = Field(
        default=None, description="Custom Houdini translation package name."
    )


class DynGuiRecordPlaybackInput(BaseModel):
    """Parameters for GUI task recording and action graph replay with boundary fuzzing."""

    action: str = Field(
        default="record",
        description="Action to perform (record, stop_record, playback, replay).",
    )
    session_id: str | None = Field(default=None, description="Optional recording session ID.")
    events: list[dict[str, Any]] | None = Field(
        default=None, description="Optional custom interaction event sequence."
    )
    fuzz_boundaries: bool = Field(
        default=False, description="Inject boundary fuzz mutations during playback."
    )
    device_id: str | None = Field(default=None, description="Target ADB device ID.")


class DynOndeviceAccessibilityAgentInput(BaseModel):
    """Parameters to control PC-less on-device Accessibility Service agent."""

    action: str = Field(
        default="start",
        description="Action (install_agent, start, stop, status).",
    )
    target_package: str | None = Field(default=None, description="Target application package.")
    exploration_mode: str = Field(
        default="autonomous_fuzz", description="Mode (autonomous_fuzz, goal_oriented)."
    )
    max_steps: int = Field(default=50, ge=1, le=500, description="Maximum exploration steps.")
    device_id: str | None = Field(default=None, description="Target ADB device ID.")


class DynQaScenarioReplayInput(BaseModel):
    """Parameters to replay QA scenario with real-time telemetry and Perfetto capture."""

    scenario_steps: list[dict[str, Any]] | None = Field(
        default=None, description="Scripted QA scenario action sequence."
    )
    target_package: str | None = Field(default=None, description="Target package name.")
    capture_perfetto_on_drop: bool = Field(
        default=True, description="Slice Perfetto trace on FPS drop or ANR."
    )
    fps_drop_threshold: int = Field(
        default=45, ge=10, le=120, description="FPS threshold triggering trace capture."
    )
    device_id: str | None = Field(default=None, description="Target ADB device ID.")


class DynAppfunctionInvokeInput(BaseModel):
    """Parameters to invoke or fuzz Android 16 AppFunctionDeclaration IPC endpoints."""

    package_name: str = Field(
        default="com.target.application", description="Target application package."
    )
    function_id: str = Field(default="orderFood", description="AppFunction identifier.")
    parameters: dict[str, Any] | None = Field(
        default=None, description="Function argument parameters map."
    )
    caller_package: str = Field(
        default="com.google.android.googlequicksearchbox",
        description="Simulated caller package name.",
    )
    fuzz_mode: bool = Field(
        default=False, description="Enable automated schema & permission boundary fuzzing."
    )
    device_id: str | None = Field(default=None, description="Target ADB device ID.")


class DynHttptoolkitVpnInterceptInput(BaseModel):
    """Parameters to manage HTTP Toolkit transparent VPN interception and CA injection."""

    action: str = Field(default="status", description="Action (start, stop, status, inject_ca).")
    package_name: str | None = Field(default=None, description="Target app package name.")
    proxy_host: str = Field(default="127.0.0.1", description="Interception proxy host.")
    proxy_port: int = Field(default=8000, ge=1024, le=65535, description="Interception proxy port.")
    ca_cert_path: str | None = Field(default=None, description="Path to CA cert PEM for inject_ca.")
    system_cert: bool = Field(default=False, description="Install into system root CA trust store.")
    device_id: str | None = Field(default=None, description="Target ADB device ID.")


class DynRaspBypassGenInput(BaseModel):
    """Parameters to synthesize and deploy targeted Frida RASP and anti-tamper hooks."""

    target_package: str = Field(
        default="com.target.application", description="Target application package."
    )
    bypasses: list[str] | None = Field(
        default=None,
        description="Bypasses: freerasp, root, debugger, emulator, signature_spoof.",
    )
    output_script_path: str | None = Field(
        default=None, description="Path to save generated Frida JS."
    )
    auto_inject: bool = Field(
        default=False, description="Inject immediately via running Frida daemon."
    )
    device_id: str | None = Field(default=None, description="Target ADB device ID.")


class DynDeviceEnvMutateInput(BaseModel):
    """Parameters to mutate device runtime environment for chaos and resilience testing."""

    action: str = Field(
        default="status",
        description="Action: status, dark_mode, network, battery, display, font_scale, reset_all.",
    )
    params: dict[str, Any] | None = Field(
        default=None, description="Mutation parameters (enabled, profile, level, charging, etc.)."
    )
    device_id: str | None = Field(default=None, description="Target ADB device ID.")


class ShizukuPrivilegedExecInput(BaseModel):
    """Parameters to execute privileged package management/appops commands via Shizuku."""

    command: str = Field(default="pm list packages", description="Shell command or sub-operation.")
    action: str = Field(
        default="exec", description="Action: exec, status, grant_permission, set_appop."
    )
    package_name: str | None = Field(default=None, description="Target package name.")
    permission: str | None = Field(default=None, description="Permission for grant_permission.")
    appop: str | None = Field(default=None, description="AppOp name for set_appop.")
    mode: str = Field(default="allow", description="AppOp mode (allow, ignore, deny, default).")
    use_rish: bool = Field(default=True, description="Prefer rish binary over direct ADB shell.")
    device_id: str | None = Field(default=None, description="Target ADB device ID.")
    timeout_seconds: int = Field(default=15, ge=1, le=120, description="Execution timeout.")


class TermuxOndeviceBinaryBundleInput(BaseModel):
    """Parameters to manage and run standalone ARM64/x86_64 AOSP analysis binaries on-device."""

    action: str = Field(default="list", description="Action: list, deploy, exec, clean.")
    binaries: list[str] | None = Field(
        default=None,
        description="Binaries to deploy (sqlite3, dexdump, busybox, strace, tcpdump, socat).",
    )
    target_dir: str = Field(
        default="/data/local/tmp/raa_bin", description="On-device destination directory."
    )
    command: str | None = Field(
        default=None, description="Command string to execute with deployed binaries."
    )
    device_id: str | None = Field(default=None, description="Target ADB device ID.")


# --- Tool Spec Helper ---


def _dynamic_spec(
    *,
    name: str,
    title: str,
    description: str,
    handler: Any,
    input_model: type[BaseModel],
    profiles: frozenset[str] = DYNAMIC,
    scopes: frozenset[str] = frozenset(),
    read_only: bool = True,
    idempotent: bool = True,
    device_required: bool = True,
) -> ToolSpec:
    return ToolSpec(
        name=name,
        title=title,
        description=description,
        input_model=input_model,
        handler=handler,
        family="dynamic",
        profiles=profiles,
        scopes=scopes,
        annotations=ToolAnnotations(read_only=read_only, idempotent=idempotent),
        cost="device",
        device_required=device_required,
    )


# --- Handlers ---


async def _device_list(ctx: ToolContext, args: DeviceListInput) -> ToolOutcome:
    devices = ctx.runtime.dynamic.list_devices(
        device_type=args.device_type,
        available_only=args.available_only,
    )
    return ToolOutcome(
        data={
            "devices": [d.model_dump(mode="json") for d in devices],
            "total": len(devices),
        }
    )


async def _device_lease(ctx: ToolContext, args: DeviceLeaseInput) -> ToolOutcome:
    lease = ctx.runtime.dynamic.lease_device(
        project_id=args.project_id,
        device_id=args.device_id,
        duration_seconds=args.duration_seconds,
    )
    return ToolOutcome(data=lease.model_dump(mode="json"))


async def _device_release(ctx: ToolContext, args: DeviceReleaseInput) -> ToolOutcome:
    res = ctx.runtime.dynamic.release_device(
        project_id=args.project_id,
        device_id=args.device_id,
    )
    return ToolOutcome(data=res)


async def _device_snapshot(ctx: ToolContext, args: DeviceSnapshotInput) -> ToolOutcome:
    res = ctx.runtime.dynamic.snapshot_device(
        project_id=args.project_id,
        device_id=args.device_id,
        name=args.name,
        action=args.action,
    )
    return ToolOutcome(data=res)


async def _app_install(ctx: ToolContext, args: AppInstallInput) -> ToolOutcome:
    res = ctx.runtime.dynamic.install_app(
        project_id=args.project_id,
        device_id=args.device_id,
        artifact_id=args.artifact_id,
        package_name=args.package_name,
    )
    return ToolOutcome(data=res.model_dump(mode="json"))


async def _app_launch(ctx: ToolContext, args: AppLaunchInput) -> ToolOutcome:
    res = ctx.runtime.dynamic.launch_app(
        project_id=args.project_id,
        device_id=args.device_id,
        package_name=args.package_name,
        activity=args.activity,
        extra_args=args.extra_args,
    )
    return ToolOutcome(data=res.model_dump(mode="json"))


async def _app_stop(ctx: ToolContext, args: AppStopInput) -> ToolOutcome:
    res = ctx.runtime.dynamic.stop_app(
        project_id=args.project_id,
        device_id=args.device_id,
        package_name=args.package_name,
    )
    return ToolOutcome(data=res.model_dump(mode="json"))


async def _instrument_start(ctx: ToolContext, args: InstrumentStartInput) -> ToolOutcome:
    session = ctx.runtime.dynamic.start_instrumentation(
        project_id=args.project_id,
        device_id=args.device_id,
        package_name=args.package_name,
        hook_ids=args.hook_ids,
    )
    return ToolOutcome(data=session.model_dump(mode="json"))


async def _instrument_stop(ctx: ToolContext, args: InstrumentStopInput) -> ToolOutcome:
    session = ctx.runtime.dynamic.stop_instrumentation(
        project_id=args.project_id,
        session_id=args.session_id,
    )
    return ToolOutcome(data=session.model_dump(mode="json"))


async def _runtime_get_events(ctx: ToolContext, args: RuntimeGetEventsInput) -> ToolOutcome:
    res = ctx.runtime.dynamic.get_runtime_events(
        project_id=args.project_id,
        session_id=args.session_id,
        category=args.category,
        limit=args.limit,
        offset=args.offset,
    )
    return ToolOutcome(data=res)


async def _runtime_get_logcat(ctx: ToolContext, args: RuntimeGetLogcatInput) -> ToolOutcome:
    res = ctx.runtime.dynamic.get_logcat(
        project_id=args.project_id,
        device_id=args.device_id,
        tag=args.tag,
        package_name=args.package_name,
        limit=args.limit,
        offset=args.offset,
    )
    return ToolOutcome(data=res)


async def _dump_dex(ctx: ToolContext, args: DumpDexInput) -> ToolOutcome:
    dumps = ctx.runtime.dynamic.dump_dex(
        project_id=args.project_id,
        device_id=args.device_id,
        package_name=args.package_name,
    )
    return ToolOutcome(
        data={
            "dumps": [d.model_dump(mode="json") for d in dumps],
            "count": len(dumps),
        }
    )


async def _dump_native(ctx: ToolContext, args: DumpNativeInput) -> ToolOutcome:
    dumps = ctx.runtime.dynamic.dump_native(
        project_id=args.project_id,
        device_id=args.device_id,
        package_name=args.package_name,
        library_name=args.library_name,
    )
    return ToolOutcome(
        data={
            "dumps": [d.model_dump(mode="json") for d in dumps],
            "count": len(dumps),
        }
    )


async def _dump_heap(ctx: ToolContext, args: DumpHeapInput) -> ToolOutcome:
    dump = ctx.runtime.dynamic.dump_heap(
        project_id=args.project_id,
        device_id=args.device_id,
        package_name=args.package_name,
        max_bytes=args.max_bytes,
    )
    return ToolOutcome(data=dump.model_dump(mode="json"))


async def _dynamic_inject_gadget(ctx: ToolContext, args: DynamicInjectGadgetInput) -> ToolOutcome:
    res = ctx.runtime.dynamic.inject_gadget(
        project_id=args.project_id,
        artifact_id=args.artifact_id,
        target_arch=args.target_arch,
    )
    return ToolOutcome(data=res)


async def _dynamic_dump_storage(ctx: ToolContext, args: DynamicDumpStorageInput) -> ToolOutcome:
    res = ctx.runtime.dynamic.dump_storage(
        project_id=args.project_id,
        device_id=args.device_id,
        target_type=args.target_type,
    )
    return ToolOutcome(data=res)


async def _dyn_webview_cdp_attach(ctx: ToolContext, args: DynWebviewCdpAttachInput) -> ToolOutcome:
    port = args.local_port or args.forwarded_port
    session = WebViewCDPSession(
        package_name=args.package_name,
        device_id=args.device_id,
        forwarded_port=port,
    )
    forward_cmd = session.get_forward_command()
    targets = session.discover_targets()
    eval_result = None
    if args.eval_script:
        eval_result = session.evaluate_javascript(args.eval_script)
    bridges = session.inspect_javascript_bridges()

    data = {
        "package_name": args.package_name,
        "forwarded_port": port,
        "local_port": port,
        "adb_forward_command": forward_cmd,
        "targets_count": len(targets),
        "targets": targets,
        "bridges": bridges,
        "eval_result": eval_result,
        "status": "connected_or_mocked",
    }
    return ToolOutcome(data=data)


async def _dyn_perfetto_record(ctx: ToolContext, args: DynPerfettoRecordInput) -> ToolOutcome:
    res = record_perfetto_trace(
        package_name=args.package_name,
        duration_ms=args.duration_ms,
        device_id=args.device_id,
        output_trace_path=args.output_trace_path,
    )
    return ToolOutcome(data=res)


async def _dyn_perfetto_query(ctx: ToolContext, args: DynPerfettoQueryInput) -> ToolOutcome:
    events = args.events_log or "binder_transaction 50000 sched_switch com.example.app"
    res = analyze_perfetto_events(
        events_log=events,
        target_package=args.target_package,
    )
    return ToolOutcome(data=res)


async def _net_iot_sniffer(ctx: ToolContext, args: NetIotSnifferInput) -> ToolOutcome:
    res = ctx.runtime.dynamic.dissect_iot(
        traffic_input=args.traffic_input,
        subnet_filter=args.subnet_filter,
    )
    return ToolOutcome(data=res)


async def _dyn_wireguard_tunnel_start(
    ctx: ToolContext, args: DynWireguardTunnelStartInput
) -> ToolOutcome:
    res = ctx.runtime.dynamic.start_wireguard(
        target_package=args.target_package,
        device_id=args.device_id,
        interface_name=args.interface_name,
        server_address=args.server_address,
        client_address=args.client_address,
        listen_port=args.listen_port,
        proxy_port=args.proxy_port,
        mtu=args.mtu,
    )
    return ToolOutcome(data=res)


async def _dyn_wireguard_tunnel_stop(
    ctx: ToolContext, args: DynWireguardTunnelStopInput
) -> ToolOutcome:
    res = ctx.runtime.dynamic.stop_wireguard(
        target_package=args.target_package,
        device_id=args.device_id,
        interface_name=args.interface_name,
    )
    return ToolOutcome(data=res)


async def _dyn_adb_fleet_discover(ctx: ToolContext, args: DynAdbFleetDiscoverInput) -> ToolOutcome:
    res = ctx.runtime.dynamic.discover_fleet(
        subnet_cidr=args.subnet_cidr,
        target_ports=args.target_ports,
        timeout_ms=args.timeout_ms,
        max_hosts=args.max_hosts,
    )
    return ToolOutcome(data=res)


async def _dyn_burp_mcp_bridge(ctx: ToolContext, args: DynBurpMcpBridgeInput) -> ToolOutcome:
    res = ctx.runtime.dynamic.configure_burp_bridge(
        burp_api_url=args.burp_api_url,
        bridge_port=args.bridge_port,
        export_tools=args.export_tools,
        sync_scope=args.sync_scope,
        enable_active_scan_hook=args.enable_active_scan_hook,
    )
    return ToolOutcome(data=res)


async def _dyn_traffic_passive_audit(
    ctx: ToolContext, args: DynTrafficPassiveAuditInput
) -> ToolOutcome:
    res = ctx.runtime.dynamic.audit_traffic(
        requests=args.requests,
        target_domain=args.target_domain,
        redact_pii=args.redact_pii,
    )
    return ToolOutcome(data=res)


async def _dyn_p2p_device_tunnel(ctx: ToolContext, args: DynP2pDeviceTunnelInput) -> ToolOutcome:
    res = ctx.runtime.dynamic.establish_p2p_tunnel(
        device_id=args.device_id,
        tunnel_type=args.tunnel_type,
        relay_node=args.relay_node,
        auth_key=args.auth_key,
        local_listen_port=args.local_listen_port,
    )
    return ToolOutcome(data=res)


async def _dyn_virtual_display_start(
    ctx: ToolContext, args: DynVirtualDisplayStartInput
) -> ToolOutcome:
    res = ctx.runtime.dynamic.start_virtual_display(
        display_name=args.display_name,
        width=args.width,
        height=args.height,
        density_dpi=args.density_dpi,
        flags=args.flags,
        target_package=args.target_package,
    )
    return ToolOutcome(data=res)


async def _dyn_virtual_display_stop(
    ctx: ToolContext, args: DynVirtualDisplayStopInput
) -> ToolOutcome:
    res = ctx.runtime.dynamic.stop_virtual_display(
        session_id=args.session_id,
        display_id=args.display_id,
    )
    return ToolOutcome(data=res)


async def _dyn_gui_agent_crawl(ctx: ToolContext, args: DynGuiAgentCrawlInput) -> ToolOutcome:
    res = ctx.runtime.dynamic.crawl_gui(
        target_package=args.target_package,
        max_steps=args.max_steps,
        goal_prompt=args.goal_prompt,
        allow_permission_bypass=args.allow_permission_bypass,
    )
    return ToolOutcome(data=res)


async def _termux_workspace_harness(
    ctx: ToolContext, args: TermuxWorkspaceHarnessInput
) -> ToolOutcome:
    res = ctx.runtime.dynamic.configure_termux(
        workspace_dir=args.workspace_dir,
        rootfs_type=args.rootfs_type,
        enable_smali_patching=args.enable_smali_patching,
        installed_packages=args.installed_packages,
    )
    return ToolOutcome(data=res)


async def _dyn_scrcpy_inject_fast(ctx: ToolContext, args: DynScrcpyInjectFastInput) -> ToolOutcome:
    res = ctx.runtime.dynamic.inject_scrcpy_fast(
        action_type=args.action_type,
        x=args.x,
        y=args.y,
        action=args.action,
        keycode=args.keycode,
        text=args.text,
        device_id=args.device_id,
        control_port=args.control_port,
    )
    return ToolOutcome(data=res)


async def _dyn_scrcpy_frame_capture(
    ctx: ToolContext, args: DynScrcpyFrameCaptureInput
) -> ToolOutcome:
    res = ctx.runtime.dynamic.capture_scrcpy_frame(
        device_id=args.device_id,
        width=args.width,
        height=args.height,
        video_codec=args.video_codec,
    )
    return ToolOutcome(data=res)


async def _dyn_gui_state_verify(ctx: ToolContext, args: DynGuiStateVerifyInput) -> ToolOutcome:
    res = ctx.runtime.dynamic.verify_gui_state(
        current_state=args.current_state,
        expected_state=args.expected_state,
        transition_action=args.transition_action,
        match_tolerance=args.match_tolerance,
    )
    return ToolOutcome(data=res)


async def _dyn_rms_hook_generate(ctx: ToolContext, args: DynRmsHookGenerateInput) -> ToolOutcome:
    res = ctx.runtime.dynamic.generate_rms_hooks(
        category=args.category,
        target_package=args.target_package,
    )
    return ToolOutcome(data=res)


async def _dyn_rms_method_override(
    ctx: ToolContext, args: DynRmsMethodOverrideInput
) -> ToolOutcome:
    res = ctx.runtime.dynamic.override_rms_method(
        target_class=args.target_class,
        target_method=args.target_method,
        param_types=args.param_types,
        return_value_override=args.return_value_override,
        log_arguments=args.log_arguments,
    )
    return ToolOutcome(data=res)


async def _dyn_lamda_daemon_connect(
    ctx: ToolContext, args: DynLamdaDaemonConnectInput
) -> ToolOutcome:
    res = ctx.runtime.dynamic.connect_lamda(
        host=args.host,
        port=args.port,
        auth_token=args.auth_token,
    )
    return ToolOutcome(data=res)


async def _dyn_lamda_touch_event(ctx: ToolContext, args: DynLamdaTouchEventInput) -> ToolOutcome:
    res = ctx.runtime.dynamic.dispatch_lamda_touch(
        session_id=args.session_id,
        event_type=args.event_type,
        x=args.x,
        y=args.y,
        points=args.points,
        duration_ms=args.duration_ms,
    )
    return ToolOutcome(data=res)


async def _dyn_docker_android_spawn(
    ctx: ToolContext, args: DynDockerAndroidSpawnInput
) -> ToolOutcome:
    res = ctx.runtime.dynamic.spawn_docker_sandbox(
        image=args.image,
        device_name=args.device_name,
        kvm_enabled=args.kvm_enabled,
        adb_port=args.adb_port,
        novnc_port=args.novnc_port,
    )
    return ToolOutcome(data=res)


async def _dyn_docker_android_teardown(
    ctx: ToolContext, args: DynDockerAndroidTeardownInput
) -> ToolOutcome:
    res = ctx.runtime.dynamic.teardown_docker_sandbox(
        container_id=args.container_id,
        purge_volumes=args.purge_volumes,
    )
    return ToolOutcome(data=res)


async def _dyn_agent_device_control(
    ctx: ToolContext, args: DynAgentDeviceControlInput
) -> ToolOutcome:
    res = ctx.runtime.dynamic.control_agent_device(
        device_id=args.device_id,
        action=args.action,
        target_package=args.target_package,
        script_js=args.script_js,
        log_filter=args.log_filter,
    )
    return ToolOutcome(data=res)


async def _dyn_visual_diff_audit(ctx: ToolContext, args: DynVisualDiffAuditInput) -> ToolOutcome:
    res = ctx.runtime.dynamic.audit_visual_diff(
        original_screenshot_path=args.original_screenshot_path,
        rebuilt_screenshot_path=args.rebuilt_screenshot_path,
        tolerance=args.tolerance,
    )
    return ToolOutcome(data=res)


async def _dyn_emulator_arm_translation_inject(
    ctx: ToolContext, args: DynEmulatorArmTranslationInjectInput
) -> ToolOutcome:
    res = ctx.runtime.dynamic.inject_arm_translation(
        device_id=args.device_id,
        emulator_abi=args.emulator_abi,
        android_api=args.android_api,
        translation_package=args.translation_package,
    )
    return ToolOutcome(data=res)


async def _dyn_gui_record_playback(
    ctx: ToolContext, args: DynGuiRecordPlaybackInput
) -> ToolOutcome:
    res = ctx.runtime.dynamic.record_or_playback_gui(
        action=args.action,
        session_id=args.session_id,
        events=args.events,
        fuzz_boundaries=args.fuzz_boundaries,
        device_id=args.device_id,
    )
    return ToolOutcome(data=res)


async def _dyn_ondevice_accessibility_agent(
    ctx: ToolContext, args: DynOndeviceAccessibilityAgentInput
) -> ToolOutcome:
    res = ctx.runtime.dynamic.control_accessibility_agent(
        action=args.action,
        target_package=args.target_package,
        exploration_mode=args.exploration_mode,
        max_steps=args.max_steps,
        device_id=args.device_id,
    )
    return ToolOutcome(data=res)


async def _dyn_qa_scenario_replay(ctx: ToolContext, args: DynQaScenarioReplayInput) -> ToolOutcome:
    res = ctx.runtime.dynamic.replay_qa_telemetry(
        scenario_steps=args.scenario_steps,
        target_package=args.target_package,
        capture_perfetto_on_drop=args.capture_perfetto_on_drop,
        fps_drop_threshold=args.fps_drop_threshold,
        device_id=args.device_id,
    )
    return ToolOutcome(data=res)


async def _dyn_appfunction_invoke(ctx: ToolContext, args: DynAppfunctionInvokeInput) -> ToolOutcome:
    res = ctx.runtime.dynamic.fuzz_appfunction(
        package_name=args.package_name,
        function_id=args.function_id,
        parameters=args.parameters,
        caller_package=args.caller_package,
        fuzz_mode=args.fuzz_mode,
        device_id=args.device_id,
    )
    return ToolOutcome(data=res)


async def _dyn_httptoolkit_vpn_intercept(
    ctx: ToolContext, args: DynHttptoolkitVpnInterceptInput
) -> ToolOutcome:
    res = ctx.runtime.dynamic.intercept_vpn(
        action=args.action,
        package_name=args.package_name,
        proxy_host=args.proxy_host,
        proxy_port=args.proxy_port,
        ca_cert_path=args.ca_cert_path,
        system_cert=args.system_cert,
        device_id=args.device_id,
    )
    return ToolOutcome(data=res)


async def _dyn_rasp_bypass_gen(ctx: ToolContext, args: DynRaspBypassGenInput) -> ToolOutcome:
    res = ctx.runtime.dynamic.generate_rasp_bypass(
        target_package=args.target_package,
        bypasses=args.bypasses,
        output_script_path=args.output_script_path,
        auto_inject=args.auto_inject,
        device_id=args.device_id,
    )
    return ToolOutcome(data=res)


async def _dyn_device_env_mutate(ctx: ToolContext, args: DynDeviceEnvMutateInput) -> ToolOutcome:
    res = ctx.runtime.dynamic.mutate_device_environment(
        action=args.action,
        params=args.params,
        device_id=args.device_id,
    )
    return ToolOutcome(data=res)


async def _shizuku_privileged_exec(
    ctx: ToolContext, args: ShizukuPrivilegedExecInput
) -> ToolOutcome:
    res = ctx.runtime.dynamic.execute_shizuku(
        command=args.command,
        action=args.action,
        package_name=args.package_name,
        permission=args.permission,
        appop=args.appop,
        mode=args.mode,
        use_rish=args.use_rish,
        device_id=args.device_id,
        timeout_seconds=args.timeout_seconds,
    )
    return ToolOutcome(data=res)


async def _termux_ondevice_binary_bundle(
    ctx: ToolContext, args: TermuxOndeviceBinaryBundleInput
) -> ToolOutcome:
    res = ctx.runtime.dynamic.manage_termux_bundle(
        action=args.action,
        binaries=args.binaries,
        target_dir=args.target_dir,
        command=args.command,
        device_id=args.device_id,
    )
    return ToolOutcome(data=res)


# --- Register Function ---


def register(registry: CapabilityRegistry) -> None:
    """Register all Phase 6 dynamic analysis and instrumentation tools."""
    registry.register(
        _dynamic_spec(
            name="device_list",
            title="List devices",
            description="Available devices and leases.",
            handler=_device_list,
            input_model=DeviceListInput,
            scopes=frozenset(),
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="device_lease",
            title="Lease device",
            description="Lease a clean device for isolated dynamic analysis.",
            handler=_device_lease,
            input_model=DeviceLeaseInput,
            scopes=frozenset({DYNAMIC_DEVICE}),
            read_only=False,
            idempotent=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="device_release",
            title="Release device",
            description="Release a leased device and reset to a clean baseline.",
            handler=_device_release,
            input_model=DeviceReleaseInput,
            scopes=frozenset({DYNAMIC_DEVICE}),
            read_only=False,
            idempotent=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="device_snapshot",
            title="Device snapshot",
            description="Create or restore a disposable device snapshot.",
            handler=_device_snapshot,
            input_model=DeviceSnapshotInput,
            scopes=frozenset({DYNAMIC_DEVICE}),
            read_only=False,
            idempotent=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="app_install",
            title="Install application",
            description="Install an authorized build APK onto a leased device.",
            handler=_app_install,
            input_model=AppInstallInput,
            scopes=frozenset({ANDROID_INSTALL}),
            read_only=False,
            idempotent=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="app_launch",
            title="Launch application",
            description="Launch package or activity on a leased device.",
            handler=_app_launch,
            input_model=AppLaunchInput,
            scopes=frozenset({DYNAMIC_DEVICE}),
            read_only=False,
            idempotent=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="app_stop",
            title="Stop application",
            description="Stop running package on a leased device.",
            handler=_app_stop,
            input_model=AppStopInput,
            scopes=frozenset({DYNAMIC_DEVICE}),
            read_only=False,
            idempotent=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="instrument_start",
            title="Start instrumentation",
            description="Start reviewed hook set on an application.",
            handler=_instrument_start,
            input_model=InstrumentStartInput,
            scopes=frozenset({DYNAMIC_INSTRUMENT}),
            read_only=False,
            idempotent=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="instrument_stop",
            title="Stop instrumentation",
            description="Stop instrumentation and finalize session manifest.",
            handler=_instrument_stop,
            input_model=InstrumentStopInput,
            scopes=frozenset({DYNAMIC_INSTRUMENT}),
            read_only=False,
            idempotent=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="runtime_get_events",
            title="Get runtime events",
            description="Paginated, redacted runtime interception events.",
            handler=_runtime_get_events,
            input_model=RuntimeGetEventsInput,
            scopes=frozenset({DYNAMIC_INSTRUMENT}),
            read_only=True,
            idempotent=True,
        )
    )
    registry.register(
        _dynamic_spec(
            name="runtime_get_logcat",
            title="Get logcat",
            description="Filtered and redacted logcat message stream.",
            handler=_runtime_get_logcat,
            input_model=RuntimeGetLogcatInput,
            scopes=frozenset({DYNAMIC_DEVICE}),
            read_only=True,
            idempotent=True,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dump_dex",
            title="Dump runtime DEX",
            description="Dump process memory-mapped DEX bytecode.",
            handler=_dump_dex,
            input_model=DumpDexInput,
            scopes=frozenset({DYNAMIC_INSTRUMENT}),
            read_only=False,
            idempotent=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dump_native",
            title="Dump native libraries",
            description="Dump loaded native shared libraries from memory.",
            handler=_dump_native,
            input_model=DumpNativeInput,
            scopes=frozenset({DYNAMIC_INSTRUMENT}),
            read_only=False,
            idempotent=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dump_heap",
            title="Dump process heap",
            description="Bounded process heap inspection and dump.",
            handler=_dump_heap,
            input_model=DumpHeapInput,
            scopes=frozenset({DYNAMIC_INSTRUMENT}),
            read_only=False,
            idempotent=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dynamic_inject_gadget",
            title="Inject Frida Gadget",
            description=(
                "Embed Frida Gadget shared library into an APK for non-rooted dynamic"
                " instrumentation."
            ),
            handler=_dynamic_inject_gadget,
            input_model=DynamicInjectGadgetInput,
            scopes=frozenset({ANDROID_PATCH, PROJECT_WRITE}),
            read_only=False,
            idempotent=False,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dynamic_dump_storage",
            title="Dump application storage",
            description=(
                "Extract internal SQLite databases and SharedPreferences XML from application"
                " sandbox."
            ),
            handler=_dynamic_dump_storage,
            input_model=DynamicDumpStorageInput,
            scopes=frozenset({DYNAMIC_DEVICE, PROJECT_READ}),
            read_only=True,
            idempotent=True,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_webview_cdp_attach",
            title="Attach to In-App WebView via CDP",
            description=(
                "Connect to running Android WebViews via Chrome DevTools Protocol "
                "for DOM inspection and JavaScript evaluation."
            ),
            handler=_dyn_webview_cdp_attach,
            input_model=DynWebviewCdpAttachInput,
            scopes=frozenset({DYNAMIC_DEVICE, PROJECT_READ}),
            read_only=True,
            idempotent=True,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_perfetto_record",
            title="Record Perfetto System Trace",
            description=(
                "Record kernel thread scheduling, Binder IPC transactions, and CPU frequency "
                "via Android Perfetto system tracer."
            ),
            handler=_dyn_perfetto_record,
            input_model=DynPerfettoRecordInput,
            scopes=frozenset({DYNAMIC_DEVICE, PROJECT_READ}),
            read_only=True,
            idempotent=True,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_perfetto_query",
            title="Analyze Perfetto Trace for Binder Storms",
            description=(
                "Analyze Perfetto ftrace event logs to detect Binder IPC storms, "
                "anti-analysis spin loops, and main thread ANR deadlocks."
            ),
            handler=_dyn_perfetto_query,
            input_model=DynPerfettoQueryInput,
            scopes=frozenset({PROJECT_READ}),
            read_only=True,
            idempotent=True,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="net_iot_sniffer",
            title="Local IoT Companion Protocol Dissector",
            description=(
                "Passively dissect and parse local multicast/broadcast traffic "
                "(mDNS, SSDP/UPnP, WS-Discovery, UDP JSON beacons) used by IoT companion apps."
            ),
            handler=_net_iot_sniffer,
            input_model=NetIotSnifferInput,
            scopes=frozenset(),
            read_only=True,
            idempotent=True,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_wireguard_tunnel_start",
            title="Start WireGuard Zero-Trust Tunnel",
            description=(
                "Establish local WireGuard VPN tunnel on test device to capture "
                "100% of L4/L7 socket packets without proxy bypasses."
            ),
            handler=_dyn_wireguard_tunnel_start,
            input_model=DynWireguardTunnelStartInput,
            scopes=frozenset(),
            read_only=False,
            idempotent=False,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_wireguard_tunnel_stop",
            title="Stop WireGuard Zero-Trust Tunnel",
            description=("Tear down active WireGuard tunnel on device and restore native routing."),
            handler=_dyn_wireguard_tunnel_stop,
            input_model=DynWireguardTunnelStopInput,
            scopes=frozenset(),
            read_only=False,
            idempotent=False,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_adb_fleet_discover",
            title="Wireless ADB Device Fleet Discovery",
            description=(
                "Discover and orchestrate persistent wireless ADB connections across "
                "local subnet device pools for non-tethered dynamic testing."
            ),
            handler=_dyn_adb_fleet_discover,
            input_model=DynAdbFleetDiscoverInput,
            scopes=frozenset(),
            read_only=True,
            idempotent=True,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_burp_mcp_bridge",
            title="Burp Suite MCP Bridge Configurator",
            description=(
                "Establish bidirectional MCP bridge between Burp Suite and RAA to "
                "expose reverse-engineering tools to Burp and stream live proxy traffic."
            ),
            handler=_dyn_burp_mcp_bridge,
            input_model=DynBurpMcpBridgeInput,
            profiles=DYNAMIC | API,
            scopes=frozenset(),
            read_only=False,
            idempotent=False,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_traffic_passive_audit",
            title="Passive HTTP Traffic Security & PII Inspector",
            description=(
                "Passively inspect HTTP traffic flows for IDOR, insecure cookies, missing "
                "security headers, administrative endpoints, and redact credentials/PII."
            ),
            handler=_dyn_traffic_passive_audit,
            input_model=DynTrafficPassiveAuditInput,
            profiles=DYNAMIC | API,
            scopes=frozenset(),
            read_only=True,
            idempotent=True,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_p2p_device_tunnel",
            title="P2P Encrypted Remote Device Tunnel",
            description=(
                "Establish encrypted peer-to-peer NAT traversal tunnel (Iroh / WireGuard DERP) "
                "to connect directly to remote Android devices behind cellular or firewall NATs."
            ),
            handler=_dyn_p2p_device_tunnel,
            input_model=DynP2pDeviceTunnelInput,
            profiles=DYNAMIC,
            scopes=frozenset(),
            read_only=False,
            idempotent=False,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_virtual_display_start",
            title="Start Headless VirtualDisplay Session",
            description=(
                "Create and orchestrate a headless Android VirtualDisplay to launch, "
                "instrument, and fuzz APKs in the background without disturbing the user screen."
            ),
            handler=_dyn_virtual_display_start,
            input_model=DynVirtualDisplayStartInput,
            profiles=DYNAMIC,
            scopes=frozenset(),
            read_only=False,
            idempotent=False,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_virtual_display_stop",
            title="Stop Headless VirtualDisplay Session",
            description=(
                "Tear down and release an active headless VirtualDisplay session and resources."
            ),
            handler=_dyn_virtual_display_stop,
            input_model=DynVirtualDisplayStopInput,
            profiles=DYNAMIC,
            scopes=frozenset(),
            read_only=False,
            idempotent=False,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_gui_agent_crawl",
            title="Multimodal Mobile GUI Agent Crawler",
            description=(
                "Autonomously navigate and crawl Flutter/Canvas mobile applications using "
                "visual grounding, bypassing permission dialogs and onboarding carousels."
            ),
            handler=_dyn_gui_agent_crawl,
            input_model=DynGuiAgentCrawlInput,
            profiles=DYNAMIC | UI,
            scopes=frozenset(),
            read_only=False,
            idempotent=False,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="termux_workspace_harness",
            title="On-Device PRoot Mobile Workspace Harness",
            description=(
                "Configure an on-device PRoot reversing and patch harness in Termux for ARM64 "
                "Android, enabling Smali inspection, diffing, and rebuilding on device."
            ),
            handler=_termux_workspace_harness,
            input_model=TermuxWorkspaceHarnessInput,
            profiles=frozenset({"core", "dynamic", "full"}),
            scopes=frozenset(),
            read_only=False,
            idempotent=False,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_scrcpy_inject_fast",
            title="Ultra-Low-Latency Scrcpy Fast Input Injection",
            description=(
                "Inject touch, key, or text actions via persistent scrcpy daemon protocol "
                "with sub-5ms latency for high-speed agent interaction."
            ),
            handler=_dyn_scrcpy_inject_fast,
            input_model=DynScrcpyInjectFastInput,
            profiles=DYNAMIC,
            scopes=frozenset(),
            read_only=False,
            idempotent=False,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_scrcpy_frame_capture",
            title="Fast Scrcpy Video Frame Capture",
            description=(
                "Capture low-latency video frame stream from SurfaceControl and MediaCodec "
                "for visual grounding and multimodal inspection."
            ),
            handler=_dyn_scrcpy_frame_capture,
            input_model=DynScrcpyFrameCaptureInput,
            profiles=DYNAMIC,
            scopes=frozenset(),
            read_only=True,
            idempotent=True,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_gui_state_verify",
            title="Deterministic Mobile GUI State Verifier",
            description=(
                "Validate mobile GUI agent action-state transitions against structured, "
                "deterministic JSON application states and evaluate parity scores."
            ),
            handler=_dyn_gui_state_verify,
            input_model=DynGuiStateVerifyInput,
            profiles=DYNAMIC | UI,
            scopes=frozenset(),
            read_only=True,
            idempotent=True,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_rms_hook_generate",
            title="RMS Pre-Configured Dynamic Hook Generator",
            description=(
                "Generate pre-configured Frida hooks for javax.crypto.Cipher, Android "
                "KeyStore, and SharedPreferences to intercept crypto and state at runtime."
            ),
            handler=_dyn_rms_hook_generate,
            input_model=DynRmsHookGenerateInput,
            profiles=DYNAMIC,
            scopes=frozenset(),
            read_only=True,
            idempotent=True,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_rms_method_override",
            title="Codeless Dynamic Method Interceptor & Return Override",
            description=(
                "Dynamically hook target Java methods, inspecting arguments in real time "
                "and overriding return values without writing custom Frida JavaScript."
            ),
            handler=_dyn_rms_method_override,
            input_model=DynRmsMethodOverrideInput,
            profiles=DYNAMIC,
            scopes=frozenset(),
            read_only=False,
            idempotent=False,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_lamda_daemon_connect",
            title="Remote LAMDA Device Agent Connect",
            description=(
                "Connect to on-device LAMDA agent daemon via WebRTC/gRPC and retrieve "
                "device capabilities."
            ),
            handler=_dyn_lamda_daemon_connect,
            input_model=DynLamdaDaemonConnectInput,
            profiles=DYNAMIC,
            scopes=frozenset(),
            read_only=True,
            idempotent=True,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_lamda_touch_event",
            title="Hardware-Level LAMDA Touch Dispatch",
            description=(
                "Dispatch multi-touch kernel input gestures with precise pressure and "
                "timing via LAMDA."
            ),
            handler=_dyn_lamda_touch_event,
            input_model=DynLamdaTouchEventInput,
            profiles=DYNAMIC,
            scopes=frozenset(),
            read_only=False,
            idempotent=False,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_docker_android_spawn",
            title="Spawn Ephemeral Docker Android Sandbox",
            description=(
                "Launch disposable containerized Android emulator sandbox with KVM "
                "acceleration and noVNC."
            ),
            handler=_dyn_docker_android_spawn,
            input_model=DynDockerAndroidSpawnInput,
            profiles=DYNAMIC,
            scopes=frozenset(),
            read_only=False,
            idempotent=False,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_docker_android_teardown",
            title="Teardown Docker Android Sandbox",
            description=(
                "Terminate and purge disposable Docker Android sandbox containers "
                "and storage volumes."
            ),
            handler=_dyn_docker_android_teardown,
            input_model=DynDockerAndroidTeardownInput,
            profiles=DYNAMIC,
            scopes=frozenset(),
            read_only=False,
            idempotent=False,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_agent_device_control",
            title="Agent-Native Device Action Dispatcher",
            description=(
                "Dispatch protocol-driven mobile agent actions including compact ax-tree "
                "and eval-js."
            ),
            handler=_dyn_agent_device_control,
            input_model=DynAgentDeviceControlInput,
            profiles=DYNAMIC,
            scopes=frozenset(),
            read_only=False,
            idempotent=False,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_visual_diff_audit",
            title="Visual Regression Layout & Font Diff Audit",
            description=(
                "Compare mobile UI screenshots with layout- and font-aware visual "
                "regression diffing."
            ),
            handler=_dyn_visual_diff_audit,
            input_model=DynVisualDiffAuditInput,
            profiles=DYNAMIC | UI,
            scopes=frozenset(),
            read_only=True,
            idempotent=True,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_emulator_arm_translation_inject",
            title="Emulator ARM/ARM64 Translation Injector",
            description=(
                "Inject Houdini or ARM64 binary translation libraries into x86/x86_64 emulators."
            ),
            handler=_dyn_emulator_arm_translation_inject,
            input_model=DynEmulatorArmTranslationInjectInput,
            profiles=DYNAMIC,
            scopes=frozenset(),
            read_only=False,
            idempotent=False,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_gui_record_playback",
            title="Demonstration GUI Task Recorder & Action Graph Replay",
            description=(
                "Record human UI interactions into an action graph and replay recorded "
                "baseline flows with boundary fuzz mutations."
            ),
            handler=_dyn_gui_record_playback,
            input_model=DynGuiRecordPlaybackInput,
            profiles=DYNAMIC,
            scopes=frozenset(),
            read_only=False,
            idempotent=False,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_ondevice_accessibility_agent",
            title="PC-Less On-Device Accessibility Fuzzing Agent",
            description=(
                "Control standalone on-device Android Accessibility Service agent to perform "
                "autonomous UI exploration without a tethered PC or ADB connection."
            ),
            handler=_dyn_ondevice_accessibility_agent,
            input_model=DynOndeviceAccessibilityAgentInput,
            profiles=DYNAMIC,
            scopes=frozenset(),
            read_only=False,
            idempotent=False,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_qa_scenario_replay",
            title="Automated QA Scenario Replay & Perfetto Telemetry Slicer",
            description=(
                "Execute scripted test scenarios over ADB with real-time FPS/RAM telemetry and "
                "automatic Perfetto trace slicing on frame drops or ANRs."
            ),
            handler=_dyn_qa_scenario_replay,
            input_model=DynQaScenarioReplayInput,
            profiles=DYNAMIC,
            scopes=frozenset(),
            read_only=False,
            idempotent=False,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_appfunction_invoke",
            title="Android 16 AppFunction Dynamic Invoker & Permission Fuzzer",
            description=(
                "Dispatch direct IPC calls to Android 16 @AppFunctionDeclaration endpoints, "
                "validating caller package authorization and fuzzing parameter schemas."
            ),
            handler=_dyn_appfunction_invoke,
            input_model=DynAppfunctionInvokeInput,
            profiles=DYNAMIC,
            scopes=frozenset(),
            read_only=False,
            idempotent=False,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_httptoolkit_vpn_intercept",
            title="HTTP Toolkit Transparent VPN Interception & CA Injector",
            description=(
                "Transparent zero-config VPN socket capture, ADB reverse proxy routing, "
                "and automated system/user CA certificate injection."
            ),
            handler=_dyn_httptoolkit_vpn_intercept,
            input_model=DynHttptoolkitVpnInterceptInput,
            profiles=DYNAMIC,
            scopes=frozenset(),
            read_only=False,
            idempotent=False,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_rasp_bypass_gen",
            title="Dynamic Frida RASP & Tamper Protection Bypass Synthesizer",
            description=(
                "Generate and deploy targeted Frida scripts neutralizing freeRASP callbacks, "
                "RootBeer/su binary checks, debugger traps, and emulator property detection."
            ),
            handler=_dyn_rasp_bypass_gen,
            input_model=DynRaspBypassGenInput,
            profiles=DYNAMIC,
            scopes=frozenset(),
            read_only=False,
            idempotent=False,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="dyn_device_env_mutate",
            title="Programmatic Device Environment & Chaos Mutator",
            description=(
                "Mutate device runtime state over ADB for chaos testing: dark mode, network "
                "throttling (offline/wifi/data), battery level/charging, and display density."
            ),
            handler=_dyn_device_env_mutate,
            input_model=DynDeviceEnvMutateInput,
            profiles=DYNAMIC,
            scopes=frozenset(),
            read_only=False,
            idempotent=False,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="shizuku_privileged_exec",
            title="Rootless Privileged Execution Bridge via Shizuku Binder IPC",
            description=(
                "Execute privileged package management, appops, and permission grants "
                "without root using Shizuku Binder IPC or rish ADB bridge."
            ),
            handler=_shizuku_privileged_exec,
            input_model=ShizukuPrivilegedExecInput,
            profiles=frozenset({"core", "full"}),
            scopes=frozenset(),
            read_only=False,
            idempotent=False,
            device_required=False,
        )
    )
    registry.register(
        _dynamic_spec(
            name="termux_ondevice_binary_bundle",
            title="Standalone ARM64/x86_64 AOSP On-Device Binary Manager",
            description=(
                "Bundle, deploy, and execute standalone command-line analysis binaries "
                "(sqlite3, dexdump, busybox, strace, tcpdump, socat) for low-overhead inspection."
            ),
            handler=_termux_ondevice_binary_bundle,
            input_model=TermuxOndeviceBinaryBundleInput,
            profiles=frozenset({"core", "full"}),
            scopes=frozenset(),
            read_only=False,
            idempotent=False,
            device_required=False,
        )
    )
