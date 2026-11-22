"""Domain models for dynamic analysis, device leases, instrumentation, and runtime dumps."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

from raa.utils.time import utc_now


class DeviceType(StrEnum):
    """Underlying platform for test devices."""

    AVD = "avd"
    REDROID = "redroid"
    PHYSICAL = "physical"
    EMULATOR = "emulator"
    MOCK = "mock"


class DeviceState(StrEnum):
    """Operational status of a device in the farm."""

    AVAILABLE = "available"
    LEASED = "leased"
    BUSY = "busy"
    OFFLINE = "offline"
    ERROR = "error"


class DeviceProfile(BaseModel):
    """Static and operational specification of an Android device or emulator."""

    device_id: str
    device_type: DeviceType = DeviceType.EMULATOR
    name: str = "Android Emulator"
    model: str = "Pixel_7"
    abi: str = "arm64-v8a"
    api_level: int = 33
    state: DeviceState = DeviceState.AVAILABLE
    current_lease_id: str | None = None
    project_id: str | None = None
    snapshots: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(
        default_factory=lambda: [
            "root",
            "frida",
            "logcat",
            "screenshot",
            "dumps",
            "install",
        ]
    )
    metadata: dict[str, Any] = Field(default_factory=dict)


class DeviceLease(BaseModel):
    """Exclusive, isolated time-bounded lease of a device for a single project."""

    lease_id: str
    device_id: str
    project_id: str
    acquired_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime
    active: bool = True
    clean_snapshot_id: str | None = None


class AppInstallResult(BaseModel):
    """Result of installing an application APK onto a leased device."""

    package_name: str
    version_code: int | None = None
    installed: bool = True
    installed_path: str = "/data/app"
    details: dict[str, Any] = Field(default_factory=dict)


class AppRunState(BaseModel):
    """Execution state of an application on a device."""

    package_name: str
    activity: str | None = None
    pid: int | None = None
    running: bool = False
    started_at: datetime | None = None


class HookCategory(StrEnum):
    """Category of runtime instrumentation interception."""

    CRYPTO = "crypto"
    NETWORK = "network"
    FILESYSTEM = "filesystem"
    IPC = "ipc"
    KEYSTORE = "keystore"
    ANTI_ANALYSIS = "anti_analysis"
    WEBVIEW = "webview"
    CUSTOM = "custom"


class HookSpec(BaseModel):
    """Reviewed and approved instrumentation hook specification."""

    id: str
    name: str
    category: HookCategory
    description: str
    script_template: str
    reviewed: bool = True
    safety_rating: Literal["safe", "invasive", "destructive"] = "safe"


class InstrumentationSession(BaseModel):
    """Active or finalized dynamic instrumentation session."""

    session_id: str
    project_id: str
    device_id: str
    package_name: str
    hook_ids: list[str] = Field(default_factory=list)
    active: bool = True
    started_at: datetime = Field(default_factory=utc_now)
    stopped_at: datetime | None = None
    event_count: int = 0


class RuntimeEvent(BaseModel):
    """Normalized, redacted interception event captured during dynamic execution."""

    event_id: str
    session_id: str
    project_id: str
    timestamp: datetime = Field(default_factory=utc_now)
    category: HookCategory
    hook_name: str
    method_signature: str | None = None
    arguments: list[Any] = Field(default_factory=list)
    return_value: Any | None = None
    backtrace: list[str] = Field(default_factory=list)
    evidence_id: str | None = None
    anti_analysis_detected: bool = False


class AntiAnalysisFinding(BaseModel):
    """Observed anti-debug, anti-Frida, root detection, or integrity check finding."""

    id: str
    category: Literal[
        "root_detection",
        "emulator_detection",
        "debugger_detection",
        "frida_detection",
        "integrity_check",
    ]
    title: str
    detail: str
    detected_by_method: str
    bypassed: bool = False
    evidence_id: str | None = None


class DumpArtifactKind(StrEnum):
    """Kind of memory or runtime dump."""

    DEX = "dex"
    VDEX = "vdex"
    NATIVE_SO = "native_so"
    HEAP = "heap"
    MEMORY_RANGE = "memory_range"


class DumpArtifact(BaseModel):
    """Metadata for an extracted memory dump or runtime unpacked artifact."""

    dump_id: str
    project_id: str
    session_id: str
    kind: DumpArtifactKind
    name: str
    sha256: str
    size_bytes: int
    stored_path: str
    address_start: str | None = None
    address_end: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    evidence_id: str | None = None


class DynamicSessionManifest(BaseModel):
    """Complete, reproducible record of an isolated dynamic analysis session."""

    session_id: str
    project_id: str
    device_id: str
    device_profile: DeviceProfile
    artifact_sha256: str | None = None
    package_name: str
    installed_version: int | None = None
    lease_id: str
    snapshots: list[str] = Field(default_factory=list)
    hooks_applied: list[str] = Field(default_factory=list)
    events_recorded: int = 0
    dumps_created: list[str] = Field(default_factory=list)
    anti_analysis_findings: list[AntiAnalysisFinding] = Field(default_factory=list)
    redaction_applied: bool = True
    started_at: datetime = Field(default_factory=utc_now)
    ended_at: datetime | None = None
    reproducible_config: dict[str, Any] = Field(default_factory=dict)
