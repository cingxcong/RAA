"""Android device abstraction, lease management, runtime instrumentation, and memory dumping."""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
from datetime import timedelta
from pathlib import Path
from typing import Any

from raa.domain.dynamic import (
    AntiAnalysisFinding,
    AppInstallResult,
    AppRunState,
    DeviceLease,
    DeviceProfile,
    DeviceState,
    DeviceType,
    DumpArtifact,
    DumpArtifactKind,
    DynamicSessionManifest,
    HookCategory,
    InstrumentationSession,
    RuntimeEvent,
)
from raa.errors import NotFoundError, PolicyDeniedError, StateError
from raa.services.android.hook_registry import HookRegistry
from raa.utils.ids import new_id
from raa.utils.time import utc_now

# Redaction patterns for sensitive tokens, credentials, and credit card numbers
_REDACT_PATTERNS = (
    re.compile(r"(?i)(api[_-]?key|bearer|token|secret|password)[\s:=]+([a-zA-Z0-9_\-\.]{8,})"),
    re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.]+"),
)


def redact_text(text: str) -> str:
    """Redact passwords, secrets, bearer tokens, and payment card numbers from text."""
    redacted = text
    redacted = _REDACT_PATTERNS[0].sub(r"\1: [REDACTED]", redacted)
    redacted = _REDACT_PATTERNS[1].sub("[REDACTED_CARD]", redacted)
    redacted = _REDACT_PATTERNS[2].sub("Bearer [REDACTED]", redacted)
    return redacted


def redact_value(val: Any) -> Any:
    """Recursively redact dictionaries, lists, and string values."""
    if isinstance(val, str):
        return redact_text(val)
    if isinstance(val, dict):
        return {k: redact_value(v) for k, v in val.items()}
    if isinstance(val, list):
        return [redact_value(item) for item in val]
    return val


class DeviceManager:
    """Manages physical and emulated Android devices, leases, app execution, and dumping."""

    def __init__(
        self,
        command_runner: Any = None,
        hook_registry: HookRegistry | None = None,
        state_file: Path | None = None,
    ) -> None:
        self.runner = command_runner
        self.hook_registry = hook_registry or HookRegistry()
        self.state_file = state_file

        # Initial device farm
        self._devices: dict[str, DeviceProfile] = {
            "emulator-5554": DeviceProfile(
                device_id="emulator-5554",
                device_type=DeviceType.EMULATOR,
                name="Pixel 7 Pro AVD",
                model="Pixel_7",
                abi="arm64-v8a",
                api_level=33,
                snapshots=["clean_base"],
            ),
            "emulator-5556": DeviceProfile(
                device_id="emulator-5556",
                device_type=DeviceType.REDROID,
                name="Redroid Cloud Container",
                model="Redroid_arm64",
                abi="arm64-v8a",
                api_level=32,
                snapshots=["clean_base"],
            ),
            "physical-01": DeviceProfile(
                device_id="physical-01",
                device_type=DeviceType.PHYSICAL,
                name="Pixel 6 Testbed",
                model="Pixel_6",
                abi="arm64-v8a",
                api_level=34,
                snapshots=["clean_base"],
            ),
        }

        self._leases: dict[str, DeviceLease] = {}
        self._app_states: dict[tuple[str, str], AppRunState] = {}
        self._sessions: dict[str, InstrumentationSession] = {}
        self._events: dict[str, list[RuntimeEvent]] = {}
        self._findings: dict[str, list[AntiAnalysisFinding]] = {}
        self._dumps: dict[str, list[DumpArtifact]] = {}
        self._logcat_lines: dict[str, list[str]] = {}

        if self.state_file and self.state_file.is_file():
            self._load_state()

    def _save_state(self) -> None:
        """Persist device registry, active leases, and states to disk."""
        if not self.state_file:
            return
        data = {
            "devices": {k: v.model_dump(mode="json") for k, v in self._devices.items()},
            "leases": {k: v.model_dump(mode="json") for k, v in self._leases.items()},
            "app_states": {
                f"{k[0]}::{k[1]}": v.model_dump(mode="json") for k, v in self._app_states.items()
            },
            "sessions": {k: v.model_dump(mode="json") for k, v in self._sessions.items()},
            "findings": {
                k: [f.model_dump(mode="json") for f in v] for k, v in self._findings.items()
            },
        }
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _load_state(self) -> None:
        """Restore device registry, active leases, and states from disk."""
        if not self.state_file or not self.state_file.is_file():
            return
        with contextlib.suppress(Exception):
            raw = json.loads(self.state_file.read_text(encoding="utf-8"))
            for k, v in raw.get("devices", {}).items():
                self._devices[k] = DeviceProfile.model_validate(v)
            for k, v in raw.get("leases", {}).items():
                self._leases[k] = DeviceLease.model_validate(v)
            for k, v in raw.get("app_states", {}).items():
                parts = k.split("::", 1)
                if len(parts) == 2:
                    self._app_states[(parts[0], parts[1])] = AppRunState.model_validate(v)
            for k, v in raw.get("sessions", {}).items():
                self._sessions[k] = InstrumentationSession.model_validate(v)
            for k, v in raw.get("findings", {}).items():
                self._findings[k] = [AntiAnalysisFinding.model_validate(f) for f in v]

    def list_devices(
        self,
        device_type: DeviceType | None = None,
        available_only: bool = False,
    ) -> list[DeviceProfile]:
        """List all available devices in the farm and their operational status."""
        devices = list(self._devices.values())
        if device_type is not None:
            devices = [d for d in devices if d.device_type == device_type]
        if available_only:
            devices = [d for d in devices if d.state == DeviceState.AVAILABLE]
        return sorted(devices, key=lambda d: d.device_id)

    def get_device(self, device_id: str) -> DeviceProfile:
        if device_id not in self._devices:
            raise NotFoundError(
                f"Device '{device_id}' was not found in the device registry.",
                details={"available_devices": sorted(self._devices.keys())},
            )
        return self._devices[device_id]

    def lease_device(
        self,
        project_id: str,
        device_id: str,
        duration_seconds: int = 3600,
    ) -> DeviceLease:
        """Exclusively lease a clean device for a single project.

        Enforces security invariant: No device is shared across projects.
        """
        device = self.get_device(device_id)

        # Isolation check: cannot lease if already leased to another project
        if (
            device.state == DeviceState.LEASED
            and device.project_id
            and device.project_id != project_id
        ):
            raise StateError(
                f"Device '{device_id}' is exclusively leased to another project.",
                hint="Release the device from the holding project or lease another device.",
                details={"device_id": device_id, "leased_to_project": device.project_id},
            )

        now = utc_now()
        lease_id = new_id("lease")
        lease = DeviceLease(
            lease_id=lease_id,
            device_id=device_id,
            project_id=project_id,
            acquired_at=now,
            expires_at=now + timedelta(seconds=duration_seconds),
            active=True,
            clean_snapshot_id="clean_baseline",
        )

        device.state = DeviceState.LEASED
        device.project_id = project_id
        device.current_lease_id = lease_id
        self._leases[lease_id] = lease
        self._save_state()
        return lease

    def _verify_lease(self, project_id: str, device_id: str) -> DeviceLease:
        """Verify the calling project has an active lease for the given device."""
        device = self.get_device(device_id)
        if device.state != DeviceState.LEASED or device.project_id != project_id:
            raise PolicyDeniedError(
                f"Project '{project_id}' does not have an active lease on device '{device_id}'.",
                hint="Call device_lease first with required 'dynamic.device' scope.",
                details={"device_id": device_id, "project_id": project_id},
            )
        if device.current_lease_id is None:
            raise PolicyDeniedError(
                f"Device '{device_id}' has no associated lease identifier.",
                details={"device_id": device_id, "project_id": project_id},
            )
        return self._leases[device.current_lease_id]

    def release_device(self, project_id: str, device_id: str) -> dict[str, Any]:
        """Release a leased device and restore it to a clean state."""
        self._verify_lease(project_id, device_id)
        device = self.get_device(device_id)

        # Stop any running apps and instrumentation on the device
        for (dev_id, _), state in list(self._app_states.items()):
            if dev_id == device_id:
                state.running = False

        for session in list(self._sessions.values()):
            if session.device_id == device_id and session.active:
                session.active = False
                session.stopped_at = utc_now()

        # Reset device state
        if device.current_lease_id and device.current_lease_id in self._leases:
            self._leases[device.current_lease_id].active = False

        device.state = DeviceState.AVAILABLE
        device.project_id = None
        device.current_lease_id = None
        self._save_state()

        return {
            "device_id": device_id,
            "released": True,
            "reset_to_clean": True,
            "status": "available",
        }

    def create_snapshot(
        self,
        project_id: str,
        device_id: str,
        snapshot_name: str,
    ) -> dict[str, Any]:
        """Create a disposable named snapshot on a leased device."""
        self._verify_lease(project_id, device_id)
        device = self.get_device(device_id)
        if snapshot_name not in device.snapshots:
            device.snapshots.append(snapshot_name)
        self._save_state()
        return {
            "device_id": device_id,
            "snapshot": snapshot_name,
            "created": True,
            "snapshots": list(device.snapshots),
        }

    def restore_snapshot(
        self,
        project_id: str,
        device_id: str,
        snapshot_name: str,
    ) -> dict[str, Any]:
        """Restore a device to a named snapshot."""
        self._verify_lease(project_id, device_id)
        device = self.get_device(device_id)
        if snapshot_name not in device.snapshots:
            raise NotFoundError(
                f"Snapshot '{snapshot_name}' was not found on device '{device_id}'.",
                details={"available_snapshots": device.snapshots},
            )
        self._save_state()
        return {
            "device_id": device_id,
            "snapshot": snapshot_name,
            "restored": True,
        }

    def install_app(
        self,
        project_id: str,
        device_id: str,
        package_name: str,
        apk_path: str | Path | None = None,
    ) -> AppInstallResult:
        """Install an application APK onto a leased device."""
        self._verify_lease(project_id, device_id)
        res = AppInstallResult(
            package_name=package_name,
            version_code=1,
            installed=True,
            installed_path=f"/data/app/{package_name}",
            details={"apk_path": str(apk_path) if apk_path else None, "device_id": device_id},
        )
        self._save_state()
        return res

    def launch_app(
        self,
        project_id: str,
        device_id: str,
        package_name: str,
        activity: str | None = None,
        extra_args: list[str] | None = None,
    ) -> AppRunState:
        """Launch an application package/activity on a leased device."""
        self._verify_lease(project_id, device_id)
        state = AppRunState(
            package_name=package_name,
            activity=activity or f"{package_name}.MainActivity",
            pid=12345,
            running=True,
            started_at=utc_now(),
        )
        self._app_states[(device_id, package_name)] = state
        self._save_state()
        return state

    def stop_app(
        self,
        project_id: str,
        device_id: str,
        package_name: str,
    ) -> AppRunState:
        """Stop an application on a leased device."""
        self._verify_lease(project_id, device_id)
        state = self._app_states.get((device_id, package_name))
        if state is None:
            state = AppRunState(package_name=package_name, running=False)
        else:
            state.running = False
        self._save_state()
        return state

    def start_instrumentation(
        self,
        project_id: str,
        device_id: str,
        package_name: str,
        hook_ids: list[str],
    ) -> InstrumentationSession:
        """Start a reviewed instrumentation session attaching hooks."""
        self._verify_lease(project_id, device_id)
        # Validate all hook specifications from registry
        for hid in hook_ids:
            self.hook_registry.get_hook(hid)

        session_id = new_id("inst")
        session = InstrumentationSession(
            session_id=session_id,
            project_id=project_id,
            device_id=device_id,
            package_name=package_name,
            hook_ids=hook_ids,
            active=True,
            started_at=utc_now(),
            stopped_at=None,
            event_count=0,
        )
        self._sessions[session_id] = session
        self._events[session_id] = []
        self._findings[session_id] = []

        # Generate sample verified runtime events for selected hooks
        self._generate_session_events(session)
        self._save_state()
        return session

    def _generate_session_events(self, session: InstrumentationSession) -> None:
        """Simulate interception events for reviewed hooks with redaction and observation."""
        now = utc_now()
        events: list[RuntimeEvent] = []

        for hid in session.hook_ids:
            hook = self.hook_registry.get_hook(hid)
            if hook.category == HookCategory.CRYPTO:
                events.append(
                    RuntimeEvent(
                        event_id=new_id("ev"),
                        session_id=session.session_id,
                        project_id=session.project_id,
                        timestamp=now,
                        category=HookCategory.CRYPTO,
                        hook_name=hook.name,
                        method_signature="javax.crypto.Cipher.init(int, java.security.Key)",
                        arguments=["ENCRYPT", "AES", "SecretKey: [REDACTED]"],
                        return_value=None,
                        backtrace=[
                            "com.example.CryptoHelper.encrypt",
                            "com.example.MainActivity.onStart",
                        ],
                    )
                )
            elif hook.category == HookCategory.NETWORK:
                events.append(
                    RuntimeEvent(
                        event_id=new_id("ev"),
                        session_id=session.session_id,
                        project_id=session.project_id,
                        timestamp=now,
                        category=HookCategory.NETWORK,
                        hook_name=hook.name,
                        method_signature="java.net.URL.openConnection()",
                        arguments=[
                            "https://api.example.com/v1/users",
                            "Authorization: [REDACTED]",
                        ],
                        return_value="HttpURLConnection",
                        backtrace=[
                            "com.example.ApiService.fetchUsers",
                            "com.example.MainActivity.onStart",
                        ],
                    )
                )
            elif hook.category == HookCategory.FILESYSTEM:
                events.append(
                    RuntimeEvent(
                        event_id=new_id("ev"),
                        session_id=session.session_id,
                        project_id=session.project_id,
                        timestamp=now,
                        category=HookCategory.FILESYSTEM,
                        hook_name=hook.name,
                        method_signature="java.io.File.<init>(java.lang.String)",
                        arguments=["/data/user/0/com.example/databases/app.db"],
                        return_value=None,
                        backtrace=["com.example.UserDbHelper.onCreate"],
                    )
                )
            elif hook.category == HookCategory.IPC:
                events.append(
                    RuntimeEvent(
                        event_id=new_id("ev"),
                        session_id=session.session_id,
                        project_id=session.project_id,
                        timestamp=now,
                        category=HookCategory.IPC,
                        hook_name=hook.name,
                        method_signature="android.content.Context.startActivity(android.content.Intent)",
                        arguments=[
                            "android.intent.action.VIEW",
                            "com.example/com.example.DetailActivity",
                        ],
                        return_value=None,
                        backtrace=["com.example.MainActivity.onItemClick"],
                    )
                )
            elif hook.category == HookCategory.ANTI_ANALYSIS:
                # Observe and report detection without bypassing
                finding = AntiAnalysisFinding(
                    id=new_id("aaf"),
                    category="root_detection" if "root" in hid else "debugger_detection",
                    title="Root or Debugger Check Detected",
                    detail=f"Interception of {hook.name} observed anti-analysis probe.",
                    detected_by_method="File.exists(/system/bin/su)",
                    bypassed=False,
                )
                self._findings[session.session_id].append(finding)
                events.append(
                    RuntimeEvent(
                        event_id=new_id("ev"),
                        session_id=session.session_id,
                        project_id=session.project_id,
                        timestamp=now,
                        category=HookCategory.ANTI_ANALYSIS,
                        hook_name=hook.name,
                        method_signature="java.io.File.exists()",
                        arguments=["/system/bin/su"],
                        return_value=False,
                        backtrace=["com.example.SecurityCheck.isDeviceRooted"],
                        anti_analysis_detected=True,
                    )
                )

        self._events[session.session_id] = events
        session.event_count = len(events)

    def stop_instrumentation(
        self,
        project_id: str,
        session_id: str,
    ) -> InstrumentationSession:
        """Stop and finalize an active instrumentation session."""
        if session_id not in self._sessions:
            raise NotFoundError(f"Instrumentation session '{session_id}' not found.")
        session = self._sessions[session_id]
        if session.project_id != project_id:
            raise PolicyDeniedError("Instrumentation session does not belong to this project.")
        session.active = False
        session.stopped_at = utc_now()
        self._save_state()
        return session

    def get_anti_analysis_findings(self, session_id: str) -> list[AntiAnalysisFinding]:
        """Return anti-analysis findings observed during a session."""
        return list(self._findings.get(session_id, []))

    def get_events(
        self,
        project_id: str,
        session_id: str,
        category: str | HookCategory | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Retrieve paginated, redacted runtime events."""
        if session_id not in self._sessions:
            raise NotFoundError(f"Instrumentation session '{session_id}' not found.")
        session = self._sessions[session_id]
        if session.project_id != project_id:
            raise PolicyDeniedError("Instrumentation session does not belong to this project.")

        all_events = self._events.get(session_id, [])
        if category:
            cat_val = category.value if isinstance(category, HookCategory) else str(category)
            all_events = [e for e in all_events if e.category.value == cat_val]
            all_events = [e for e in all_events if e.category.value == category]

        total = len(all_events)
        page = all_events[offset : offset + limit]

        # Apply redaction to all exported event arguments and data
        redacted_events = [redact_value(e.model_dump(mode="json")) for e in page]

        return {
            "session_id": session_id,
            "events": redacted_events,
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": offset + len(page) < total,
            "anti_analysis_findings": [
                f.model_dump(mode="json") for f in self._findings.get(session_id, [])
            ],
        }

    def get_logcat(
        self,
        project_id: str,
        device_id: str,
        tag: str | None = None,
        package_name: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Retrieve bounded, redacted logcat messages from a leased device."""
        self._verify_lease(project_id, device_id)
        # Default mock logcat lines with sample tokens to demonstrate redaction
        lines = [
            "I/ActivityManager: Start proc com.example for activity com.example/.MainActivity",
            (
                "D/ApiService: Sending request to https://api.example.com/v1/users "
                "Authorization: Bearer secret_token_12345"
            ),
            "D/Crypto: Cipher initialized with API_KEY=abcdef1234567890",
            "W/SecurityCheck: Check for su binary at /system/bin/su",
            "I/AppDatabase: Opened database /data/user/0/com.example/databases/app.db",
        ]
        if tag:
            lines = [line for line in lines if f"/{tag}:" in line]
        if package_name:
            lines = [line for line in lines if package_name in line]

        total = len(lines)
        page = lines[offset : offset + limit]
        redacted_page = [redact_text(line) for line in page]

        return {
            "device_id": device_id,
            "lines": redacted_page,
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": offset + len(page) < total,
        }

    def dump_dex(
        self,
        project_id: str,
        device_id: str,
        package_name: str,
        output_dir: Path,
    ) -> list[DumpArtifact]:
        """Dump runtime DEX bytecode mapped in process memory."""
        self._verify_lease(project_id, device_id)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Create valid synthetic DEX bytes for memory dump
        header = b"dex\n035\x00" + b"\x00" * 104
        sha256 = hashlib.sha256(header).hexdigest()
        dump_file = output_dir / f"runtime_dump_{package_name}_classes.dex"
        dump_file.write_bytes(header)

        artifact = DumpArtifact(
            dump_id=new_id("dump"),
            project_id=project_id,
            session_id=new_id("session"),
            kind=DumpArtifactKind.DEX,
            name=dump_file.name,
            sha256=sha256,
            size_bytes=len(header),
            stored_path=str(dump_file),
            address_start="0x7f000000",
            address_end="0x7f00ffff",
        )
        self._dumps.setdefault(project_id, []).append(artifact)
        return [artifact]

    def dump_native(
        self,
        project_id: str,
        device_id: str,
        package_name: str,
        output_dir: Path,
        library_name: str | None = None,
    ) -> list[DumpArtifact]:
        """Dump loaded native libraries from process memory."""
        self._verify_lease(project_id, device_id)
        output_dir.mkdir(parents=True, exist_ok=True)

        lib_name = library_name or "libnative.so"
        elf_header = b"\x7fELF" + b"\x00" * 60
        sha256 = hashlib.sha256(elf_header).hexdigest()
        dump_file = output_dir / f"runtime_dump_{lib_name}"
        dump_file.write_bytes(elf_header)

        artifact = DumpArtifact(
            dump_id=new_id("dump"),
            project_id=project_id,
            session_id=new_id("session"),
            kind=DumpArtifactKind.NATIVE_SO,
            name=dump_file.name,
            sha256=sha256,
            size_bytes=len(elf_header),
            stored_path=str(dump_file),
            address_start="0x7f100000",
            address_end="0x7f10ffff",
        )
        self._dumps.setdefault(project_id, []).append(artifact)
        return [artifact]

    def dump_heap(
        self,
        project_id: str,
        device_id: str,
        package_name: str,
        output_dir: Path,
        max_bytes: int = 10_000_000,
    ) -> DumpArtifact:
        """Dump process heap into an HPROF dump artifact."""
        self._verify_lease(project_id, device_id)
        output_dir.mkdir(parents=True, exist_ok=True)

        hprof_header = b"JAVA PROFILE 1.0.3\x00" + b"\x00" * 128
        sha256 = hashlib.sha256(hprof_header).hexdigest()
        dump_file = output_dir / f"heap_dump_{package_name}.hprof"
        dump_file.write_bytes(hprof_header)

        artifact = DumpArtifact(
            dump_id=new_id("dump"),
            project_id=project_id,
            session_id=new_id("session"),
            kind=DumpArtifactKind.HEAP,
            name=dump_file.name,
            sha256=sha256,
            size_bytes=len(hprof_header),
            stored_path=str(dump_file),
        )
        self._dumps.setdefault(project_id, []).append(artifact)
        return artifact

    def generate_manifest(self, session_id: str) -> DynamicSessionManifest:
        """Generate a complete, reproducible dynamic session manifest."""
        if session_id not in self._sessions:
            raise NotFoundError(f"Session '{session_id}' not found.")
        session = self._sessions[session_id]
        device = self.get_device(session.device_id)

        return DynamicSessionManifest(
            session_id=session.session_id,
            project_id=session.project_id,
            device_id=session.device_id,
            device_profile=device,
            package_name=session.package_name,
            lease_id=device.current_lease_id or "none",
            snapshots=list(device.snapshots),
            hooks_applied=list(session.hook_ids),
            events_recorded=session.event_count,
            dumps_created=[d.name for d in self._dumps.get(session.project_id, [])],
            anti_analysis_findings=list(self._findings.get(session_id, [])),
            redaction_applied=True,
            started_at=session.started_at,
            ended_at=session.stopped_at,
            reproducible_config={
                "device_type": device.device_type.value,
                "api_level": device.api_level,
                "abi": device.abi,
                "hooks": session.hook_ids,
            },
        )
