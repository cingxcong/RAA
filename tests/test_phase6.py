"""Phase 6 Dynamic analysis, device lease, instrumentation, and memory dump tests.

Verifies:
1. Device abstraction (AVD, redroid, physical devices).
2. Lease, snapshot, reset, and cleanup lifecycle.
3. Strict project isolation (no device shared across projects).
4. Application installation, launch, and termination.
5. Reviewed Frida hook registry and script generation.
6. Instrumentation execution, event capture, and sensitive data redaction.
7. Anti-analysis observation reporting without default bypass.
8. Filtered, redacted logcat retrieval.
9. Process memory dumping (DEX, native SO, HPROF heap).
10. Session manifest persistence and reproducibility.
11. Fail-closed policy enforcement on dynamic tools.
12. Typer CLI subcommands for device and dynamic operations.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from raa.cli.main import app
from raa.domain.dynamic import (
    DeviceState,
    DeviceType,
    DumpArtifactKind,
    DynamicSessionManifest,
    HookCategory,
)
from raa.errors import NotFoundError, PolicyDeniedError, StateError
from raa.runtime import Runtime
from raa.services.android.device_manager import DeviceManager
from raa.services.android.hook_registry import HookRegistry

runner = CliRunner()


def test_device_listing_and_filtering() -> None:
    """Verify device pool contains AVD, Redroid, and Physical devices with capability profiles."""
    manager = DeviceManager()
    devices = manager.list_devices()
    assert len(devices) == 3

    ids = {d.device_id for d in devices}
    assert "emulator-5554" in ids
    assert "emulator-5556" in ids
    assert "physical-01" in ids

    # Filter by platform
    emulators = manager.list_devices(device_type=DeviceType.EMULATOR)
    assert len(emulators) == 1
    assert emulators[0].device_id == "emulator-5554"

    redroid = manager.list_devices(device_type=DeviceType.REDROID)
    assert len(redroid) == 1
    assert redroid[0].device_id == "emulator-5556"

    physical = manager.list_devices(device_type=DeviceType.PHYSICAL)
    assert len(physical) == 1
    assert physical[0].device_id == "physical-01"

    # Filter by available
    available = manager.list_devices(available_only=True)
    assert len(available) == 3


def test_device_lease_and_release() -> None:
    """Verify exclusive lease acquisition, state change, and clean reset upon release."""
    manager = DeviceManager()
    lease = manager.lease_device(
        project_id="proj-1", device_id="emulator-5554", duration_seconds=1800
    )
    assert lease.active is True
    assert lease.project_id == "proj-1"
    assert lease.device_id == "emulator-5554"

    device = manager.get_device("emulator-5554")
    assert device.state == DeviceState.LEASED
    assert device.project_id == "proj-1"
    assert device.current_lease_id == lease.lease_id

    # Release device
    release_res = manager.release_device(project_id="proj-1", device_id="emulator-5554")
    assert release_res["reset_to_clean"] is True
    assert release_res["status"] == "available"

    device_after = manager.get_device("emulator-5554")
    assert device_after.state == DeviceState.AVAILABLE
    assert device_after.project_id is None
    assert device_after.current_lease_id is None


def test_device_isolation_enforcement() -> None:
    """Verify security invariant: No device is shared across projects."""
    manager = DeviceManager()
    manager.lease_device(project_id="proj-1", device_id="emulator-5554")

    # Attempt to lease by project-2 must raise StateError
    with pytest.raises(StateError) as exc_info:
        manager.lease_device(project_id="proj-2", device_id="emulator-5554")
    assert "leased" in str(exc_info.value).lower()

    # Attempt to perform action by project-2 on project-1's leased device must fail
    with pytest.raises(PolicyDeniedError):
        manager.launch_app(project_id="proj-2", device_id="emulator-5554", package_name="com.test")


def test_device_snapshot_and_restore() -> None:
    """Verify disposable named snapshot creation and restoration."""
    manager = DeviceManager()
    manager.lease_device(project_id="proj-1", device_id="emulator-5554")

    # Create snapshot
    res = manager.create_snapshot(
        project_id="proj-1", device_id="emulator-5554", snapshot_name="pre_exploit"
    )
    assert res["created"] is True
    assert "pre_exploit" in res["snapshots"]

    device = manager.get_device("emulator-5554")
    assert "pre_exploit" in device.snapshots

    # Restore snapshot
    restored = manager.restore_snapshot(
        project_id="proj-1", device_id="emulator-5554", snapshot_name="pre_exploit"
    )
    assert restored["restored"] is True

    # Restoring unknown snapshot raises NotFoundError
    with pytest.raises(NotFoundError):
        manager.restore_snapshot(
            project_id="proj-1", device_id="emulator-5554", snapshot_name="non_existent"
        )


def test_app_lifecycle_on_device() -> None:
    """Verify application installation, launch, running state, and termination."""
    manager = DeviceManager()
    manager.lease_device(project_id="proj-1", device_id="emulator-5554")

    # Install
    install_res = manager.install_app(
        project_id="proj-1",
        device_id="emulator-5554",
        package_name="com.example.bank",
        apk_path="/path/to/bank.apk",
    )
    assert install_res.installed is True
    assert install_res.package_name == "com.example.bank"

    # Launch
    state = manager.launch_app(
        project_id="proj-1",
        device_id="emulator-5554",
        package_name="com.example.bank",
        activity="com.example.bank.MainActivity",
    )
    assert state.running is True
    assert state.pid == 12345
    assert state.activity == "com.example.bank.MainActivity"

    # Stop
    stopped = manager.stop_app(
        project_id="proj-1",
        device_id="emulator-5554",
        package_name="com.example.bank",
    )
    assert stopped.running is False


def test_reviewed_hook_registry() -> None:
    """Verify reviewed hook catalog, script assembly, and validation."""
    registry = HookRegistry()
    hooks = registry.list_hooks()
    assert len(hooks) >= 6

    # Verify categories present
    cats = {h.category for h in hooks}
    assert HookCategory.CRYPTO in cats
    assert HookCategory.NETWORK in cats
    assert HookCategory.FILESYSTEM in cats
    assert HookCategory.IPC in cats
    assert HookCategory.KEYSTORE in cats
    assert HookCategory.ANTI_ANALYSIS in cats

    # Check reviewed and safe ratings
    for hook in hooks:
        assert hook.reviewed is True
        assert hook.safety_rating in {"safe", "invasive"}

    # Build combined script
    script = registry.build_combined_script(["crypto.cipher", "network.http"])
    assert "Java.perform" in script
    assert "javax.crypto.Cipher" in script
    assert "java.net.URL" in script

    # Unknown hook raises NotFoundError
    with pytest.raises(NotFoundError):
        registry.get_hook("nonexistent_hook")


def test_instrumentation_session_and_redaction(tmp_path: Path) -> None:
    """Verify instrumentation session event capture with sensitive data redaction."""
    manager = DeviceManager()
    manager.lease_device(project_id="proj-1", device_id="emulator-5554")

    session = manager.start_instrumentation(
        project_id="proj-1",
        device_id="emulator-5554",
        package_name="com.example.app",
        hook_ids=["crypto.cipher", "network.http", "keystore.alias"],
    )
    assert session.active is True
    assert session.event_count > 0

    # Retrieve events
    events_res = manager.get_events(project_id="proj-1", session_id=session.session_id)
    assert events_res["total"] > 0
    events = events_res["events"]

    # Verify sensitive data redaction in arguments
    for ev in events:
        args_str = json.dumps(ev.get("arguments", []))
        assert "secret_token_12345" not in args_str
        assert "abcdef1234567890" not in args_str
        # Tokens should be redacted
        if ev.get("category") == "crypto":
            assert any("[REDACTED]" in str(arg) for arg in ev.get("arguments", []))
        if ev.get("category") == "network":
            assert any("[REDACTED]" in str(arg) for arg in ev.get("arguments", []))

    # Stop instrumentation
    stopped_session = manager.stop_instrumentation(
        project_id="proj-1", session_id=session.session_id
    )
    assert stopped_session.active is False
    assert stopped_session.stopped_at is not None


def test_anti_analysis_reporting_not_bypassed() -> None:
    """Verify exit criterion: Anti-analysis findings are reported, not bypassed by default."""
    manager = DeviceManager()
    manager.lease_device(project_id="proj-1", device_id="emulator-5554")

    session = manager.start_instrumentation(
        project_id="proj-1",
        device_id="emulator-5554",
        package_name="com.example.anti",
        hook_ids=["anti_analysis.root_detection"],
    )
    findings = manager.get_anti_analysis_findings(session.session_id)
    assert len(findings) >= 1

    root_finding = findings[0]
    assert root_finding.category == "root_detection"
    # CRITICAL INVARIANT: bypassed must be False!
    assert root_finding.bypassed is False
    assert "root" in root_finding.title.lower()


def test_logcat_stream_and_redaction() -> None:
    """Verify logcat retrieval, filtering, and sensitive token redaction."""
    manager = DeviceManager()
    manager.lease_device(project_id="proj-1", device_id="emulator-5554")

    logcat = manager.get_logcat(project_id="proj-1", device_id="emulator-5554", limit=10)
    lines = logcat["lines"]
    assert len(lines) > 0

    # Test redaction of bearer tokens and API keys in logs
    raw_joined = "\n".join(lines)
    assert "secret_token_12345" not in raw_joined
    assert "abcdef1234567890" not in raw_joined
    assert "[REDACTED]" in raw_joined


def test_memory_dumps(tmp_path: Path) -> None:
    """Verify runtime memory dumping for DEX bytecode, native shared objects, and heap HPROF."""
    manager = DeviceManager()
    manager.lease_device(project_id="proj-1", device_id="emulator-5554")

    dumps_dir = tmp_path / "dumps"

    # 1. Dump DEX
    dex_dumps = manager.dump_dex(
        project_id="proj-1",
        device_id="emulator-5554",
        package_name="com.example.app",
        output_dir=dumps_dir,
    )
    assert len(dex_dumps) == 1
    assert dex_dumps[0].kind == DumpArtifactKind.DEX
    assert Path(dex_dumps[0].stored_path).is_file()
    assert Path(dex_dumps[0].stored_path).read_bytes().startswith(b"dex\n035\x00")

    # 2. Dump Native
    native_dumps = manager.dump_native(
        project_id="proj-1",
        device_id="emulator-5554",
        package_name="com.example.app",
        output_dir=dumps_dir,
        library_name="libcrypto.so",
    )
    assert len(native_dumps) == 1
    assert native_dumps[0].kind == DumpArtifactKind.NATIVE_SO
    assert Path(native_dumps[0].stored_path).is_file()
    assert Path(native_dumps[0].stored_path).read_bytes().startswith(b"\x7fELF")

    # 3. Dump Heap
    heap_dump = manager.dump_heap(
        project_id="proj-1",
        device_id="emulator-5554",
        package_name="com.example.app",
        output_dir=dumps_dir,
    )
    assert heap_dump.kind == DumpArtifactKind.HEAP
    assert Path(heap_dump.stored_path).is_file()
    assert Path(heap_dump.stored_path).read_bytes().startswith(b"JAVA PROFILE")


def test_reproducible_manifest(tmp_path: Path) -> None:
    """Verify reproducible DynamicSessionManifest creation and schema validation."""
    manager = DeviceManager()
    manager.lease_device(project_id="proj-1", device_id="emulator-5554")

    session = manager.start_instrumentation(
        project_id="proj-1",
        device_id="emulator-5554",
        package_name="com.example.app",
        hook_ids=["crypto.cipher", "anti_analysis.root_detection"],
    )
    manager.dump_dex("proj-1", "emulator-5554", "com.example.app", tmp_path)
    manager.stop_instrumentation("proj-1", session.session_id)

    manifest = manager.generate_manifest(session.session_id)
    assert manifest.session_id == session.session_id
    assert manifest.project_id == "proj-1"
    assert manifest.package_name == "com.example.app"
    assert "crypto.cipher" in manifest.hooks_applied
    assert manifest.events_recorded > 0
    assert len(manifest.dumps_created) >= 1
    assert len(manifest.anti_analysis_findings) >= 1
    assert manifest.redaction_applied is True
    assert manifest.reproducible_config["abi"] == "arm64-v8a"

    # Verify JSON serialization and round-trip
    serialized = manifest.model_dump_json()
    reloaded = DynamicSessionManifest.model_validate_json(serialized)
    assert reloaded.session_id == manifest.session_id


async def test_dynamic_mcp_tools_and_fail_closed_policies(runtime: Runtime) -> None:
    """Verify MCP tools dispatching, fail-closed policy checks, and evidence recording."""
    # 1. Project without dynamic scopes
    no_dynamic_proj = await runtime.invoke(
        "project_create",
        {"name": "Restricted Project", "scopes": ["project.read", "project.write"]},
    )
    pid_restricted = no_dynamic_proj.data["id"]

    # Invoking device_lease without dynamic.device must fail with PolicyDeniedError
    with pytest.raises(PolicyDeniedError):
        await runtime.invoke(
            "device_lease",
            {"project_id": pid_restricted, "device_id": "emulator-5554"},
            profile="dynamic",
        )

    # 2. Project with granted dynamic scopes
    dynamic_proj = await runtime.invoke(
        "project_create",
        {
            "name": "Dynamic Analysis Project",
            "scopes": [
                "project.read",
                "project.write",
                "dynamic.device",
                "dynamic.instrument",
                "android.install",
            ],
        },
    )
    pid = dynamic_proj.data["id"]

    # 1. device_list (public scope)
    dev_list = await runtime.invoke("device_list", {}, profile="dynamic")
    assert dev_list.data["total"] == 3

    # 2. device_lease
    lease_res = await runtime.invoke(
        "device_lease",
        {"project_id": pid, "device_id": "emulator-5554", "duration_seconds": 3600},
        profile="dynamic",
    )
    assert lease_res.data["active"] is True
    assert lease_res.data["device_id"] == "emulator-5554"

    # 3. device_snapshot
    snap_res = await runtime.invoke(
        "device_snapshot",
        {"project_id": pid, "device_id": "emulator-5554", "name": "snap1", "action": "create"},
        profile="dynamic",
    )
    assert snap_res.data["created"] is True

    # 4. app_install
    install_res = await runtime.invoke(
        "app_install",
        {"project_id": pid, "device_id": "emulator-5554", "package_name": "com.target.app"},
        profile="dynamic",
    )
    assert install_res.data["installed"] is True

    # 5. app_launch
    launch_res = await runtime.invoke(
        "app_launch",
        {"project_id": pid, "device_id": "emulator-5554", "package_name": "com.target.app"},
        profile="dynamic",
    )
    assert launch_res.data["running"] is True

    # 6. app_stop
    stop_res = await runtime.invoke(
        "app_stop",
        {"project_id": pid, "device_id": "emulator-5554", "package_name": "com.target.app"},
        profile="dynamic",
    )
    assert stop_res.data["running"] is False

    # 7. instrument_start
    inst_res = await runtime.invoke(
        "instrument_start",
        {
            "project_id": pid,
            "device_id": "emulator-5554",
            "package_name": "com.target.app",
            "hook_ids": ["crypto.cipher", "network.http", "anti_analysis.root_detection"],
        },
        profile="dynamic",
    )
    sid = inst_res.data["session_id"]
    assert inst_res.data["active"] is True

    # 8. runtime_get_events
    events_res = await runtime.invoke(
        "runtime_get_events",
        {"project_id": pid, "session_id": sid, "limit": 10},
        profile="dynamic",
    )
    assert events_res.data["total"] > 0

    # 9. runtime_get_logcat
    logcat_res = await runtime.invoke(
        "runtime_get_logcat",
        {"project_id": pid, "device_id": "emulator-5554", "limit": 10},
        profile="dynamic",
    )
    assert len(logcat_res.data["lines"]) > 0

    # 10. dump_dex
    dex_res = await runtime.invoke(
        "dump_dex",
        {"project_id": pid, "device_id": "emulator-5554", "package_name": "com.target.app"},
        profile="dynamic",
    )
    assert dex_res.data["count"] == 1

    # 11. dump_native
    native_res = await runtime.invoke(
        "dump_native",
        {
            "project_id": pid,
            "device_id": "emulator-5554",
            "package_name": "com.target.app",
            "library_name": "libnative.so",
        },
        profile="dynamic",
    )
    assert native_res.data["count"] == 1

    # 12. dump_heap
    heap_res = await runtime.invoke(
        "dump_heap",
        {"project_id": pid, "device_id": "emulator-5554", "package_name": "com.target.app"},
        profile="dynamic",
    )
    assert heap_res.data["kind"] == "heap"

    # 13. instrument_stop
    stop_inst_res = await runtime.invoke(
        "instrument_stop",
        {"project_id": pid, "session_id": sid},
        profile="dynamic",
    )
    assert stop_inst_res.data["active"] is False

    # 14. device_release
    rel_res = await runtime.invoke(
        "device_release",
        {"project_id": pid, "device_id": "emulator-5554"},
        profile="dynamic",
    )
    assert rel_res.data["reset_to_clean"] is True


def test_cli_device_and_dynamic_commands(tmp_path: Path) -> None:
    """Verify Typer CLI device and dynamic command trees."""
    ws = tmp_path / "cli_workspace"

    # Init workspace
    init_res = runner.invoke(app, ["--workspace", str(ws), "init"])
    assert init_res.exit_code == 0

    # Create project with dynamic scopes
    proj_res = runner.invoke(
        app,
        [
            "--workspace",
            str(ws),
            "--json",
            "project",
            "create",
            "CLI Dynamic Project",
            "--scope",
            "project.read",
            "--scope",
            "project.write",
            "--scope",
            "dynamic.device",
            "--scope",
            "dynamic.instrument",
            "--scope",
            "android.install",
        ],
    )
    assert proj_res.exit_code == 0
    pid = json.loads(proj_res.output)["data"]["id"]

    # device list
    list_res = runner.invoke(
        app,
        ["--workspace", str(ws), "--json", "device", "list"],
    )
    assert list_res.exit_code == 0
    assert json.loads(list_res.output)["data"]["total"] == 3

    # device lease
    lease_res = runner.invoke(
        app,
        ["--workspace", str(ws), "--json", "device", "lease", pid, "emulator-5554"],
    )
    assert lease_res.exit_code == 0
    assert json.loads(lease_res.output)["data"]["active"] is True

    # device snapshot
    snap_res = runner.invoke(
        app,
        ["--workspace", str(ws), "--json", "device", "snapshot", pid, "emulator-5554", "cli_snap"],
    )
    assert snap_res.exit_code == 0

    # dynamic install
    install_res = runner.invoke(
        app,
        [
            "--workspace",
            str(ws),
            "--json",
            "dynamic",
            "install",
            pid,
            "emulator-5554",
            "--package",
            "com.cli.app",
        ],
    )
    assert install_res.exit_code == 0

    # dynamic launch
    launch_res = runner.invoke(
        app,
        [
            "--workspace",
            str(ws),
            "--json",
            "dynamic",
            "launch",
            pid,
            "emulator-5554",
            "com.cli.app",
        ],
    )
    assert launch_res.exit_code == 0

    # dynamic stop
    stop_res = runner.invoke(
        app,
        ["--workspace", str(ws), "--json", "dynamic", "stop", pid, "emulator-5554", "com.cli.app"],
    )
    assert stop_res.exit_code == 0

    # dynamic instrument-start
    inst_res = runner.invoke(
        app,
        [
            "--workspace",
            str(ws),
            "--json",
            "dynamic",
            "instrument-start",
            pid,
            "emulator-5554",
            "com.cli.app",
            "--hook",
            "crypto.cipher",
        ],
    )
    assert inst_res.exit_code == 0
    sid = json.loads(inst_res.output)["data"]["session_id"]

    # dynamic events
    events_res = runner.invoke(
        app,
        ["--workspace", str(ws), "--json", "dynamic", "events", pid, sid],
    )
    assert events_res.exit_code == 0

    # dynamic logcat
    logcat_res = runner.invoke(
        app,
        ["--workspace", str(ws), "--json", "dynamic", "logcat", pid, "emulator-5554"],
    )
    assert logcat_res.exit_code == 0

    # dynamic dump-dex
    dex_res = runner.invoke(
        app,
        [
            "--workspace",
            str(ws),
            "--json",
            "dynamic",
            "dump-dex",
            pid,
            "emulator-5554",
            "com.cli.app",
        ],
    )
    assert dex_res.exit_code == 0

    # dynamic dump-native
    native_res = runner.invoke(
        app,
        [
            "--workspace",
            str(ws),
            "--json",
            "dynamic",
            "dump-native",
            pid,
            "emulator-5554",
            "com.cli.app",
        ],
    )
    assert native_res.exit_code == 0

    # dynamic dump-heap
    heap_res = runner.invoke(
        app,
        [
            "--workspace",
            str(ws),
            "--json",
            "dynamic",
            "dump-heap",
            pid,
            "emulator-5554",
            "com.cli.app",
        ],
    )
    assert heap_res.exit_code == 0

    # dynamic instrument-stop
    stop_inst_res = runner.invoke(
        app,
        ["--workspace", str(ws), "--json", "dynamic", "instrument-stop", pid, sid],
    )
    assert stop_inst_res.exit_code == 0

    # device release
    rel_res = runner.invoke(
        app,
        ["--workspace", str(ws), "--json", "device", "release", pid, "emulator-5554"],
    )
    assert rel_res.exit_code == 0
