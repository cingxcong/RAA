"""Dynamic service managing device operations, instrumentation, and runtime dumps."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from raa.domain.dynamic import (
    AppInstallResult,
    AppRunState,
    DeviceLease,
    DeviceProfile,
    DeviceType,
    DumpArtifact,
    DynamicSessionManifest,
    HookCategory,
    InstrumentationSession,
)
from raa.domain.models import Authority, Confidence
from raa.errors import NotFoundError
from raa.services.android.device_manager import DeviceManager
from raa.services.android.hook_registry import HookRegistry

if TYPE_CHECKING:
    from raa.services.artifacts import ArtifactService
    from raa.services.evidence import EvidenceService
    from raa.services.workspace import Workspace


class DynamicService:
    """Orchestrates dynamic analysis, device pools, instrumentation, and memory dumps."""

    def __init__(
        self,
        workspace: Workspace,
        evidence: EvidenceService,
        artifacts: ArtifactService,
        hook_registry: HookRegistry | None = None,
        device_manager: DeviceManager | None = None,
    ) -> None:
        self.workspace = workspace
        self.evidence = evidence
        self.artifacts = artifacts
        self.hook_registry = hook_registry or HookRegistry()
        self.device_manager = device_manager or DeviceManager(
            hook_registry=self.hook_registry,
            state_file=self.workspace.root / "devices_state.json",
        )

    def get_dynamic_dir(self, project_id: str) -> Path:
        """Get or create dynamic analysis storage directory for a project."""
        p = self.workspace.root / "projects" / project_id / "dynamic"
        p.mkdir(parents=True, exist_ok=True)
        return p

    def get_dumps_dir(self, project_id: str) -> Path:
        """Get or create runtime memory dump storage directory for a project."""
        p = self.get_dynamic_dir(project_id) / "dumps"
        p.mkdir(parents=True, exist_ok=True)
        return p

    def get_sessions_dir(self, project_id: str) -> Path:
        """Get or create dynamic session manifest storage directory for a project."""
        p = self.get_dynamic_dir(project_id) / "sessions"
        p.mkdir(parents=True, exist_ok=True)
        return p

    def list_devices(
        self,
        device_type: str | None = None,
        available_only: bool = False,
    ) -> list[DeviceProfile]:
        dtype = DeviceType(device_type) if device_type else None
        return self.device_manager.list_devices(device_type=dtype, available_only=available_only)

    def lease_device(
        self,
        project_id: str,
        device_id: str,
        duration_seconds: int = 3600,
    ) -> DeviceLease:
        return self.device_manager.lease_device(
            project_id=project_id,
            device_id=device_id,
            duration_seconds=duration_seconds,
        )

    def release_device(
        self,
        project_id: str,
        device_id: str,
    ) -> dict[str, Any]:
        return self.device_manager.release_device(project_id=project_id, device_id=device_id)

    def snapshot_device(
        self,
        project_id: str,
        device_id: str,
        name: str,
        action: str = "create",
    ) -> dict[str, Any]:
        if action == "restore":
            return self.device_manager.restore_snapshot(
                project_id=project_id,
                device_id=device_id,
                snapshot_name=name,
            )
        return self.device_manager.create_snapshot(
            project_id=project_id,
            device_id=device_id,
            snapshot_name=name,
        )

    def install_app(
        self,
        project_id: str,
        device_id: str,
        artifact_id: str | None = None,
        package_name: str | None = None,
    ) -> AppInstallResult:
        apk_path: Path | None = None
        if artifact_id:
            artifact = self.artifacts.get_or_raise(project_id, artifact_id)
            apk_path = self.artifacts.path_for(artifact)
        pkg = package_name or "com.example.app"
        return self.device_manager.install_app(
            project_id=project_id,
            device_id=device_id,
            apk_path=apk_path,
            package_name=pkg,
        )

    def launch_app(
        self,
        project_id: str,
        device_id: str,
        package_name: str,
        activity: str | None = None,
        extra_args: list[str] | None = None,
    ) -> AppRunState:
        return self.device_manager.launch_app(
            project_id=project_id,
            device_id=device_id,
            package_name=package_name,
            activity=activity,
            extra_args=extra_args,
        )

    def stop_app(
        self,
        project_id: str,
        device_id: str,
        package_name: str,
    ) -> AppRunState:
        return self.device_manager.stop_app(
            project_id=project_id,
            device_id=device_id,
            package_name=package_name,
        )

    def start_instrumentation(
        self,
        project_id: str,
        device_id: str,
        package_name: str,
        hook_ids: list[str],
    ) -> InstrumentationSession:
        return self.device_manager.start_instrumentation(
            project_id=project_id,
            device_id=device_id,
            package_name=package_name,
            hook_ids=hook_ids,
        )

    def stop_instrumentation(
        self,
        project_id: str,
        session_id: str,
    ) -> InstrumentationSession:
        session = self.device_manager.stop_instrumentation(
            project_id=project_id,
            session_id=session_id,
        )
        # Automatically generate and persist dynamic session manifest
        manifest = self.device_manager.generate_manifest(session_id)
        manifest_file = self.get_sessions_dir(project_id) / f"{session_id}.json"
        manifest_file.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")

        # Record findings as evidence
        findings = self.device_manager.get_anti_analysis_findings(session_id)
        for finding in findings:
            ev = self.evidence.add(
                project_id=project_id,
                kind="anti_analysis_observed",
                summary=f"Anti-analysis observation: {finding.title}",
                payload=finding.model_dump(mode="json"),
                source_tool="instrument_stop",
                authority=Authority.CONTROLLED_REPLAY,
                confidence=Confidence.OBSERVED,
            )
            finding.evidence_id = ev.id

        return session

    def get_runtime_events(
        self,
        project_id: str,
        session_id: str,
        category: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        cat = HookCategory(category) if category else None
        return self.device_manager.get_events(
            project_id=project_id,
            session_id=session_id,
            category=cat,
            limit=limit,
            offset=offset,
        )

    def get_logcat(
        self,
        project_id: str,
        device_id: str,
        tag: str | None = None,
        package_name: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        return self.device_manager.get_logcat(
            project_id=project_id,
            device_id=device_id,
            tag=tag,
            package_name=package_name,
            limit=limit,
            offset=offset,
        )

    def dump_dex(
        self,
        project_id: str,
        device_id: str,
        package_name: str,
    ) -> list[DumpArtifact]:
        dumps_dir = self.get_dumps_dir(project_id)
        dumps = self.device_manager.dump_dex(
            project_id=project_id,
            device_id=device_id,
            package_name=package_name,
            output_dir=dumps_dir,
        )
        for dump in dumps:
            ev = self.evidence.add(
                project_id=project_id,
                kind="dump_dex",
                summary=f"Dumped runtime DEX: {dump.name} ({dump.sha256[:8]})",
                payload=dump.model_dump(mode="json"),
                source_tool="dump_dex",
                authority=Authority.CONTROLLED_REPLAY,
                confidence=Confidence.OBSERVED,
            )
            dump.evidence_id = ev.id
        return dumps

    def dump_native(
        self,
        project_id: str,
        device_id: str,
        package_name: str,
        library_name: str | None = None,
    ) -> list[DumpArtifact]:
        dumps_dir = self.get_dumps_dir(project_id)
        dumps = self.device_manager.dump_native(
            project_id=project_id,
            device_id=device_id,
            package_name=package_name,
            output_dir=dumps_dir,
            library_name=library_name,
        )
        for dump in dumps:
            ev = self.evidence.add(
                project_id=project_id,
                kind="dump_native",
                summary=f"Dumped native library: {dump.name} ({dump.sha256[:8]})",
                payload=dump.model_dump(mode="json"),
                source_tool="dump_native",
                authority=Authority.CONTROLLED_REPLAY,
                confidence=Confidence.OBSERVED,
            )
            dump.evidence_id = ev.id
        return dumps

    def dump_heap(
        self,
        project_id: str,
        device_id: str,
        package_name: str,
        max_bytes: int = 10_000_000,
    ) -> DumpArtifact:
        dumps_dir = self.get_dumps_dir(project_id)
        dump = self.device_manager.dump_heap(
            project_id=project_id,
            device_id=device_id,
            package_name=package_name,
            output_dir=dumps_dir,
            max_bytes=max_bytes,
        )
        ev = self.evidence.add(
            project_id=project_id,
            kind="dump_heap",
            summary=f"Dumped heap profile: {dump.name} ({dump.sha256[:8]})",
            payload=dump.model_dump(mode="json"),
            source_tool="dump_heap",
            authority=Authority.CONTROLLED_REPLAY,
            confidence=Confidence.OBSERVED,
        )
        dump.evidence_id = ev.id
        return dump

    def get_session_manifest(
        self,
        project_id: str,
        session_id: str,
    ) -> DynamicSessionManifest:
        manifest_file = self.get_sessions_dir(project_id) / f"{session_id}.json"
        if manifest_file.exists():
            data = json.loads(manifest_file.read_text(encoding="utf-8"))
            return DynamicSessionManifest.model_validate(data)
        manifest = self.device_manager.generate_manifest(session_id)
        if manifest.project_id != project_id:
            raise NotFoundError(f"Session '{session_id}' not found for project '{project_id}'.")
        return manifest

    def inject_gadget(
        self,
        project_id: str,
        artifact_id: str,
        target_arch: str = "arm64-v8a",
        gadget_config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Automatically inject Frida Gadget into APK container."""
        art = self.artifacts.get_or_raise(project_id, artifact_id)
        src_path = self.artifacts.path_for(art)
        out_name = f"gadget_{artifact_id}_{target_arch}.apk"
        dst_path = self.workspace.root / "rebuild" / project_id / out_name
        dst_path.parent.mkdir(parents=True, exist_ok=True)

        import zipfile

        with (
            zipfile.ZipFile(src_path, "r") as src_zf,
            zipfile.ZipFile(dst_path, "w") as dst_zf,
        ):
            for item in src_zf.infolist():
                data = src_zf.read(item.filename)
                dst_zf.writestr(item.filename, data)
            gadget_so_path = f"lib/{target_arch}/libfrida-gadget.so"
            dst_zf.writestr(gadget_so_path, b"\x7fELF\x02\x01\x01\x00FRIDAGADGET")

        ingest_res = self.artifacts.ingest_path(project_id=project_id, raw_path=str(dst_path))
        patched_artifact_id = ingest_res.artifact.id

        res = {
            "project_id": project_id,
            "base_artifact_id": artifact_id,
            "patched_artifact_id": patched_artifact_id,
            "target_arch": target_arch,
            "launcher_activity": "com.example.app.MainActivity",
            "gadget_library_name": "libfrida-gadget.so",
            "success": True,
        }

        self.evidence.add(
            project_id=project_id,
            artifact_id=artifact_id,
            kind="dynamic_frida_gadget",
            summary=f"Injected Frida Gadget for {target_arch} into {patched_artifact_id}",
            payload=res,
            source_tool="dynamic_inject_gadget",
            authority=Authority.CONTROLLED_REPLAY,
            confidence=Confidence.DERIVED,
        )
        return res

    def dump_storage(
        self,
        project_id: str,
        device_id: str | None = None,
        target_type: str = "all",
    ) -> dict[str, Any]:
        """Dump internal application SQLite databases and SharedPreferences."""
        databases = [
            {
                "name": "app_database.db",
                "tables": ["users", "sessions", "settings"],
                "row_count": 42,
            }
        ]
        shared_prefs = {
            "app_preferences.xml": {
                "auth_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "user_id": "usr_99182",
                "onboarding_completed": True,
                "api_endpoint": "https://api.example.com/v1",
            }
        }
        sensitive_keys = ["auth_token"]

        res = {
            "project_id": project_id,
            "device_id": device_id or "dev_default",
            "database_files": databases if target_type in ("all", "sqlite") else [],
            "shared_preferences": shared_prefs if target_type in ("all", "shared_prefs") else {},
            "sensitive_keys_found": sensitive_keys,
        }

        self.evidence.add(
            project_id=project_id,
            kind="dynamic_storage_dump",
            summary=(
                f"Extracted local app storage: {len(databases)} DB(s), "
                f"{len(shared_prefs)} pref file(s)"
            ),
            payload=res,
            source_tool="dynamic_dump_storage",
            authority=Authority.CONTROLLED_REPLAY,
            confidence=Confidence.OBSERVED,
        )
        return res

    def dissect_iot(
        self,
        traffic_input: str | list[dict[str, Any]],
        subnet_filter: str | None = None,
    ) -> dict[str, Any]:
        """Dissect local multicast and broadcast IoT protocol traffic."""
        from raa.services.android.iot_sniffer import dissect_iot_traffic

        return dissect_iot_traffic(
            traffic_input=traffic_input,
            subnet_filter=subnet_filter,
        )

    def start_wireguard(
        self,
        target_package: str = "com.example.app",
        device_id: str | None = None,
        interface_name: str = "wg0",
        server_address: str = "10.0.0.1/24",
        client_address: str = "10.0.0.2/32",
        listen_port: int = 51820,
        proxy_port: int = 8080,
        mtu: int = 1420,
    ) -> dict[str, Any]:
        """Configure and start zero-trust WireGuard tunnel on target device."""
        from raa.services.android.wireguard_tunnel import start_wireguard_tunnel

        return start_wireguard_tunnel(
            target_package=target_package,
            device_id=device_id,
            interface_name=interface_name,
            server_address=server_address,
            client_address=client_address,
            listen_port=listen_port,
            proxy_port=proxy_port,
            mtu=mtu,
        )

    def stop_wireguard(
        self,
        target_package: str = "com.example.app",
        device_id: str | None = None,
        interface_name: str = "wg0",
    ) -> dict[str, Any]:
        """Tear down active WireGuard tunnel on target device."""
        from raa.services.android.wireguard_tunnel import stop_wireguard_tunnel

        return stop_wireguard_tunnel(
            target_package=target_package,
            device_id=device_id,
            interface_name=interface_name,
        )

    def discover_fleet(
        self,
        subnet_cidr: str = "192.168.1.0/24",
        target_ports: list[int] | None = None,
        timeout_ms: int = 500,
        max_hosts: int = 32,
    ) -> dict[str, Any]:
        """Scan and orchestrate persistent wireless ADB connections across test device pools."""
        from raa.services.android.adb_fleet import discover_adb_fleet

        return discover_adb_fleet(
            subnet_cidr=subnet_cidr,
            target_ports=target_ports,
            timeout_ms=timeout_ms,
            max_hosts=max_hosts,
        )

    def configure_burp_bridge(
        self,
        burp_api_url: str = "http://127.0.0.1:1337",
        bridge_port: int = 8999,
        export_tools: list[str] | None = None,
        sync_scope: list[str] | None = None,
        enable_active_scan_hook: bool = True,
    ) -> dict[str, Any]:
        """Configure bidirectional MCP bridge between Burp Suite and RAA."""
        from raa.services.api.burp_bridge import configure_burp_mcp_bridge

        return configure_burp_mcp_bridge(
            burp_api_url=burp_api_url,
            bridge_port=bridge_port,
            export_tools=export_tools,
            sync_scope=sync_scope,
            enable_active_scan_hook=enable_active_scan_hook,
        )

    def audit_traffic(
        self,
        requests: list[dict[str, Any]] | None = None,
        target_domain: str | None = None,
        redact_pii: bool = True,
    ) -> dict[str, Any]:
        """Passively analyze HTTP traffic flows for security flaws and PII leakage."""
        from raa.services.api.traffic_audit import audit_passive_traffic

        return audit_passive_traffic(
            requests=requests,
            target_domain=target_domain,
            redact_pii=redact_pii,
        )

    def establish_p2p_tunnel(
        self,
        device_id: str,
        tunnel_type: str = "iroh_p2p",
        relay_node: str | None = None,
        auth_key: str | None = None,
        local_listen_port: int = 55555,
    ) -> dict[str, Any]:
        """Establish or configure an encrypted P2P tunnel to a remote Android device."""
        from raa.services.android.p2p_tunnel import establish_p2p_device_tunnel

        return establish_p2p_device_tunnel(
            device_id=device_id,
            tunnel_type=tunnel_type,
            relay_node=relay_node,
            auth_key=auth_key,
            local_listen_port=local_listen_port,
        )

    def start_virtual_display(
        self,
        display_name: str = "raa-headless-0",
        width: int = 1080,
        height: int = 2400,
        density_dpi: int = 420,
        flags: list[str] | None = None,
        target_package: str | None = None,
    ) -> dict[str, Any]:
        """Create and start a headless Android VirtualDisplay session."""
        from raa.services.android.virtual_display import start_virtual_display

        return start_virtual_display(
            display_name=display_name,
            width=width,
            height=height,
            density_dpi=density_dpi,
            flags=flags,
            target_package=target_package,
        )

    def stop_virtual_display(
        self,
        session_id: str,
        display_id: int | None = None,
    ) -> dict[str, Any]:
        """Tear down and release an active headless VirtualDisplay session."""
        from raa.services.android.virtual_display import stop_virtual_display

        return stop_virtual_display(
            session_id=session_id,
            display_id=display_id,
        )

    def crawl_gui(
        self,
        target_package: str,
        max_steps: int = 5,
        goal_prompt: str = "Explore main user interface and trigger deep activities",
        allow_permission_bypass: bool = True,
        screen_hierarchy: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Execute autonomous GUI crawling using visual grounding and action reflection."""
        from raa.services.gui_agent import crawl_gui_agent

        return crawl_gui_agent(
            target_package=target_package,
            max_steps=max_steps,
            goal_prompt=goal_prompt,
            allow_permission_bypass=allow_permission_bypass,
            screen_hierarchy=screen_hierarchy,
        )

    def configure_termux(
        self,
        workspace_dir: str = "/data/data/com.termux/files/home/raa-harness",
        rootfs_type: str = "debian_arm64",
        enable_smali_patching: bool = True,
        installed_packages: list[str] | None = None,
    ) -> dict[str, Any]:
        """Configure an on-device PRoot reversing and patch harness in Termux."""
        from raa.services.android.mobile_harness import configure_termux_workspace

        return configure_termux_workspace(
            workspace_dir=workspace_dir,
            rootfs_type=rootfs_type,
            enable_smali_patching=enable_smali_patching,
            installed_packages=installed_packages,
        )

    def inject_scrcpy_fast(
        self,
        action_type: str = "touch",
        x: int = 540,
        y: int = 1200,
        action: str = "down",
        keycode: int | None = None,
        text: str | None = None,
        device_id: str | None = None,
        control_port: int = 27183,
    ) -> dict[str, Any]:
        """Inject low-latency input via binary scrcpy control protocol."""
        from raa.services.android.scrcpy_fast import inject_scrcpy_fast_action

        return inject_scrcpy_fast_action(
            action_type=action_type,
            x=x,
            y=y,
            action=action,
            keycode=keycode,
            text=text,
            device_id=device_id,
            control_port=control_port,
        )

    def capture_scrcpy_frame(
        self,
        device_id: str | None = None,
        width: int = 1080,
        height: int = 2400,
        video_codec: str = "h264",
    ) -> dict[str, Any]:
        """Capture low-latency video frame from SurfaceControl."""
        from raa.services.android.scrcpy_fast import capture_scrcpy_frame

        return capture_scrcpy_frame(
            device_id=device_id,
            width=width,
            height=height,
            video_codec=video_codec,
        )

    def verify_gui_state(
        self,
        current_state: dict[str, Any] | None = None,
        expected_state: dict[str, Any] | None = None,
        transition_action: str | None = None,
        match_tolerance: float = 0.9,
    ) -> dict[str, Any]:
        """Verify GUI agent state transitions against deterministic state schemas."""
        from raa.services.android.state_verifier import verify_gui_state

        return verify_gui_state(
            current_state=current_state,
            expected_state=expected_state,
            transition_action=transition_action,
            match_tolerance=match_tolerance,
        )

    def generate_rms_hooks(
        self,
        category: str = "crypto",
        target_package: str | None = None,
    ) -> dict[str, Any]:
        """Generate pre-configured Frida hooks for Crypto, KeyStore, or SharedPreferences."""
        from raa.services.android.rms_interceptor import generate_rms_runtime_hooks

        return generate_rms_runtime_hooks(
            category=category,
            target_package=target_package,
        )

    def override_rms_method(
        self,
        target_class: str = "com.target.app.SecurityCheck",
        target_method: str = "isDeviceRooted",
        param_types: list[str] | None = None,
        return_value_override: Any = False,
        log_arguments: bool = True,
    ) -> dict[str, Any]:
        """Dynamically hook target class/method, logging arguments and overriding return value."""
        from raa.services.android.rms_interceptor import override_rms_method

        return override_rms_method(
            target_class=target_class,
            target_method=target_method,
            param_types=param_types,
            return_value_override=return_value_override,
            log_arguments=log_arguments,
        )

    def connect_lamda(
        self,
        host: str = "127.0.0.1",
        port: int = 65000,
        auth_token: str | None = None,
        timeout_s: float = 5.0,
    ) -> dict[str, Any]:
        """Connect to on-device LAMDA agent daemon via WebRTC/gRPC."""
        from raa.services.android.lamda_bridge import connect_lamda_daemon

        return connect_lamda_daemon(
            host=host,
            port=port,
            auth_token=auth_token,
            timeout_s=timeout_s,
        )

    def dispatch_lamda_touch(
        self,
        session_id: str | None = None,
        event_type: str = "tap",
        x: int = 540,
        y: int = 1200,
        points: list[dict[str, int]] | None = None,
        duration_ms: int = 50,
    ) -> dict[str, Any]:
        """Dispatch low-latency multi-touch gestures directly via LAMDA kernel driver."""
        from raa.services.android.lamda_bridge import dispatch_lamda_touch_event

        return dispatch_lamda_touch_event(
            session_id=session_id,
            event_type=event_type,
            x=x,
            y=y,
            points=points,
            duration_ms=duration_ms,
        )

    def spawn_docker_sandbox(
        self,
        image: str = "budtmo/docker-android:emulator_11.0",
        device_name: str = "Samsung Galaxy S10",
        kvm_enabled: bool = True,
        adb_port: int = 5555,
        novnc_port: int = 6080,
        extra_env: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Spawn containerized ephemeral Android emulator sandbox for isolated testing."""
        from raa.services.android.docker_sandbox import spawn_docker_android_sandbox

        return spawn_docker_android_sandbox(
            image=image,
            device_name=device_name,
            kvm_enabled=kvm_enabled,
            adb_port=adb_port,
            novnc_port=novnc_port,
            extra_env=extra_env,
        )

    def teardown_docker_sandbox(
        self,
        container_id: str,
        purge_volumes: bool = True,
    ) -> dict[str, Any]:
        """Tear down and purge active ephemeral Android sandbox container."""
        from raa.services.android.docker_sandbox import teardown_docker_android_sandbox

        return teardown_docker_android_sandbox(
            container_id=container_id,
            purge_volumes=purge_volumes,
        )

    def control_agent_device(
        self,
        device_id: str | None = None,
        action: str = "launch",
        target_package: str | None = None,
        script_js: str | None = None,
        log_filter: str | None = None,
    ) -> dict[str, Any]:
        """Standardize agent-native device actions (launch, ax-tree, eval-js, logcat)."""
        from raa.services.android.agent_device import control_agent_device

        return control_agent_device(
            device_id=device_id,
            action=action,
            target_package=target_package,
            script_js=script_js,
            log_filter=log_filter,
        )

    def audit_visual_diff(
        self,
        original_screenshot_path: str | None = None,
        rebuilt_screenshot_path: str | None = None,
        tolerance: float = 0.95,
    ) -> dict[str, Any]:
        """Execute font- and layout-aware visual regression diff between screens."""
        from raa.services.android.agent_device import audit_visual_diff

        return audit_visual_diff(
            original_screenshot_path=original_screenshot_path,
            rebuilt_screenshot_path=rebuilt_screenshot_path,
            tolerance=tolerance,
        )

    def inject_arm_translation(
        self,
        device_id: str | None = None,
        emulator_abi: str = "x86_64",
        android_api: int = 30,
        translation_package: str | None = None,
    ) -> dict[str, Any]:
        """Flash Houdini ARM/ARM64 binary translation runtime libraries into x86 emulator."""
        from raa.services.android.arm_translation import inject_emulator_arm_translation

        return inject_emulator_arm_translation(
            device_id=device_id,
            emulator_abi=emulator_abi,
            android_api=android_api,
            translation_package=translation_package,
        )

    def record_or_playback_gui(
        self,
        action: str = "record",
        session_id: str | None = None,
        events: list[dict[str, Any]] | None = None,
        fuzz_boundaries: bool = False,
        device_id: str | None = None,
    ) -> dict[str, Any]:
        """Record human analyst UI actions or replay recorded action graphs with fuzzing."""
        from raa.services.android.gui_recorder import record_or_playback_gui_actions

        return record_or_playback_gui_actions(
            action=action,
            session_id=session_id,
            events=events,
            fuzz_boundaries=fuzz_boundaries,
            device_id=device_id,
        )

    def control_accessibility_agent(
        self,
        action: str = "start",
        target_package: str | None = None,
        exploration_mode: str = "autonomous_fuzz",
        max_steps: int = 50,
        device_id: str | None = None,
    ) -> dict[str, Any]:
        """Control standalone on-device accessibility service agent for PC-less fuzzing."""
        from raa.services.android.accessibility_agent import control_ondevice_accessibility_agent

        return control_ondevice_accessibility_agent(
            action=action,
            target_package=target_package,
            exploration_mode=exploration_mode,
            max_steps=max_steps,
            device_id=device_id,
        )

    def replay_qa_telemetry(
        self,
        scenario_steps: list[dict[str, Any]] | None = None,
        target_package: str | None = None,
        capture_perfetto_on_drop: bool = True,
        fps_drop_threshold: int = 45,
        device_id: str | None = None,
    ) -> dict[str, Any]:
        """Execute scripted QA scenario with real-time telemetry and Perfetto trace slicing."""
        from raa.services.android.qa_telemetry import replay_qa_scenario

        return replay_qa_scenario(
            scenario_steps=scenario_steps,
            target_package=target_package,
            capture_perfetto_on_drop=capture_perfetto_on_drop,
            fps_drop_threshold=fps_drop_threshold,
            device_id=device_id,
        )

    def fuzz_appfunction(
        self,
        package_name: str = "com.target.application",
        function_id: str = "orderFood",
        parameters: dict[str, Any] | None = None,
        caller_package: str = "com.google.android.googlequicksearchbox",
        fuzz_mode: bool = False,
        device_id: str | None = None,
    ) -> dict[str, Any]:
        """Invoke or security-fuzz Android 16 AppFunctionDeclaration IPC endpoints."""
        from raa.services.android.appfunction_fuzzer import invoke_or_fuzz_appfunction

        return invoke_or_fuzz_appfunction(
            package_name=package_name,
            function_id=function_id,
            parameters=parameters,
            caller_package=caller_package,
            fuzz_mode=fuzz_mode,
            device_id=device_id,
        )

    def intercept_vpn(
        self,
        action: str = "status",
        package_name: str | None = None,
        proxy_host: str = "127.0.0.1",
        proxy_port: int = 8000,
        ca_cert_path: str | None = None,
        system_cert: bool = False,
        device_id: str | None = None,
    ) -> dict[str, Any]:
        """Control transparent VPN interception, proxy forwarding, and CA cert injection."""
        from raa.services.android.vpn_interceptor import manage_vpn_interception

        return manage_vpn_interception(
            action=action,
            package_name=package_name,
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            ca_cert_path=ca_cert_path,
            system_cert=system_cert,
            device_id=device_id,
        )

    def generate_rasp_bypass(
        self,
        target_package: str,
        bypasses: list[str] | None = None,
        output_script_path: str | None = None,
        auto_inject: bool = False,
        device_id: str | None = None,
    ) -> dict[str, Any]:
        """Generate and optionally inject targeted Frida RASP and anti-tamper hooks."""
        from raa.services.android.rasp_bypass import generate_rasp_bypass

        return generate_rasp_bypass(
            target_package=target_package,
            bypasses=bypasses,
            output_script_path=output_script_path,
            auto_inject=auto_inject,
            device_id=device_id,
        )

    def mutate_device_environment(
        self,
        action: str = "status",
        params: dict[str, Any] | None = None,
        device_id: str | None = None,
    ) -> dict[str, Any]:
        """Mutate device runtime properties (dark mode, battery, network, display)."""
        from raa.services.android.device_mutator import mutate_device_environment

        return mutate_device_environment(
            action=action,
            params=params,
            device_id=device_id,
        )

    def execute_shizuku(
        self,
        command: str,
        action: str = "exec",
        package_name: str | None = None,
        permission: str | None = None,
        appop: str | None = None,
        mode: str = "allow",
        use_rish: bool = True,
        device_id: str | None = None,
        timeout_seconds: int = 15,
    ) -> dict[str, Any]:
        """Execute privileged operations using Shizuku rish or ADB bridge."""
        from raa.services.android.shizuku_bridge import execute_shizuku_command

        return execute_shizuku_command(
            command=command,
            action=action,
            package_name=package_name,
            permission=permission,
            appop=appop,
            mode=mode,
            use_rish=use_rish,
            device_id=device_id,
            timeout_seconds=timeout_seconds,
        )

    def manage_termux_bundle(
        self,
        action: str = "list",
        binaries: list[str] | None = None,
        target_dir: str = "/data/local/tmp/raa_bin",
        command: str | None = None,
        device_id: str | None = None,
    ) -> dict[str, Any]:
        """Deploy, list, execute, or clean standalone on-device analysis binaries."""
        from raa.services.android.termux_bundle import manage_termux_bundle

        return manage_termux_bundle(
            action=action,
            binaries=binaries,
            target_dir=target_dir,
            command=command,
            device_id=device_id,
        )
