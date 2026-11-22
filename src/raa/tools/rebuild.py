"""Test generation, controlled rebuild, APK patching, signing, and verification MCP tools."""

from __future__ import annotations

import io
from typing import Any, Literal

from pydantic import BaseModel, Field

from raa.policy.scopes import (
    ANDROID_INSTALL,
    ANDROID_PATCH,
    ANDROID_SIGN,
    DYNAMIC_DEVICE,
    PROJECT_READ,
    STATIC_READ,
)
from raa.registry.models import (
    CapabilityRegistry,
    ToolAnnotations,
    ToolContext,
    ToolOutcome,
    ToolSpec,
)
from raa.registry.profiles import CORE

# --- Input Models ---


class TestGenerateInput(BaseModel):
    """Parameters to generate automated UI or API tests from analysis evidence."""

    project_id: str = Field(min_length=1, description="Target project identifier.")
    artifact_id: str = Field(min_length=1, description="Target artifact identifier.")
    test_type: Literal["api", "ui", "integration"] = Field(
        default="api", description="Test suite type (api, ui, integration)."
    )
    framework: Literal["pytest", "appium", "espresso", "playwright"] = Field(
        default="pytest", description="Testing framework."
    )
    operations: list[dict[str, Any]] | None = Field(
        default=None, description="Optional subset of API operations to test."
    )
    screens: list[dict[str, Any]] | None = Field(
        default=None, description="Optional subset of UI screen states to test."
    )


class TestRunInput(BaseModel):
    """Parameters to execute a test suite against an authorized target environment."""

    project_id: str = Field(min_length=1, description="Target project identifier.")
    test_id: str = Field(min_length=1, description="Generated test suite identifier.")
    target_url: str | None = Field(default=None, description="Optional target base URL.")
    device_id: str | None = Field(default=None, description="Optional target leased device ID.")


class ApkPatchInput(BaseModel):
    """Parameters to plan and apply authorized modifications to an APK container."""

    project_id: str = Field(min_length=1, description="Target project identifier.")
    artifact_id: str = Field(min_length=1, description="Target base artifact identifier.")
    operation: Literal[
        "network_security_bypass",
        "set_debuggable",
        "set_allow_backup",
        "inject_frida_gadget",
        "custom_smali",
    ] = Field(description="Patch operation to apply.")
    parameters: dict[str, Any] | None = Field(
        default=None, description="Optional patch-specific parameters."
    )
    dry_run: bool = Field(
        default=True,
        description="Simulate changes without producing a new APK file (defaults to True).",
    )


class ApkSignInput(BaseModel):
    """Parameters to sign an APK container with test or project credentials."""

    project_id: str = Field(min_length=1, description="Target project identifier.")
    artifact_id: str = Field(min_length=1, description="Target artifact identifier to sign.")


class DeviceInstallInput(BaseModel):
    """Parameters to install an APK onto a leased Android device."""

    project_id: str = Field(min_length=1, description="Target project identifier.")
    device_id: str = Field(min_length=1, description="Leased target device identifier.")
    artifact_id: str = Field(min_length=1, description="Artifact identifier to install.")


class VerifyBehaviorInput(BaseModel):
    """Parameters to compare behavioral divergence between baseline and patched artifacts."""

    project_id: str = Field(min_length=1, description="Target project identifier.")
    base_artifact_id: str = Field(min_length=1, description="Original baseline artifact ID.")
    patched_artifact_id: str = Field(min_length=1, description="Patched comparison artifact ID.")
    baseline_events: list[dict[str, Any]] | None = Field(
        default=None, description="Optional baseline runtime events."
    )
    patched_events: list[dict[str, Any]] | None = Field(
        default=None, description="Optional patched runtime events."
    )


class ElfAlign16KbInput(BaseModel):
    """Parameters to audit and patch native ELF libraries for Android 15 16KB alignment."""

    project_id: str = Field(min_length=1, description="Target project identifier.")
    artifact_id: str = Field(min_length=1, description="Target APK artifact identifier.")
    patch: bool = Field(
        default=False,
        description="Whether to patch ELF headers in non-compliant .so files.",
    )


class RebuildAgentsSpecGenerateInput(BaseModel):
    """Parameters to generate standardized repository-level AGENTS.md contract."""

    project_id: str | None = Field(default=None, description="Optional target project ID.")
    project_dir: str | None = Field(
        default=None, description="Optional target repository root directory."
    )
    app_name: str = Field(default="ModernizedApp", description="Application name for guidelines.")
    output_path: str | None = Field(
        default=None, description="Optional filesystem path to save AGENTS.md."
    )


# --- Handlers ---


async def _test_generate(ctx: ToolContext, args: TestGenerateInput) -> ToolOutcome:
    report = ctx.runtime.rebuild.generate_tests(
        project_id=args.project_id,
        artifact_id=args.artifact_id,
        test_type=args.test_type,
        framework=args.framework,
        operations=args.operations,
        screens=args.screens,
    )
    return ToolOutcome(data=report.model_dump(mode="json"))


async def _test_run(ctx: ToolContext, args: TestRunInput) -> ToolOutcome:
    report = ctx.runtime.rebuild.run_tests(
        project_id=args.project_id,
        test_id=args.test_id,
        target_url=args.target_url,
        device_id=args.device_id,
    )
    return ToolOutcome(data=report.model_dump(mode="json"))


async def _apk_patch(ctx: ToolContext, args: ApkPatchInput) -> ToolOutcome:
    result = ctx.runtime.rebuild.patch_apk(
        project_id=args.project_id,
        artifact_id=args.artifact_id,
        operation=args.operation,
        parameters=args.parameters,
        dry_run=args.dry_run,
    )
    return ToolOutcome(data=result.model_dump(mode="json"))


async def _apk_sign(ctx: ToolContext, args: ApkSignInput) -> ToolOutcome:
    result = ctx.runtime.rebuild.sign_apk(
        project_id=args.project_id,
        artifact_id=args.artifact_id,
    )
    return ToolOutcome(data=result.model_dump(mode="json"))


async def _device_install(ctx: ToolContext, args: DeviceInstallInput) -> ToolOutcome:
    result = ctx.runtime.rebuild.install_device(
        project_id=args.project_id,
        device_id=args.device_id,
        artifact_id=args.artifact_id,
    )
    return ToolOutcome(data=result)


async def _verify_behavior(ctx: ToolContext, args: VerifyBehaviorInput) -> ToolOutcome:
    report = ctx.runtime.rebuild.verify_behavior(
        project_id=args.project_id,
        base_artifact_id=args.base_artifact_id,
        patched_artifact_id=args.patched_artifact_id,
        baseline_events=args.baseline_events,
        patched_events=args.patched_events,
    )
    return ToolOutcome(data=report.model_dump(mode="json"))


async def _rebuild_elf_align_16kb(ctx: ToolContext, args: ElfAlign16KbInput) -> ToolOutcome:
    from raa.services.android.elf_aligner import audit_apk_16kb_alignment, patch_elf_16kb_alignment

    art = ctx.runtime.artifacts.get_or_raise(args.project_id, args.artifact_id)
    apk_path = ctx.runtime.artifacts.path_for(art)

    audit_result = audit_apk_16kb_alignment(apk_path)
    if args.patch and audit_result["non_compliant_libraries"] > 0:
        import zipfile

        patched_data = bytearray()
        with zipfile.ZipFile(apk_path, "r") as src_zf:
            bio = io.BytesIO()
            with zipfile.ZipFile(bio, "w") as dst_zf:
                for item in src_zf.infolist():
                    content = src_zf.read(item.filename)
                    if item.filename.startswith("lib/") and item.filename.endswith(".so"):
                        content = patch_elf_16kb_alignment(content)
                    dst_zf.writestr(item, content)
            patched_data = bio.getvalue()

        patched_name = f"aligned_16kb_{args.artifact_id}.apk"
        dst_path = ctx.runtime.rebuild.get_rebuild_dir(args.project_id) / patched_name
        dst_path.write_bytes(patched_data)
        ingest_res = ctx.runtime.artifacts.ingest_path(
            project_id=args.project_id, raw_path=str(dst_path)
        )
        audit_result["patched_artifact_id"] = ingest_res.artifact.id
        audit_result["patched_apk_path"] = str(dst_path)

    return ToolOutcome(data=audit_result)


async def _rebuild_agents_spec_generate(
    ctx: ToolContext, args: RebuildAgentsSpecGenerateInput
) -> ToolOutcome:
    res = ctx.runtime.rebuild.generate_agents_contract(
        project_id=args.project_id,
        project_dir=args.project_dir,
        app_name=args.app_name,
        output_path=args.output_path,
    )
    return ToolOutcome(data=res)


# --- Helper ---


def _rebuild_spec(
    name: str,
    title: str,
    description: str,
    handler: Any,
    input_model: type[BaseModel],
    scopes: frozenset[str],
    read_only: bool = False,
    idempotent: bool = False,
    profiles: frozenset[str] = CORE,
) -> ToolSpec:
    return ToolSpec(
        name=name,
        title=title,
        description=description,
        handler=handler,
        input_model=input_model,
        family="rebuild",
        profiles=profiles,
        scopes=scopes,
        annotations=ToolAnnotations(
            read_only=read_only,
            idempotent=idempotent,
        ),
        version="0.1.0",
    )


# --- Registration ---


def register(registry: CapabilityRegistry) -> None:
    """Register all Phase 10 controlled rebuild and testing tools."""
    registry.register(
        _rebuild_spec(
            name="test_generate",
            title="Generate tests",
            description="Generate UI and API functional tests derived from analysis evidence.",
            handler=_test_generate,
            input_model=TestGenerateInput,
            scopes=frozenset({PROJECT_READ, STATIC_READ}),
            read_only=True,
            idempotent=True,
        )
    )
    registry.register(
        _rebuild_spec(
            name="test_run",
            title="Run tests",
            description="Execute generated test suites against an authorized target environment.",
            handler=_test_run,
            input_model=TestRunInput,
            scopes=frozenset({PROJECT_READ, DYNAMIC_DEVICE}),
            read_only=False,
            idempotent=False,
        )
    )
    registry.register(
        _rebuild_spec(
            name="apk_patch",
            title="Patch APK",
            description="Apply authorized patch (dry-run default) to modify container or manifest.",
            handler=_apk_patch,
            input_model=ApkPatchInput,
            scopes=frozenset({PROJECT_READ, ANDROID_PATCH}),
            read_only=False,
            idempotent=False,
        )
    )
    registry.register(
        _rebuild_spec(
            name="apk_sign",
            title="Sign APK",
            description="Sign an APK container with project test or debug key.",
            handler=_apk_sign,
            input_model=ApkSignInput,
            scopes=frozenset({PROJECT_READ, ANDROID_SIGN}),
            read_only=False,
            idempotent=False,
        )
    )
    registry.register(
        _rebuild_spec(
            name="device_install",
            title="Install on device",
            description="Install rebuilt APK onto an authorized leased device.",
            handler=_device_install,
            input_model=DeviceInstallInput,
            scopes=frozenset({PROJECT_READ, ANDROID_INSTALL, DYNAMIC_DEVICE}),
            read_only=False,
            idempotent=False,
        )
    )
    registry.register(
        _rebuild_spec(
            name="verify_behavior",
            title="Verify behavior",
            description="Compare runtime behavior before and after rebuild to detect divergence.",
            handler=_verify_behavior,
            input_model=VerifyBehaviorInput,
            scopes=frozenset({PROJECT_READ, DYNAMIC_DEVICE}),
            read_only=True,
            idempotent=True,
        )
    )
    registry.register(
        _rebuild_spec(
            name="rebuild_elf_align_16kb",
            title="ELF 16KB alignment audit and patch",
            description=(
                "Audit and patch native ELF shared libraries for Android 15 "
                "16KB memory page alignment."
            ),
            handler=_rebuild_elf_align_16kb,
            input_model=ElfAlign16KbInput,
            scopes=frozenset({PROJECT_READ, ANDROID_PATCH}),
            read_only=False,
            idempotent=False,
        )
    )
    registry.register(
        _rebuild_spec(
            name="rebuild_agents_spec_generate",
            title="Generate AGENTS.md Repository Architecture Contract",
            description=(
                "Synthesize standardized repository-level AGENTS.md contract for rebuilt and "
                "modernized APK projects for AI coding assistants."
            ),
            handler=_rebuild_agents_spec_generate,
            input_model=RebuildAgentsSpecGenerateInput,
            scopes=frozenset(),
            profiles=frozenset({"core", "full"}),
            read_only=True,
            idempotent=True,
        )
    )
