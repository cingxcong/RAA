"""Platform, lifecycle and policy tools."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from raa.policy.scopes import ALL_SCOPES, DANGEROUS_SCOPES, DEFAULT_PROJECT_SCOPES
from raa.registry.models import (
    CapabilityRegistry,
    ToolAnnotations,
    ToolContext,
    ToolInput,
    ToolOutcome,
    ToolSpec,
)
from raa.registry.profiles import CORE, CORE_AND_ADMIN, MINIMAL


class CapabilitiesInput(ToolInput):
    pass


class ProjectCreateInput(ToolInput):
    name: str = Field(min_length=1, max_length=120, description="Human-readable project name.")
    description: str = Field(default="", max_length=2000, description="Optional notes.")
    scopes: list[str] | None = Field(
        default=None,
        description="Explicit project scopes. Defaults to read/write/static/export.",
    )
    authorization_ref: str | None = Field(
        default=None,
        max_length=500,
        description="Reference to an external authorization or engagement record.",
    )


class ProjectGetInput(ToolInput):
    project_id: str = Field(description="Project identifier returned by project_create.")


class ProjectListInput(ToolInput):
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)


class PolicyGetInput(ToolInput):
    project_id: str | None = Field(
        default=None,
        description="Optional project whose effective scopes should be returned.",
    )


class McpToolSearchInput(ToolInput):
    """Parameters to search registered capabilities in the registry."""

    query: str = Field(
        min_length=1,
        description="Search keywords or reversing goals (e.g. 'ELF', 'frida ssl', 'wasm').",
    )
    profile: str | None = Field(
        default=None,
        description="Optional profile filter (minimal, core, dynamic, api, ui, admin, full).",
    )
    family: str | None = Field(
        default=None,
        description="Optional tool family filter (e.g. static, dynamic, api, security, source).",
    )
    limit: int = Field(
        default=20,
        ge=1,
        le=100,
        description="Maximum matching tools to return.",
    )


class IosIpaInspectInput(ToolInput):
    """Parameters to inspect an Apple iOS .ipa application container."""

    ipa_path: str = Field(min_length=1, description="Path to iOS .ipa file.")
    extract_entitlements: bool = Field(
        default=True, description="Extract entitlements from embedded.mobileprovision."
    )


class IosMachoDisassembleInput(ToolInput):
    """Parameters to disassemble and inspect a Mach-O 64-bit binary executable."""

    binary_path: str = Field(min_length=1, description="Path to Mach-O executable file.")
    deep_symbols: bool = Field(
        default=True, description="Scan for Swift runtime and Objective-C symbols."
    )


class HarmonyHapInspectInput(ToolInput):
    """Parameters to inspect a Huawei HarmonyOS / OpenHarmony .hap package."""

    hap_path: str = Field(min_length=1, description="Path to HarmonyOS .hap package.")


class HarmonyAbcDisassembleInput(ToolInput):
    """Parameters to disassemble an ArkTS classes.abc Panda bytecode file."""

    abc_path: str = Field(min_length=1, description="Path to ArkTS classes.abc bytecode file.")


class TermuxProotWorkspaceManageInput(ToolInput):
    """Parameters to manage an on-device standalone Linux PRoot container."""

    action: str = Field(
        default="status",
        description="Action: status, init, exec, install_pkg, purge.",
    )
    distro: str = Field(
        default="debian", description="Linux distribution (debian, ubuntu, alpine)."
    )
    command: str | None = Field(default=None, description="Command to execute inside PRoot.")
    packages: list[str] | None = Field(default=None, description="Packages to install.")
    workspace_dir: str = Field(
        default="/data/local/tmp/raa_proot", description="On-device rootfs directory."
    )
    device_id: str | None = Field(default=None, description="Target ADB device ID.")


class WarpBlockSessionManageInput(ToolInput):
    """Parameters to manage interactive Warp-style terminal block sessions."""

    action: str = Field(
        default="record_block",
        description="Action: record_block, get_session, bookmark_block, export_runbook, clear.",
    )
    session_id: str = Field(default="default_session", description="Unique Warp session ID.")
    command: str | None = Field(default=None, description="Shell command string.")
    output: str | None = Field(default=None, description="Command output.")
    exit_code: int = Field(default=0, description="Process exit code.")
    duration_ms: int = Field(default=150, description="Command execution duration in ms.")
    tags: list[str] | None = Field(default=None, description="Audit tags.")
    block_id: str | None = Field(default=None, description="Block ID for bookmarking.")
    bookmarked: bool = Field(default=False, description="Flag as bookmarked.")


class PlatformCrossTargetCompareInput(ToolInput):
    """Parameters to compare parity across Android APK, iOS IPA, and HarmonyOS HAP."""

    android_apk_path: str | None = Field(default=None, description="Path to Android APK.")
    ios_ipa_path: str | None = Field(default=None, description="Path to Apple iOS IPA.")
    harmony_hap_path: str | None = Field(default=None, description="Path to HarmonyOS HAP.")


async def _capabilities(ctx: ToolContext, args: CapabilitiesInput) -> ToolOutcome:
    del args
    return ToolOutcome(data=ctx.runtime.info())


async def _project_create(ctx: ToolContext, args: ProjectCreateInput) -> ToolOutcome:
    project = ctx.runtime.projects.create(
        name=args.name,
        description=args.description,
        scopes=args.scopes,
    )
    warnings: list[str] = []
    if args.authorization_ref:
        warnings.append(
            "authorization_ref is accepted for workflow compatibility but is "
            "not persisted in this build."
        )
    return ToolOutcome(data=project, warnings=warnings)


async def _project_get(ctx: ToolContext, args: ProjectGetInput) -> ToolOutcome:
    return ToolOutcome(data=ctx.runtime.projects.get_or_raise(args.project_id))


async def _project_list(ctx: ToolContext, args: ProjectListInput) -> ToolOutcome:
    items = ctx.runtime.projects.list(limit=args.limit, offset=args.offset)
    return ToolOutcome(
        data={
            "items": [project.model_dump(mode="json") for project in items],
            "count": len(items),
            "limit": args.limit,
            "offset": args.offset,
        }
    )


async def _admin_policy_get(ctx: ToolContext, args: PolicyGetInput) -> ToolOutcome:
    payload: dict[str, Any] = {
        "all_scopes": sorted(ALL_SCOPES),
        "dangerous_scopes": sorted(DANGEROUS_SCOPES),
        "default_project_scopes": list(DEFAULT_PROJECT_SCOPES),
        "admin_enabled": ctx.runtime.settings.admin_enabled,
    }
    if args.project_id:
        project = ctx.runtime.projects.get_or_raise(args.project_id)
        payload["project_id"] = project.id
        payload["project_scopes"] = project.scopes
    return ToolOutcome(data=payload)


async def _mcp_tool_search(ctx: ToolContext, args: McpToolSearchInput) -> ToolOutcome:
    from raa.services.mcp.tool_search import search_tools

    res = search_tools(
        registry=ctx.runtime.registry,
        query=args.query,
        profile=args.profile,
        family=args.family,
        limit=args.limit,
    )
    return ToolOutcome(data=res)


async def _ios_ipa_inspect(ctx: ToolContext, args: IosIpaInspectInput) -> ToolOutcome:
    del ctx
    from raa.services.platform.ios_inspector import inspect_ios_ipa

    res = inspect_ios_ipa(
        ipa_path=args.ipa_path,
        extract_entitlements=args.extract_entitlements,
    )
    return ToolOutcome(data=res)


async def _ios_macho_disassemble(ctx: ToolContext, args: IosMachoDisassembleInput) -> ToolOutcome:
    del ctx
    from raa.services.platform.ios_inspector import disassemble_macho

    res = disassemble_macho(
        binary_path_or_bytes=args.binary_path,
        deep_symbols=args.deep_symbols,
    )
    return ToolOutcome(data=res)


async def _harmony_hap_inspect(ctx: ToolContext, args: HarmonyHapInspectInput) -> ToolOutcome:
    del ctx
    from raa.services.platform.harmony_inspector import inspect_harmony_hap

    res = inspect_harmony_hap(hap_path=args.hap_path)
    return ToolOutcome(data=res)


async def _harmony_abc_disassemble(
    ctx: ToolContext, args: HarmonyAbcDisassembleInput
) -> ToolOutcome:
    del ctx
    from raa.services.platform.harmony_inspector import disassemble_harmony_abc

    res = disassemble_harmony_abc(abc_path_or_bytes=args.abc_path)
    return ToolOutcome(data=res)


async def _termux_proot_workspace_manage(
    ctx: ToolContext, args: TermuxProotWorkspaceManageInput
) -> ToolOutcome:
    del ctx
    from raa.services.platform.proot_engine import manage_proot_workspace

    res = manage_proot_workspace(
        action=args.action,
        distro=args.distro,
        command=args.command,
        packages=args.packages,
        workspace_dir=args.workspace_dir,
        device_id=args.device_id,
    )
    return ToolOutcome(data=res)


async def _warp_block_session_manage(
    ctx: ToolContext, args: WarpBlockSessionManageInput
) -> ToolOutcome:
    del ctx
    from raa.services.platform.warp_session import manage_warp_block_session

    res = manage_warp_block_session(
        action=args.action,
        session_id=args.session_id,
        command=args.command,
        output=args.output,
        exit_code=args.exit_code,
        duration_ms=args.duration_ms,
        tags=args.tags,
        block_id=args.block_id,
        bookmarked=args.bookmarked,
    )
    return ToolOutcome(data=res)


async def _platform_cross_target_compare(
    ctx: ToolContext, args: PlatformCrossTargetCompareInput
) -> ToolOutcome:
    del ctx
    from raa.services.platform.cross_target_compare import compare_cross_targets

    res = compare_cross_targets(
        android_apk_path=args.android_apk_path,
        ios_ipa_path=args.ios_ipa_path,
        harmony_hap_path=args.harmony_hap_path,
    )
    return ToolOutcome(data=res)


def register(registry: CapabilityRegistry) -> None:
    registry.register(
        ToolSpec(
            name="capabilities_get",
            title="Server capabilities",
            description=(
                "Return RAA version, protocol baseline, profiles, scope names, "
                "implemented tool count, engine availability and planned extensions."
            ),
            input_model=CapabilitiesInput,
            handler=_capabilities,
            family="platform",
            profiles=MINIMAL,
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="project_create",
            title="Create project",
            description=(
                "Create an isolated project. Scopes default to project read/write, "
                "static read and export write; dynamic and network scopes are opt-in."
            ),
            input_model=ProjectCreateInput,
            handler=_project_create,
            family="platform",
            profiles=MINIMAL,
            annotations=ToolAnnotations(
                read_only=False,
                destructive=False,
                idempotent=False,
            ),
        )
    )
    registry.register(
        ToolSpec(
            name="project_get",
            title="Get project",
            description="Return project metadata and granted scopes.",
            input_model=ProjectGetInput,
            handler=_project_get,
            family="platform",
            profiles=MINIMAL,
            scopes=frozenset({"project.read"}),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="project_list",
            title="List projects",
            description="List projects with their identifiers and scope sets.",
            input_model=ProjectListInput,
            handler=_project_list,
            family="platform",
            profiles=CORE,
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="admin_policy_get",
            title="Get policy",
            description=(
                "Return valid scopes, dangerous scopes, defaults and, optionally, "
                "the effective scopes of one project."
            ),
            input_model=PolicyGetInput,
            handler=_admin_policy_get,
            family="admin",
            profiles=CORE_AND_ADMIN,
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="mcp_tool_search",
            title="Search-First MCP Capability Index",
            description=(
                "Search available tools by semantic keywords, descriptions, and reversing "
                "goals to prevent LLM context bloat."
            ),
            input_model=McpToolSearchInput,
            handler=_mcp_tool_search,
            family="platform",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True, idempotent=True),
        )
    )
    registry.register(
        ToolSpec(
            name="ios_ipa_inspect",
            title="Inspect Apple iOS IPA Application Container",
            description=(
                "Parse iOS .ipa archives, extracting bundle metadata, Info.plist permissions, "
                "App Transport Security configuration, and embedded.mobileprovision entitlements."
            ),
            input_model=IosIpaInspectInput,
            handler=_ios_ipa_inspect,
            family="platform",
            profiles=frozenset({"core", "full"}),
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True, idempotent=True),
        )
    )
    registry.register(
        ToolSpec(
            name="ios_macho_disassemble",
            title="Disassemble Apple Mach-O 64-Bit Binary",
            description=(
                "Analyze Mach-O binary headers, dynamic libraries, segments, FairPlay encryption "
                "status (cryptid), and Swift/Objective-C runtime symbols."
            ),
            input_model=IosMachoDisassembleInput,
            handler=_ios_macho_disassemble,
            family="platform",
            profiles=frozenset({"core", "full"}),
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True, idempotent=True),
        )
    )
    registry.register(
        ToolSpec(
            name="harmony_hap_inspect",
            title="Inspect Huawei HarmonyOS / OpenHarmony HAP Package",
            description=(
                "Inspect HarmonyOS .hap application containers, parsing Stage (module.json) and "
                "FA (config.json) manifests, abilities, device types, and permissions."
            ),
            input_model=HarmonyHapInspectInput,
            handler=_harmony_hap_inspect,
            family="platform",
            profiles=frozenset({"core", "full"}),
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True, idempotent=True),
        )
    )
    registry.register(
        ToolSpec(
            name="harmony_abc_disassemble",
            title="Disassemble Huawei ArkTS ABC Bytecode",
            description=(
                "Parse and disassemble ArkTS classes.abc Panda bytecode files, extracting "
                "decorators (@Component, @Entry), ArkUI view components, and methods."
            ),
            input_model=HarmonyAbcDisassembleInput,
            handler=_harmony_abc_disassemble,
            family="platform",
            profiles=frozenset({"core", "full"}),
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True, idempotent=True),
        )
    )
    registry.register(
        ToolSpec(
            name="termux_proot_workspace_manage",
            title="Manage Standalone On-Device PRoot Linux Container",
            description=(
                "Orchestrate an isolated on-device Debian/Ubuntu/Alpine Linux userspace container "
                "via PRoot for autonomous offline analysis without PC tethering or root."
            ),
            input_model=TermuxProotWorkspaceManageInput,
            handler=_termux_proot_workspace_manage,
            family="platform",
            profiles=frozenset({"core", "full"}),
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=False, idempotent=False),
        )
    )
    registry.register(
        ToolSpec(
            name="warp_block_session_manage",
            title="Interactive Warp-Style Terminal Block Session Manager",
            description=(
                "Record, filter, bookmark, and export terminal command execution blocks with "
                "duration metrics, exit codes, and markdown audit runbook synthesis."
            ),
            input_model=WarpBlockSessionManageInput,
            handler=_warp_block_session_manage,
            family="platform",
            profiles=frozenset({"core", "full"}),
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=False, idempotent=False),
        )
    )
    registry.register(
        ToolSpec(
            name="platform_cross_target_compare",
            title="Cross-Platform Android, iOS & HarmonyOS Target Compare",
            description=(
                "Side-by-side comparative analysis of Android APK, iOS IPA, and HarmonyOS HAP "
                "evaluating feature parity, permission matrices, and security posture."
            ),
            input_model=PlatformCrossTargetCompareInput,
            handler=_platform_cross_target_compare,
            family="platform",
            profiles=frozenset({"core", "full"}),
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True, idempotent=True),
        )
    )
