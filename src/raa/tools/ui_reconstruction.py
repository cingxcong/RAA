"""Phase 18 Tools: Autonomous UI Reconstruction, Living Canvas & Cross-Platform Re-Engineering.

Registers 20 tools:
- stitch_ui_modernize
- stitch_design_spec_export
- hig_doctor_compliance_audit
- ui_liquid_glass_widget_gen
- ui_bento_grid_summary_render
- reconstruct_clean_arch_lint
- clean_room_spec_extract
- ui_multi_viewport_match
- assets_palette_typography_extract
- game_unity_asset_dump
- game_godot_pck_extract
- db_sqlite_forensic_extract
- docmd_llms_txt_compile
- task_observer_skill_evolve
- dot_coworker_webrtc_session
- ekko_canvas_pipeline_run
- tui_codewhale_session
- receipt_cryptographic_sign
- sodu_cicd_pipeline_run
- gh_actions_build_android
"""

from __future__ import annotations

from typing import Any, Literal

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


class StitchUIModernizeInput(ToolInput):
    project_id: str = Field(min_length=1, description="Target project ID.")
    layout_xml: str = Field(min_length=1, description="Android XML layout content.")
    target_framework: Literal["jetpack_compose", "react_native", "flutter"] = Field(
        default="jetpack_compose",
        description="Target modern UI framework.",
    )


class StitchDesignSpecExportInput(ToolInput):
    project_id: str = Field(min_length=1, description="Target project ID.")
    theme_name: str = Field(default="MaterialTheme", description="Theme name.")


class HIGDoctorComplianceAuditInput(ToolInput):
    project_id: str = Field(min_length=1, description="Target project ID.")
    target_view: str = Field(min_length=1, description="View name or screen identifier.")


class UILiquidGlassWidgetGenInput(ToolInput):
    widget_name: str = Field(min_length=1, description="Widget name.")
    framework: Literal["flutter", "swiftui"] = Field(
        default="flutter", description="Target framework."
    )


class UIBentoGridSummaryRenderInput(ToolInput):
    grid_title: str = Field(min_length=1, description="Presentation title.")
    metrics: dict[str, Any] = Field(default_factory=dict, description="Audit metrics to present.")


class ReconstructCleanArchLintInput(ToolInput):
    file_path: str = Field(min_length=1, description="Source file path.")
    source_code: str = Field(min_length=1, description="Decompiled source code.")


class CleanRoomSpecExtractInput(ToolInput):
    module_name: str = Field(min_length=1, description="Module or component name.")
    decompiled_context: str = Field(min_length=1, description="Decompiled codebase context.")


class UIMultiViewportMatchInput(ToolInput):
    screen_name: str = Field(min_length=1, description="Screen name to validate.")


class AssetsPaletteTypographyExtractInput(ToolInput):
    apk_path: str = Field(min_length=1, description="Path to target APK.")


class GameUnityAssetDumpInput(ToolInput):
    package_name: str = Field(min_length=1, description="Game package name.")


class GameGodotPckExtractInput(ToolInput):
    package_name: str = Field(min_length=1, description="Game package name.")


class DBSqliteForensicExtractInput(ToolInput):
    database_path: str = Field(min_length=1, description="Path to SQLite database file.")
    encryption_key: str | None = Field(default=None, description="Optional SQLCipher key.")


class DocmdLlmsTxtCompileInput(ToolInput):
    project_id: str = Field(min_length=1, description="Target project ID.")
    title: str = Field(default="RAA Intelligence Portal", description="Portal title.")


class TaskObserverSkillEvolveInput(ToolInput):
    skill_name: str = Field(min_length=1, description="Skill name.")
    feedback_history: list[str] = Field(
        default_factory=list, description="User corrections and feedback."
    )


class DotCoworkerWebRTCSessionInput(ToolInput):
    action: Literal["connect", "status", "disconnect"] = Field(
        default="connect",
        description="WebRTC coworker action.",
    )


class EkkoCanvasPipelineRunInput(ToolInput):
    graph_name: str = Field(min_length=1, description="Visual node graph name.")


class TuiCodewhaleSessionInput(ToolInput):
    action: Literal["launch", "status", "detach"] = Field(
        default="launch",
        description="Codewhale TUI action.",
    )


class ReceiptCryptographicSignInput(ToolInput):
    tool_name: str = Field(min_length=1, description="Tool name invoked.")
    input_data: str = Field(min_length=1, description="Serialized tool input.")
    output_data: str = Field(min_length=1, description="Serialized tool output.")


class SoduCicdPipelineRunInput(ToolInput):
    target_apk: str = Field(min_length=1, description="Target APK path.")
    patch_recipe: str = Field(min_length=1, description="Patch recipe identifier or path.")


class GHActionsBuildAndroidInput(ToolInput):
    app_name: str = Field(default="MobileApp", description="Application name.")


# --- Handlers ---


async def _stitch_ui_modernize(ctx: ToolContext, args: StitchUIModernizeInput) -> ToolOutcome:
    res = ctx.runtime.ui_reconstruction.modernize_ui_stitch(
        project_id=args.project_id,
        layout_xml=args.layout_xml,
        target_framework=args.target_framework,
    )
    return ToolOutcome(data=res.model_dump())


async def _stitch_design_spec_export(
    ctx: ToolContext, args: StitchDesignSpecExportInput
) -> ToolOutcome:
    res = ctx.runtime.ui_reconstruction.export_stitch_design_spec(
        project_id=args.project_id,
        theme_name=args.theme_name,
    )
    return ToolOutcome(data=res.model_dump())


async def _hig_doctor_compliance_audit(
    ctx: ToolContext, args: HIGDoctorComplianceAuditInput
) -> ToolOutcome:
    res = ctx.runtime.ui_reconstruction.audit_hig_compliance(
        project_id=args.project_id,
        target_view=args.target_view,
    )
    return ToolOutcome(data=res.model_dump())


async def _ui_liquid_glass_widget_gen(
    ctx: ToolContext, args: UILiquidGlassWidgetGenInput
) -> ToolOutcome:
    res = ctx.runtime.ui_reconstruction.generate_liquid_glass_widget(
        widget_name=args.widget_name,
        framework=args.framework,
    )
    return ToolOutcome(data=res.model_dump())


async def _ui_bento_grid_summary_render(
    ctx: ToolContext, args: UIBentoGridSummaryRenderInput
) -> ToolOutcome:
    res = ctx.runtime.ui_reconstruction.render_bento_grid_summary(
        grid_title=args.grid_title,
        metrics=args.metrics,
    )
    return ToolOutcome(data=res.model_dump())


async def _reconstruct_clean_arch_lint(
    ctx: ToolContext, args: ReconstructCleanArchLintInput
) -> ToolOutcome:
    res = ctx.runtime.ui_reconstruction.lint_clean_architecture(
        file_path=args.file_path,
        source_code=args.source_code,
    )
    return ToolOutcome(data=res.model_dump())


async def _clean_room_spec_extract(
    ctx: ToolContext, args: CleanRoomSpecExtractInput
) -> ToolOutcome:
    res = ctx.runtime.ui_reconstruction.extract_clean_room_spec(
        module_name=args.module_name,
        decompiled_context=args.decompiled_context,
    )
    return ToolOutcome(data=res.model_dump())


async def _ui_multi_viewport_match(
    ctx: ToolContext, args: UIMultiViewportMatchInput
) -> ToolOutcome:
    res = ctx.runtime.ui_reconstruction.match_multi_viewport(screen_name=args.screen_name)
    return ToolOutcome(data=res.model_dump())


async def _assets_palette_typography_extract(
    ctx: ToolContext, args: AssetsPaletteTypographyExtractInput
) -> ToolOutcome:
    res = ctx.runtime.ui_reconstruction.extract_palette_and_typography(apk_path=args.apk_path)
    return ToolOutcome(data=res.model_dump())


async def _game_unity_asset_dump(ctx: ToolContext, args: GameUnityAssetDumpInput) -> ToolOutcome:
    res = ctx.runtime.ui_reconstruction.dump_game_assets(
        package_name=args.package_name, engine="unity"
    )
    return ToolOutcome(data=res.model_dump())


async def _game_godot_pck_extract(ctx: ToolContext, args: GameGodotPckExtractInput) -> ToolOutcome:
    res = ctx.runtime.ui_reconstruction.dump_game_assets(
        package_name=args.package_name, engine="godot"
    )
    return ToolOutcome(data=res.model_dump())


async def _db_sqlite_forensic_extract(
    ctx: ToolContext, args: DBSqliteForensicExtractInput
) -> ToolOutcome:
    res = ctx.runtime.ui_reconstruction.extract_sqlite_forensics(
        database_path=args.database_path,
        encryption_key=args.encryption_key,
    )
    return ToolOutcome(data=res.model_dump())


async def _docmd_llms_txt_compile(ctx: ToolContext, args: DocmdLlmsTxtCompileInput) -> ToolOutcome:
    res = ctx.runtime.ui_reconstruction.compile_docmd_llms_txt(
        project_id=args.project_id,
        title=args.title,
    )
    return ToolOutcome(data=res.model_dump())


async def _task_observer_skill_evolve(
    ctx: ToolContext, args: TaskObserverSkillEvolveInput
) -> ToolOutcome:
    res = ctx.runtime.ui_reconstruction.evolve_task_observer_skill(
        skill_name=args.skill_name,
        feedback_history=args.feedback_history,
    )
    return ToolOutcome(data=res.model_dump())


async def _dot_coworker_webrtc_session(
    ctx: ToolContext, args: DotCoworkerWebRTCSessionInput
) -> ToolOutcome:
    res = ctx.runtime.ui_reconstruction.manage_dot_coworker_webrtc(action=args.action)
    return ToolOutcome(data=res.model_dump())


async def _ekko_canvas_pipeline_run(
    ctx: ToolContext, args: EkkoCanvasPipelineRunInput
) -> ToolOutcome:
    res = ctx.runtime.ui_reconstruction.run_ekko_canvas_pipeline(graph_name=args.graph_name)
    return ToolOutcome(data=res.model_dump())


async def _tui_codewhale_session(ctx: ToolContext, args: TuiCodewhaleSessionInput) -> ToolOutcome:
    res = ctx.runtime.ui_reconstruction.manage_codewhale_tui(action=args.action)
    return ToolOutcome(data=res.model_dump())


async def _receipt_cryptographic_sign(
    ctx: ToolContext, args: ReceiptCryptographicSignInput
) -> ToolOutcome:
    res = ctx.runtime.ui_reconstruction.sign_cryptographic_receipt(
        tool_name=args.tool_name,
        input_data=args.input_data,
        output_data=args.output_data,
    )
    return ToolOutcome(data=res.model_dump())


async def _sodu_cicd_pipeline_run(ctx: ToolContext, args: SoduCicdPipelineRunInput) -> ToolOutcome:
    res = ctx.runtime.ui_reconstruction.run_sodu_cicd_pipeline(
        target_apk=args.target_apk,
        patch_recipe=args.patch_recipe,
    )
    return ToolOutcome(data=res.model_dump())


async def _gh_actions_build_android(
    ctx: ToolContext, args: GHActionsBuildAndroidInput
) -> ToolOutcome:
    res = ctx.runtime.ui_reconstruction.generate_gh_actions_workflow(app_name=args.app_name)
    return ToolOutcome(data=res.model_dump())


# --- Register Function ---


def register(registry: CapabilityRegistry) -> None:
    # 1. stitch_ui_modernize
    registry.register(
        ToolSpec(
            name="stitch_ui_modernize",
            title="Google Stitch UI Screen Modernization Engine",
            description="Converts legacy Android XML layouts into modern Material 3 Jetpack Compose or React Native screens.",
            input_model=StitchUIModernizeInput,
            handler=_stitch_ui_modernize,
            family="ui",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    # 2. stitch_design_spec_export
    registry.register(
        ToolSpec(
            name="stitch_design_spec_export",
            title="Google Stitch DESIGN.md Design System Exporter",
            description="Generates comprehensive DESIGN.md token specifications and component catalogs from mobile assets.",
            input_model=StitchDesignSpecExportInput,
            handler=_stitch_design_spec_export,
            family="ui",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    # 3. hig_doctor_compliance_audit
    registry.register(
        ToolSpec(
            name="hig_doctor_compliance_audit",
            title="Apple Human Interface Guidelines (HIG) Doctor",
            description="Audits layouts for Apple HIG compliance, 44pt touch targets, and Dynamic Type scaling.",
            input_model=HIGDoctorComplianceAuditInput,
            handler=_hig_doctor_compliance_audit,
            family="ui",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    # 4. ui_liquid_glass_widget_gen
    registry.register(
        ToolSpec(
            name="ui_liquid_glass_widget_gen",
            title="Liquid Glass Fragment Shader & Physics Widget Studio",
            description="Synthesizes Flutter and SwiftUI components with real fragment shader specular blurs and morphing physics.",
            input_model=UILiquidGlassWidgetGenInput,
            handler=_ui_liquid_glass_widget_gen,
            family="ui",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    # 5. ui_bento_grid_summary_render
    registry.register(
        ToolSpec(
            name="ui_bento_grid_summary_render",
            title="Apple Bento Grid Visual Dashboard Studio",
            description="Renders Apple-style Bento Grid presentation summaries of visual diffs, security ratings, and views.",
            input_model=UIBentoGridSummaryRenderInput,
            handler=_ui_bento_grid_summary_render,
            family="ui",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    # 6. reconstruct_clean_arch_lint
    registry.register(
        ToolSpec(
            name="reconstruct_clean_arch_lint",
            title="Clean Architecture & Domain-Driven Design Linter",
            description="Lints and refactors decompiled code according to Clean Architecture and DDD principles.",
            input_model=ReconstructCleanArchLintInput,
            handler=_reconstruct_clean_arch_lint,
            family="ui",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    # 7. clean_room_spec_extract
    registry.register(
        ToolSpec(
            name="clean_room_spec_extract",
            title="Clean-Room Functional Specification Synthesizer",
            description="Synthesizes clean functional specification documents stripped of proprietary assets and copyrighted code.",
            input_model=CleanRoomSpecExtractInput,
            handler=_clean_room_spec_extract,
            family="ui",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    # 8. ui_multi_viewport_match
    registry.register(
        ToolSpec(
            name="ui_multi_viewport_match",
            title="Multi-Viewport Layout Parity & Semantic Matcher",
            description="Validates reconstructed layouts across phone, foldable, and tablet screen sizes with semantic AST parity.",
            input_model=UIMultiViewportMatchInput,
            handler=_ui_multi_viewport_match,
            family="ui",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    # 9. assets_palette_typography_extract
    registry.register(
        ToolSpec(
            name="assets_palette_typography_extract",
            title="Mobile Design Token & Typography Extractor",
            description="Extracts color schemes, typography hierarchies, and spacing grids into structured tokens.json.",
            input_model=AssetsPaletteTypographyExtractInput,
            handler=_assets_palette_typography_extract,
            family="ui",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    # 10. game_unity_asset_dump
    registry.register(
        ToolSpec(
            name="game_unity_asset_dump",
            title="Unity Android Game Asset & Serialized Data Dumper",
            description="Extracts serialized AssetBundles, meshes, shaders, and C# scripts from Unity Android games.",
            input_model=GameUnityAssetDumpInput,
            handler=_game_unity_asset_dump,
            family="game",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    # 11. game_godot_pck_extract
    registry.register(
        ToolSpec(
            name="game_godot_pck_extract",
            title="Godot Embedded PCK Archive Extractor",
            description="Unpacks embedded .pck game archives, GDScript sources, and scene trees from Godot mobile APKs.",
            input_model=GameGodotPckExtractInput,
            handler=_game_godot_pck_extract,
            family="game",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    # 12. db_sqlite_forensic_extract
    registry.register(
        ToolSpec(
            name="db_sqlite_forensic_extract",
            title="Mobile SQLite & SQLCipher Forensic Extractor",
            description="Forensically recovers mobile SQLite/Room databases, fragmented WAL records, and SQLCipher keys.",
            input_model=DBSqliteForensicExtractInput,
            handler=_db_sqlite_forensic_extract,
            family="forensics",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    # 13. docmd_llms_txt_compile
    registry.register(
        ToolSpec(
            name="docmd_llms_txt_compile",
            title="docmd llms.txt & Static Portal Compiler",
            description="Compiles workspace documentation into single-source static HTML sites and llms.txt context files.",
            input_model=DocmdLlmsTxtCompileInput,
            handler=_docmd_llms_txt_compile,
            family="documentation",
            profiles=ADMIN,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    # 14. task_observer_skill_evolve
    registry.register(
        ToolSpec(
            name="task_observer_skill_evolve",
            title="Task Observer & Adaptive Skill Evolution Meta-Agent",
            description="Analyzes session feedback history to propose automated prompt improvements for RAA skills.",
            input_model=TaskObserverSkillEvolveInput,
            handler=_task_observer_skill_evolve,
            family="meta",
            profiles=ADMIN,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=False),
        )
    )
    # 15. dot_coworker_webrtc_session
    registry.register(
        ToolSpec(
            name="dot_coworker_webrtc_session",
            title="RAA Dot Persistent Reversing Coworker WebRTC Session",
            description="Manages WebRTC audio/video feeds and situational awareness with the always-on reversing coworker agent.",
            input_model=DotCoworkerWebRTCSessionInput,
            handler=_dot_coworker_webrtc_session,
            family="coworker",
            profiles=DYNAMIC,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=False),
        )
    )
    # 16. ekko_canvas_pipeline_run
    registry.register(
        ToolSpec(
            name="ekko_canvas_pipeline_run",
            title="Ekko Studio Visual Node Reversing Pipeline Runner",
            description="Executes visual node-based reversing workflow graphs connecting decompile, audit, and patch stages.",
            input_model=EkkoCanvasPipelineRunInput,
            handler=_ekko_canvas_pipeline_run,
            family="workflow",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=False),
        )
    )
    # 17. tui_codewhale_session
    registry.register(
        ToolSpec(
            name="tui_codewhale_session",
            title="Codewhale High-Performance Terminal TUI Session",
            description="Manages interactive Ratatui-based terminal sessions with real-time log streaming and subagent monitoring.",
            input_model=TuiCodewhaleSessionInput,
            handler=_tui_codewhale_session,
            family="tui",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=False),
        )
    )
    # 18. receipt_cryptographic_sign
    registry.register(
        ToolSpec(
            name="receipt_cryptographic_sign",
            title="Forensic SHA-256 HMAC Cryptographic Execution Receipt",
            description="Generates HMAC-signed execution receipts for tool invocations establishing forensic chain of custody.",
            input_model=ReceiptCryptographicSignInput,
            handler=_receipt_cryptographic_sign,
            family="audit",
            profiles=ADMIN,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    # 19. sodu_cicd_pipeline_run
    registry.register(
        ToolSpec(
            name="sodu_cicd_pipeline_run",
            title="Sodu Closed-Loop Decompile-Patch-Build CI/CD Pipeline",
            description="Executes automated decompile-patch-recompile-align-sign pipeline with rollback verification.",
            input_model=SoduCicdPipelineRunInput,
            handler=_sodu_cicd_pipeline_run,
            family="rebuild",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=False),
        )
    )
    # 20. gh_actions_build_android
    registry.register(
        ToolSpec(
            name="gh_actions_build_android",
            title="GitHub Actions Rebuild & Sign Workflow Generator",
            description="Generates GitHub Actions CI/CD workflow YAML for automated Android APK building, 16KB alignment, and v2/v3 signing.",
            input_model=GHActionsBuildAndroidInput,
            handler=_gh_actions_build_android,
            family="rebuild",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
