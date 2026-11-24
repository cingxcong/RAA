"""Phase 20 Tools: Offensive Security Operations, Yaklang HackSkills & Autonomous Exploit Validation.

Registers 10 tools:
- hack_yak_skill_run
- hack_403_deep_mutate
- computer_use_gui_execute
- frontier_mode_switch
- mausbot_gatekeeper_prompt
- exploit_chain_verify
- skillnet_benchmark_eval
- skillpack_bundle_manage
- audit_tamper_seal_v3
- v3_full_system_benchmark
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


class HackYakSkillRunInput(ToolInput):
    playbook_name: str = Field(min_length=1, description="Yaklang playbook name.")
    target_endpoint: str = Field(min_length=1, description="Target API endpoint URL.")


class Hack403DeepMutateInput(ToolInput):
    target_url: str = Field(min_length=1, description="401/403 restricted URL to mutate.")


class ComputerUseGUIExecuteInput(ToolInput):
    target_application: Literal["ghidra", "ida_pro", "jadx_gui", "burp_suite"] = Field(
        description="Target reversing desktop application.",
    )
    task_description: str = Field(min_length=1, description="Autonomous task description.")


class FrontierModeSwitchInput(ToolInput):
    desired_mode: Literal["react_fast", "swarm_deep"] = Field(
        description="Desired execution paradigm.",
    )
    reason: str = Field(min_length=1, description="Justification for mode switch.")


class MausbotGatekeeperPromptInput(ToolInput):
    operation_name: str = Field(min_length=1, description="Operation to inspect.")
    payload_preview: str = Field(min_length=1, description="Preview of action payload or diff.")


class ExploitChainVerifyInput(ToolInput):
    vulnerability_id: str = Field(min_length=1, description="Vulnerability identifier.")
    proposed_chain: list[str] = Field(
        default_factory=list, description="Proposed non-destructive chain steps."
    )


class SkillNetBenchmarkEvalInput(ToolInput):
    benchmark_suite: str = Field(
        default="full_reverse_gym", description="Evaluation benchmark suite."
    )


class SkillPackBundleManageInput(ToolInput):
    action: Literal["package", "validate", "install", "list"] = Field(
        default="list",
        description="SkillPack action.",
    )
    skillpack_name: str = Field(default="mobile_exploit_pack", description="SkillPack name.")


class AuditTamperSealV3Input(ToolInput):
    report_content: str = Field(min_length=1, description="Audit report markdown or JSON content.")


class V3FullSystemBenchmarkInput(ToolInput):
    target_environment: str = Field(default="production", description="Verification environment.")


# --- Handlers ---


async def _hack_yak_skill_run(ctx: ToolContext, args: HackYakSkillRunInput) -> ToolOutcome:
    res = ctx.runtime.offensive.run_yak_skill_playbook(
        playbook_name=args.playbook_name,
        target_endpoint=args.target_endpoint,
    )
    return ToolOutcome(data=res.model_dump())


async def _hack_403_deep_mutate(ctx: ToolContext, args: Hack403DeepMutateInput) -> ToolOutcome:
    res = ctx.runtime.offensive.mutate_http_403_bypass(target_url=args.target_url)
    return ToolOutcome(data=res.model_dump())


async def _computer_use_gui_execute(
    ctx: ToolContext, args: ComputerUseGUIExecuteInput
) -> ToolOutcome:
    res = ctx.runtime.offensive.execute_computer_use_gui(
        target_application=args.target_application,
        task_description=args.task_description,
    )
    return ToolOutcome(data=res.model_dump())


async def _frontier_mode_switch(ctx: ToolContext, args: FrontierModeSwitchInput) -> ToolOutcome:
    res = ctx.runtime.offensive.switch_frontier_mode(
        desired_mode=args.desired_mode,
        reason=args.reason,
    )
    return ToolOutcome(data=res.model_dump())


async def _mausbot_gatekeeper_prompt(
    ctx: ToolContext, args: MausbotGatekeeperPromptInput
) -> ToolOutcome:
    res = ctx.runtime.offensive.prompt_mausbot_gatekeeper(
        operation_name=args.operation_name,
        payload_preview=args.payload_preview,
    )
    return ToolOutcome(data=res.model_dump())


async def _exploit_chain_verify(ctx: ToolContext, args: ExploitChainVerifyInput) -> ToolOutcome:
    res = ctx.runtime.offensive.verify_exploit_chain(
        vulnerability_id=args.vulnerability_id,
        proposed_chain=args.proposed_chain,
    )
    return ToolOutcome(data=res.model_dump())


async def _skillnet_benchmark_eval(
    ctx: ToolContext, args: SkillNetBenchmarkEvalInput
) -> ToolOutcome:
    res = ctx.runtime.offensive.evaluate_skillnet_benchmark(benchmark_suite=args.benchmark_suite)
    return ToolOutcome(data=res.model_dump())


async def _skillpack_bundle_manage(
    ctx: ToolContext, args: SkillPackBundleManageInput
) -> ToolOutcome:
    res = ctx.runtime.offensive.manage_skillpack_bundle(
        action=args.action,
        skillpack_name=args.skillpack_name,
    )
    return ToolOutcome(data=res.model_dump())


async def _audit_tamper_seal_v3(ctx: ToolContext, args: AuditTamperSealV3Input) -> ToolOutcome:
    res = ctx.runtime.offensive.generate_audit_tamper_seal_v3(report_content=args.report_content)
    return ToolOutcome(data=res.model_dump())


async def _v3_full_system_benchmark(
    ctx: ToolContext, args: V3FullSystemBenchmarkInput
) -> ToolOutcome:
    res = ctx.runtime.offensive.run_v3_full_system_benchmark()
    return ToolOutcome(data=res.model_dump())


# --- Register Function ---


def register(registry: CapabilityRegistry) -> None:
    # 1. hack_yak_skill_run
    registry.register(
        ToolSpec(
            name="hack_yak_skill_run",
            title="Yaklang HackSkills Offensive Penetration Playbook",
            description="Executes automated penetration testing playbooks against mobile backend endpoints via Yaklang HackSkills.",
            input_model=HackYakSkillRunInput,
            handler=_hack_yak_skill_run,
            family="pentest",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    # 2. hack_403_deep_mutate
    registry.register(
        ToolSpec(
            name="hack_403_deep_mutate",
            title="Deep HTTP 401/403 Access Control Bypass Mutator",
            description="Performs deep HTTP access control bypass mutations (header spoofing, path normalization, verb tunneling).",
            input_model=Hack403DeepMutateInput,
            handler=_hack_403_deep_mutate,
            family="pentest",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    # 3. computer_use_gui_execute
    registry.register(
        ToolSpec(
            name="computer_use_gui_execute",
            title="Autonomous Computer-Use GUI Reversing Operator",
            description="Operates desktop GUI reversing tools (Ghidra, IDA Pro, Jadx-GUI, Burp Suite) via autonomous OS computer-use.",
            input_model=ComputerUseGUIExecuteInput,
            handler=_computer_use_gui_execute,
            family="computer_use",
            profiles=DYNAMIC,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=False),
        )
    )
    # 4. frontier_mode_switch
    registry.register(
        ToolSpec(
            name="frontier_mode_switch",
            title="FrontierAgent Dual ReAct / Swarm Switcher",
            description="Dynamically toggles between high-speed single-agent ReAct loops and multi-agent collaborative swarms.",
            input_model=FrontierModeSwitchInput,
            handler=_frontier_mode_switch,
            family="orchestration",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=False),
        )
    )
    # 5. mausbot_gatekeeper_prompt
    registry.register(
        ToolSpec(
            name="mausbot_gatekeeper_prompt",
            title="OpenMausBot Safe Execution Gatekeeper & Diff Prompt",
            description="Presents human-readable impact summaries and diff previews before executing high-risk operations.",
            input_model=MausbotGatekeeperPromptInput,
            handler=_mausbot_gatekeeper_prompt,
            family="safety",
            profiles=ADMIN,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    # 6. exploit_chain_verify
    registry.register(
        ToolSpec(
            name="exploit_chain_verify",
            title="Non-Destructive Exploit PoC Chaining & Validator",
            description="Autonomously chains and validates non-destructive exploit PoCs for discovered mobile vulnerabilities.",
            input_model=ExploitChainVerifyInput,
            handler=_exploit_chain_verify,
            family="exploit",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    # 7. skillnet_benchmark_eval
    registry.register(
        ToolSpec(
            name="skillnet_benchmark_eval",
            title="SkillNet Systematic Benchmark & Evaluation Gym",
            description="Evaluates all RAA agent skills across standardized benchmarks for invocation accuracy and token overhead.",
            input_model=SkillNetBenchmarkEvalInput,
            handler=_skillnet_benchmark_eval,
            family="evaluation",
            profiles=ADMIN,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    # 8. skillpack_bundle_manage
    registry.register(
        ToolSpec(
            name="skillpack_bundle_manage",
            title="Portable Reversing SkillPack Packaging & Distribution",
            description="Packages, validates, and distributes versioned portable reverse engineering skill bundles (.skillpack).",
            input_model=SkillPackBundleManageInput,
            handler=_skillpack_bundle_manage,
            family="packaging",
            profiles=ADMIN,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=False),
        )
    )
    # 9. audit_tamper_seal_v3
    registry.register(
        ToolSpec(
            name="audit_tamper_seal_v3",
            title="v3.0 Tamper-Evident Report Seal & Final Manifest",
            description="Generates cryptographic SHA-256 seal and CycloneDX 1.5 SBOM manifest for v3.0 production audit reports.",
            input_model=AuditTamperSealV3Input,
            handler=_audit_tamper_seal_v3,
            family="compliance",
            profiles=ADMIN,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    # 10. v3_full_system_benchmark
    registry.register(
        ToolSpec(
            name="v3_full_system_benchmark",
            title="v3.0 Full-System Benchmark & Production Quality Gate",
            description="Executes end-to-end performance and regression verification across all 322 tools and 36 skills.",
            input_model=V3FullSystemBenchmarkInput,
            handler=_v3_full_system_benchmark,
            family="benchmark",
            profiles=ADMIN,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
