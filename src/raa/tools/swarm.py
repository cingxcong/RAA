"""Phase 15 Tools: Multi-Agent Swarm Governance, Orchestration & Memory Federation.

Registers 9 tools:
- swarm_org_govern
- swarm_budget_meter
- subagent_deerflow_spawn
- memory_tideline_sync
- sop_pipeline_execute
- swarm_blackboard_post
- swarm_blackboard_read
- swarm_edict_gate_evaluate
- loopx_goal_control_plane
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from raa.policy.scopes import PROJECT_READ, PROJECT_WRITE
from raa.registry.models import (
    CapabilityRegistry,
    ToolAnnotations,
    ToolContext,
    ToolInput,
    ToolOutcome,
    ToolSpec,
)
from raa.registry.profiles import ADMIN_AND_SWARM, CORE_AND_SWARM

# --- Input Models ---


def _default_swarm_roles() -> list[dict[str, Any]]:
    return [
        {
            "role_id": "swarm_director_agent",
            "name": "Swarm Director",
            "description": "Orchestrates reversing priorities and delegates subtasks.",
            "subordinates": ["budget_enforcer_agent", "sop_orchestrator_agent"],
        },
        {
            "role_id": "budget_enforcer_agent",
            "name": "Budget Enforcer",
            "description": "Monitors token and dollar spending against caps.",
            "reports_to": "swarm_director_agent",
        },
        {
            "role_id": "sop_orchestrator_agent",
            "name": "SOP Orchestrator",
            "description": "Executes standardized multi-role reverse-engineering SOPs.",
            "reports_to": "swarm_director_agent",
        },
    ]


class SwarmOrgGovernInput(ToolInput):
    project_id: str = Field(min_length=1, description="Target project ID.")
    swarm_name: str = Field(
        default="RAA Autonomous Reversing Swarm", description="Swarm group name."
    )
    lead_role: str = Field(default="swarm_director_agent", description="Lead coordinator role ID.")
    roles: list[dict[str, Any]] = Field(
        default_factory=_default_swarm_roles,
        description="List of swarm agent role definitions.",
    )


class SwarmBudgetMeterInput(ToolInput):
    project_id: str = Field(min_length=1, description="Target project ID.")
    tokens: int = Field(default=0, ge=0, description="Tokens consumed in invocation.")
    cost_usd: float = Field(default=0.0, ge=0.0, description="Cost in USD for invocation.")
    subagent_name: str | None = Field(default=None, description="Subagent reporting spend.")
    set_token_cap: int | None = Field(default=None, ge=1, description="Update project token cap.")
    set_cost_cap_usd: float | None = Field(
        default=None, ge=0.0, description="Update project cost cap in USD."
    )


class SubagentDeerflowSpawnInput(ToolInput):
    project_id: str = Field(min_length=1, description="Target project ID.")
    agent_name: str = Field(default="deerflow_researcher", description="Subagent name.")
    mission_goal: str = Field(min_length=1, description="Detailed deep research mission goal.")
    max_depth: int = Field(
        default=3, ge=1, le=10, description="Maximum recursive exploration depth."
    )
    steps: list[str] | None = Field(default=None, description="Initial exploration steps.")


class MemoryTidelineSyncInput(ToolInput):
    project_id: str = Field(min_length=1, description="Target project ID.")
    domain: str = Field(
        min_length=1, description="Knowledge domain (e.g., 'crypto', 'network', 'storage')."
    )
    entity_key: str = Field(min_length=1, description="Key identifying the entity or symbol.")
    attributes: dict[str, Any] = Field(description="Dictionary of discovered facts and attributes.")


class SopPipelineExecuteInput(ToolInput):
    project_id: str = Field(min_length=1, description="Target project ID.")
    sop_name: str = Field(
        default="framework_audit",
        description="SOP template name ('framework_audit', 'api_key_extraction', 'ui_reconstruction').",
    )
    target_entity: str = Field(min_length=1, description="Target APK, component, or package.")
    params: dict[str, Any] = Field(default_factory=dict, description="Execution parameters.")


class SwarmBlackboardPostInput(ToolInput):
    project_id: str = Field(min_length=1, description="Target project ID.")
    topic: str = Field(
        min_length=1, description="Blackboard channel/topic (e.g., 'crypto', 'network')."
    )
    author: str = Field(min_length=1, description="Agent authoring the post.")
    hypothesis: str = Field(min_length=1, description="Hypothesis, finding, or observed evidence.")
    evidence_ids: list[str] = Field(default_factory=list, description="Associated evidence IDs.")
    confidence: float = Field(default=0.7, ge=0.0, le=1.0, description="Confidence score.")
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Additional structured metadata."
    )


class SwarmBlackboardReadInput(ToolInput):
    project_id: str = Field(min_length=1, description="Target project ID.")
    topic: str | None = Field(default=None, description="Optional topic filter.")
    author: str | None = Field(default=None, description="Optional author filter.")
    min_confidence: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Minimum confidence filter."
    )


class SwarmEdictGateEvaluateInput(ToolInput):
    project_id: str = Field(min_length=1, description="Target project ID.")
    action_type: str = Field(
        min_length=1, description="Proposed action type (e.g. 'mutate_smali', 'clear_credentials')."
    )
    draft_summary: str = Field(min_length=1, description="Drafted changes and justification.")
    risk_level: Literal["low", "medium", "high", "critical"] = Field(
        default="medium",
        description="Assessed risk level.",
    )
    bypass_requested: bool = Field(
        default=False, description="Whether caller requested policy bypass."
    )


class LoopXGoalControlPlaneInput(ToolInput):
    action: Literal["create", "status", "enqueue_attention", "step", "checkpoint", "list"] = Field(
        description="Goal control action.",
    )
    project_id: str = Field(min_length=1, description="Target project ID.")
    goal_id: str | None = Field(default=None, description="Optional existing goal ID.")
    title: str = Field(default="", description="Goal title (when creating).")
    attention_item: str | None = Field(
        default=None, description="Item to append to attention queue."
    )
    checkpoint_data: dict[str, Any] | None = Field(
        default=None, description="State snapshot for checkpoint."
    )


# --- Handlers ---


async def _swarm_org_govern(ctx: ToolContext, args: SwarmOrgGovernInput) -> ToolOutcome:
    config = ctx.runtime.swarm.configure_org(
        project_id=args.project_id,
        swarm_name=args.swarm_name,
        lead_role=args.lead_role,
        roles=args.roles,
    )
    return ToolOutcome(data=config.model_dump())


async def _swarm_budget_meter(ctx: ToolContext, args: SwarmBudgetMeterInput) -> ToolOutcome:
    budget = ctx.runtime.swarm.meter_budget(
        project_id=args.project_id,
        tokens=args.tokens,
        cost_usd=args.cost_usd,
        subagent_name=args.subagent_name,
        set_token_cap=args.set_token_cap,
        set_cost_cap_usd=args.set_cost_cap_usd,
    )
    return ToolOutcome(data=budget.model_dump())


async def _subagent_deerflow_spawn(
    ctx: ToolContext, args: SubagentDeerflowSpawnInput
) -> ToolOutcome:
    res = ctx.runtime.swarm.spawn_deerflow_subagent(
        project_id=args.project_id,
        agent_name=args.agent_name,
        mission_goal=args.mission_goal,
        max_depth=args.max_depth,
        steps=args.steps,
    )
    return ToolOutcome(data=res)


async def _memory_tideline_sync(ctx: ToolContext, args: MemoryTidelineSyncInput) -> ToolOutcome:
    res = ctx.runtime.swarm.sync_tideline_memory(
        project_id=args.project_id,
        domain=args.domain,
        entity_key=args.entity_key,
        attributes=args.attributes,
    )
    return ToolOutcome(data=res)


async def _sop_pipeline_execute(ctx: ToolContext, args: SopPipelineExecuteInput) -> ToolOutcome:
    res = ctx.runtime.swarm.execute_sop_pipeline(
        project_id=args.project_id,
        sop_name=args.sop_name,
        target_entity=args.target_entity,
        params=args.params,
    )
    return ToolOutcome(data=res)


async def _swarm_blackboard_post(ctx: ToolContext, args: SwarmBlackboardPostInput) -> ToolOutcome:
    entry = ctx.runtime.swarm.post_to_blackboard(
        project_id=args.project_id,
        topic=args.topic,
        author=args.author,
        hypothesis=args.hypothesis,
        evidence_ids=args.evidence_ids,
        confidence=args.confidence,
        metadata=args.metadata,
    )
    return ToolOutcome(data=entry.model_dump())


async def _swarm_blackboard_read(ctx: ToolContext, args: SwarmBlackboardReadInput) -> ToolOutcome:
    entries = ctx.runtime.swarm.read_blackboard(
        project_id=args.project_id,
        topic=args.topic,
        author=args.author,
        min_confidence=args.min_confidence,
    )
    return ToolOutcome(data={"entries": [e.model_dump() for e in entries], "count": len(entries)})


async def _swarm_edict_gate_evaluate(
    ctx: ToolContext, args: SwarmEdictGateEvaluateInput
) -> ToolOutcome:
    res = ctx.runtime.swarm.evaluate_edict_gate(
        project_id=args.project_id,
        action_type=args.action_type,
        draft_summary=args.draft_summary,
        risk_level=args.risk_level,
        bypass_requested=args.bypass_requested,
    )
    return ToolOutcome(data=res.model_dump())


async def _loopx_goal_control_plane(
    ctx: ToolContext, args: LoopXGoalControlPlaneInput
) -> ToolOutcome:
    res = ctx.runtime.swarm.manage_loopx_goal(
        action=args.action,
        project_id=args.project_id,
        goal_id=args.goal_id,
        title=args.title,
        attention_item=args.attention_item,
        checkpoint_data=args.checkpoint_data,
    )
    return ToolOutcome(data=res)


# --- Register Function ---


def register(registry: CapabilityRegistry) -> None:
    registry.register(
        ToolSpec(
            name="swarm_org_govern",
            title="Configure Swarm Roles and Hierarchy",
            description="Configures swarm roles, reporting hierarchies, and delegation paths for multi-agent audits.",
            input_model=SwarmOrgGovernInput,
            handler=_swarm_org_govern,
            family="swarm",
            profiles=ADMIN_AND_SWARM,
            scopes=frozenset({PROJECT_READ}),
            annotations=ToolAnnotations(read_only=False),
        )
    )
    registry.register(
        ToolSpec(
            name="swarm_budget_meter",
            title="Track Token and Cost Budget",
            description="Enforces hard token and cost ceilings per project, session, and subagent.",
            input_model=SwarmBudgetMeterInput,
            handler=_swarm_budget_meter,
            family="swarm",
            profiles=ADMIN_AND_SWARM,
            scopes=frozenset({PROJECT_READ}),
            annotations=ToolAnnotations(read_only=False),
        )
    )
    registry.register(
        ToolSpec(
            name="subagent_deerflow_spawn",
            title="Spawn Long-Horizon Recursive Research Subagent",
            description="Spawns autonomous recursive exploration subagents with persistent isolated scratchpads.",
            input_model=SubagentDeerflowSpawnInput,
            handler=_subagent_deerflow_spawn,
            family="swarm",
            profiles=CORE_AND_SWARM,
            scopes=frozenset({PROJECT_READ, PROJECT_WRITE}),
            annotations=ToolAnnotations(read_only=False),
        )
    )
    registry.register(
        ToolSpec(
            name="memory_tideline_sync",
            title="Synchronize Persistent Tideline Memory Graph",
            description="Synchronizes discovered entities, symbols, and attributes into persistent Tideline memory.",
            input_model=MemoryTidelineSyncInput,
            handler=_memory_tideline_sync,
            family="swarm",
            profiles=CORE_AND_SWARM,
            scopes=frozenset({PROJECT_READ, PROJECT_WRITE}),
            annotations=ToolAnnotations(read_only=False),
        )
    )
    registry.register(
        ToolSpec(
            name="sop_pipeline_execute",
            title="Execute Standardized Reverse-Engineering SOP",
            description="Executes standardized multi-role reverse-engineering SOP state machines across agents.",
            input_model=SopPipelineExecuteInput,
            handler=_sop_pipeline_execute,
            family="swarm",
            profiles=CORE_AND_SWARM,
            scopes=frozenset({PROJECT_READ}),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="swarm_blackboard_post",
            title="Post Hypothesis or Evidence to Swarm Blackboard",
            description="Posts observations, hypotheses, and evidence findings to the shared swarm blackboard.",
            input_model=SwarmBlackboardPostInput,
            handler=_swarm_blackboard_post,
            family="swarm",
            profiles=CORE_AND_SWARM,
            scopes=frozenset({PROJECT_READ, PROJECT_WRITE}),
            annotations=ToolAnnotations(read_only=False),
        )
    )
    registry.register(
        ToolSpec(
            name="swarm_blackboard_read",
            title="Query Shared Swarm Blackboard",
            description="Queries and filters the shared swarm blackboard by topic, author, or confidence score.",
            input_model=SwarmBlackboardReadInput,
            handler=_swarm_blackboard_read,
            family="swarm",
            profiles=CORE_AND_SWARM,
            scopes=frozenset({PROJECT_READ}),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="swarm_edict_gate_evaluate",
            title="Evaluate Tri-Chamber Edict Governance Gate",
            description="Evaluates proposed actions through Tri-Chamber review and enforces veto gates.",
            input_model=SwarmEdictGateEvaluateInput,
            handler=_swarm_edict_gate_evaluate,
            family="swarm",
            profiles=ADMIN_AND_SWARM,
            scopes=frozenset({PROJECT_READ}),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="loopx_goal_control_plane",
            title="Manage Long-Horizon Reversing Goals and Attention Queue",
            description="Manages long-horizon reversing goals, attention queues, and persistent session state.",
            input_model=LoopXGoalControlPlaneInput,
            handler=_loopx_goal_control_plane,
            family="swarm",
            profiles=ADMIN_AND_SWARM,
            scopes=frozenset({PROJECT_READ, PROJECT_WRITE}),
            annotations=ToolAnnotations(read_only=False),
        )
    )
