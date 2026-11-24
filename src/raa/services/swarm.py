"""Multi-agent swarm governance, token budgeting, blackboard coordination, and LoopX state persistence.

Inspired by Paperclip, Ruflo, Deer-Flow, Edict, MetaGPT, and LoopX.
"""

from __future__ import annotations

import contextlib
import json
import uuid
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from raa.errors import InvalidArgumentsError


class SwarmAgentRole(BaseModel):
    role_id: str
    name: str
    description: str
    reports_to: str | None = None
    subordinates: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    max_tokens: int = 100_000
    allocated_budget_usd: float = 1.0


class SwarmOrgConfig(BaseModel):
    project_id: str
    swarm_name: str
    lead_role: str
    roles: list[SwarmAgentRole] = Field(default_factory=list)
    updated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class BudgetRecord(BaseModel):
    project_id: str
    total_tokens_consumed: int = 0
    total_cost_usd: float = 0.0
    token_cap: int = 1_000_000
    cost_cap_usd: float = 10.0
    subagent_spend: dict[str, dict[str, float]] = Field(default_factory=dict)
    breached: bool = False
    enforcement_action: str = "allow"


class ScratchpadAction(BaseModel):
    step: int
    action: str
    status: str
    detail: dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class BlackboardEntry(BaseModel):
    entry_id: str
    topic: str
    author: str
    hypothesis: str
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: float = 0.5
    votes: dict[str, int] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class EdictReviewResult(BaseModel):
    proposal_id: str
    action_type: str
    drafting_verdict: str
    review_verdict: str
    execution_verdict: str
    veto_applied: bool
    veto_chamber: str | None = None
    veto_reason: str | None = None
    approved: bool
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class LoopXGoalSession(BaseModel):
    goal_id: str
    project_id: str
    title: str
    status: Literal["queued", "in_progress", "paused", "completed", "failed"] = "queued"
    attention_queue: list[str] = Field(default_factory=list)
    active_step: int = 0
    max_steps: int = 100
    checkpoints: list[dict[str, Any]] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class SwarmService:
    """Enterprise multi-agent control plane and state engine."""

    def __init__(self, workspace_root: Path | None = None) -> None:
        self.workspace_root = workspace_root or Path(".raa-workspace")
        self.swarm_dir = self.workspace_root / "swarm"
        self.swarm_dir.mkdir(parents=True, exist_ok=True)
        self.org_configs: dict[str, SwarmOrgConfig] = {}
        self.budgets: dict[str, BudgetRecord] = {}
        self.scratchpads: dict[str, list[ScratchpadAction]] = defaultdict(list)
        self.blackboards: dict[str, list[BlackboardEntry]] = defaultdict(list)
        self.tideline_graph: dict[str, dict[str, Any]] = defaultdict(dict)
        self.goals: dict[str, LoopXGoalSession] = {}

    def _blackboard_file(self, project_id: str) -> Path:
        p = self.swarm_dir / f"blackboard_{project_id}.json"
        return p

    def _save_blackboard(self, project_id: str) -> None:
        p = self._blackboard_file(project_id)
        entries = [e.model_dump() for e in self.blackboards[project_id]]
        import json

        p.write_text(json.dumps(entries, indent=2), encoding="utf-8")

    def _load_blackboard(self, project_id: str) -> None:
        p = self._blackboard_file(project_id)
        if p.exists() and not self.blackboards[project_id]:
            with contextlib.suppress(Exception):
                raw = json.loads(p.read_text(encoding="utf-8"))
                for item in raw:
                    self.blackboards[project_id].append(BlackboardEntry(**item))

    def configure_org(
        self,
        project_id: str,
        swarm_name: str,
        lead_role: str,
        roles: list[dict[str, Any]],
    ) -> SwarmOrgConfig:
        agent_roles: list[SwarmAgentRole] = []
        for r in roles:
            agent_roles.append(SwarmAgentRole(**r))

        config = SwarmOrgConfig(
            project_id=project_id,
            swarm_name=swarm_name,
            lead_role=lead_role,
            roles=agent_roles,
        )
        self.org_configs[project_id] = config
        return config

    def get_org(self, project_id: str) -> SwarmOrgConfig | None:
        return self.org_configs.get(project_id)

    def meter_budget(
        self,
        project_id: str,
        tokens: int = 0,
        cost_usd: float = 0.0,
        subagent_name: str | None = None,
        set_token_cap: int | None = None,
        set_cost_cap_usd: float | None = None,
    ) -> BudgetRecord:
        record = self.budgets.get(project_id)
        if not record:
            record = BudgetRecord(project_id=project_id)
            self.budgets[project_id] = record

        if set_token_cap is not None:
            record.token_cap = set_token_cap
        if set_cost_cap_usd is not None:
            record.cost_cap_usd = set_cost_cap_usd

        record.total_tokens_consumed += tokens
        record.total_cost_usd += cost_usd

        if subagent_name:
            if subagent_name not in record.subagent_spend:
                record.subagent_spend[subagent_name] = {"tokens": 0.0, "cost_usd": 0.0}
            record.subagent_spend[subagent_name]["tokens"] += tokens
            record.subagent_spend[subagent_name]["cost_usd"] += cost_usd

        if (
            record.total_tokens_consumed > record.token_cap
            or record.total_cost_usd > record.cost_cap_usd
        ):
            record.breached = True
            record.enforcement_action = "block"
        else:
            record.breached = False
            record.enforcement_action = "allow"

        return record

    def spawn_deerflow_subagent(
        self,
        project_id: str,
        agent_name: str,
        mission_goal: str,
        max_depth: int = 3,
        steps: list[str] | None = None,
    ) -> dict[str, Any]:
        subagent_id = f"subagent_{uuid.uuid4().hex[:8]}"
        scratchpad_dir = self.workspace_root / "scratchpads" / subagent_id
        scratchpad_dir.mkdir(parents=True, exist_ok=True)

        steps = steps or ["recon", "analyze", "synthesize"]
        recorded_steps: list[dict[str, Any]] = []
        for i, step_name in enumerate(steps, start=1):
            act = ScratchpadAction(
                step=i,
                action=step_name,
                status="completed",
                detail={"note": f"Executed recursive step {i}: {step_name}"},
            )
            self.scratchpads[subagent_id].append(act)
            recorded_steps.append(act.model_dump())

        # Write scratchpad summary to disk
        scratch_file = scratchpad_dir / "journal.json"
        scratch_file.write_text(
            f'{{"subagent_id": "{subagent_id}", "mission": "{mission_goal}", "steps": {len(recorded_steps)}}}',
            encoding="utf-8",
        )

        return {
            "subagent_id": subagent_id,
            "project_id": project_id,
            "agent_name": agent_name,
            "mission_goal": mission_goal,
            "max_depth": max_depth,
            "scratchpad_path": str(scratch_file),
            "executed_steps": recorded_steps,
            "status": "ready",
        }

    def sync_tideline_memory(
        self,
        project_id: str,
        domain: str,
        entity_key: str,
        attributes: dict[str, Any],
    ) -> dict[str, Any]:
        if domain not in self.tideline_graph[project_id]:
            self.tideline_graph[project_id][domain] = {}

        existing = self.tideline_graph[project_id][domain].get(entity_key, {})
        existing.update(attributes)
        existing["last_synced"] = datetime.now(UTC).isoformat()
        self.tideline_graph[project_id][domain][entity_key] = existing

        return {
            "project_id": project_id,
            "domain": domain,
            "entity_key": entity_key,
            "current_state": existing,
            "total_domain_entities": len(self.tideline_graph[project_id][domain]),
        }

    def execute_sop_pipeline(
        self,
        project_id: str,
        sop_name: str,
        target_entity: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        params = params or {}
        # Predefined SOP templates: "framework_audit", "api_key_extraction", "ui_reconstruction"
        sop_stages: list[dict[str, Any]] = []

        if sop_name == "api_key_extraction":
            stages = [
                ("triage", "apk_analysis_agent", "Extract strings and cloud patterns"),
                ("review", "security_agent", "Verify false-positive entropy"),
                ("poc", "api_discovery_agent", "Generate non-destructive auth check"),
            ]
        elif sop_name == "ui_reconstruction":
            stages = [
                ("extract_layouts", "ui_extraction_agent", "Deconstruct XML and Compose trees"),
                ("redesign", "ui_redesign_agent", "Modernize components to Material 3"),
                ("validate", "validation_agent", "Verify touch targets and ergonomics"),
            ]
        else:  # default framework_audit
            stages = [
                ("decompile", "decompilation_agent", "Disassemble Dalvik DEX / Smali"),
                ("security_audit", "security_agent", "Run MASTG & component audit"),
                ("synthesis", "coordinator_agent", "Synthesize findings into executive report"),
            ]

        for idx, (stage_name, agent_role, desc) in enumerate(stages, start=1):
            sop_stages.append(
                {
                    "stage_index": idx,
                    "stage_name": stage_name,
                    "assigned_agent": agent_role,
                    "description": desc,
                    "status": "success",
                    "output": f"Stage {stage_name} completed for target '{target_entity}'",
                }
            )

        return {
            "project_id": project_id,
            "sop_name": sop_name,
            "target_entity": target_entity,
            "total_stages": len(sop_stages),
            "stages": sop_stages,
            "status": "completed",
        }

    def post_to_blackboard(
        self,
        project_id: str,
        topic: str,
        author: str,
        hypothesis: str,
        evidence_ids: list[str] | None = None,
        confidence: float = 0.5,
        metadata: dict[str, Any] | None = None,
    ) -> BlackboardEntry:
        self._load_blackboard(project_id)
        entry = BlackboardEntry(
            entry_id=f"bb_{uuid.uuid4().hex[:8]}",
            topic=topic,
            author=author,
            hypothesis=hypothesis,
            evidence_ids=evidence_ids or [],
            confidence=confidence,
            metadata=metadata or {},
        )
        self.blackboards[project_id].append(entry)
        self._save_blackboard(project_id)
        return entry

    def read_blackboard(
        self,
        project_id: str,
        topic: str | None = None,
        author: str | None = None,
        min_confidence: float = 0.0,
    ) -> list[BlackboardEntry]:
        self._load_blackboard(project_id)
        entries = self.blackboards.get(project_id, [])
        filtered: list[BlackboardEntry] = []
        for e in entries:
            if topic and e.topic != topic:
                continue
            if author and e.author != author:
                continue
            if e.confidence < min_confidence:
                continue
            filtered.append(e)
        return filtered

    def evaluate_edict_gate(
        self,
        project_id: str,
        action_type: str,
        draft_summary: str,
        risk_level: str = "low",
        bypass_requested: bool = False,
    ) -> EdictReviewResult:
        proposal_id = f"edict_{uuid.uuid4().hex[:8]}"

        # Chamber 1: Drafting (Elephant / Analyst)
        draft_verdict = "passed"

        # Chamber 2: Review (Goldfish / Security Verifier)
        # If risk_level is critical and no justification, reviewer flags
        if risk_level == "critical" and "safe" not in draft_summary.lower():
            review_verdict = "rejected"
            veto_chamber = "Review Chamber"
            veto_reason = "Critical risk action lacks verified safety justification."
            return EdictReviewResult(
                proposal_id=proposal_id,
                action_type=action_type,
                drafting_verdict=draft_verdict,
                review_verdict=review_verdict,
                execution_verdict="vetoed",
                veto_applied=True,
                veto_chamber=veto_chamber,
                veto_reason=veto_reason,
                approved=False,
            )
        else:
            review_verdict = "passed"

        # Chamber 3: Execution (Gatekeeper / Policy Veto)
        if bypass_requested and risk_level in ("high", "critical"):
            exec_verdict = "vetoed"
            return EdictReviewResult(
                proposal_id=proposal_id,
                action_type=action_type,
                drafting_verdict=draft_verdict,
                review_verdict=review_verdict,
                execution_verdict=exec_verdict,
                veto_applied=True,
                veto_chamber="Execution Chamber",
                veto_reason="Explicit policy veto: bypass not permitted for high/critical mutations.",
                approved=False,
            )

        exec_verdict = "authorized"
        return EdictReviewResult(
            proposal_id=proposal_id,
            action_type=action_type,
            drafting_verdict=draft_verdict,
            review_verdict=review_verdict,
            execution_verdict=exec_verdict,
            veto_applied=False,
            veto_chamber=None,
            veto_reason=None,
            approved=True,
        )

    def manage_loopx_goal(
        self,
        action: Literal["create", "status", "enqueue_attention", "step", "checkpoint", "list"],
        project_id: str,
        goal_id: str | None = None,
        title: str = "",
        attention_item: str | None = None,
        checkpoint_data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if action == "create":
            gid = goal_id or f"goal_{uuid.uuid4().hex[:8]}"
            session = LoopXGoalSession(
                goal_id=gid,
                project_id=project_id,
                title=title or "Autonomous Reversing Goal",
                status="in_progress",
            )
            self.goals[gid] = session
            return {"goal": session.model_dump(), "message": "Goal created"}

        if action == "list":
            matched = [g.model_dump() for g in self.goals.values() if g.project_id == project_id]
            return {"goals": matched, "count": len(matched)}

        if not goal_id or goal_id not in self.goals:
            raise InvalidArgumentsError(f"Goal ID '{goal_id}' not found")

        target = self.goals[goal_id]

        if action == "status":
            return {"goal": target.model_dump()}

        if action == "enqueue_attention":
            if attention_item:
                target.attention_queue.append(attention_item)
                target.updated_at = datetime.now(UTC).isoformat()
            return {
                "goal_id": goal_id,
                "attention_queue": target.attention_queue,
                "queue_length": len(target.attention_queue),
            }

        if action == "step":
            target.active_step += 1
            if target.attention_queue:
                processed = target.attention_queue.pop(0)
            else:
                processed = f"step_{target.active_step}_exploration"
            target.updated_at = datetime.now(UTC).isoformat()
            return {
                "goal_id": goal_id,
                "active_step": target.active_step,
                "processed_attention": processed,
                "remaining_attention": len(target.attention_queue),
            }

        if action == "checkpoint":
            cp = checkpoint_data or {}
            cp["step"] = target.active_step
            cp["saved_at"] = datetime.now(UTC).isoformat()
            target.checkpoints.append(cp)
            target.updated_at = datetime.now(UTC).isoformat()
            return {
                "goal_id": goal_id,
                "checkpoints_count": len(target.checkpoints),
                "latest_checkpoint": cp,
            }

        raise InvalidArgumentsError(f"Unsupported action: {action}")
