"""Phase 16 Tools: Dual-Context Adversarial Auditing, Cognitive Reasoning & Exploit Economics.

Registers 9 tools:
- audit_elephant_draft_spec
- audit_goldfish_adversarial_review
- adk_workflow_run
- reasoning_strategy_select
- fin_iap_billing_audit
- exploit_payoff_simulate
- exec_briefing_synthesize
- sec_research_whitepaper_synthesize
- rag_haystack_query
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
from raa.registry.profiles import ADMIN, API, CORE

# --- Input Models ---


class AuditElephantDraftSpecInput(ToolInput):
    project_id: str = Field(min_length=1, description="Target project ID.")
    target_component: str = Field(
        min_length=1, description="Target class, component or native library."
    )
    architecture_overview: str = Field(
        min_length=1, description="Elephant broad architectural overview."
    )
    codebase_context: str = Field(min_length=1, description="Comprehensive codebase context.")
    claims: list[dict[str, Any]] = Field(
        default_factory=list, description="Reversing hypotheses and findings."
    )


class AuditGoldfishAdversarialReviewInput(ToolInput):
    project_id: str = Field(min_length=1, description="Target project ID.")
    claim_id: str = Field(min_length=1, description="Identifier of the claim under review.")
    claim_text: str = Field(min_length=1, description="Claim text to be adversarially examined.")
    isolated_evidence: list[str] = Field(
        description="Strictly isolated evidence snippets with zero prior chat context."
    )
    prior_confidence: float = Field(
        default=0.8, ge=0.0, le=1.0, description="Prior confidence score."
    )


class ADKWorkflowRunInput(ToolInput):
    project_id: str = Field(min_length=1, description="Target project ID.")
    workflow_name: str = Field(
        default="adk_reversing_pipeline",
        description="Name of the Google ADK Python state machine workflow.",
    )
    initial_state: dict[str, Any] = Field(
        default_factory=dict, description="Initial workflow state parameters."
    )


class ReasoningStrategySelectInput(ToolInput):
    target: str = Field(min_length=1, description="Target APK or component identifier.")
    obfuscation_level: Literal["none", "low", "medium", "high", "packed"] = Field(
        default="low",
        description="Assessed code obfuscation level.",
    )
    has_native_crypto: bool = Field(
        default=False, description="Whether target utilizes native JNI cryptography."
    )
    lines_of_code: int = Field(
        default=1000, ge=1, description="Estimated total lines of decompiled code."
    )


class FinIAPBillingAuditInput(ToolInput):
    project_id: str = Field(min_length=1, description="Target project ID.")
    declared_permissions: list[str] = Field(
        default_factory=list, description="Extracted manifest permissions."
    )
    decompiled_classes: list[str] = Field(
        default_factory=list, description="List of class names identified."
    )
    string_constants: list[str] = Field(
        default_factory=list, description="Extracted strings and method names."
    )


class ExploitPayoffSimulateInput(ToolInput):
    vulnerability_id: str = Field(min_length=1, description="Vulnerability tracking identifier.")
    vulnerability_title: str = Field(min_length=1, description="Descriptive title of the flaw.")
    severity: Literal["low", "medium", "high", "critical"] = Field(
        default="high",
        description="Assessed severity level.",
    )
    attacker_skill_required: Literal["script_kiddie", "intermediate", "expert", "nation_state"] = (
        Field(
            default="intermediate",
            description="Required attacker competence.",
        )
    )
    exploit_asset_type: Literal["data_leak", "payment_bypass", "rce", "privilege_escalation"] = (
        Field(
            default="payment_bypass",
            description="Type of exploit impact.",
        )
    )


class ExecBriefingSynthesizeInput(ToolInput):
    project_id: str = Field(min_length=1, description="Target project ID.")
    app_name: str = Field(min_length=1, description="Application name.")
    vulnerabilities: list[dict[str, Any]] = Field(
        default_factory=list, description="List of confirmed vulnerabilities."
    )
    total_users: int = Field(default=100000, ge=1, description="Estimated total active users.")


class SecResearchWhitepaperSynthesizeInput(ToolInput):
    project_id: str = Field(min_length=1, description="Target project ID.")
    paper_title: str = Field(min_length=1, description="Title of the research paper.")
    vulnerability_mechanisms: list[str] = Field(
        description="List of technical root causes and exploit vectors."
    )
    cve_candidate: str | None = Field(
        default=None, description="Optional designated CVE candidate ID."
    )


class RagHaystackQueryInput(ToolInput):
    project_id: str = Field(min_length=1, description="Target project ID.")
    query: str = Field(
        min_length=1, description="Semantic or keyword query across decompiled codebase."
    )
    top_k: int = Field(default=5, ge=1, le=50, description="Number of results to return.")
    index_documents: dict[str, str] | None = Field(
        default=None, description="Optional code files to index."
    )


# --- Handlers ---


async def _audit_elephant_draft_spec(
    ctx: ToolContext, args: AuditElephantDraftSpecInput
) -> ToolOutcome:
    spec = ctx.runtime.cognitive.draft_elephant_spec(
        project_id=args.project_id,
        target_component=args.target_component,
        architecture_overview=args.architecture_overview,
        codebase_context=args.codebase_context,
        claims=args.claims,
    )
    return ToolOutcome(data=spec.model_dump())


async def _audit_goldfish_adversarial_review(
    ctx: ToolContext, args: AuditGoldfishAdversarialReviewInput
) -> ToolOutcome:
    review = ctx.runtime.cognitive.review_goldfish_adversarial(
        project_id=args.project_id,
        claim_id=args.claim_id,
        claim_text=args.claim_text,
        isolated_evidence=args.isolated_evidence,
        prior_confidence=args.prior_confidence,
    )
    return ToolOutcome(data=review.model_dump())


async def _adk_workflow_run(ctx: ToolContext, args: ADKWorkflowRunInput) -> ToolOutcome:
    result = ctx.runtime.cognitive.run_adk_workflow(
        project_id=args.project_id,
        workflow_name=args.workflow_name,
        initial_state=args.initial_state,
    )
    return ToolOutcome(data=result.model_dump())


async def _reasoning_strategy_select(
    ctx: ToolContext, args: ReasoningStrategySelectInput
) -> ToolOutcome:
    decision = ctx.runtime.cognitive.select_reasoning_strategy(
        target=args.target,
        obfuscation_level=args.obfuscation_level,
        has_native_crypto=args.has_native_crypto,
        lines_of_code=args.lines_of_code,
    )
    return ToolOutcome(data=decision.model_dump())


async def _fin_iap_billing_audit(ctx: ToolContext, args: FinIAPBillingAuditInput) -> ToolOutcome:
    report = ctx.runtime.cognitive.audit_iap_billing(
        project_id=args.project_id,
        declared_permissions=args.declared_permissions,
        decompiled_classes=args.decompiled_classes,
        string_constants=args.string_constants,
    )
    return ToolOutcome(data=report.model_dump())


async def _exploit_payoff_simulate(
    ctx: ToolContext, args: ExploitPayoffSimulateInput
) -> ToolOutcome:
    matrix = ctx.runtime.cognitive.simulate_exploit_payoff(
        vulnerability_id=args.vulnerability_id,
        vulnerability_title=args.vulnerability_title,
        severity=args.severity,
        attacker_skill_required=args.attacker_skill_required,
        exploit_asset_type=args.exploit_asset_type,
    )
    return ToolOutcome(data=matrix.model_dump())


async def _exec_briefing_synthesize(
    ctx: ToolContext, args: ExecBriefingSynthesizeInput
) -> ToolOutcome:
    briefing = ctx.runtime.cognitive.synthesize_exec_briefing(
        project_id=args.project_id,
        app_name=args.app_name,
        vulnerabilities=args.vulnerabilities,
        total_users=args.total_users,
    )
    return ToolOutcome(data=briefing.model_dump())


async def _sec_research_whitepaper_synthesize(
    ctx: ToolContext, args: SecResearchWhitepaperSynthesizeInput
) -> ToolOutcome:
    whitepaper = ctx.runtime.cognitive.synthesize_research_whitepaper(
        project_id=args.project_id,
        paper_title=args.paper_title,
        vulnerability_mechanisms=args.vulnerability_mechanisms,
        cve_candidate=args.cve_candidate,
    )
    return ToolOutcome(data=whitepaper.model_dump())


async def _rag_haystack_query(ctx: ToolContext, args: RagHaystackQueryInput) -> ToolOutcome:
    if args.index_documents:
        ctx.runtime.cognitive.index_code_documents(args.project_id, args.index_documents)
    results = ctx.runtime.cognitive.query_haystack_rag(
        project_id=args.project_id,
        query=args.query,
        top_k=args.top_k,
    )
    return ToolOutcome(data=results)


# --- Register Function ---


def register(registry: CapabilityRegistry) -> None:
    registry.register(
        ToolSpec(
            name="audit_elephant_draft_spec",
            title="Draft Full-Context Reversing Specification",
            description="Drafts comprehensive reverse-engineering and patch specifications using complete codebase context.",
            input_model=AuditElephantDraftSpecInput,
            handler=_audit_elephant_draft_spec,
            family="cognitive",
            profiles=CORE,
            scopes=frozenset({PROJECT_READ, PROJECT_WRITE}),
            annotations=ToolAnnotations(read_only=False),
        )
    )
    registry.register(
        ToolSpec(
            name="audit_goldfish_adversarial_review",
            title="Adversarial Zero-Context Finding Verification",
            description="Executes zero-context adversarial review on proposed claims to eliminate hallucination and confirmation bias.",
            input_model=AuditGoldfishAdversarialReviewInput,
            handler=_audit_goldfish_adversarial_review,
            family="cognitive",
            profiles=CORE,
            scopes=frozenset({PROJECT_READ}),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="adk_workflow_run",
            title="Execute Code-First Google ADK Python Workflow",
            description="Executes deterministic Python state machines with OpenTelemetry span tracing.",
            input_model=ADKWorkflowRunInput,
            handler=_adk_workflow_run,
            family="cognitive",
            profiles=CORE,
            scopes=frozenset({PROJECT_READ}),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="reasoning_strategy_select",
            title="Select Optimal Cognitive Reasoning Paradigm",
            description="Selects optimal agent reasoning paradigm (Fast ReAct, Plan-Solve, Debate) based on complexity and packing.",
            input_model=ReasoningStrategySelectInput,
            handler=_reasoning_strategy_select,
            family="cognitive",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="fin_iap_billing_audit",
            title="Audit In-App Purchase and Billing Workflows",
            description="Audits client-side receipt validation flaws, intent spoofing in payment callbacks, and unverified server responses.",
            input_model=FinIAPBillingAuditInput,
            handler=_fin_iap_billing_audit,
            family="monetization",
            profiles=API,
            scopes=frozenset({PROJECT_READ}),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="exploit_payoff_simulate",
            title="Simulate Quantitative Exploit Economics Matrix",
            description="Calculates quantitative exploit payoff matrices: evaluates attacker cost vs potential economic payoff.",
            input_model=ExploitPayoffSimulateInput,
            handler=_exploit_payoff_simulate,
            family="economics",
            profiles=ADMIN,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="exec_briefing_synthesize",
            title="Synthesize Board-Level Executive Risk Briefing",
            description="Synthesizes non-technical C-suite risk summaries detailing compliance exposure and remediation roadmaps.",
            input_model=ExecBriefingSynthesizeInput,
            handler=_exec_briefing_synthesize,
            family="reporting",
            profiles=ADMIN,
            scopes=frozenset({PROJECT_READ}),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="sec_research_whitepaper_synthesize",
            title="Synthesize Academic Vulnerability Research Whitepaper",
            description="Synthesizes academic-grade vulnerability whitepapers, literature reviews, and CVE disclosure briefs.",
            input_model=SecResearchWhitepaperSynthesizeInput,
            handler=_sec_research_whitepaper_synthesize,
            family="reporting",
            profiles=ADMIN,
            scopes=frozenset({PROJECT_READ}),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="rag_haystack_query",
            title="Query Decompiled Code via Haystack RAG Pipeline",
            description="Queries decompiled code repositories using hybrid semantic and sparse BM25 search pipelines.",
            input_model=RagHaystackQueryInput,
            handler=_rag_haystack_query,
            family="cognitive",
            profiles=CORE,
            scopes=frozenset({PROJECT_READ}),
            annotations=ToolAnnotations(read_only=True),
        )
    )
