"""Phase 19 Tools: Enterprise MCP & Multi-Harness CLI Ecosystem Integration.

Registers 12 tools:
- mcp_postman_collection_run
- mcp_postman_test_assert
- mcp_github_pr_manage
- mcp_playwright_webview_test
- mcp_apify_store_scrape
- cli_harness_dispatch
- omnigent_meta_policy_enforce
- spring_ai_nacos_register
- n8n_workflow_bridge_sync
- engine_wasm_plugin_sandbox
- binary_byte_search_entropy
- forensic_mutation_digest_guard
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


class MCPPostmanCollectionRunInput(ToolInput):
    collection_path: str = Field(min_length=1, description="Path to Postman collection JSON.")
    environment_vars: dict[str, str] = Field(
        default_factory=dict, description="Environment variables."
    )


class MCPPostmanTestAssertInput(ToolInput):
    endpoint_url: str = Field(min_length=1, description="Endpoint URL to test.")
    expected_status: int = Field(default=200, description="Expected HTTP response status code.")


class MCPGitHubPRManageInput(ToolInput):
    repo: str = Field(min_length=1, description="GitHub repository (owner/repo).")
    title: str = Field(min_length=1, description="PR Title.")
    head_branch: str = Field(min_length=1, description="Head feature branch name.")
    base_branch: str = Field(default="main", description="Base branch name.")


class MCPPlaywrightWebViewTestInput(ToolInput):
    target_url: str = Field(min_length=1, description="Target WebView or companion URL.")
    capture_oauth: bool = Field(default=True, description="Capture OAuth tokens.")


class MCPApifyStoreScrapeInput(ToolInput):
    store: Literal["google_play", "apple_app_store"] = Field(
        default="google_play",
        description="Target app marketplace.",
    )
    app_id: str = Field(min_length=1, description="Target application package ID.")


class CLIHarnessDispatchInput(ToolInput):
    harness: Literal[
        "claude_code",
        "codex",
        "gemini_cli",
        "antigravity",
        "deepseek_cli",
        "minimax_cli",
        "grok_build",
    ] = Field(
        description="Target external coding CLI.",
    )
    task_instruction: str = Field(
        min_length=1, description="Task instruction for the external CLI."
    )


class OmnigentMetaPolicyEnforceInput(ToolInput):
    agent_id: str = Field(min_length=1, description="Subagent or external agent ID.")
    requested_action: str = Field(min_length=1, description="Requested action or tool name.")


class SpringAINacosRegisterInput(ToolInput):
    service_name: str = Field(
        default="raa-mcp-service", description="Service name in Nacos registry."
    )
    tools_count: int = Field(default=312, description="Number of tools to register.")


class N8NWorkflowBridgeSyncInput(ToolInput):
    workflow_name: str = Field(min_length=1, description="n8n workflow name.")
    trigger_event: str = Field(min_length=1, description="Event triggering the workflow.")


class EngineWASMPluginSandboxInput(ToolInput):
    plugin_name: str = Field(min_length=1, description="WASM plugin name.")
    plugin_bytes_hex: str = Field(default="0061736d", description="Hex-encoded WASM binary.")


class BinaryByteSearchEntropyInput(ToolInput):
    target_binary: str = Field(min_length=1, description="Path to target native binary.")


class ForensicMutationDigestGuardInput(ToolInput):
    file_path: str = Field(min_length=1, description="Target file path.")
    pre_data_hex: str = Field(min_length=2, description="Pre-mutation hex-encoded bytes.")
    post_data_hex: str = Field(min_length=2, description="Post-mutation hex-encoded bytes.")


# --- Handlers ---


async def _mcp_postman_collection_run(
    ctx: ToolContext, args: MCPPostmanCollectionRunInput
) -> ToolOutcome:
    res = ctx.runtime.enterprise.run_postman_collection(
        collection_path=args.collection_path,
        environment_vars=args.environment_vars,
    )
    return ToolOutcome(data=res.model_dump())


async def _mcp_postman_test_assert(
    ctx: ToolContext, args: MCPPostmanTestAssertInput
) -> ToolOutcome:
    res = ctx.runtime.enterprise.assert_postman_endpoint(
        endpoint_url=args.endpoint_url,
        expected_status=args.expected_status,
    )
    return ToolOutcome(data=res.model_dump())


async def _mcp_github_pr_manage(ctx: ToolContext, args: MCPGitHubPRManageInput) -> ToolOutcome:
    res = ctx.runtime.enterprise.manage_github_pr(
        repo=args.repo,
        title=args.title,
        head_branch=args.head_branch,
        base_branch=args.base_branch,
    )
    return ToolOutcome(data=res.model_dump())


async def _mcp_playwright_webview_test(
    ctx: ToolContext, args: MCPPlaywrightWebViewTestInput
) -> ToolOutcome:
    res = ctx.runtime.enterprise.test_playwright_webview(
        target_url=args.target_url,
        capture_oauth=args.capture_oauth,
    )
    return ToolOutcome(data=res.model_dump())


async def _mcp_apify_store_scrape(ctx: ToolContext, args: MCPApifyStoreScrapeInput) -> ToolOutcome:
    res = ctx.runtime.enterprise.scrape_apify_store(
        store=args.store,
        app_id=args.app_id,
    )
    return ToolOutcome(data=res.model_dump())


async def _cli_harness_dispatch(ctx: ToolContext, args: CLIHarnessDispatchInput) -> ToolOutcome:
    res = ctx.runtime.enterprise.dispatch_cli_harness(
        harness=args.harness,
        task_instruction=args.task_instruction,
    )
    return ToolOutcome(data=res.model_dump())


async def _omnigent_meta_policy_enforce(
    ctx: ToolContext, args: OmnigentMetaPolicyEnforceInput
) -> ToolOutcome:
    res = ctx.runtime.enterprise.enforce_omnigent_policy(
        agent_id=args.agent_id,
        requested_action=args.requested_action,
    )
    return ToolOutcome(data=res.model_dump())


async def _spring_ai_nacos_register(
    ctx: ToolContext, args: SpringAINacosRegisterInput
) -> ToolOutcome:
    res = ctx.runtime.enterprise.register_spring_ai_nacos(
        service_name=args.service_name,
        tools_count=args.tools_count,
    )
    return ToolOutcome(data=res.model_dump())


async def _n8n_workflow_bridge_sync(
    ctx: ToolContext, args: N8NWorkflowBridgeSyncInput
) -> ToolOutcome:
    res = ctx.runtime.enterprise.sync_n8n_workflow(
        workflow_name=args.workflow_name,
        trigger_event=args.trigger_event,
    )
    return ToolOutcome(data=res.model_dump())


async def _engine_wasm_plugin_sandbox(
    ctx: ToolContext, args: EngineWASMPluginSandboxInput
) -> ToolOutcome:
    res = ctx.runtime.enterprise.execute_wasm_plugin(
        plugin_name=args.plugin_name,
        plugin_bytes_hex=args.plugin_bytes_hex,
    )
    return ToolOutcome(data=res.model_dump())


async def _binary_byte_search_entropy(
    ctx: ToolContext, args: BinaryByteSearchEntropyInput
) -> ToolOutcome:
    res = ctx.runtime.enterprise.scan_binary_simd_entropy(target_binary=args.target_binary)
    return ToolOutcome(data=res.model_dump())


async def _forensic_mutation_digest_guard(
    ctx: ToolContext, args: ForensicMutationDigestGuardInput
) -> ToolOutcome:
    pre_bytes = bytes.fromhex(args.pre_data_hex)
    post_bytes = bytes.fromhex(args.post_data_hex)
    res = ctx.runtime.enterprise.verify_mutation_digest(
        file_path=args.file_path,
        pre_data=pre_bytes,
        post_data=post_bytes,
    )
    return ToolOutcome(data=res.model_dump())


# --- Register Function ---


def register(registry: CapabilityRegistry) -> None:
    # 1. mcp_postman_collection_run
    registry.register(
        ToolSpec(
            name="mcp_postman_collection_run",
            title="Postman MCP API Test Collection Runner",
            description="Executes Postman API collections and automated assertions against live backend APIs via Postman MCP.",
            input_model=MCPPostmanCollectionRunInput,
            handler=_mcp_postman_collection_run,
            family="api",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    # 2. mcp_postman_test_assert
    registry.register(
        ToolSpec(
            name="mcp_postman_test_assert",
            title="Postman MCP Living Contract Assertion Tester",
            description="Validates API endpoint responses against expected security schemas, status codes, and headers.",
            input_model=MCPPostmanTestAssertInput,
            handler=_mcp_postman_test_assert,
            family="api",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    # 3. mcp_github_pr_manage
    registry.register(
        ToolSpec(
            name="mcp_github_pr_manage",
            title="GitHub MCP Repository & Pull Request Manager",
            description="Manages Git repositories, commits decompiled source trees, and opens Pull Requests via GitHub MCP.",
            input_model=MCPGitHubPRManageInput,
            handler=_mcp_github_pr_manage,
            family="scm",
            profiles=ADMIN,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=False),
        )
    )
    # 4. mcp_playwright_webview_test
    registry.register(
        ToolSpec(
            name="mcp_playwright_webview_test",
            title="Playwright MCP In-App WebView & OAuth Driver",
            description="Drives in-app WebViews and mobile web companions, intercepting OAuth tokens and authorization codes.",
            input_model=MCPPlaywrightWebViewTestInput,
            handler=_mcp_playwright_webview_test,
            family="browser",
            profiles=DYNAMIC,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    # 5. mcp_apify_store_scrape
    registry.register(
        ToolSpec(
            name="mcp_apify_store_scrape",
            title="Apify MCP Google Play & App Store Scraper",
            description="Scrapes Google Play Store and App Store metadata, version histories, and developer profiles.",
            input_model=MCPApifyStoreScrapeInput,
            handler=_mcp_apify_store_scrape,
            family="osint",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    # 6. cli_harness_dispatch
    registry.register(
        ToolSpec(
            name="cli_harness_dispatch",
            title="Universal Multi-Harness 7-CLI Gateway Dispatcher",
            description="Dispatches tasks to external coding CLIs (Claude, Codex, Gemini, AGY, DeepSeek, MiniMax, Grok).",
            input_model=CLIHarnessDispatchInput,
            handler=_cli_harness_dispatch,
            family="harness",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=False),
        )
    )
    # 7. omnigent_meta_policy_enforce
    registry.register(
        ToolSpec(
            name="omnigent_meta_policy_enforce",
            title="Omnigent Meta-Policy & Contextual Boundary Enforcer",
            description="Enforces fail-closed security policies, workspace boundaries, and token budgets across external agents.",
            input_model=OmnigentMetaPolicyEnforceInput,
            handler=_omnigent_meta_policy_enforce,
            family="governance",
            profiles=ADMIN,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    # 8. spring_ai_nacos_register
    registry.register(
        ToolSpec(
            name="spring_ai_nacos_register",
            title="Spring AI Nacos Service Discovery Registry Bridge",
            description="Registers RAA MCP tool capabilities into enterprise Nacos service discovery registries.",
            input_model=SpringAINacosRegisterInput,
            handler=_spring_ai_nacos_register,
            family="enterprise",
            profiles=ADMIN,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=False),
        )
    )
    # 9. n8n_workflow_bridge_sync
    registry.register(
        ToolSpec(
            name="n8n_workflow_bridge_sync",
            title="Enterprise n8n Workflow Automation Bridge",
            description="Emits and synchronizes n8n workflow definitions as code (n8nac) connecting RAA triggers to enterprise pipelines.",
            input_model=N8NWorkflowBridgeSyncInput,
            handler=_n8n_workflow_bridge_sync,
            family="enterprise",
            profiles=ADMIN,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=False),
        )
    )
    # 10. engine_wasm_plugin_sandbox
    registry.register(
        ToolSpec(
            name="engine_wasm_plugin_sandbox",
            title="WebAssembly (WASM) Sandboxed Tool Plugin Runtime",
            description="Executes third-party inspection plugins safely inside a sandboxed WASM runtime with strict quotas.",
            input_model=EngineWASMPluginSandboxInput,
            handler=_engine_wasm_plugin_sandbox,
            family="sandbox",
            profiles=ADMIN,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    # 11. binary_byte_search_entropy
    registry.register(
        ToolSpec(
            name="binary_byte_search_entropy",
            title="SIMD Byte Search & Shannon Entropy Analyzer",
            description="Scans raw binary sections for entropy heatmaps, encrypted blobs, and packing boundaries via SIMD.",
            input_model=BinaryByteSearchEntropyInput,
            handler=_binary_byte_search_entropy,
            family="binary",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    # 12. forensic_mutation_digest_guard
    registry.register(
        ToolSpec(
            name="forensic_mutation_digest_guard",
            title="Forensic Binary Mutation Digest & Non-Repudiation Guardrail",
            description="Enforces pre- and post-operation SHA-256 mutation verification guardrails to guarantee forensic chain-of-custody.",
            input_model=ForensicMutationDigestGuardInput,
            handler=_forensic_mutation_digest_guard,
            family="forensics",
            profiles=ADMIN,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True),
        )
    )
