"""Toolchain, licence, production hardening, and enterprise admin tools."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field

from raa.policy.scopes import PROJECT_READ
from raa.registry.models import (
    CapabilityRegistry,
    ToolAnnotations,
    ToolContext,
    ToolInput,
    ToolOutcome,
    ToolSpec,
)
from raa.registry.profiles import ADMIN, CORE_AND_ADMIN


class EmptyInput(ToolInput):
    pass


class AdminEngineVerifyInput(ToolInput):
    engine_id: str | None = Field(default=None, description="Optional engine ID to verify.")


class AgentCoverageGetInput(ToolInput):
    project_id: str = Field(min_length=1, description="Target project ID.")


class AdminAuditQueryInput(ToolInput):
    tool: str | None = Field(default=None, description="Filter by tool name.")
    outcome: str | None = Field(default=None, description="Filter by outcome (success, error).")
    error_code: str | None = Field(default=None, description="Filter by error code.")
    project_id: str | None = Field(default=None, description="Filter by project ID.")
    request_id: str | None = Field(default=None, description="Filter by request ID.")
    limit: int = Field(default=50, ge=1, le=500, description="Max audit entries to return.")
    offset: int = Field(default=0, ge=0, description="Pagination offset.")


class AdminSignatureVerifyInput(ToolInput):
    content_type: str = Field(
        default="skill",
        description="Type of content being verified: 'skill', 'recipe', 'manifest', or 'file'.",
    )
    name: str = Field(min_length=1, description="Content or item name.")
    signature: str | None = Field(default=None, description="Optional signature hex digest.")
    file_path: str | None = Field(
        default=None,
        description="Optional file path on disk to verify with detached signature.",
    )


class AdminSbomGenerateInput(ToolInput):
    format: str = Field(
        default="cyclonedx",
        description="SBOM format: 'cyclonedx' (CycloneDX v1.5 JSON) or 'spdx' (SPDX 2.3 JSON).",
    )


class AdminBackupCreateInput(ToolInput):
    project_id: str = Field(min_length=1, description="Target project ID to back up.")
    output_path: str | None = Field(
        default=None,
        description="Optional custom path for the generated .raa.bundle.tar.gz file.",
    )


class AdminBackupRestoreInput(ToolInput):
    bundle_path: str = Field(
        min_length=1,
        description="Path to the .raa.bundle.tar.gz file on disk.",
    )
    new_name: str | None = Field(
        default=None,
        description="Optional new name for the restored project.",
    )


class AdminRetentionPurgeInput(ToolInput):
    retention_days: int = Field(
        default=30,
        ge=1,
        le=3650,
        description=(
            "Prune temporary bundles and expired artifacts older than this threshold in days."
        ),
    )


class AdminZtnaTunnelConfigInput(ToolInput):
    """Parameters to configure a Zero-Trust Remote MCP Gateway."""

    server_name: str = Field(default="raa-mcp-gateway", description="Gateway server name.")
    listen_port: int = Field(default=8443, ge=1024, le=65535, description="Gateway listen port.")
    allowed_clients: list[str] | None = Field(default=None, description="Allowed client agent IDs.")
    auth_token: str | None = Field(default=None, description="Optional fixed bearer token.")
    enable_mtls: bool = Field(default=True, description="Whether to enable mutual TLS.")


async def _admin_engine_list(ctx: ToolContext, args: EmptyInput) -> ToolOutcome:
    del args
    statuses = ctx.runtime.engines.discover()
    return ToolOutcome(
        data={
            "summary": ctx.runtime.engines.summary(),
            "engines": [status.to_dict() for status in statuses],
        }
    )


async def _admin_engine_verify(ctx: ToolContext, args: AdminEngineVerifyInput) -> ToolOutcome:
    report = ctx.runtime.engines.verify(args.engine_id)
    return ToolOutcome(data=report)


async def _admin_license_report(ctx: ToolContext, args: EmptyInput) -> ToolOutcome:
    del args
    return ToolOutcome(data=ctx.runtime.engines.license_report())


async def _admin_audit_query(ctx: ToolContext, args: AdminAuditQueryInput) -> ToolOutcome:
    payload = ctx.runtime.audit.query(
        tool=args.tool,
        outcome=args.outcome,
        error_code=args.error_code,
        project_id=args.project_id,
        request_id=args.request_id,
        limit=args.limit,
        offset=args.offset,
    )
    return ToolOutcome(data=payload)


async def _admin_audit_verify(ctx: ToolContext, args: EmptyInput) -> ToolOutcome:
    del args
    report = ctx.runtime.audit.verify_integrity()
    return ToolOutcome(data=report)


async def _admin_doctor(ctx: ToolContext, args: EmptyInput) -> ToolOutcome:
    del args
    payload = ctx.runtime.engines.doctor(
        settings=ctx.runtime.settings,
        workspace=ctx.runtime.workspace,
        database=ctx.runtime.database,
    )
    payload["implemented_tools"] = ctx.runtime.registry.count()
    return ToolOutcome(data=payload)


async def _agent_coverage_get(ctx: ToolContext, args: AgentCoverageGetInput) -> ToolOutcome:
    res = ctx.runtime.coverage.get_coverage(project_id=args.project_id)
    return ToolOutcome(data=res)


async def _admin_signature_verify(ctx: ToolContext, args: AdminSignatureVerifyInput) -> ToolOutcome:
    if args.file_path:
        res = ctx.runtime.signing.verify_file(Path(args.file_path))
    else:
        res = ctx.runtime.signing.verify_content(
            content_type=args.content_type,
            name=args.name,
            content=args.name,
            signature=args.signature,
        )
    return ToolOutcome(data=res)


async def _admin_sbom_generate(ctx: ToolContext, args: AdminSbomGenerateInput) -> ToolOutcome:
    if args.format.lower() == "spdx":
        res = ctx.runtime.sbom.generate_spdx()
    else:
        res = ctx.runtime.sbom.generate_cyclonedx()
    return ToolOutcome(data=res)


async def _admin_backup_create(ctx: ToolContext, args: AdminBackupCreateInput) -> ToolOutcome:
    out_path = Path(args.output_path) if args.output_path else None
    res = ctx.runtime.backup.create_backup(project_id=args.project_id, output_path=out_path)
    return ToolOutcome(data=res)


async def _admin_backup_restore(ctx: ToolContext, args: AdminBackupRestoreInput) -> ToolOutcome:
    res = ctx.runtime.backup.restore_backup(
        bundle_path=Path(args.bundle_path),
        new_name=args.new_name,
    )
    return ToolOutcome(data=res)


async def _admin_retention_purge(ctx: ToolContext, args: AdminRetentionPurgeInput) -> ToolOutcome:
    res = ctx.runtime.backup.purge_retention(retention_days=args.retention_days)
    return ToolOutcome(data=res)


async def _admin_system_metrics(ctx: ToolContext, args: EmptyInput) -> ToolOutcome:
    del args
    res = ctx.runtime.metrics.get_system_metrics()
    return ToolOutcome(data=res)


async def _admin_ztna_tunnel_config(
    ctx: ToolContext, args: AdminZtnaTunnelConfigInput
) -> ToolOutcome:
    del ctx
    from raa.services.admin.ztna_gateway import configure_ztna_gateway

    res = configure_ztna_gateway(
        server_name=args.server_name,
        listen_port=args.listen_port,
        allowed_clients=args.allowed_clients,
        auth_token=args.auth_token,
        enable_mtls=args.enable_mtls,
    )
    return ToolOutcome(data=res)


def register(registry: CapabilityRegistry) -> None:
    registry.register(
        ToolSpec(
            name="admin_engine_list",
            title="List engines",
            description=(
                "Return the engine catalogue with tier, licence, integration mode, "
                "distribution class and local availability."
            ),
            input_model=EmptyInput,
            handler=_admin_engine_list,
            family="admin",
            profiles=ADMIN,
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="admin_engine_verify",
            title="Verify engines",
            description="Verify engine pack manifest, integration mode, and binary hash integrity.",
            input_model=AdminEngineVerifyInput,
            handler=_admin_engine_verify,
            family="admin",
            profiles=ADMIN,
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="admin_license_report",
            title="Licence inventory",
            description="Group catalogued engines by licence and distribution class.",
            input_model=EmptyInput,
            handler=_admin_license_report,
            family="admin",
            profiles=ADMIN,
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="admin_audit_query",
            title="Query audit events",
            description="Query append-only audit trail logs with filtering and pagination.",
            input_model=AdminAuditQueryInput,
            handler=_admin_audit_query,
            family="admin",
            profiles=ADMIN,
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="admin_audit_verify",
            title="Verify audit trail integrity",
            description=(
                "Cryptographically verify the tamper-evident SHA-256 hash chain of the audit trail"
                " to detect unauthorized tampering, insertion, or record deletion."
            ),
            input_model=EmptyInput,
            handler=_admin_audit_verify,
            family="admin",
            profiles=CORE_AND_ADMIN,
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="admin_doctor",
            title="Environment diagnostics",
            description=(
                "Check workspace, database, MCP SDK, engine availability and tool count. "
                "Does not execute external engines."
            ),
            input_model=EmptyInput,
            handler=_admin_doctor,
            family="admin",
            profiles=CORE_AND_ADMIN,
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="agent_coverage_get",
            title="Get agent analysis coverage",
            description=(
                "Compute reverse engineering and reconstruction coverage metrics across"
                " activities, API endpoints, native binaries, and UI screens."
            ),
            input_model=AgentCoverageGetInput,
            handler=_agent_coverage_get,
            family="admin",
            profiles=CORE_AND_ADMIN,
            scopes=frozenset({PROJECT_READ}),
            annotations=ToolAnnotations(read_only=True, idempotent=True),
        )
    )
    registry.register(
        ToolSpec(
            name="admin_signature_verify",
            title="Verify digital signatures",
            description=(
                "Verify HMAC-SHA256 and Ed25519 digital signatures of skills, recipes, manifests, "
                "and detached signature files to ensure authenticity and reject untrusted content."
            ),
            input_model=AdminSignatureVerifyInput,
            handler=_admin_signature_verify,
            family="admin",
            profiles=ADMIN,
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="admin_sbom_generate",
            title="Generate Software Bill of Materials",
            description=(
                "Generate standardized CycloneDX v1.5 or SPDX 2.3 Software Bill of Materials "
                "(SBOM) for all RAA runtime components, dependencies, native engines, and licenses."
            ),
            input_model=AdminSbomGenerateInput,
            handler=_admin_sbom_generate,
            family="admin",
            profiles=CORE_AND_ADMIN,
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="admin_backup_create",
            title="Create project backup",
            description=(
                "Create a compressed .raa.bundle.tar.gz archive containing all project database "
                "records, artifacts, and integrity checksums for enterprise disaster recovery."
            ),
            input_model=AdminBackupCreateInput,
            handler=_admin_backup_create,
            family="admin",
            profiles=ADMIN,
            scopes=frozenset({PROJECT_READ}),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="admin_backup_restore",
            title="Restore project backup",
            description=(
                "Validate and restore an enterprise project from a .raa.bundle.tar.gz backup "
                "bundle with checksum verification."
            ),
            input_model=AdminBackupRestoreInput,
            handler=_admin_backup_restore,
            family="admin",
            profiles=ADMIN,
            annotations=ToolAnnotations(read_only=False),
        )
    )
    registry.register(
        ToolSpec(
            name="admin_retention_purge",
            title="Enforce retention policy",
            description=(
                "Enforce enterprise data retention policy by pruning expired backup archives and "
                "temporary caches older than the specified retention threshold."
            ),
            input_model=AdminRetentionPurgeInput,
            handler=_admin_retention_purge,
            family="admin",
            profiles=ADMIN,
            annotations=ToolAnnotations(read_only=False),
        )
    )
    registry.register(
        ToolSpec(
            name="admin_system_metrics",
            title="System metrics and worker telemetry",
            description=(
                "Collect system observability metrics including SQLite database/WAL size, "
                "workspace storage utilization, active threads, and audit integrity status."
            ),
            input_model=EmptyInput,
            handler=_admin_system_metrics,
            family="admin",
            profiles=CORE_AND_ADMIN,
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="admin_ztna_tunnel_config",
            title="Configure Zero-Trust Remote MCP Gateway",
            description=(
                "Generate encrypted, token-authenticated zero-trust network access (ZTNA) "
                "gateway and agent client configurations inspired by Octelium."
            ),
            input_model=AdminZtnaTunnelConfigInput,
            handler=_admin_ztna_tunnel_config,
            family="admin",
            profiles=ADMIN,
            annotations=ToolAnnotations(read_only=True, idempotent=True),
        )
    )
