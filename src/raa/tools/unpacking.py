"""Unpacking, deobfuscation, and retrace MCP tools."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from raa.policy.scopes import EXPORT_WRITE, PROJECT_READ, STATIC_READ
from raa.registry.models import (
    CapabilityRegistry,
    ToolAnnotations,
    ToolContext,
    ToolOutcome,
    ToolSpec,
)
from raa.registry.profiles import CORE

# --- Input Models ---


class UnpackExtractInput(BaseModel):
    """Parameters to statically carve and extract embedded DEX or payload containers."""

    project_id: str = Field(min_length=1, description="Target project ID.")
    artifact_id: str | None = Field(default=None, description="Optional target artifact ID.")
    output_dir: str | None = Field(
        default=None, description="Optional destination directory for carved payloads."
    )


class UnpackVerifyInput(BaseModel):
    """Parameters to verify structural integrity and completeness of a dumped DEX."""

    project_id: str = Field(min_length=1, description="Target project ID.")
    file_path: str = Field(min_length=1, description="Path to dumped/extracted DEX file.")
    reanalyze: bool = Field(
        default=True,
        description="Whether to ingest the verified DEX into project catalog for re-analysis.",
    )


class DeobfuscateInput(BaseModel):
    """Parameters to apply Dalvik deobfuscation transformations."""

    project_id: str = Field(min_length=1, description="Target project ID.")
    target: str = Field(
        min_length=1,
        description="Target class or component name (e.g. 'com.example.ObfuscatedClass').",
    )
    strategy: Literal["simplify", "reflection_resolve", "string_decrypt", "dead_code_prune"] = (
        Field(
            default="simplify",
            description="Deobfuscation strategy (simplify, reflection_resolve, etc.).",
        )
    )
    source_text: str | None = Field(
        default=None, description="Optional source or Smali code string to deobfuscate."
    )


class RetraceInput(BaseModel):
    """Parameters to parse ProGuard/R8 mapping files and translate symbols or stack traces."""

    project_id: str = Field(min_length=1, description="Target project ID.")
    mapping_file: str = Field(min_length=1, description="Path to ProGuard/R8 mapping.txt file.")
    stack_trace: str | None = Field(
        default=None,
        description="Optional obfuscated crash log or stack trace string to retrace.",
    )


# --- Tool Spec Helper ---


def _unpacking_spec(
    *,
    name: str,
    title: str,
    description: str,
    handler: Any,
    input_model: type[BaseModel],
    profiles: frozenset[str] = CORE,
    scopes: frozenset[str] = frozenset({PROJECT_READ, STATIC_READ}),
    read_only: bool = True,
    idempotent: bool = True,
) -> ToolSpec:
    return ToolSpec(
        name=name,
        title=title,
        description=description,
        input_model=input_model,
        handler=handler,
        family="unpacking",
        profiles=profiles,
        scopes=scopes,
        annotations=ToolAnnotations(read_only=read_only, idempotent=idempotent),
        cost="fast",
    )


# --- Handlers ---


async def _unpack_extract(ctx: ToolContext, args: UnpackExtractInput) -> ToolOutcome:
    out_p = Path(args.output_dir) if args.output_dir else None
    report = ctx.runtime.unpacking.extract_payloads(
        project_id=args.project_id,
        artifact_id=args.artifact_id,
        output_dir=out_p,
    )
    return ToolOutcome(data=report.model_dump(mode="json"))


async def _unpack_verify(ctx: ToolContext, args: UnpackVerifyInput) -> ToolOutcome:
    report = ctx.runtime.unpacking.verify_dump(
        project_id=args.project_id,
        file_path=Path(args.file_path),
        reanalyze=args.reanalyze,
    )
    return ToolOutcome(data=report.model_dump(mode="json"))


async def _deobfuscate(ctx: ToolContext, args: DeobfuscateInput) -> ToolOutcome:
    result = ctx.runtime.unpacking.deobfuscate(
        project_id=args.project_id,
        target=args.target,
        strategy=args.strategy,
        source_text=args.source_text,
    )
    return ToolOutcome(data=result.model_dump(mode="json"))


async def _retrace(ctx: ToolContext, args: RetraceInput) -> ToolOutcome:
    report = ctx.runtime.unpacking.retrace(
        project_id=args.project_id,
        mapping_path=Path(args.mapping_file),
        stack_trace=args.stack_trace,
    )
    return ToolOutcome(data=report.model_dump(mode="json"))


# --- Register Function ---


def register(registry: CapabilityRegistry) -> None:
    """Register all Phase 8 unpacking and obfuscation tools."""
    registry.register(
        _unpacking_spec(
            name="unpack_extract",
            title="Extract static payloads",
            description=(
                "Statically carve and extract embedded DEX files, nested ZIP archives, "
                "and XOR-obfuscated payloads from APK assets and resources."
            ),
            handler=_unpack_extract,
            input_model=UnpackExtractInput,
            profiles=CORE,
            scopes=frozenset({PROJECT_READ, STATIC_READ, EXPORT_WRITE}),
            read_only=False,
            idempotent=False,
        )
    )
    registry.register(
        _unpacking_spec(
            name="unpack_verify",
            title="Verify dump completeness",
            description=(
                "Validate structural integrity, Adler32 checksums, SHA-1 signatures, "
                "and real bytecode vs shell stubs in a dumped DEX file."
            ),
            handler=_unpack_verify,
            input_model=UnpackVerifyInput,
            profiles=CORE,
            scopes=frozenset({PROJECT_READ, STATIC_READ}),
            read_only=False,
            idempotent=False,
        )
    )
    registry.register(
        _unpacking_spec(
            name="deobfuscate",
            title="Deobfuscate bytecode and symbols",
            description=(
                "Apply Dalvik deobfuscation transformations: reflection resolution, "
                "string decryption, and dead code pruning with provenance tracking."
            ),
            handler=_deobfuscate,
            input_model=DeobfuscateInput,
            profiles=CORE,
            scopes=frozenset({PROJECT_READ, STATIC_READ, EXPORT_WRITE}),
            read_only=False,
            idempotent=False,
        )
    )
    registry.register(
        _unpacking_spec(
            name="retrace",
            title="Retrace obfuscated symbols",
            description=(
                "Parse ProGuard/R8 mapping files, retrace stack traces, "
                "and calculate retrace coverage statistics."
            ),
            handler=_retrace,
            input_model=RetraceInput,
            profiles=CORE,
            scopes=frozenset({PROJECT_READ, STATIC_READ}),
            read_only=True,
            idempotent=True,
        )
    )
