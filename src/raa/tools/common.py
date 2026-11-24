"""Shared helpers for tool handlers."""

from __future__ import annotations

from typing import cast

from pydantic import Field

from raa.domain.models import AnalysisReport, Project
from raa.errors import InternalError
from raa.registry.models import ToolContext, ToolInput


class PaginationInput(ToolInput):
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


def project_of(ctx: ToolContext) -> Project:
    if ctx.project is None:
        raise InternalError("Tool requires a resolved project context.")
    return ctx.project


def report_of(ctx: ToolContext, project_id: str, job_id: str) -> AnalysisReport:
    return cast(AnalysisReport, ctx.runtime.analysis.get_report(project_id, job_id))
