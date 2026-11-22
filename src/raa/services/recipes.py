"""Versioned macro-workflows over registered tools.

A recipe never manipulates storage directly when a tool already exists. That
keeps policy checks, evidence and audit behaviour identical to direct calls.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field, ValidationError

from raa.errors import InvalidArgumentsError, NotFoundError
from raa.registry.models import ToolContext, ToolInput

if TYPE_CHECKING:
    from raa.runtime import Runtime


class TriageArguments(ToolInput):
    project_id: str = Field(description="Project that owns the artifact.")
    artifact_id: str | None = Field(
        default=None,
        description="Previously ingested artifact. Provide this or path.",
    )
    path: str | None = Field(
        default=None,
        description="Path to an APK/AAB/APKS/XAPK inside an allowed input root.",
    )
    stages: list[str] | None = Field(
        default=None,
        description="Optional subset of analysis stages.",
    )


class ProjectOverviewArguments(ToolInput):
    project_id: str = Field(description="Project to summarize.")


@dataclass(frozen=True, slots=True)
class RecipeSpec:
    id: str
    version: str
    title: str
    description: str
    input_model: type[BaseModel]
    steps: tuple[str, ...]
    scopes: frozenset[str]

    def describe(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "version": self.version,
            "title": self.title,
            "description": self.description,
            "input_schema": self.input_model.model_json_schema(),
            "steps": list(self.steps),
            "scopes": sorted(self.scopes),
        }


RECIPES: dict[str, RecipeSpec] = {
    "triage": RecipeSpec(
        id="triage",
        version="1.0.0",
        title="Artifact triage",
        description=(
            "Ingest an artifact if needed, run the built-in static inspection, "
            "then return the report and evidence identifiers."
        ),
        input_model=TriageArguments,
        steps=("artifact_ingest", "analysis_start", "analysis_get_report"),
        scopes=frozenset({"project.write", "static.read"}),
    ),
    "project_overview": RecipeSpec(
        id="project_overview",
        version="1.0.0",
        title="Project overview",
        description="Summarize a project, its artifacts and existing evidence.",
        input_model=ProjectOverviewArguments,
        steps=("project_get", "artifact_list", "evidence_list"),
        scopes=frozenset({"project.read"}),
    ),
}


class RecipeService:
    def __init__(self) -> None:
        self._runs: dict[str, dict[str, Any]] = {}

    def list(self) -> list[RecipeSpec]:
        return list(RECIPES.values())

    def get(self, recipe_id: str) -> RecipeSpec:
        recipe = RECIPES.get(recipe_id)
        if recipe is None:
            raise NotFoundError(
                f"Recipe not found: {recipe_id}",
                hint="Call recipe_list to discover installed recipes.",
            )
        return recipe

    def describe(self, recipe_id: str) -> dict[str, Any]:
        return self.get(recipe_id).describe()

    def get_run(self, run_id: str) -> dict[str, Any]:
        trace = self._runs.get(run_id)
        if trace is None:
            raise NotFoundError(
                f"Recipe run not found: {run_id}",
                hint="Check the run_id returned by recipe_run.",
            )
        return trace

    async def run(
        self,
        runtime: Runtime,
        ctx: ToolContext,
        recipe_id: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        recipe = self.get(recipe_id)
        try:
            parsed = recipe.input_model.model_validate(arguments)
        except ValidationError as exc:
            raise InvalidArgumentsError(
                f"Invalid arguments for recipe '{recipe.id}'.",
                hint="Call recipe_describe to inspect the input schema.",
                details={"errors": exc.errors(include_url=False, include_input=False)},
            ) from exc

        run_id = f"run_{uuid.uuid4().hex[:10]}"
        trace: dict[str, Any] = {
            "run_id": run_id,
            "recipe_id": recipe.id,
            "status": "running",
            "steps": list(recipe.steps),
            "step_results": {},
        }
        self._runs[run_id] = trace

        try:
            if recipe.id == "triage":
                result = await self._triage(runtime, ctx, parsed)
            elif recipe.id == "project_overview":
                result = await self._project_overview(runtime, ctx, parsed)
            else:
                raise InvalidArgumentsError(f"Recipe has no runner: {recipe.id}")
            result["run_id"] = run_id
            trace["status"] = "completed"
            trace["result"] = result
            return result
        except Exception as exc:
            trace["status"] = "failed"
            trace["error"] = str(exc)
            raise

    async def _triage(
        self,
        runtime: Runtime,
        ctx: ToolContext,
        parsed: BaseModel,
    ) -> dict[str, Any]:
        args = TriageArguments.model_validate(parsed.model_dump())
        if bool(args.artifact_id) == bool(args.path):
            raise InvalidArgumentsError(
                "Provide exactly one of artifact_id or path.",
                hint="Use artifact_id for an ingested artifact, or path to ingest a new file.",
            )

        evidence_ids: list[str] = []
        if args.path:
            ingested = await runtime.invoke(
                "artifact_ingest",
                {"project_id": args.project_id, "path": args.path},
                profile=ctx.profile,
                surface=ctx.surface,
            )
            artifact = ingested.data
            evidence_ids.extend(ingested.evidence_ids)
        else:
            artifact = (
                await runtime.invoke(
                    "artifact_get_info",
                    {
                        "project_id": args.project_id,
                        "artifact_id": args.artifact_id,
                    },
                    profile=ctx.profile,
                    surface=ctx.surface,
                )
            ).data

        started = await runtime.invoke(
            "analysis_start",
            {
                "project_id": args.project_id,
                "artifact_id": artifact["id"],
                "stages": args.stages,
            },
            profile=ctx.profile,
            surface=ctx.surface,
        )
        job = started.data
        finished = await runtime.analysis.wait(args.project_id, job["id"])
        if finished.status.value != "completed":
            return {
                "artifact": artifact,
                "job": finished.model_dump(mode="json"),
                "report": None,
                "evidence_ids": evidence_ids,
                "warning": finished.error or f"Job ended as {finished.status.value}.",
            }

        report = (
            await runtime.invoke(
                "analysis_get_report",
                {"project_id": args.project_id, "job_id": finished.id},
                profile=ctx.profile,
                surface=ctx.surface,
            )
        ).data
        evidence_ids.extend(report.get("evidence_ids", []))
        return {
            "artifact": artifact,
            "job": finished.model_dump(mode="json"),
            "report": report,
            "evidence_ids": list(dict.fromkeys(evidence_ids)),
        }

    async def _project_overview(
        self,
        runtime: Runtime,
        ctx: ToolContext,
        parsed: BaseModel,
    ) -> dict[str, Any]:
        args = ProjectOverviewArguments.model_validate(parsed.model_dump())
        project = (
            await runtime.invoke(
                "project_get",
                {"project_id": args.project_id},
                profile=ctx.profile,
                surface=ctx.surface,
            )
        ).data
        artifacts = (
            await runtime.invoke(
                "artifact_list",
                {"project_id": args.project_id},
                profile=ctx.profile,
                surface=ctx.surface,
            )
        ).data
        evidence = (
            await runtime.invoke(
                "evidence_list",
                {"project_id": args.project_id, "limit": 50},
                profile=ctx.profile,
                surface=ctx.surface,
            )
        ).data
        return {
            "project": project,
            "artifact_count": len(artifacts.get("items", [])),
            "artifacts": artifacts.get("items", []),
            "evidence_count": len(evidence.get("items", [])),
        }
