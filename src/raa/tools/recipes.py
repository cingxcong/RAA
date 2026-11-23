"""Recipe discovery and execution tools."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from raa.registry.models import (
    CapabilityRegistry,
    ToolAnnotations,
    ToolContext,
    ToolInput,
    ToolOutcome,
    ToolSpec,
)
from raa.registry.profiles import CORE, MINIMAL


class EmptyInput(ToolInput):
    pass


class RecipeDescribeInput(ToolInput):
    recipe_id: str


class RecipeGetRunInput(ToolInput):
    run_id: str = Field(description="Recipe execution run identifier.")


class RecipeRunInput(ToolInput):
    recipe_id: str
    arguments: dict[str, Any] = Field(
        default_factory=dict,
        description="Recipe-specific arguments; inspect recipe_describe for the schema.",
    )


class SkillGetInput(ToolInput):
    skill_id: str = Field(description="Unique skill identifier.")


async def _recipe_list(ctx: ToolContext, args: EmptyInput) -> ToolOutcome:
    del args
    recipes = ctx.runtime.recipes.list()
    return ToolOutcome(
        data={
            "recipes": [
                {
                    "id": recipe.id,
                    "version": recipe.version,
                    "title": recipe.title,
                    "description": recipe.description,
                    "steps": list(recipe.steps),
                }
                for recipe in recipes
            ],
            "count": len(recipes),
        }
    )


async def _recipe_describe(ctx: ToolContext, args: RecipeDescribeInput) -> ToolOutcome:
    return ToolOutcome(data=ctx.runtime.recipes.describe(args.recipe_id))


async def _recipe_run(ctx: ToolContext, args: RecipeRunInput) -> ToolOutcome:
    result = await ctx.runtime.recipes.run(
        ctx.runtime,
        ctx,
        args.recipe_id,
        args.arguments,
    )
    evidence_ids = result.get("evidence_ids", [])
    return ToolOutcome(data=result, evidence_ids=list(evidence_ids))


async def _recipe_get_run(ctx: ToolContext, args: RecipeGetRunInput) -> ToolOutcome:
    trace = ctx.runtime.recipes.get_run(args.run_id)
    return ToolOutcome(data=trace)


async def _skill_list(ctx: ToolContext, args: EmptyInput) -> ToolOutcome:
    del args
    skills = ctx.runtime.skills.discover()
    active_profile = ctx.runtime.settings.profile
    profile_tools = {t.name for t in ctx.runtime.registry.for_profile(active_profile)}

    summaries = []
    for s in skills:
        summary = s.summary()
        # Annotate tool availability based on the active runtime profile
        summary["tools"] = list(s.tools)
        summary["active_profile"] = active_profile
        summary["available_tools"] = [t for t in s.tools if t in profile_tools]
        summary["unavailable_tools"] = [t for t in s.tools if t not in profile_tools]
        summaries.append(summary)

    return ToolOutcome(data={"count": len(skills), "skills": summaries})


async def _skill_get(ctx: ToolContext, args: SkillGetInput) -> ToolOutcome:
    skill = ctx.runtime.skills.get(args.skill_id)
    summary = skill.summary()
    summary["content"] = skill.content
    active_profile = ctx.runtime.settings.profile
    profile_tools = {t.name for t in ctx.runtime.registry.for_profile(active_profile)}
    summary["active_profile"] = active_profile
    summary["available_tools"] = [t for t in skill.tools if t in profile_tools]
    summary["unavailable_tools"] = [t for t in skill.tools if t not in profile_tools]
    return ToolOutcome(data=summary)


def register(registry: CapabilityRegistry) -> None:
    registry.register(
        ToolSpec(
            name="recipe_list",
            title="List recipes",
            description="List versioned macro-workflows and their steps.",
            input_model=EmptyInput,
            handler=_recipe_list,
            family="recipes",
            profiles=CORE,
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="recipe_describe",
            title="Describe recipe",
            description="Return a recipe's input schema, scopes, steps and outputs.",
            input_model=RecipeDescribeInput,
            handler=_recipe_describe,
            family="recipes",
            profiles=CORE,
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="recipe_run",
            title="Run recipe",
            description=(
                "Run a recipe. 'triage' ingests an artifact, runs static inspection "
                "and returns the completed report. Inner tool calls are policy-checked."
            ),
            input_model=RecipeRunInput,
            handler=_recipe_run,
            family="recipes",
            profiles=MINIMAL,
            annotations=ToolAnnotations(
                read_only=False,
                destructive=False,
                idempotent=False,
            ),
            cost="slow",
        )
    )
    registry.register(
        ToolSpec(
            name="recipe_get_run",
            title="Get recipe run trace",
            description="Retrieve execution trace and step outcomes of a recipe run.",
            input_model=RecipeGetRunInput,
            handler=_recipe_get_run,
            family="recipes",
            profiles=CORE,
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="skill_list",
            title="List skills",
            description="List installed procedural skill packages and their tools.",
            input_model=EmptyInput,
            handler=_skill_list,
            family="skills",
            profiles=CORE,
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="skill_get",
            title="Get skill",
            description="Retrieve instructions, references, and files of a skill bundle.",
            input_model=SkillGetInput,
            handler=_skill_get,
            family="skills",
            profiles=CORE,
            annotations=ToolAnnotations(read_only=True),
        )
    )
