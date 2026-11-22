"""Project lifecycle."""

from __future__ import annotations

from raa.domain.models import Project
from raa.errors import InvalidArgumentsError, NotFoundError
from raa.policy.scopes import DEFAULT_PROJECT_SCOPES, normalize_scopes
from raa.storage.repositories import ProjectRepository
from raa.utils.ids import new_id
from raa.utils.time import utc_now


class ProjectService:
    def __init__(self, repository: ProjectRepository) -> None:
        self.repository = repository

    def create(
        self,
        name: str,
        description: str = "",
        scopes: list[str] | None = None,
    ) -> Project:
        cleaned_name = name.strip()
        if not cleaned_name:
            raise InvalidArgumentsError("Project name must not be empty.")
        if len(cleaned_name) > 120:
            raise InvalidArgumentsError("Project name must be 120 characters or fewer.")
        normalized = list(DEFAULT_PROJECT_SCOPES) if scopes is None else normalize_scopes(scopes)
        now = utc_now()
        project = Project(
            id=new_id("prj"),
            name=cleaned_name,
            description=description.strip(),
            scopes=normalized,
            created_at=now,
            updated_at=now,
        )
        return self.repository.create(project)

    def get(self, project_id: str) -> Project | None:
        return self.repository.get(project_id)

    def get_or_raise(self, project_id: str) -> Project:
        project = self.get(project_id)
        if project is None:
            raise NotFoundError(
                f"Project not found: {project_id}",
                hint="Call project_list to discover valid project identifiers.",
            )
        return project

    def list(self, limit: int = 100, offset: int = 0) -> list[Project]:
        return self.repository.list(limit=limit, offset=offset)

    def count(self) -> int:
        return len(self.repository.list(limit=100000))
