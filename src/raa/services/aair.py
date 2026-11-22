"""AAIR workspace service orchestrating graph extraction, caching, and intelligence queries."""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from raa.domain.aair import (
    AAIREdgeKind,
    AAIREntityKind,
    AAIRGraph,
    migrate_aair,
)
from raa.errors import NotFoundError
from raa.services.android.aair import build_aair_graph
from raa.services.android.arsc import decode_resource_table
from raa.services.android.dex import decode_dex_index
from raa.services.android.manifest import decode_manifest

if TYPE_CHECKING:
    from raa.services.analysis import AnalysisService
    from raa.services.artifacts import ArtifactService
    from raa.services.evidence import EvidenceService
    from raa.services.workspace import Workspace


class AAIRService:
    """Manages AAIR graph extraction, caching, persistence, and intelligence queries."""

    def __init__(
        self,
        workspace: Workspace,
        evidence: EvidenceService,
        artifacts: ArtifactService,
        analysis: AnalysisService,
    ) -> None:
        self.workspace = workspace
        self.evidence = evidence
        self.artifacts = artifacts
        self.analysis = analysis
        self._graphs: dict[str, AAIRGraph] = {}

    def get_aair_dir(self, project_id: str) -> Path:
        p = self.workspace.root / "projects" / project_id / "aair"
        p.mkdir(parents=True, exist_ok=True)
        return p

    def get_or_build_graph(self, project_id: str, job_id: str) -> AAIRGraph:
        """Retrieve cached AAIR graph or build it on demand from job analysis state."""
        cache_key = f"{project_id}:{job_id}"
        if cache_key in self._graphs:
            return self._graphs[cache_key]

        aair_file = self.get_aair_dir(project_id) / f"{job_id}.json"
        if aair_file.exists():
            with contextlib.suppress(Exception):
                data = json.loads(aair_file.read_text(encoding="utf-8"))
                graph = migrate_aair(data)
                self._graphs[cache_key] = graph
                return graph

        report = self.analysis.get_report(project_id, job_id)
        artifact = self.artifacts.get_or_raise(report.project_id, report.artifact_id)
        path = self.artifacts.path_for(artifact)

        manifest = None
        if "manifest" in report.stages:
            try:
                manifest = decode_manifest(
                    path,
                    artifact.artifact_type,
                    max_bytes=self.analysis.settings.max_manifest_bytes,
                )
            except Exception:
                manifest = report.manifest

        dex_index = None
        if "code" in report.stages:
            with contextlib.suppress(Exception):
                dex_index = decode_dex_index(
                    path,
                    artifact.artifact_type,
                    max_bytes=self.analysis.settings.max_dex_bytes,
                    include_references=True,
                    max_instruction_units=self.analysis.settings.max_dex_instruction_units,
                    max_references=self.analysis.settings.max_dex_references,
                )

        resource_summary = report.resource_summary
        if resource_summary is None and "resources" in report.stages:
            with contextlib.suppress(Exception):
                table = decode_resource_table(
                    path,
                    artifact.artifact_type,
                    max_bytes=self.analysis.settings.max_resource_bytes,
                )
                resource_summary = table.summary()

        graph = build_aair_graph(
            project_id=project_id,
            artifact_id=artifact.id,
            manifest=manifest,
            dex_index=dex_index,
            resource_summary=resource_summary,
            native_libraries=report.native_libraries,
            framework_findings=report.frameworks,
            evidence_ids=report.evidence_ids,
        )

        # Cache in memory and persist to disk
        self._graphs[cache_key] = graph
        with contextlib.suppress(Exception):
            aair_file.write_text(
                json.dumps(graph.model_dump(mode="json"), indent=2),
                encoding="utf-8",
            )

        return graph

    def trace_endpoint(
        self,
        project_id: str,
        job_id: str,
        endpoint_query: str,
    ) -> dict[str, Any]:
        """Trace a known endpoint to its source method(s) and callers."""
        graph = self.get_or_build_graph(project_id, job_id)

        target_ep = None
        for entity in graph.entities.values():
            if entity.kind == AAIREntityKind.ENDPOINT and (
                endpoint_query in entity.name or endpoint_query in entity.id
            ):
                target_ep = entity
                break

        if target_ep is None:
            raise NotFoundError(
                f"Endpoint '{endpoint_query}' was not found in the AAIR graph.",
                details={"project_id": project_id, "job_id": job_id},
            )

        # Find incoming TRIGGERS_ENDPOINT edges to discover source methods
        source_methods: list[dict[str, Any]] = []
        callers: list[dict[str, Any]] = []

        for edge in graph.incoming_edges(target_ep.id):
            if edge.kind == AAIREdgeKind.TRIGGERS_ENDPOINT:
                src_entity = graph.get_entity(edge.source_id)
                source_methods.append(
                    {
                        "method_id": edge.source_id,
                        "method_name": src_entity.name if src_entity else edge.source_id,
                        "confidence": edge.confidence.value,
                        "evidence_ids": edge.evidence_ids,
                    }
                )
                # Find callers of this source method
                for call_edge in graph.incoming_edges(edge.source_id):
                    if call_edge.kind == AAIREdgeKind.CALLS:
                        caller_entity = graph.get_entity(call_edge.source_id)
                        caller_name = caller_entity.name if caller_entity else call_edge.source_id
                        callers.append(
                            {
                                "caller_id": call_edge.source_id,
                                "caller_name": caller_name,
                                "target_method_id": edge.source_id,
                                "metadata": call_edge.metadata,
                                "confidence": call_edge.confidence.value,
                                "evidence_ids": call_edge.evidence_ids,
                            }
                        )

        # Also fallback to attribute metadata if edges were indirect
        if not source_methods and "source_methods" in target_ep.attributes:
            for m_id in target_ep.attributes["source_methods"]:
                src_entity = graph.get_entity(m_id)
                source_methods.append(
                    {
                        "method_id": m_id,
                        "method_name": src_entity.name if src_entity else m_id,
                        "confidence": "observed",
                        "evidence_ids": target_ep.evidence_ids,
                    }
                )

        if not callers and "callers" in target_ep.attributes:
            callers.extend(target_ep.attributes["callers"])

        evidence_ids = list(
            set(target_ep.evidence_ids)
            | {ev for sm in source_methods for ev in sm.get("evidence_ids", [])}
            | {ev for c in callers for ev in c.get("evidence_ids", [])}
        )

        return {
            "endpoint": target_ep.model_dump(mode="json"),
            "source_methods": source_methods,
            "callers": callers,
            "trace_complete": len(source_methods) > 0 and len(callers) > 0,
            "evidence_ids": sorted(evidence_ids),
        }

    def get_hierarchy(
        self,
        project_id: str,
        job_id: str,
        class_name: str,
        *,
        direction: str = "both",
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        graph = self.get_or_build_graph(project_id, job_id)
        return graph.get_hierarchy(class_name, direction=direction, limit=limit, offset=offset)

    def get_xrefs(
        self,
        project_id: str,
        job_id: str,
        symbol: str,
        *,
        kind: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        graph = self.get_or_build_graph(project_id, job_id)
        return graph.get_xrefs(symbol, kind=kind, limit=limit, offset=offset)

    def query_graph(
        self,
        project_id: str,
        job_id: str,
        *,
        root_id: str | None = None,
        edge_kinds: list[str] | None = None,
        target_kinds: list[str] | None = None,
        max_depth: int = 2,
        direction: str = "outgoing",
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        graph = self.get_or_build_graph(project_id, job_id)
        return graph.query(
            root_id=root_id,
            edge_kinds=edge_kinds,
            target_kinds=target_kinds,
            max_depth=max_depth,
            direction=direction,
            limit=limit,
            offset=offset,
        )

    def get_neighborhood(
        self,
        project_id: str,
        job_id: str,
        entity_id: str,
        *,
        radius: int = 1,
        edge_kinds: list[str] | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        graph = self.get_or_build_graph(project_id, job_id)
        return graph.get_neighborhood(
            entity_id,
            radius=radius,
            edge_kinds=edge_kinds,
            limit=limit,
            offset=offset,
        )
