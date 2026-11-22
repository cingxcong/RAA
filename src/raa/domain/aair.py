"""Android Application Intermediate Representation (AAIR) domain models.

Defines normalized, evidence-linked entities, relationships, graph container,
and migration logic for application intelligence.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from raa.domain.models import Authority, Confidence, Representation
from raa.utils.time import utc_now


class AAIREntityKind(StrEnum):
    """Kinds of normalized AAIR entities."""

    ARTIFACT = "artifact"
    PACKAGE = "package"
    SPLIT = "split"
    FRAMEWORK = "framework"
    COMPONENT = "component"
    CLASS = "class"
    METHOD = "method"
    FIELD = "field"
    RESOURCE = "resource"
    ASSET = "asset"
    NATIVE_LIBRARY = "native_library"
    NATIVE_SYMBOL = "native_symbol"
    ENDPOINT = "endpoint"
    API_OPERATION = "api_operation"
    API_SCHEMA = "api_schema"
    AUTH_SCHEME = "auth_scheme"
    DATABASE = "database"
    TABLE = "table"
    QUERY = "query"
    STORAGE_KEY = "storage_key"
    PERMISSION = "permission"
    SCREEN = "screen"
    UI_REGION = "ui_region"


class AAIREdgeKind(StrEnum):
    """Kinds of directed relationships in the AAIR graph."""

    CONTAINS = "CONTAINS"
    CALLS = "CALLS"
    REFERENCES = "REFERENCES"
    IMPLEMENTS = "IMPLEMENTS"
    EXTENDS = "EXTENDS"
    READS = "READS"
    WRITES = "WRITES"
    REQUESTS = "REQUESTS"
    NAVIGATES_TO = "NAVIGATES_TO"
    LOADS_LIBRARY = "LOADS_LIBRARY"
    JNI_BRIDGE = "JNI_BRIDGE"
    FRAMEWORK_BRIDGE = "FRAMEWORK_BRIDGE"
    RENDERS_RESOURCE = "RENDERS_RESOURCE"
    TRIGGERS_ENDPOINT = "TRIGGERS_ENDPOINT"
    ACCESSES_STORAGE = "ACCESSES_STORAGE"
    OBSERVED_IN = "OBSERVED_IN"
    SUPPORTED_BY = "SUPPORTED_BY"


# Stable structural ID formatters per Technical-and-Architecture.md Section 9.4
def make_package_id(package: str) -> str:
    return f"package:{package}"


def make_class_id(class_name: str) -> str:
    return f"class:{class_name}"


def make_method_id(class_name: str, method_name: str, descriptor: str) -> str:
    return f"method:{class_name}#{method_name}{descriptor}"


def make_field_id(class_name: str, field_name: str, type_name: str) -> str:
    return f"field:{class_name}#{field_name}:{type_name}"


def make_resource_id(resource_type: str, name: str) -> str:
    return f"resource:{resource_type}/{name}"


def make_component_id(package: str, name: str) -> str:
    return f"component:{package}/{name}"


def make_endpoint_id(method: str, url_or_path: str) -> str:
    return f"endpoint:{method.upper()}:{url_or_path}"


def make_database_id(name: str) -> str:
    return f"database:{name}"


def make_table_id(database: str, table: str) -> str:
    return f"table:{database}#{table}"


def make_storage_key_id(store: str, key: str) -> str:
    return f"storage_key:{store}#{key}"


def make_native_lib_id(abi: str, name: str) -> str:
    return f"native_library:{abi}/{name}"


def make_native_sym_id(lib_name: str, sym_name: str) -> str:
    return f"native_symbol:{lib_name}#{sym_name}"


def make_permission_id(permission: str) -> str:
    return f"permission:{permission}"


def make_screen_id(package: str, route: str, state_hash: str = "default") -> str:
    return f"screen:{package}/{route}#{state_hash}"


def make_edge_id(kind: str, source_id: str, target_id: str) -> str:
    return f"{kind}:{source_id}->{target_id}"


class AAIREntity(BaseModel):
    """A normalized, evidence-linked node in the AAIR graph."""

    id: str
    kind: AAIREntityKind
    name: str
    parent_id: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    confidence: Confidence = Confidence.OBSERVED
    authority: Authority = Authority.SHIPPED_ARTIFACT
    representation: Representation = Representation.ORIGINAL
    evidence_ids: list[str] = Field(default_factory=list)


class AAIREdge(BaseModel):
    """A directed, typed, evidence-linked edge between two AAIR entities."""

    id: str
    source_id: str
    target_id: str
    kind: AAIREdgeKind
    confidence: Confidence = Confidence.OBSERVED
    weight: float = 1.0
    metadata: dict[str, Any] = Field(default_factory=dict)
    evidence_ids: list[str] = Field(default_factory=list)


CURRENT_AAIR_SCHEMA_VERSION = "1.0.0"


class AAIRGraph(BaseModel):
    """Graph container holding AAIR entities and edges with bounded query capabilities."""

    schema_version: str = CURRENT_AAIR_SCHEMA_VERSION
    project_id: str
    artifact_id: str
    entities: dict[str, AAIREntity] = Field(default_factory=dict)
    edges: list[AAIREdge] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)

    # In-memory adjacency caches
    _outgoing: dict[str, list[AAIREdge]] | None = None
    _incoming: dict[str, list[AAIREdge]] | None = None

    def _ensure_indexes(self) -> None:
        if self._outgoing is not None and self._incoming is not None:
            return
        out_map: dict[str, list[AAIREdge]] = {}
        in_map: dict[str, list[AAIREdge]] = {}
        for edge in self.edges:
            out_map.setdefault(edge.source_id, []).append(edge)
            in_map.setdefault(edge.target_id, []).append(edge)
        self._outgoing = out_map
        self._incoming = in_map

    def add_entity(self, entity: AAIREntity) -> None:
        self.entities[entity.id] = entity

    def add_edge(self, edge: AAIREdge) -> None:
        self.edges.append(edge)
        if self._outgoing is not None:
            self._outgoing.setdefault(edge.source_id, []).append(edge)
        if self._incoming is not None:
            self._incoming.setdefault(edge.target_id, []).append(edge)

    def get_entity(self, entity_id: str) -> AAIREntity | None:
        return self.entities.get(entity_id)

    def outgoing_edges(self, entity_id: str) -> list[AAIREdge]:
        self._ensure_indexes()
        if self._outgoing is None:
            return []
        return self._outgoing.get(entity_id, [])

    def incoming_edges(self, entity_id: str) -> list[AAIREdge]:
        self._ensure_indexes()
        if self._incoming is None:
            return []
        return self._incoming.get(entity_id, [])

    def get_neighborhood(
        self,
        entity_id: str,
        *,
        radius: int = 1,
        edge_kinds: list[str] | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Retrieve bounded local subgraph around an entity."""
        center = self.get_entity(entity_id)
        if center is None:
            return {
                "entity": None,
                "radius": radius,
                "neighbors": [],
                "edges": [],
                "total_neighbors": 0,
                "limit": limit,
                "offset": offset,
                "has_more": False,
                "evidence_ids": [],
            }

        radius = max(1, min(radius, 3))
        limit = max(1, min(limit, 500))
        offset = max(0, offset)
        filter_kinds = set(edge_kinds) if edge_kinds else None

        visited_nodes: set[str] = {entity_id}
        collected_edges: list[AAIREdge] = []
        edge_ids_seen: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(entity_id, 0)])

        while queue:
            current_id, current_depth = queue.popleft()
            if current_depth >= radius:
                continue

            # Outgoing edges
            for edge in self.outgoing_edges(current_id):
                if filter_kinds and edge.kind.value not in filter_kinds:
                    continue
                if edge.id not in edge_ids_seen:
                    edge_ids_seen.add(edge.id)
                    collected_edges.append(edge)
                target = edge.target_id
                if target not in visited_nodes:
                    visited_nodes.add(target)
                    queue.append((target, current_depth + 1))

            # Incoming edges
            for edge in self.incoming_edges(current_id):
                if filter_kinds and edge.kind.value not in filter_kinds:
                    continue
                if edge.id not in edge_ids_seen:
                    edge_ids_seen.add(edge.id)
                    collected_edges.append(edge)
                source = edge.source_id
                if source not in visited_nodes:
                    visited_nodes.add(source)
                    queue.append((source, current_depth + 1))

        # Collect neighbors (excluding center)
        neighbor_ids = sorted(visited_nodes - {entity_id})
        total_neighbors = len(neighbor_ids)
        page_ids = neighbor_ids[offset : offset + limit]
        neighbors = [
            self.entities[nid].model_dump(mode="json") for nid in page_ids if nid in self.entities
        ]

        node_evs = {
            ev
            for nid in visited_nodes
            if nid in self.entities
            for ev in self.entities[nid].evidence_ids
        }
        edge_evs = {ev for edge in collected_edges for ev in edge.evidence_ids}
        evidence_ids = sorted(node_evs | edge_evs)

        return {
            "entity": center.model_dump(mode="json"),
            "radius": radius,
            "neighbors": neighbors,
            "edges": [edge.model_dump(mode="json") for edge in collected_edges],
            "total_neighbors": total_neighbors,
            "limit": limit,
            "offset": offset,
            "has_more": offset + len(page_ids) < total_neighbors,
            "evidence_ids": sorted(evidence_ids),
        }

    def get_hierarchy(
        self,
        class_name: str,
        *,
        direction: str = "both",
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Traverse class inheritance and interface implementation hierarchy."""
        target_id = make_class_id(class_name)
        target = self.get_entity(target_id)
        if target is None:
            # Fallback search by class name suffix
            candidates = [
                e
                for e in self.entities.values()
                if e.kind == AAIREntityKind.CLASS
                and (e.name == class_name or e.name.endswith(f".{class_name}"))
            ]
            if candidates:
                target = candidates[0]
                target_id = target.id

        if target is None:
            return {
                "class_name": class_name,
                "found": False,
                "superclasses": [],
                "interfaces": [],
                "subclasses": [],
                "implementers": [],
                "total": 0,
                "limit": limit,
                "offset": offset,
                "has_more": False,
                "evidence_ids": [],
            }

        superclasses: list[dict[str, Any]] = []
        interfaces: list[dict[str, Any]] = []
        subclasses: list[dict[str, Any]] = []
        implementers: list[dict[str, Any]] = []

        # Direction "up" (EXTENDS and IMPLEMENTS outgoing)
        if direction in {"up", "both"}:
            for edge in self.outgoing_edges(target_id):
                if edge.kind == AAIREdgeKind.EXTENDS:
                    parent = self.get_entity(edge.target_id)
                    superclasses.append(
                        {
                            "id": edge.target_id,
                            "name": parent.name if parent else edge.target_id.replace("class:", ""),
                            "confidence": edge.confidence.value,
                        }
                    )
                elif edge.kind == AAIREdgeKind.IMPLEMENTS:
                    iface = self.get_entity(edge.target_id)
                    interfaces.append(
                        {
                            "id": edge.target_id,
                            "name": iface.name if iface else edge.target_id.replace("class:", ""),
                            "confidence": edge.confidence.value,
                        }
                    )

        # Direction "down" (EXTENDS and IMPLEMENTS incoming)
        if direction in {"down", "both"}:
            for edge in self.incoming_edges(target_id):
                if edge.kind == AAIREdgeKind.EXTENDS:
                    child = self.get_entity(edge.source_id)
                    subclasses.append(
                        {
                            "id": edge.source_id,
                            "name": child.name if child else edge.source_id.replace("class:", ""),
                            "confidence": edge.confidence.value,
                        }
                    )
                elif edge.kind == AAIREdgeKind.IMPLEMENTS:
                    impl = self.get_entity(edge.source_id)
                    implementers.append(
                        {
                            "id": edge.source_id,
                            "name": impl.name if impl else edge.source_id.replace("class:", ""),
                            "confidence": edge.confidence.value,
                        }
                    )

        all_relatives = [
            *({"rel": "superclass", **item} for item in superclasses),
            *({"rel": "interface", **item} for item in interfaces),
            *({"rel": "subclass", **item} for item in subclasses),
            *({"rel": "implementer", **item} for item in implementers),
        ]
        total = len(all_relatives)
        page = all_relatives[offset : offset + limit]

        evidence_ids = list(
            {ev for edge in self.outgoing_edges(target_id) for ev in edge.evidence_ids}
            | {ev for edge in self.incoming_edges(target_id) for ev in edge.evidence_ids}
            | set(target.evidence_ids)
        )

        return {
            "class_name": target.name,
            "class_id": target.id,
            "found": True,
            "direction": direction,
            "superclasses": superclasses,
            "interfaces": interfaces,
            "subclasses": subclasses,
            "implementers": implementers,
            "items": page,
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": offset + len(page) < total,
            "evidence_ids": sorted(evidence_ids),
        }

    def get_xrefs(
        self,
        symbol: str,
        *,
        kind: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Find cross-references to a symbol or entity with kind and confidence."""
        # Find matching target entity IDs
        target_ids: set[str] = set()
        if symbol in self.entities:
            target_ids.add(symbol)
        else:
            for entity in self.entities.values():
                name_match = entity.name == symbol
                suffix_match = entity.id.endswith(f":{symbol}")
                hash_match = f"#{symbol}" in entity.id
                if name_match or suffix_match or hash_match:
                    target_ids.add(entity.id)

        matching_edges: list[AAIREdge] = []
        filter_kind = kind.upper() if kind else None

        for tid in target_ids:
            for edge in self.incoming_edges(tid):
                if filter_kind and edge.kind.value != filter_kind:
                    continue
                matching_edges.append(edge)

        matching_edges.sort(key=lambda e: (e.kind.value, e.source_id, e.target_id))
        total = len(matching_edges)
        page = matching_edges[offset : offset + limit]

        xrefs: list[dict[str, Any]] = []
        for edge in page:
            source = self.get_entity(edge.source_id)
            xrefs.append(
                {
                    "edge_id": edge.id,
                    "kind": edge.kind.value,
                    "source_id": edge.source_id,
                    "source_name": source.name if source else edge.source_id,
                    "source_kind": source.kind.value if source else "unknown",
                    "target_id": edge.target_id,
                    "confidence": edge.confidence.value,
                    "metadata": edge.metadata,
                    "evidence_ids": edge.evidence_ids,
                }
            )

        edge_evs = {ev for edge in matching_edges for ev in edge.evidence_ids}
        entity_evs = {
            ev
            for tid in target_ids
            if tid in self.entities
            for ev in self.entities[tid].evidence_ids
        }
        evidence_ids = sorted(edge_evs | entity_evs)

        return {
            "symbol": symbol,
            "matched_entities": sorted(target_ids),
            "xrefs": xrefs,
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": offset + len(page) < total,
            "evidence_ids": sorted(evidence_ids),
        }

    def query(
        self,
        *,
        root_id: str | None = None,
        edge_kinds: list[str] | None = None,
        target_kinds: list[str] | None = None,
        max_depth: int = 2,
        direction: str = "outgoing",
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Bounded, paginated traversal of the AAIR graph."""
        max_depth = max(1, min(max_depth, 5))
        limit = max(1, min(limit, 500))
        offset = max(0, offset)
        filter_edge_kinds = set(edge_kinds) if edge_kinds else None
        filter_target_kinds = set(target_kinds) if target_kinds else None

        if root_id is None:
            # Global entity search filtered by target_kinds
            all_entities = list(self.entities.values())
            if filter_target_kinds:
                all_entities = [e for e in all_entities if e.kind.value in filter_target_kinds]
            all_entities.sort(key=lambda e: (e.kind.value, e.id))
            total = len(all_entities)
            page = all_entities[offset : offset + limit]
            return {
                "root_id": None,
                "nodes": [e.model_dump(mode="json") for e in page],
                "edges": [],
                "total_nodes": total,
                "total_edges": 0,
                "limit": limit,
                "offset": offset,
                "has_more": offset + len(page) < total,
                "evidence_ids": sorted({ev for e in page for ev in e.evidence_ids}),
            }

        root = self.get_entity(root_id)
        if root is None:
            return {
                "root_id": root_id,
                "nodes": [],
                "edges": [],
                "total_nodes": 0,
                "total_edges": 0,
                "limit": limit,
                "offset": offset,
                "has_more": False,
                "evidence_ids": [],
            }

        visited_nodes: set[str] = {root_id}
        collected_edges: list[AAIREdge] = []
        edge_ids_seen: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(root_id, 0)])

        while queue:
            curr_id, depth = queue.popleft()
            if depth >= max_depth:
                continue

            candidates: list[tuple[AAIREdge, str]] = []
            if direction in {"outgoing", "both"}:
                candidates.extend((e, e.target_id) for e in self.outgoing_edges(curr_id))
            if direction in {"incoming", "both"}:
                candidates.extend((e, e.source_id) for e in self.incoming_edges(curr_id))

            for edge, next_id in candidates:
                if filter_edge_kinds and edge.kind.value not in filter_edge_kinds:
                    continue
                next_entity = self.get_entity(next_id)
                if (
                    filter_target_kinds
                    and next_entity
                    and next_entity.kind.value not in filter_target_kinds
                ):
                    continue

                if edge.id not in edge_ids_seen:
                    edge_ids_seen.add(edge.id)
                    collected_edges.append(edge)

                if next_id not in visited_nodes:
                    visited_nodes.add(next_id)
                    queue.append((next_id, depth + 1))

        node_ids = sorted(visited_nodes)
        total_nodes = len(node_ids)
        page_ids = node_ids[offset : offset + limit]
        nodes = [
            self.entities[nid].model_dump(mode="json") for nid in page_ids if nid in self.entities
        ]

        node_evs = {
            ev
            for nid in visited_nodes
            if nid in self.entities
            for ev in self.entities[nid].evidence_ids
        }
        edge_evs = {ev for edge in collected_edges for ev in edge.evidence_ids}
        evidence_ids = sorted(node_evs | edge_evs)

        return {
            "root_id": root_id,
            "nodes": nodes,
            "edges": [e.model_dump(mode="json") for e in collected_edges],
            "total_nodes": total_nodes,
            "total_edges": len(collected_edges),
            "limit": limit,
            "offset": offset,
            "has_more": offset + len(page_ids) < total_nodes,
            "evidence_ids": sorted(evidence_ids),
        }


def migrate_aair(data: dict[str, Any]) -> AAIRGraph:
    """Migrate older or partial serialized AAIR graph representations to the latest schema."""
    _ = data.get("schema_version", "0.1.0")
    project_id = data.get("project_id", "migrated_project")
    artifact_id = data.get("artifact_id", "migrated_artifact")

    entities_data = data.get("entities", {})
    edges_data = data.get("edges", [])

    entities: dict[str, AAIREntity] = {}
    edges: list[AAIREdge] = []

    # Handle entities format (either dict of id->entity or list of entities)
    if isinstance(entities_data, dict):
        for eid, edict in entities_data.items():
            if not isinstance(edict, dict):
                continue
            edict.setdefault("id", eid)
            edict.setdefault("kind", AAIREntityKind.CLASS)
            edict.setdefault("name", eid)
            entities[eid] = AAIREntity.model_validate(edict)
    elif isinstance(entities_data, list):
        for edict in entities_data:
            if isinstance(edict, dict) and "id" in edict:
                entities[edict["id"]] = AAIREntity.model_validate(edict)

    # Handle edges format
    for edata in edges_data:
        if not isinstance(edata, dict):
            continue
        edata.setdefault(
            "id",
            make_edge_id(
                edata.get("kind", "REFERENCES"),
                edata.get("source_id", ""),
                edata.get("target_id", ""),
            ),
        )
        edges.append(AAIREdge.model_validate(edata))

    graph = AAIRGraph(
        schema_version=CURRENT_AAIR_SCHEMA_VERSION,
        project_id=project_id,
        artifact_id=artifact_id,
        entities=entities,
        edges=edges,
    )
    return graph
