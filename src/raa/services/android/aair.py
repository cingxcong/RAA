"""AAIR builder and intelligence service for Android applications.

Constructs normalized, evidence-linked AAIR graphs connecting manifest components,
DEX bytecode, endpoints, storage schemas, JNI native mappings, and framework bridges.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from raa.domain.aair import (
    AAIREdge,
    AAIREdgeKind,
    AAIREntity,
    AAIREntityKind,
    AAIRGraph,
    make_class_id,
    make_component_id,
    make_database_id,
    make_edge_id,
    make_endpoint_id,
    make_field_id,
    make_method_id,
    make_native_lib_id,
    make_native_sym_id,
    make_package_id,
    make_permission_id,
    make_resource_id,
    make_storage_key_id,
    make_table_id,
)
from raa.domain.models import Confidence

if TYPE_CHECKING:
    from raa.domain.manifest import ManifestInfo
    from raa.domain.models import FrameworkFinding, NativeLibrary
    from raa.domain.resources import ResourceSummary
    from raa.services.android.dex import DexIndex

_URL_PATTERN = re.compile(
    r"^https?://[a-zA-Z0-9][-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:/[-a-zA-Z0-9()@:%_+.~#?&/=]*)?",
    re.IGNORECASE,
)
_API_PATH_PATTERN = re.compile(r"^/(?:api|v[0-9]+)/[-a-zA-Z0-9_./]*", re.IGNORECASE)
_DB_PATTERN = re.compile(r"^[\w.-]+\.(?:db|sqlite|sqlite3)$", re.IGNORECASE)
_PREFS_PATTERN = re.compile(r"^[\w.-]+_(?:preferences?|prefs?)(?:\.xml)?$", re.IGNORECASE)
_CREATE_TABLE_PATTERN = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([`\"']?(\w+)[`\"']?)\s*\((.*?)\)",
    re.IGNORECASE | re.DOTALL,
)

_IGNORED_URL_PREFIXES = (
    "http://schemas.android.com/",
    "https://schemas.android.com/",
    "http://schemas.xmlsoap.org/",
    "https://schemas.xmlsoap.org/",
    "http://www.w3.org/",
    "https://www.w3.org/",
    "http://xmlpull.org/",
    "http://www.apache.org/",
    "https://www.apache.org/",
)


def _parse_columns(columns_raw: str) -> list[dict[str, Any]]:
    """Parse a column definitions block from CREATE TABLE SQL."""
    columns: list[dict[str, Any]] = []
    # Split on top-level commas (ignoring commas inside parentheses)
    tokens: list[str] = []
    current: list[str] = []
    paren_depth = 0
    for char in columns_raw:
        if char == "(":
            paren_depth += 1
        elif char == ")":
            paren_depth -= 1
        elif char == "," and paren_depth == 0:
            tokens.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    if current:
        tokens.append("".join(current).strip())

    for token in tokens:
        if not token:
            continue
        upper = token.upper()
        if (
            upper.startswith("PRIMARY KEY")
            or upper.startswith("FOREIGN KEY")
            or upper.startswith("UNIQUE")
            or upper.startswith("CHECK")
            or upper.startswith("CONSTRAINT")
        ):
            continue
        parts = token.split(None, 2)
        if not parts:
            continue
        col_name = parts[0].strip("`\"'[]")
        col_type = parts[1].upper() if len(parts) > 1 else "TEXT"
        is_pk = "PRIMARY KEY" in upper
        is_not_null = "NOT NULL" in upper
        columns.append(
            {
                "name": col_name,
                "type": col_type,
                "primary_key": is_pk,
                "not_null": is_not_null,
                "definition": token,
            }
        )
    return columns


def build_aair_graph(
    project_id: str,
    artifact_id: str,
    *,
    manifest: ManifestInfo | None = None,
    dex_index: DexIndex | None = None,
    resource_summary: ResourceSummary | None = None,
    native_libraries: list[NativeLibrary] | None = None,
    framework_findings: list[FrameworkFinding] | None = None,
    elf_symbols: list[dict[str, Any]] | None = None,
    evidence_ids: list[str] | None = None,
) -> AAIRGraph:
    """Build a comprehensive, normalized AAIR graph from analysis stages."""
    graph = AAIRGraph(project_id=project_id, artifact_id=artifact_id)
    ev_ids = list(evidence_ids or [])

    # 1. Package & Artifact entities
    pkg_name = manifest.package if manifest and manifest.package else "unknown.package"
    pkg_id = make_package_id(pkg_name)
    graph.add_entity(
        AAIREntity(
            id=pkg_id,
            kind=AAIREntityKind.PACKAGE,
            name=pkg_name,
            attributes={
                "version_name": manifest.version_name if manifest else None,
                "version_code": manifest.version_code if manifest else None,
            },
            evidence_ids=ev_ids,
        )
    )

    art_id = f"artifact:{artifact_id}"
    graph.add_entity(
        AAIREntity(
            id=art_id,
            kind=AAIREntityKind.ARTIFACT,
            name=artifact_id,
            attributes={"project_id": project_id},
            evidence_ids=ev_ids,
        )
    )
    graph.add_edge(
        AAIREdge(
            id=make_edge_id("CONTAINS", art_id, pkg_id),
            source_id=art_id,
            target_id=pkg_id,
            kind=AAIREdgeKind.CONTAINS,
            evidence_ids=ev_ids,
        )
    )

    # 2. Manifest Components & Permissions
    if manifest:
        # Permissions
        for perm in manifest.requested_permissions:
            perm_id = make_permission_id(perm.name)
            graph.add_entity(
                AAIREntity(
                    id=perm_id,
                    kind=AAIREntityKind.PERMISSION,
                    name=perm.name,
                    attributes={"max_sdk": perm.max_sdk_version},
                    evidence_ids=ev_ids,
                )
            )
            graph.add_edge(
                AAIREdge(
                    id=make_edge_id("REQUESTS", pkg_id, perm_id),
                    source_id=pkg_id,
                    target_id=perm_id,
                    kind=AAIREdgeKind.REQUESTS,
                    evidence_ids=ev_ids,
                )
            )

        # Components: activities, services, receivers, providers
        for comp in manifest.components:
            comp_id = make_component_id(pkg_name, comp.name)
            actions = [a for f in comp.intent_filters for a in f.actions]
            categories = [c for f in comp.intent_filters for c in f.categories]
            graph.add_entity(
                AAIREntity(
                    id=comp_id,
                    kind=AAIREntityKind.COMPONENT,
                    name=comp.name,
                    parent_id=pkg_id,
                    attributes={
                        "kind": str(comp.kind),
                        "exported": comp.exported,
                        "permission": comp.permission,
                        "actions": actions,
                        "categories": categories,
                    },
                    evidence_ids=ev_ids,
                )
            )
            graph.add_edge(
                AAIREdge(
                    id=make_edge_id("CONTAINS", pkg_id, comp_id),
                    source_id=pkg_id,
                    target_id=comp_id,
                    kind=AAIREdgeKind.CONTAINS,
                    evidence_ids=ev_ids,
                )
            )

            # Link component to its Java class
            cls_id = make_class_id(comp.name)
            graph.add_edge(
                AAIREdge(
                    id=make_edge_id("IMPLEMENTS", comp_id, cls_id),
                    source_id=comp_id,
                    target_id=cls_id,
                    kind=AAIREdgeKind.IMPLEMENTS,
                    evidence_ids=ev_ids,
                )
            )

        # Deep links in manifest
        for dl in manifest.deep_links:
            dl_url = f"{dl.scheme}://{dl.host or ''}{dl.path or dl.path_prefix or ''}"
            ep_id = make_endpoint_id("DEEPLINK", dl_url)
            graph.add_entity(
                AAIREntity(
                    id=ep_id,
                    kind=AAIREntityKind.ENDPOINT,
                    name=dl_url,
                    attributes={
                        "scheme": dl.scheme,
                        "host": dl.host,
                        "path": dl.path or dl.path_prefix,
                        "component": dl.component,
                    },
                    evidence_ids=ev_ids,
                )
            )
            comp_id = make_component_id(pkg_name, dl.component)
            graph.add_edge(
                AAIREdge(
                    id=make_edge_id("NAVIGATES_TO", comp_id, ep_id),
                    source_id=comp_id,
                    target_id=ep_id,
                    kind=AAIREdgeKind.NAVIGATES_TO,
                    evidence_ids=ev_ids,
                )
            )

    # 3. DEX Classes, Methods, Fields, and Bytecode References
    string_to_methods: dict[str, list[str]] = {}
    method_to_callers: dict[str, list[dict[str, Any]]] = {}

    if dex_index:
        for klass in dex_index.classes:
            cls_id = make_class_id(klass.name)
            graph.add_entity(
                AAIREntity(
                    id=cls_id,
                    kind=AAIREntityKind.CLASS,
                    name=klass.name,
                    parent_id=pkg_id,
                    attributes={
                        "descriptor": klass.descriptor,
                        "access_flags": klass.access_flags,
                        "superclass": klass.superclass,
                        "interfaces": klass.interfaces,
                        "dex_file": klass.dex_file,
                    },
                    evidence_ids=ev_ids,
                )
            )
            graph.add_edge(
                AAIREdge(
                    id=make_edge_id("CONTAINS", pkg_id, cls_id),
                    source_id=pkg_id,
                    target_id=cls_id,
                    kind=AAIREdgeKind.CONTAINS,
                    evidence_ids=ev_ids,
                )
            )

            # Superclass inheritance
            if klass.superclass and klass.superclass not in {
                "java.lang.Object",
                "Ljava/lang/Object;",
            }:
                super_id = make_class_id(klass.superclass)
                if not graph.get_entity(super_id):
                    graph.add_entity(
                        AAIREntity(
                            id=super_id,
                            kind=AAIREntityKind.CLASS,
                            name=klass.superclass,
                            confidence=Confidence.DERIVED,
                            evidence_ids=ev_ids,
                        )
                    )
                graph.add_edge(
                    AAIREdge(
                        id=make_edge_id("EXTENDS", cls_id, super_id),
                        source_id=cls_id,
                        target_id=super_id,
                        kind=AAIREdgeKind.EXTENDS,
                        confidence=Confidence.OBSERVED,
                        evidence_ids=ev_ids,
                    )
                )

            # Implemented interfaces
            for iface in klass.interfaces:
                iface_id = make_class_id(iface)
                if not graph.get_entity(iface_id):
                    graph.add_entity(
                        AAIREntity(
                            id=iface_id,
                            kind=AAIREntityKind.CLASS,
                            name=iface,
                            confidence=Confidence.DERIVED,
                            evidence_ids=ev_ids,
                        )
                    )
                graph.add_edge(
                    AAIREdge(
                        id=make_edge_id("IMPLEMENTS", cls_id, iface_id),
                        source_id=cls_id,
                        target_id=iface_id,
                        kind=AAIREdgeKind.IMPLEMENTS,
                        confidence=Confidence.OBSERVED,
                        evidence_ids=ev_ids,
                    )
                )

            # Fields
            for field in klass.fields:
                fld_id = make_field_id(klass.name, field.name, field.descriptor)
                graph.add_entity(
                    AAIREntity(
                        id=fld_id,
                        kind=AAIREntityKind.FIELD,
                        name=field.name,
                        parent_id=cls_id,
                        attributes={
                            "descriptor": field.descriptor,
                            "access_flags": field.access_flags,
                        },
                        evidence_ids=ev_ids,
                    )
                )
                graph.add_edge(
                    AAIREdge(
                        id=make_edge_id("CONTAINS", cls_id, fld_id),
                        source_id=cls_id,
                        target_id=fld_id,
                        kind=AAIREdgeKind.CONTAINS,
                        evidence_ids=ev_ids,
                    )
                )

            # Methods
            for method in klass.methods:
                mth_id = make_method_id(klass.name, method.name, method.descriptor)
                is_native = bool(method.access_flags & 0x0100)
                graph.add_entity(
                    AAIREntity(
                        id=mth_id,
                        kind=AAIREntityKind.METHOD,
                        name=method.name,
                        parent_id=cls_id,
                        attributes={
                            "descriptor": method.descriptor,
                            "access_flags": method.access_flags,
                            "is_native": is_native,
                        },
                        evidence_ids=ev_ids,
                    )
                )
                graph.add_edge(
                    AAIREdge(
                        id=make_edge_id("CONTAINS", cls_id, mth_id),
                        source_id=cls_id,
                        target_id=mth_id,
                        kind=AAIREdgeKind.CONTAINS,
                        evidence_ids=ev_ids,
                    )
                )

        # Bytecode references (calls, fields, strings)
        for ref in dex_index.references:
            src_mth = make_method_id(ref.from_class, ref.from_method, ref.from_descriptor)

            if ref.kind == "method_call" and ref.target_class and ref.target_name:
                tgt_mth = make_method_id(
                    ref.target_class, ref.target_name, ref.target_descriptor or "()V"
                )
                if not graph.get_entity(tgt_mth):
                    graph.add_entity(
                        AAIREntity(
                            id=tgt_mth,
                            kind=AAIREntityKind.METHOD,
                            name=ref.target_name,
                            confidence=Confidence.DERIVED,
                            evidence_ids=ev_ids,
                        )
                    )
                graph.add_edge(
                    AAIREdge(
                        id=make_edge_id("CALLS", src_mth, tgt_mth),
                        source_id=src_mth,
                        target_id=tgt_mth,
                        kind=AAIREdgeKind.CALLS,
                        metadata={"offset": ref.offset, "dex_file": ref.dex_file},
                        evidence_ids=ev_ids,
                    )
                )
                # Index callers for fast endpoint correlation
                caller_rec = {
                    "caller_id": src_mth,
                    "class": ref.from_class,
                    "method": ref.from_method,
                    "offset": ref.offset,
                }
                method_to_callers.setdefault(tgt_mth, []).append(caller_rec)

            elif ref.kind == "field_access" and ref.target_class and ref.target_name:
                tgt_fld = make_field_id(
                    ref.target_class, ref.target_name, ref.target_descriptor or ""
                )
                if not graph.get_entity(tgt_fld):
                    graph.add_entity(
                        AAIREntity(
                            id=tgt_fld,
                            kind=AAIREntityKind.FIELD,
                            name=ref.target_name,
                            confidence=Confidence.DERIVED,
                            evidence_ids=ev_ids,
                        )
                    )
                graph.add_edge(
                    AAIREdge(
                        id=make_edge_id("REFERENCES", src_mth, tgt_fld),
                        source_id=src_mth,
                        target_id=tgt_fld,
                        kind=AAIREdgeKind.REFERENCES,
                        metadata={"offset": ref.offset},
                        evidence_ids=ev_ids,
                    )
                )

            elif ref.kind == "string_reference" and ref.value:
                string_to_methods.setdefault(ref.value, []).append(src_mth)

    # 4. Endpoint Discovery & Source Correlation
    # Discover endpoints from string pools and references
    candidate_urls: set[str] = set()
    candidate_paths: set[str] = set()

    if dex_index:
        for dex_f in dex_index.files:
            for s in dex_f.strings:
                stripped = s.strip()
                if _URL_PATTERN.match(stripped):
                    if not any(stripped.startswith(p) for p in _IGNORED_URL_PREFIXES):
                        candidate_urls.add(stripped)
                elif _API_PATH_PATTERN.match(stripped):
                    candidate_paths.add(stripped)

    # Also include strings from string_to_methods
    for s in string_to_methods:
        stripped = s.strip()
        if _URL_PATTERN.match(stripped) and not any(
            stripped.startswith(p) for p in _IGNORED_URL_PREFIXES
        ):
            candidate_urls.add(stripped)
        elif _API_PATH_PATTERN.match(stripped):
            candidate_paths.add(stripped)

    all_endpoints = sorted(candidate_urls | candidate_paths)
    for endpoint in all_endpoints:
        ep_id = make_endpoint_id("HTTP", endpoint)
        referencing_methods = string_to_methods.get(endpoint, [])

        # Gather callers of referencing methods
        all_callers: list[dict[str, Any]] = []
        for m_id in referencing_methods:
            all_callers.extend(method_to_callers.get(m_id, []))

        graph.add_entity(
            AAIREntity(
                id=ep_id,
                kind=AAIREntityKind.ENDPOINT,
                name=endpoint,
                attributes={
                    "url": endpoint,
                    "source_methods": sorted(set(referencing_methods)),
                    "callers": all_callers,
                    "trace_available": len(referencing_methods) > 0,
                },
                confidence=Confidence.OBSERVED,
                evidence_ids=ev_ids,
            )
        )

        # Create TRIGGERS_ENDPOINT edge from referencing method to endpoint
        for m_id in referencing_methods:
            graph.add_edge(
                AAIREdge(
                    id=make_edge_id("TRIGGERS_ENDPOINT", m_id, ep_id),
                    source_id=m_id,
                    target_id=ep_id,
                    kind=AAIREdgeKind.TRIGGERS_ENDPOINT,
                    confidence=Confidence.OBSERVED,
                    evidence_ids=ev_ids,
                )
            )

    # 5. Storage & Schema Discovery
    all_strings: set[str] = set()
    if dex_index:
        for dex_f in dex_index.files:
            all_strings.update(dex_f.strings)
    all_strings.update(string_to_methods.keys())

    discovered_dbs: set[str] = set()
    discovered_prefs: set[str] = set()

    for s in all_strings:
        stripped = s.strip()
        if _DB_PATTERN.match(stripped):
            discovered_dbs.add(stripped)
        elif _PREFS_PATTERN.match(stripped):
            discovered_prefs.add(stripped)

    # Fallback default DB if SQLiteOpenHelper found
    if dex_index:
        for klass in dex_index.classes:
            if (
                klass.superclass in {"android.database.sqlite.SQLiteOpenHelper", "SQLiteOpenHelper"}
                and not discovered_dbs
            ):
                discovered_dbs.add("app.db")

    # Add Database entities
    for db_name in sorted(discovered_dbs):
        db_id = make_database_id(db_name)
        graph.add_entity(
            AAIREntity(
                id=db_id,
                kind=AAIREntityKind.DATABASE,
                name=db_name,
                parent_id=pkg_id,
                evidence_ids=ev_ids,
            )
        )
        graph.add_edge(
            AAIREdge(
                id=make_edge_id("CONTAINS", pkg_id, db_id),
                source_id=pkg_id,
                target_id=db_id,
                kind=AAIREdgeKind.CONTAINS,
                evidence_ids=ev_ids,
            )
        )

    # Discover Tables and Columns from SQL CREATE TABLE statements
    primary_db_name = sorted(discovered_dbs)[0] if discovered_dbs else "app.db"
    for s in all_strings:
        for match in _CREATE_TABLE_PATTERN.finditer(s):
            table_name = match.group(2)
            columns_raw = match.group(3)
            cols = _parse_columns(columns_raw)
            tbl_id = make_table_id(primary_db_name, table_name)

            graph.add_entity(
                AAIREntity(
                    id=tbl_id,
                    kind=AAIREntityKind.TABLE,
                    name=table_name,
                    parent_id=make_database_id(primary_db_name),
                    attributes={
                        "table_name": table_name,
                        "columns": cols,
                        "raw_sql": match.group(0),
                    },
                    confidence=Confidence.OBSERVED,
                    evidence_ids=ev_ids,
                )
            )
            graph.add_edge(
                AAIREdge(
                    id=make_edge_id("CONTAINS", make_database_id(primary_db_name), tbl_id),
                    source_id=make_database_id(primary_db_name),
                    target_id=tbl_id,
                    kind=AAIREdgeKind.CONTAINS,
                    evidence_ids=ev_ids,
                )
            )

            # Correlate methods referencing this CREATE TABLE string
            for m_id in string_to_methods.get(s, []):
                graph.add_edge(
                    AAIREdge(
                        id=make_edge_id("ACCESSES_STORAGE", m_id, tbl_id),
                        source_id=m_id,
                        target_id=tbl_id,
                        kind=AAIREdgeKind.ACCESSES_STORAGE,
                        confidence=Confidence.OBSERVED,
                        evidence_ids=ev_ids,
                    )
                )

    # SharedPreferences keys discovery
    for pref_store in sorted(discovered_prefs):
        pref_id = make_database_id(pref_store)
        graph.add_entity(
            AAIREntity(
                id=pref_id,
                kind=AAIREntityKind.DATABASE,
                name=pref_store,
                parent_id=pkg_id,
                attributes={"storage_type": "shared_preferences"},
                evidence_ids=ev_ids,
            )
        )
        graph.add_edge(
            AAIREdge(
                id=make_edge_id("CONTAINS", pkg_id, pref_id),
                source_id=pkg_id,
                target_id=pref_id,
                kind=AAIREdgeKind.CONTAINS,
                evidence_ids=ev_ids,
            )
        )
        for s in all_strings:
            if s.startswith("key_") or s.startswith("pref_") or s.endswith("_key"):
                k_id = make_storage_key_id(pref_store, s)
                if not graph.get_entity(k_id):
                    graph.add_entity(
                        AAIREntity(
                            id=k_id,
                            kind=AAIREntityKind.STORAGE_KEY,
                            name=s,
                            parent_id=pref_id,
                            attributes={"store": pref_store},
                            evidence_ids=ev_ids,
                        )
                    )
                    graph.add_edge(
                        AAIREdge(
                            id=make_edge_id("CONTAINS", pref_id, k_id),
                            source_id=pref_id,
                            target_id=k_id,
                            kind=AAIREdgeKind.CONTAINS,
                            evidence_ids=ev_ids,
                        )
                    )

    # 6. Native Libraries and JNI Bridges
    if native_libraries:
        for lib in native_libraries:
            nlib_id = make_native_lib_id(lib.abi, lib.name)
            graph.add_entity(
                AAIREntity(
                    id=nlib_id,
                    kind=AAIREntityKind.NATIVE_LIBRARY,
                    name=lib.name,
                    parent_id=pkg_id,
                    attributes={"abi": lib.abi, "size_bytes": lib.size_bytes},
                    evidence_ids=ev_ids,
                )
            )
            graph.add_edge(
                AAIREdge(
                    id=make_edge_id("LOADS_LIBRARY", pkg_id, nlib_id),
                    source_id=pkg_id,
                    target_id=nlib_id,
                    kind=AAIREdgeKind.LOADS_LIBRARY,
                    evidence_ids=ev_ids,
                )
            )

    # Map native Java methods to native symbols via JNI bridges
    if dex_index:
        for klass in dex_index.classes:
            for method in klass.methods:
                is_native = bool(method.access_flags & 0x0100) or getattr(
                    method, "is_native", False
                )
                if is_native:
                    mth_id = make_method_id(klass.name, method.name, method.descriptor)
                    # Expected standard JNI export name
                    mangled_cls = klass.name.replace(".", "_").replace("/", "_")
                    mangled_name = f"Java_{mangled_cls}_{method.name}"
                    sym_id = make_native_sym_id("native.so", mangled_name)

                    if not graph.get_entity(sym_id):
                        graph.add_entity(
                            AAIREntity(
                                id=sym_id,
                                kind=AAIREntityKind.NATIVE_SYMBOL,
                                name=mangled_name,
                                confidence=Confidence.DERIVED,
                                evidence_ids=ev_ids,
                            )
                        )
                    graph.add_edge(
                        AAIREdge(
                            id=make_edge_id("JNI_BRIDGE", mth_id, sym_id),
                            source_id=mth_id,
                            target_id=sym_id,
                            kind=AAIREdgeKind.JNI_BRIDGE,
                            confidence=Confidence.OBSERVED,
                            metadata={"jni_symbol": mangled_name},
                            evidence_ids=ev_ids,
                        )
                    )

    # 7. Framework Bridges
    if framework_findings:
        for fw in framework_findings:
            fw_id = f"framework:{fw.id}"
            graph.add_entity(
                AAIREntity(
                    id=fw_id,
                    kind=AAIREntityKind.FRAMEWORK,
                    name=fw.name,
                    attributes={"category": fw.category, "markers": fw.markers},
                    confidence=fw.confidence,
                    evidence_ids=ev_ids,
                )
            )
            graph.add_edge(
                AAIREdge(
                    id=make_edge_id("CONTAINS", pkg_id, fw_id),
                    source_id=pkg_id,
                    target_id=fw_id,
                    kind=AAIREdgeKind.CONTAINS,
                    evidence_ids=ev_ids,
                )
            )

            # Link React Native native modules
            if fw.id == "react_native" and dex_index:
                for klass in dex_index.classes:
                    if (
                        "NativeModule" in klass.interfaces
                        or "com.facebook.react.bridge.NativeModule" in klass.interfaces
                    ):
                        cls_id = make_class_id(klass.name)
                        graph.add_edge(
                            AAIREdge(
                                id=make_edge_id("FRAMEWORK_BRIDGE", fw_id, cls_id),
                                source_id=fw_id,
                                target_id=cls_id,
                                kind=AAIREdgeKind.FRAMEWORK_BRIDGE,
                                confidence=Confidence.OBSERVED,
                                metadata={"bridge": "react_native_module"},
                                evidence_ids=ev_ids,
                            )
                        )

            # Link Flutter method channels
            if fw.id == "flutter" and dex_index:
                for s in all_strings:
                    if s.startswith("plugins.flutter.io/") or "flutter/methodchannel" in s.lower():
                        targets = string_to_methods.get(s, []) or [pkg_id]
                        for tgt_id in targets:
                            graph.add_edge(
                                AAIREdge(
                                    id=make_edge_id("FRAMEWORK_BRIDGE", fw_id, tgt_id),
                                    source_id=fw_id,
                                    target_id=tgt_id,
                                    kind=AAIREdgeKind.FRAMEWORK_BRIDGE,
                                    confidence=Confidence.DERIVED,
                                    metadata={"channel": s},
                                    evidence_ids=ev_ids,
                                )
                            )

    # 8. Resources
    if resource_summary:
        for type_summary in resource_summary.types:
            res_id = make_resource_id("type", type_summary.type)
            graph.add_entity(
                AAIREntity(
                    id=res_id,
                    kind=AAIREntityKind.RESOURCE,
                    name=type_summary.type,
                    attributes={
                        "entry_count": type_summary.entry_count,
                        "value_count": type_summary.value_count,
                    },
                    evidence_ids=ev_ids,
                )
            )

    return graph
