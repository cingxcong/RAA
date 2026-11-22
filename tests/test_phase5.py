"""Phase 5 AAIR and application intelligence tests.

Verifies:
1. Extended AAIR schema and migration.
2. Stable structural ID generation.
3. Storage/schema discovery (SQLite CREATE TABLE parsing, column types, SharedPreferences).
4. Endpoint discovery and source correlation (endpoint -> source method -> caller).
5. JNI bridge and framework bridge edges.
6. Bounded graph queries (hierarchy, xrefs, query, neighborhood).
7. MCP tool invocation and CLI subcommands.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from raa.cli.main import app
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
    migrate_aair,
)
from raa.domain.manifest import ComponentInfo, ManifestInfo
from raa.domain.models import Confidence, FrameworkFinding, NativeLibrary
from raa.runtime import Runtime
from raa.services.android.aair import _parse_columns, build_aair_graph
from tests.conftest import make_apk
from tests.dex_builder import (
    DexClassSpec,
    DexInsn,
    DexMethodSpec,
    build_dex,
)

runner = CliRunner()


def test_aair_domain_models_and_stable_ids() -> None:
    """Verify stable structural ID generation and in-memory graph indexing."""
    assert make_package_id("com.example.app") == "package:com.example.app"
    assert make_class_id("com.example.MainActivity") == "class:com.example.MainActivity"
    assert (
        make_method_id("com.example.MainActivity", "onCreate", "(Landroid/os/Bundle;)V")
        == "method:com.example.MainActivity#onCreate(Landroid/os/Bundle;)V"
    )
    assert (
        make_field_id("com.example.MainActivity", "mDb", "Landroid/database/sqlite/SQLiteDatabase;")
        == "field:com.example.MainActivity#mDb:Landroid/database/sqlite/SQLiteDatabase;"
    )
    assert make_resource_id("layout", "activity_main") == "resource:layout/activity_main"
    assert (
        make_component_id("com.example.app", "MainActivity")
        == "component:com.example.app/MainActivity"
    )
    assert (
        make_endpoint_id("GET", "https://api.example.com/v1/users")
        == "endpoint:GET:https://api.example.com/v1/users"
    )
    assert make_database_id("app.db") == "database:app.db"
    assert make_table_id("app.db", "users") == "table:app.db#users"
    assert make_storage_key_id("app_prefs", "token") == "storage_key:app_prefs#token"
    assert make_native_lib_id("arm64-v8a", "libapp.so") == "native_library:arm64-v8a/libapp.so"
    assert (
        make_native_sym_id("libnative.so", "Java_com_example_MainActivity_nativeInit")
        == "native_symbol:libnative.so#Java_com_example_MainActivity_nativeInit"
    )
    assert (
        make_permission_id("android.permission.INTERNET")
        == "permission:android.permission.INTERNET"
    )
    assert (
        make_edge_id("CALLS", "method:A#foo()V", "method:B#bar()V")
        == "CALLS:method:A#foo()V->method:B#bar()V"
    )

    graph = AAIRGraph(project_id="p1", artifact_id="a1")
    e1 = AAIREntity(
        id="class:com.example.A",
        kind=AAIREntityKind.CLASS,
        name="com.example.A",
    )
    e2 = AAIREntity(
        id="class:com.example.B",
        kind=AAIREntityKind.CLASS,
        name="com.example.B",
    )
    graph.add_entity(e1)
    graph.add_entity(e2)

    edge = AAIREdge(
        id=make_edge_id("EXTENDS", e1.id, e2.id),
        source_id=e1.id,
        target_id=e2.id,
        kind=AAIREdgeKind.EXTENDS,
    )
    graph.add_edge(edge)

    assert graph.get_entity("class:com.example.A") == e1
    assert len(graph.outgoing_edges(e1.id)) == 1
    assert len(graph.incoming_edges(e2.id)) == 1


def test_aair_migration() -> None:
    """Verify AAIR schema migrator upgrades partial/older data to 1.0.0."""
    legacy_data = {
        "schema_version": "0.1.0",
        "project_id": "legacy_proj",
        "artifact_id": "legacy_art",
        "entities": {
            "class:com.example.Old": {
                "id": "class:com.example.Old",
                "kind": "class",
                "name": "com.example.Old",
            }
        },
        "edges": [
            {
                "source_id": "class:com.example.Old",
                "target_id": "class:java.lang.Object",
                "kind": "EXTENDS",
            }
        ],
    }
    migrated = migrate_aair(legacy_data)
    assert migrated.schema_version == "1.0.0"
    assert "class:com.example.Old" in migrated.entities
    assert len(migrated.edges) == 1
    assert migrated.edges[0].kind == AAIREdgeKind.EXTENDS


def test_sqlite_create_table_parsing() -> None:
    """Verify SQL CREATE TABLE parsing extracts tables, columns, and constraints."""
    sql = """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        email TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT u_user UNIQUE (username)
    )
    """
    cols = _parse_columns(sql.split("(", 1)[1].rsplit(")", 1)[0])
    col_names = [c["name"] for c in cols]
    assert "id" in col_names
    assert "username" in col_names
    assert "email" in col_names
    assert "created_at" in col_names

    id_col = next(c for c in cols if c["name"] == "id")
    assert id_col["type"] == "INTEGER"
    assert id_col["primary_key"] is True

    user_col = next(c for c in cols if c["name"] == "username")
    assert user_col["type"] == "TEXT"
    assert user_col["not_null"] is True


def _build_intelligence_dex() -> bytes:
    """Synthesize DEX with classes, method calls, string endpoint references, and SQL."""
    api_service = DexClassSpec(
        name="Lcom/example/ApiService;",
        superclass="Ljava/lang/Object;",
        methods=(
            DexMethodSpec(
                name="fetchUsers",
                params=(),
                returns="V",
                instructions=(DexInsn(opcode=0x1A, target="https://api.example.com/v1/users"),),
            ),
        ),
    )
    main_activity = DexClassSpec(
        name="Lcom/example/MainActivity;",
        superclass="Landroid/app/Activity;",
        interfaces=("Lcom/example/UserCallback;",),
        methods=(
            DexMethodSpec(
                name="onStart",
                params=(),
                returns="V",
                instructions=(
                    DexInsn(opcode=0x6E, target="Lcom/example/ApiService;->fetchUsers()V"),
                    DexInsn(opcode=0x1A, target="plugins.flutter.io/url_launcher"),
                ),
            ),
            DexMethodSpec(
                name="nativeInit",
                params=(),
                returns="V",
                access_flags=0x0101,  # native
                code=False,
            ),
        ),
    )
    return build_dex(
        [api_service, main_activity],
        extra_strings=(
            "https://api.example.com/v1/users",
            "CREATE TABLE IF NOT EXISTS users "
            "(id INTEGER PRIMARY KEY, username TEXT NOT NULL, email TEXT)",
            "app.db",
            "user_settings_preferences.xml",
            "pref_auth_token",
            "plugins.flutter.io/url_launcher",
        ),
    )


async def test_endpoint_source_correlation_trace(runtime: Runtime, tmp_path: Path) -> None:
    """Verify Phase 5 Exit Criterion: A known endpoint traces to its source method and caller."""
    dex_bytes = _build_intelligence_dex()
    apk = make_apk(
        tmp_path / "endpoint_trace.apk",
        include_dex=False,
        entries={"classes.dex": dex_bytes},
    )

    proj = await runtime.invoke("project_create", {"name": "Endpoint Trace Project"})
    pid = proj.data["id"]

    ingest = await runtime.invoke("artifact_ingest", {"project_id": pid, "path": str(apk)})
    aid = ingest.data["id"]

    start = await runtime.invoke("analysis_start", {"project_id": pid, "artifact_id": aid})
    job = await runtime.analysis.wait(pid, start.data["id"])
    jid = str(job.id)

    # Trace endpoint via AAIR service
    trace = runtime.aair.trace_endpoint(pid, jid, "https://api.example.com/v1/users")
    assert trace["trace_complete"] is True

    # Source method check: ApiService.fetchUsers()V
    source_method_ids = [sm["method_id"] for sm in trace["source_methods"]]
    assert any("fetchUsers" in sm_id for sm_id in source_method_ids)
    assert any("ApiService" in sm_id for sm_id in source_method_ids)

    # Caller check: MainActivity.onStart()V
    caller_ids = [c["caller_id"] for c in trace["callers"]]
    assert any("onStart" in c_id for c_id in caller_ids)
    assert any("MainActivity" in c_id for c_id in caller_ids)


async def test_storage_schema_discovery(runtime: Runtime, tmp_path: Path) -> None:
    """Verify SQLite database, table schemas with columns, and SharedPreferences keys."""
    dex_bytes = _build_intelligence_dex()
    apk = make_apk(
        tmp_path / "storage_schema.apk",
        include_dex=False,
        entries={"classes.dex": dex_bytes},
    )

    proj = await runtime.invoke("project_create", {"name": "Storage Project"})
    pid = proj.data["id"]

    ingest = await runtime.invoke("artifact_ingest", {"project_id": pid, "path": str(apk)})
    aid = ingest.data["id"]

    start = await runtime.invoke("analysis_start", {"project_id": pid, "artifact_id": aid})
    job = await runtime.analysis.wait(pid, start.data["id"])
    jid = str(job.id)

    graph = runtime.aair.get_or_build_graph(pid, jid)

    # 1. Database entity
    db_entity = graph.get_entity("database:app.db")
    assert db_entity is not None
    assert db_entity.kind == AAIREntityKind.DATABASE

    # 2. Table entity with columns
    table_entity = graph.get_entity("table:app.db#users")
    assert table_entity is not None
    assert table_entity.kind == AAIREntityKind.TABLE
    cols = table_entity.attributes["columns"]
    col_names = {c["name"] for c in cols}
    assert {"id", "username", "email"} <= col_names

    # 3. SharedPreferences store & keys
    prefs_entity = graph.get_entity("database:user_settings_preferences.xml")
    assert prefs_entity is not None

    key_entity = graph.get_entity("storage_key:user_settings_preferences.xml#pref_auth_token")
    assert key_entity is not None
    assert key_entity.kind == AAIREntityKind.STORAGE_KEY


def test_jni_and_framework_bridge_edges() -> None:
    """Verify JNI bridge edges to native symbols and framework bridges."""
    dex_bytes = _build_intelligence_dex()
    from raa.services.android.dex import DexIndex, parse_dex

    parsed_dex = parse_dex(dex_bytes)
    dex_index = DexIndex(files=[parsed_dex])

    manifest = ManifestInfo(
        package="com.example",
        components=[ComponentInfo(kind="activity", name="com.example.MainActivity", exported=True)],
    )
    native_libs = [NativeLibrary(abi="arm64-v8a", name="libnative.so", size_bytes=4096)]
    frameworks = [
        FrameworkFinding(
            id="flutter",
            name="Flutter",
            category="cross_platform",
            confidence=Confidence.OBSERVED,
        )
    ]

    graph = build_aair_graph(
        project_id="test_proj",
        artifact_id="test_art",
        manifest=manifest,
        dex_index=dex_index,
        native_libraries=native_libs,
        framework_findings=frameworks,
    )

    # JNI Bridge
    jni_edges = [e for e in graph.edges if e.kind == AAIREdgeKind.JNI_BRIDGE]
    assert len(jni_edges) >= 1
    assert "nativeInit" in jni_edges[0].source_id
    assert "Java_com_example_MainActivity_nativeInit" in jni_edges[0].target_id

    # Framework Bridge
    fw_edges = [e for e in graph.edges if e.kind == AAIREdgeKind.FRAMEWORK_BRIDGE]
    assert len(fw_edges) >= 1
    assert fw_edges[0].source_id == "framework:flutter"


async def test_mcp_source_get_hierarchy_and_xrefs(runtime: Runtime, tmp_path: Path) -> None:
    """Verify MCP source_get_hierarchy and source_get_xrefs tools with bounded pagination."""
    dex_bytes = _build_intelligence_dex()
    apk = make_apk(
        tmp_path / "hierarchy_xrefs.apk",
        include_dex=False,
        entries={"classes.dex": dex_bytes},
    )

    proj = await runtime.invoke("project_create", {"name": "Hierarchy Project"})
    pid = proj.data["id"]

    ingest = await runtime.invoke("artifact_ingest", {"project_id": pid, "path": str(apk)})
    aid = ingest.data["id"]

    start = await runtime.invoke("analysis_start", {"project_id": pid, "artifact_id": aid})
    job = await runtime.analysis.wait(pid, start.data["id"])
    jid = str(job.id)

    # 1. source_get_hierarchy
    hier = await runtime.invoke(
        "source_get_hierarchy",
        {
            "project_id": pid,
            "job_id": jid,
            "class_name": "com.example.MainActivity",
            "direction": "both",
            "limit": 10,
        },
    )
    assert hier.data["found"] is True
    assert hier.data["class_name"] == "com.example.MainActivity"
    superclasses = [s["name"] for s in hier.data["superclasses"]]
    assert "android.app.Activity" in superclasses
    interfaces = [i["name"] for i in hier.data["interfaces"]]
    assert "com.example.UserCallback" in interfaces

    # 2. source_get_xrefs
    xrefs = await runtime.invoke(
        "source_get_xrefs",
        {
            "project_id": pid,
            "job_id": jid,
            "symbol": "fetchUsers",
            "limit": 10,
        },
    )
    assert xrefs.data["total"] >= 1
    assert any("onStart" in x["source_id"] for x in xrefs.data["xrefs"])


async def test_mcp_graph_query_and_neighborhood(runtime: Runtime, tmp_path: Path) -> None:
    """Verify MCP graph_query and graph_get_neighborhood tools with bounded traversal."""
    dex_bytes = _build_intelligence_dex()
    apk = make_apk(
        tmp_path / "graph_tools.apk",
        include_dex=False,
        entries={"classes.dex": dex_bytes},
    )

    proj = await runtime.invoke("project_create", {"name": "Graph Tools Project"})
    pid = proj.data["id"]

    ingest = await runtime.invoke("artifact_ingest", {"project_id": pid, "path": str(apk)})
    aid = ingest.data["id"]

    start = await runtime.invoke("analysis_start", {"project_id": pid, "artifact_id": aid})
    job = await runtime.analysis.wait(pid, start.data["id"])
    jid = str(job.id)

    # 1. graph_query top-level
    g_all = await runtime.invoke(
        "graph_query",
        {"project_id": pid, "job_id": jid, "limit": 20},
    )
    assert g_all.data["total_nodes"] >= 5

    # 2. graph_query from root node
    g_root = await runtime.invoke(
        "graph_query",
        {
            "project_id": pid,
            "job_id": jid,
            "root_id": "class:com.example.MainActivity",
            "max_depth": 2,
            "direction": "both",
            "limit": 20,
        },
    )
    assert g_root.data["total_nodes"] >= 2
    assert len(g_root.data["edges"]) >= 1

    # 3. graph_get_neighborhood around endpoint
    endpoint_id = "endpoint:HTTP:https://api.example.com/v1/users"
    neigh = await runtime.invoke(
        "graph_get_neighborhood",
        {
            "project_id": pid,
            "job_id": jid,
            "entity_id": endpoint_id,
            "radius": 2,
            "limit": 20,
        },
    )
    assert neigh.data["entity"]["id"] == endpoint_id
    assert neigh.data["total_neighbors"] >= 1
    neighbor_ids = [n["id"] for n in neigh.data["neighbors"]]
    assert any("fetchUsers" in nid for nid in neighbor_ids)


def _invoke_cli(tmp_path: Path, *args: str):
    return runner.invoke(
        app,
        ["--workspace", str(tmp_path / "workspace"), *args],
    )


def test_cli_graph_and_source_commands(tmp_path: Path) -> None:
    """Verify CLI subcommands for hierarchy, xrefs, and graph traversal."""
    dex_bytes = _build_intelligence_dex()
    apk = make_apk(
        tmp_path / "cli_graph.apk",
        include_dex=False,
        entries={"classes.dex": dex_bytes},
    )

    created = _invoke_cli(tmp_path, "--json", "project", "create", "CLI Graph Proj")
    assert created.exit_code == 0
    pid = json.loads(created.stdout)["data"]["id"]

    ingested = _invoke_cli(tmp_path, "--json", "artifact", "ingest", pid, str(apk))
    assert ingested.exit_code == 0
    aid = json.loads(ingested.stdout)["data"]["id"]

    started = _invoke_cli(tmp_path, "--json", "analyze", pid, aid)
    assert started.exit_code == 0
    jid = json.loads(started.stdout)["job"]["id"]

    # CLI source hierarchy
    hier = _invoke_cli(
        tmp_path,
        "--json",
        "source",
        "hierarchy",
        pid,
        jid,
        "com.example.MainActivity",
    )
    assert hier.exit_code == 0
    hier_data = json.loads(hier.stdout)["data"]
    assert hier_data["found"] is True

    # CLI source xrefs
    xrefs = _invoke_cli(
        tmp_path,
        "--json",
        "source",
        "xrefs",
        pid,
        jid,
        "fetchUsers",
    )
    assert xrefs.exit_code == 0
    xrefs_data = json.loads(xrefs.stdout)["data"]
    assert xrefs_data["total"] >= 1

    # CLI graph query
    g_query = _invoke_cli(
        tmp_path,
        "--json",
        "graph",
        "query",
        pid,
        jid,
        "--root",
        "class:com.example.MainActivity",
    )
    assert g_query.exit_code == 0
    g_data = json.loads(g_query.stdout)["data"]
    assert g_data["total_nodes"] >= 1

    # CLI graph neighborhood
    g_neigh = _invoke_cli(
        tmp_path,
        "--json",
        "graph",
        "neighborhood",
        pid,
        jid,
        "endpoint:HTTP:https://api.example.com/v1/users",
    )
    assert g_neigh.exit_code == 0
    neigh_data = json.loads(g_neigh.stdout)["data"]
    assert "entity" in neigh_data
