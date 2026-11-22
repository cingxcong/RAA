"""Phase 4 UI reconstruction, static layout inventory, screen graphs, and runtime capture tests."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from raa.domain.dex import DexClassInfo
from raa.domain.manifest import ComponentInfo, ManifestInfo
from raa.domain.resources import ResourceSummary, ResourceTypeSummary
from raa.domain.ui import (
    ScreenModel,
    ScreenRoute,
    ScreenState,
    UIRegion,
    UIRegionBounds,
)
from raa.errors import PolicyDeniedError
from raa.runtime import Runtime
from raa.services.android.ui_graph import build_screen_graph, compute_ui_coverage
from raa.services.android.ui_runtime import (
    compare_screens,
    extract_ocr_from_regions,
    parse_uiautomator_bounds,
    parse_uiautomator_hierarchy,
)
from raa.services.android.ui_static import (
    detect_compose_indicators,
    discover_static_screens,
    extract_ui_assets,
    parse_layout_regions,
    parse_navigation_graph,
)
from raa.services.android.ui_to_code import export_screen_to_code


def _make_sample_apk() -> bytes:
    """Build a minimal in-memory APK archive containing layout, navigation, and drawable files."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", b"\x00" * 32)
        zf.writestr(
            "res/layout/activity_main.xml",
            (
                b'<?xml version="1.0" encoding="utf-8"?>\n'
                b'<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"\n'
                b'    android:id="@+id/main_layout" '
                b'android:layout_width="match_parent" android:layout_height="match_parent">\n'
                b'    <TextView android:id="@+id/title" android:text="Welcome to RAA" '
                b'android:layout_width="wrap_content" android:layout_height="wrap_content" />\n'
                b'    <Button android:id="@+id/btn_login" android:text="Log In" '
                b'android:layout_width="match_parent" android:layout_height="wrap_content" />\n'
                b'    <EditText android:id="@+id/input_user" android:text="username" '
                b'android:layout_width="match_parent" android:layout_height="wrap_content" />\n'
                b"</LinearLayout>"
            ),
        )
        zf.writestr(
            "res/navigation/nav_graph.xml",
            (
                b'<?xml version="1.0" encoding="utf-8"?>\n'
                b'<navigation xmlns:android="http://schemas.android.com/apk/res/android"\n'
                b'    xmlns:app="http://schemas.android.com/apk/res-auto" '
                b'android:id="@+id/nav_main">\n'
                b'    <fragment android:id="@+id/home_dest" '
                b'android:name="com.example.HomeFragment">\n'
                b'        <action android:id="@+id/action_home_to_details" '
                b'app:destination="@id/details_dest" />\n'
                b"    </fragment>\n"
                b'    <fragment android:id="@+id/details_dest" '
                b'android:name="com.example.DetailsFragment" />\n'
                b"</navigation>"
            ),
        )
        zf.writestr("res/drawable/ic_launcher.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
        zf.writestr("res/font/roboto_regular.ttf", b"\x00\x01\x00\x00" + b"\x00" * 32)
        zf.writestr("res/menu/bottom_menu.xml", b"<menu></menu>")
    return buf.getvalue()


def test_ui_asset_inventory_extraction() -> None:
    names = [
        "res/layout/activity_main.xml",
        "res/layout-land/activity_main.xml",
        "res/drawable-xxhdpi/logo.png",
        "res/mipmap/ic_launcher.png",
        "res/font/custom_font.ttf",
        "res/navigation/main_nav.xml",
        "res/menu/drawer_menu.xml",
        "res/anim/fade_in.xml",
        "classes.dex",
    ]
    res_summary = ResourceSummary(
        package_count=1,
        types=[
            ResourceTypeSummary(
                type="string", entry_count=25, value_count=25, default_count=25, config_count=0
            ),
            ResourceTypeSummary(
                type="color", entry_count=10, value_count=10, default_count=10, config_count=0
            ),
            ResourceTypeSummary(
                type="style", entry_count=8, value_count=8, default_count=8, config_count=0
            ),
        ],
    )
    inventory = extract_ui_assets(names, res_summary)
    assert inventory.total_count == 8
    assert inventory.counts_by_kind["layout"] == 2
    assert inventory.counts_by_kind["drawable"] == 2
    assert inventory.counts_by_kind["font"] == 1
    assert inventory.counts_by_kind["navigation"] == 1
    assert inventory.counts_by_kind["string"] == 25
    assert inventory.counts_by_kind["color"] == 10
    assert inventory.counts_by_kind["theme"] == 8


def test_layout_xml_and_navigation_parsing() -> None:
    layout_xml = (
        b'<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android">\n'
        b'    <TextView android:id="@+id/tv_title" android:text="Header Text" />\n'
        b'    <Button android:id="@+id/btn_action" android:text="Submit" />\n'
        b'    <EditText android:id="@+id/et_name" android:text="input" />\n'
        b"</LinearLayout>"
    )

    regions = parse_layout_regions(layout_xml, "test_layout")
    assert len(regions) == 4
    roles = [r.role for r in regions]
    assert "container" in roles
    assert "text" in roles
    assert "button" in roles
    assert "input" in roles

    nav_xml = (
        b'<navigation xmlns:android="http://schemas.android.com/apk/res/android"\n'
        b'    xmlns:app="http://schemas.android.com/apk/res-auto">\n'
        b'    <fragment android:id="@+id/frag_first">\n'
        b'        <action android:id="@+id/act_1" app:destination="@id/frag_second" />\n'
        b"    </fragment>\n"
        b'    <fragment android:id="@+id/frag_second" />\n'
        b"</navigation>"
    )

    transitions = parse_navigation_graph(nav_xml)
    assert len(transitions) == 1
    assert transitions[0].source_screen_id == "screen-static-frag_first"
    assert transitions[0].target_screen_id == "screen-static-frag_second"
    assert transitions[0].trigger == "navigation_action"


def test_compose_indicator_detection() -> None:
    classes = [
        DexClassInfo(
            name="androidx.compose.ui.platform.ComposeView",
            descriptor="Landroidx/compose/ui/platform/ComposeView;",
            access_flags=1,
            dex_file="classes.dex",
        ),
        DexClassInfo(
            name="com.example.ui.HomeScreenKt$Composable",
            descriptor="Lcom/example/ui/HomeScreenKt$Composable;",
            access_flags=1,
            dex_file="classes.dex",
        ),
    ]
    indicators = detect_compose_indicators(classes)
    assert len(indicators) >= 2
    assert any("compose_package" in ind for ind in indicators)
    assert any("composable_symbol" in ind for ind in indicators)


def test_discover_static_screens_from_apk() -> None:
    apk_data = _make_sample_apk()
    manifest = ManifestInfo(
        package="com.example.sample",
        components=[
            ComponentInfo(
                kind="activity",
                name="com.example.sample.MainActivity",
                launcher=True,
                effective_exported=True,
            ),
            ComponentInfo(
                kind="activity",
                name="com.example.sample.SettingsActivity",
                launcher=False,
                effective_exported=False,
            ),
        ],
    )

    screens, transitions = discover_static_screens(
        project_id="p1",
        artifact_id="a1",
        manifest=manifest,
        archive_names=[
            "res/layout/activity_main.xml",
            "res/navigation/nav_graph.xml",
        ],
        archive_bytes=apk_data,
    )

    assert len(screens) == 2
    main_screen = next(s for s in screens if "mainactivity" in s.screen_id)
    assert main_screen.state.parameters["launcher"] is True
    assert len(main_screen.regions) >= 3
    # Check bounds are within [0.0, 1.0]
    for reg in main_screen.regions:
        assert 0.0 <= reg.bounds.x <= 1.0
        assert 0.0 <= reg.bounds.y <= 1.0
        assert 0.0 <= reg.bounds.w <= 1.0
        assert 0.0 <= reg.bounds.h <= 1.0

    assert len(transitions) == 1
    assert transitions[0].trigger == "navigation_action"


def test_uiautomator_bounds_and_hierarchy_parsing() -> None:
    bounds = parse_uiautomator_bounds("[100,200][1080,2400]")
    assert bounds == [100, 200, 1080, 2400]

    xml = (
        '<hierarchy rotation="0">'
        '  <node index="0" class="android.widget.FrameLayout" bounds="[0,0][1080,2400]">'
        '    <node index="0" class="android.widget.TextView" text="Dashboard" '
        'bounds="[50,100][500,200]" />'
        '    <node index="1" class="android.widget.Button" text="Confirm" '
        'clickable="true" bounds="[50,300][900,450]" />'
        "  </node>"
        "</hierarchy>"
    )

    tree, regions = parse_uiautomator_hierarchy(xml, "cap-test", 1080, 2400)
    assert tree.total_nodes == 3
    assert len(regions) == 2
    roles = [r.role for r in regions]
    assert "text" in roles
    assert "button" in roles
    # All runtime regions must be tagged is_runtime=True
    for reg in regions:
        assert reg.is_runtime is True
        assert reg.confidence == 1.0

    ocr = extract_ocr_from_regions(regions, "cap-test")
    assert "Dashboard" in ocr.full_text
    assert "Confirm" in ocr.full_text
    assert len(ocr.regions) == 2


def test_screen_graph_and_coverage() -> None:
    s1 = ScreenModel(
        screen_id="screen-1",
        project_id="p1",
        artifact_id="a1",
        title="Home",
        route=ScreenRoute(kind="activity", value="com.example.Home"),
        state=ScreenState(parameters={"launcher": True}),
        is_runtime=True,
    )
    s2 = ScreenModel(
        screen_id="screen-2",
        project_id="p1",
        artifact_id="a1",
        title="Settings",
        route=ScreenRoute(kind="activity", value="com.example.Settings"),
        state=ScreenState(parameters={"exported": True}),
        is_runtime=False,
    )
    s3 = ScreenModel(
        screen_id="screen-3",
        project_id="p1",
        artifact_id="a1",
        title="SecretAdmin",
        route=ScreenRoute(kind="activity", value="com.example.Admin"),
        state=ScreenState(parameters={"exported": False}),
        is_runtime=False,
    )

    graph = build_screen_graph([s1, s2, s3])
    assert graph.start_screen_id == "screen-1"
    assert graph.total_screens == 3

    coverage = compute_ui_coverage(graph)
    assert coverage.discovered_screens == 3
    assert coverage.visited_screens == 1
    assert coverage.unvisited_screens == 1
    assert coverage.unreachable_screens == 1
    assert coverage.coverage_percentage == 33.3


def test_screen_comparison() -> None:
    reg1 = UIRegion(
        region_id="r1",
        bounds=UIRegionBounds(x=0.1, y=0.1, w=0.8, h=0.2),
        role="button",
        text="Click Me",
    )
    reg2 = UIRegion(
        region_id="r2",
        bounds=UIRegionBounds(x=0.1, y=0.1, w=0.8, h=0.2),
        role="button",
        text="Click Me",
    )

    sa = ScreenModel(
        screen_id="sa",
        project_id="p1",
        artifact_id="a1",
        title="A",
        route=ScreenRoute(value="com.example.A"),
        regions=[reg1],
    )
    sb = ScreenModel(
        screen_id="sb",
        project_id="p1",
        artifact_id="a1",
        title="B",
        route=ScreenRoute(value="com.example.A"),
        regions=[reg2],
    )

    ocr_a = extract_ocr_from_regions([reg1])
    ocr_b = extract_ocr_from_regions([reg2])

    comp = compare_screens(sa, sb, ocr_a, ocr_b)
    assert comp.ocr_match_score == 1.0
    assert comp.region_iou_score == 1.0
    assert comp.ssim_score == 1.0
    assert comp.overall_fidelity == 1.0


def test_ui_to_code_generators() -> None:
    reg_btn = UIRegion(
        region_id="r1",
        bounds=UIRegionBounds(x=0.05, y=0.1, w=0.9, h=0.08),
        role="button",
        text="Sign In",
    )
    reg_input = UIRegion(
        region_id="r2",
        bounds=UIRegionBounds(x=0.05, y=0.2, w=0.9, h=0.08),
        role="input",
        text="Email Address",
    )
    screen = ScreenModel(
        screen_id="screen-login",
        project_id="p1",
        artifact_id="a1",
        title="Login Screen",
        route=ScreenRoute(kind="activity", value="com.example.LoginActivity"),
        regions=[reg_btn, reg_input],
    )

    # Compose export
    compose_res = export_screen_to_code(screen, "compose")
    assert "GENERATED BY RAA (NOT ORIGINAL SOURCE)" in compose_res.code
    assert "@Composable" in compose_res.code
    assert "Button(" in compose_res.code
    assert "OutlinedTextField(" in compose_res.code
    assert compose_res.mapped_regions_count == 2

    # Flutter export
    flutter_res = export_screen_to_code(screen, "flutter")
    assert "StatelessWidget" in flutter_res.code
    assert "ElevatedButton(" in flutter_res.code
    assert "TextField(" in flutter_res.code

    # React Native export
    rn_res = export_screen_to_code(screen, "react_native")
    assert "TouchableOpacity" in rn_res.code
    assert "TextInput" in rn_res.code

    # HTML export
    html_res = export_screen_to_code(screen, "html")
    assert "<button class='btn'>Sign In</button>" in html_res.code
    assert "<input class='input'" in html_res.code


@pytest.mark.asyncio
async def test_ui_mcp_tools_and_scoping(runtime: Runtime, tmp_path: Path) -> None:
    # Ingest a sample APK
    apk_data = _make_sample_apk()
    apk_file = tmp_path / "ui_sample.apk"
    apk_file.write_bytes(apk_data)

    p_res = await runtime.invoke("project_create", {"name": "UI Project"})
    project_id = p_res.data["id"]

    ingest_res = await runtime.invoke(
        "artifact_ingest",
        {"project_id": project_id, "path": str(apk_file)},
    )
    artifact_id = ingest_res.data["id"]

    analysis_res = await runtime.invoke(
        "analysis_start",
        {"project_id": project_id, "artifact_id": artifact_id},
    )
    job = await runtime.analysis.wait(project_id, analysis_res.data["id"])
    assert job.status.value == "completed"
    job_id = str(job.id)

    # 1. ui_list_screens
    screens_res = await runtime.invoke(
        "ui_list_screens",
        {"project_id": project_id, "job_id": job_id},
        profile="ui",
    )
    assert screens_res.data["total"] >= 1
    screen_id = screens_res.data["items"][0]["screen_id"]

    # 2. ui_get_screen
    screen_res = await runtime.invoke(
        "ui_get_screen",
        {"project_id": project_id, "job_id": job_id, "screen_id": screen_id},
        profile="ui",
    )
    assert screen_res.data["screen_id"] == screen_id
    assert len(screen_res.data["regions"]) >= 1

    # 3. ui_list_assets
    assets_res = await runtime.invoke(
        "ui_list_assets",
        {"project_id": project_id, "job_id": job_id},
        profile="ui",
    )
    assert assets_res.data["total_count"] >= 3

    # 4. ui_get_hierarchy
    hier_res = await runtime.invoke(
        "ui_get_hierarchy",
        {"project_id": project_id, "job_id": job_id, "screen_id": screen_id},
        profile="ui",
    )
    assert hier_res.data["total_nodes"] >= 1

    # 5. ui_get_ocr
    ocr_res = await runtime.invoke(
        "ui_get_ocr",
        {"project_id": project_id, "job_id": job_id, "screen_id": screen_id},
        profile="ui",
    )
    assert "regions" in ocr_res.data

    # 6. ui_get_source_correlations
    corr_res = await runtime.invoke(
        "ui_get_source_correlations",
        {"project_id": project_id, "job_id": job_id, "screen_id": screen_id},
        profile="ui",
    )
    assert "correlations" in corr_res.data

    # 7. ui_get_coverage
    cov_res = await runtime.invoke(
        "ui_get_coverage",
        {"project_id": project_id, "job_id": job_id},
        profile="ui",
    )
    assert cov_res.data["discovered_screens"] >= 1

    # 8. Scope check: ui_start_capture_session requires 'dynamic.device'
    with pytest.raises(PolicyDeniedError):
        await runtime.invoke(
            "ui_start_capture_session",
            {"project_id": project_id, "device_id": "test-device"},
            profile="ui",
        )

    # 9. Scope check: ui_to_code requires 'export.raw'
    with pytest.raises(PolicyDeniedError):
        await runtime.invoke(
            "ui_to_code",
            {
                "project_id": project_id,
                "job_id": job_id,
                "screen_id": screen_id,
                "target": "compose",
            },
            profile="ui",
        )

    # Create authorized project with dynamic.device and export.raw scopes
    p_auth = await runtime.invoke(
        "project_create",
        {
            "name": "Authorized UI Project",
            "scopes": [
                "project.read",
                "project.write",
                "static.read",
                "export.write",
                "export.raw",
                "dynamic.device",
            ],
        },
    )
    auth_pid = p_auth.data["id"]
    ingest_auth = await runtime.invoke(
        "artifact_ingest",
        {"project_id": auth_pid, "path": str(apk_file)},
    )
    start_auth = await runtime.invoke(
        "analysis_start",
        {"project_id": auth_pid, "artifact_id": ingest_auth.data["id"]},
    )
    job_auth = await runtime.analysis.wait(auth_pid, start_auth.data["id"])
    auth_jid = str(job_auth.id)

    auth_screens = await runtime.invoke(
        "ui_list_screens",
        {"project_id": auth_pid, "job_id": auth_jid},
        profile="ui",
    )
    auth_screen_id = auth_screens.data["items"][0]["screen_id"]

    # 10. ui_start_capture_session now succeeds on authorized project
    sess_res = await runtime.invoke(
        "ui_start_capture_session",
        {"project_id": auth_pid, "device_id": "emulator-5554"},
        profile="ui",
    )
    assert sess_res.data["session_id"].startswith("session_")

    # 11. ui_capture_screenshot succeeds
    cap_res = await runtime.invoke(
        "ui_capture_screenshot",
        {"project_id": auth_pid, "job_id": auth_jid, "session_id": sess_res.data["session_id"]},
        profile="ui",
    )
    assert cap_res.data["capture_id"].startswith("cap_")

    # 12. ui_record_transition succeeds
    trans_res = await runtime.invoke(
        "ui_record_transition",
        {
            "project_id": auth_pid,
            "source_screen_id": auth_screen_id,
            "target_screen_id": cap_res.data["screen_id"],
            "trigger": "tap",
        },
        profile="ui",
    )
    assert trans_res.data["source_screen_id"] == auth_screen_id

    # 13. ui_compare_screens
    comp_res = await runtime.invoke(
        "ui_compare_screens",
        {
            "project_id": auth_pid,
            "job_id": auth_jid,
            "screen_a_id": auth_screen_id,
            "screen_b_id": cap_res.data["screen_id"],
        },
        profile="ui",
    )
    assert "overall_fidelity" in comp_res.data

    # 14. ui_to_code now succeeds on authorized project
    code_res = await runtime.invoke(
        "ui_to_code",
        {
            "project_id": auth_pid,
            "job_id": auth_jid,
            "screen_id": auth_screen_id,
            "target": "compose",
        },
        profile="ui",
    )
    assert "GENERATED BY RAA (NOT ORIGINAL SOURCE)" in code_res.data["code"]
    assert code_res.data["target"] == "compose"
