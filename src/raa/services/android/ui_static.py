"""Static UI resource, layout, and component extraction service.

Discovers UI assets, parses binary and plain XML layouts, extracts navigation graphs,
detects Compose and Fragment usage, and builds static candidate screen models.
"""

from __future__ import annotations

import contextlib
import logging
import re
import xml.etree.ElementTree as ET
import zipfile
from io import BytesIO
from typing import Any

from raa.domain.dex import DexSummary
from raa.domain.manifest import ManifestInfo
from raa.domain.resources import ResourceSummary
from raa.domain.ui import (
    ScreenModel,
    ScreenRoute,
    ScreenState,
    ScreenTransition,
    SourceCorrelation,
    UIAsset,
    UIAssetInventory,
    UIRegion,
    UIRegionBounds,
)
from raa.services.android.axml import XmlElement, parse_binary_xml

logger = logging.getLogger(__name__)

# Common Android View class mapping to UI roles
VIEW_ROLE_MAP: dict[str, str] = {
    "Button": "button",
    "ImageButton": "button",
    "MaterialButton": "button",
    "FloatingActionButton": "button",
    "TextView": "text",
    "MaterialTextView": "text",
    "ImageView": "image",
    "ShapeableImageView": "image",
    "EditText": "input",
    "TextInputEditText": "input",
    "TextInputLayout": "input",
    "CheckBox": "input",
    "RadioButton": "input",
    "Switch": "input",
    "SwitchCompat": "input",
    "MaterialSwitch": "input",
    "SeekBar": "input",
    "ProgressBar": "view",
    "Toolbar": "nav_bar",
    "MaterialToolbar": "nav_bar",
    "BottomNavigationView": "nav_bar",
    "NavigationBarView": "nav_bar",
    "TabLayout": "tab",
    "RecyclerView": "list_item",
    "ListView": "list_item",
    "CardView": "card",
    "MaterialCardView": "card",
    "LinearLayout": "container",
    "RelativeLayout": "container",
    "FrameLayout": "container",
    "ConstraintLayout": "container",
    "ScrollView": "container",
    "NestedScrollView": "container",
    "ViewPager2": "container",
    "ComposeView": "container",
}


def extract_ui_assets(
    archive_names: list[str],
    resource_summary: ResourceSummary | None = None,
) -> UIAssetInventory:
    """Extract an inventory of UI-related assets from archive entries and resources."""
    assets: list[UIAsset] = []
    counts: dict[str, int] = {}

    def _add_asset(kind: str, name: str, path: str | None = None, value: Any = None) -> None:
        asset_id = f"asset-{kind}-{len(assets) + 1:04d}"
        assets.append(UIAsset(id=asset_id, kind=kind, name=name, path=path, value=value))
        counts[kind] = counts.get(kind, 0) + 1

    for name in archive_names:
        lower = name.lower()
        if lower.startswith("res/layout"):
            base = lower.split("/")[-1].replace(".xml", "")
            _add_asset("layout", base, path=name)
        elif lower.startswith("res/drawable") or lower.startswith("res/mipmap"):
            base = lower.split("/")[-1]
            _add_asset("drawable", base, path=name)
        elif lower.startswith("res/font") or lower.startswith("assets/fonts"):
            base = lower.split("/")[-1]
            _add_asset("font", base, path=name)
        elif lower.startswith("res/navigation"):
            base = lower.split("/")[-1].replace(".xml", "")
            _add_asset("navigation", base, path=name)
        elif lower.startswith("res/menu"):
            base = lower.split("/")[-1].replace(".xml", "")
            _add_asset("menu", base, path=name)
        elif lower.startswith("res/anim"):
            base = lower.split("/")[-1].replace(".xml", "")
            _add_asset("anim", base, path=name)

    if resource_summary:
        for rtype in resource_summary.types:
            if rtype.type == "string":
                counts["string"] = counts.get("string", 0) + rtype.entry_count
            elif rtype.type == "color":
                counts["color"] = counts.get("color", 0) + rtype.entry_count
            elif rtype.type in {"style", "theme"}:
                counts["theme"] = counts.get("theme", 0) + rtype.entry_count

    return UIAssetInventory(assets=assets, total_count=len(assets), counts_by_kind=counts)


def parse_layout_regions(data: bytes, layout_name: str = "") -> list[UIRegion]:
    """Parse binary or plain XML layout into semantic UIRegions."""
    if data.startswith(b"\x03\x00"):
        with contextlib.suppress(Exception):
            doc = parse_binary_xml(data)
            return _parse_axml_regions(doc.root, layout_name)

    with contextlib.suppress(Exception):
        text = data.decode("utf-8", errors="replace")
        root = ET.fromstring(text)  # noqa: S314
        return _parse_xml_regions(root, layout_name)

    return []


def _parse_axml_regions(
    root: XmlElement, layout_name: str, depth: int = 0, y_offset: float = 0.05
) -> list[UIRegion]:
    regions: list[UIRegion] = []
    current_y = y_offset

    def _walk(elem: XmlElement, d: int) -> None:
        nonlocal current_y
        simple_tag = elem.name.split(".")[-1]
        role = VIEW_ROLE_MAP.get(simple_tag, "view")
        res_id = elem.value("id") or elem.value("android:id")
        text = elem.value("text") or elem.value("android:text")

        h = 0.08 if role in {"button", "input", "nav_bar"} else 0.06
        reg_id = f"r-{len(regions) + 1:02d}"
        bounds = UIRegionBounds(x=0.05, y=min(current_y, 0.90), w=0.90, h=h)
        current_y += h + 0.02

        asset_matches = [f"res/layout/{layout_name}.xml"] if layout_name else []
        candidates = [elem.name]
        if res_id:
            candidates.append(f"id/{res_id.split('/')[-1]}")

        regions.append(
            UIRegion(
                region_id=reg_id,
                bounds=bounds,
                role=role,
                text=str(text) if text else None,
                hierarchy_node=None,
                asset_matches=asset_matches,
                source_candidates=candidates,
                confidence=0.85,
                is_runtime=False,
            )
        )

        for child in elem.children:
            _walk(child, d + 1)

    _walk(root, depth)
    return regions


def _parse_xml_regions(
    root: ET.Element, layout_name: str, depth: int = 0, y_offset: float = 0.05
) -> list[UIRegion]:
    regions: list[UIRegion] = []
    current_y = y_offset

    def _walk(elem: ET.Element, d: int) -> None:
        nonlocal current_y
        tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
        simple_tag = tag.split(".")[-1]
        role = VIEW_ROLE_MAP.get(simple_tag, "view")

        res_id = elem.attrib.get("{http://schemas.android.com/apk/res/android}id", "")
        text = elem.attrib.get("{http://schemas.android.com/apk/res/android}text", "")

        h = 0.08 if role in {"button", "input", "nav_bar"} else 0.06
        reg_id = f"r-{len(regions) + 1:02d}"
        bounds = UIRegionBounds(x=0.05, y=min(current_y, 0.90), w=0.90, h=h)
        current_y += h + 0.02

        asset_matches = [f"res/layout/{layout_name}.xml"] if layout_name else []
        candidates = [tag]
        if res_id:
            candidates.append(f"id/{res_id.split('/')[-1]}")

        regions.append(
            UIRegion(
                region_id=reg_id,
                bounds=bounds,
                role=role,
                text=text if text else None,
                hierarchy_node=None,
                asset_matches=asset_matches,
                source_candidates=candidates,
                confidence=0.90,
                is_runtime=False,
            )
        )

        for child in elem:
            _walk(child, d + 1)

    _walk(root, depth)
    return regions


def parse_navigation_graph(data: bytes, source_screen_id: str = "") -> list[ScreenTransition]:
    """Extract screen transitions from navigation graph XML."""
    transitions: list[ScreenTransition] = []

    def _handle_element(
        tag: str, attrs: dict[str, str], current_dest: str
    ) -> tuple[str, list[ScreenTransition]]:
        dest = current_dest
        new_transitions: list[ScreenTransition] = []
        if tag in {"fragment", "activity", "dialog", "navigation"}:
            dest_id = attrs.get("id", "").replace("@+id/", "").replace("@id/", "")
            if dest_id:
                dest = f"screen-static-{dest_id.lower()}"
        elif tag == "action":
            destination = attrs.get("destination", "").replace("@+id/", "").replace("@id/", "")
            if destination:
                target_id = f"screen-static-{destination.lower()}"
                src = dest or source_screen_id or "screen-static-root"
                new_transitions.append(
                    ScreenTransition(
                        source_screen_id=src,
                        target_screen_id=target_id,
                        trigger="navigation_action",
                        confidence=0.95,
                    )
                )
        return dest, new_transitions

    if data.startswith(b"\x03\x00"):
        try:
            doc = parse_binary_xml(data)

            def _walk_axml(elem: XmlElement, curr_dest: str) -> None:
                tag = elem.name
                attrs = {
                    "id": elem.value("id") or "",
                    "destination": elem.value("destination") or "",
                }
                new_dest, ts = _handle_element(tag, attrs, curr_dest)
                transitions.extend(ts)
                for child in elem.children:
                    _walk_axml(child, new_dest)

            _walk_axml(doc.root, source_screen_id)
            return transitions
        except Exception as err:
            logger.debug("Binary AXML navigation graph parse fallback: %s", err)

    try:
        text = data.decode("utf-8", errors="replace")
        root = ET.fromstring(text)  # noqa: S314

        def _walk_xml(elem: ET.Element, curr_dest: str) -> None:
            tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            attrs = {
                "id": elem.attrib.get("{http://schemas.android.com/apk/res/android}id", ""),
                "destination": elem.attrib.get(
                    "{http://schemas.android.com/apk/res-auto}destination",
                    elem.attrib.get("app:destination", ""),
                ),
            }
            new_dest, ts = _handle_element(tag, attrs, curr_dest)
            transitions.extend(ts)
            for child in elem:
                _walk_xml(child, new_dest)

        _walk_xml(root, source_screen_id)
    except Exception as err:
        logger.debug("Plain XML navigation graph parse failed: %s", err)

    return transitions


def detect_compose_indicators(dex_source: Any = None) -> list[str]:
    """Detect Jetpack Compose indicators across indexed DEX classes or class lists."""
    if not dex_source:
        return []
    classes = getattr(
        dex_source,
        "classes",
        dex_source if isinstance(dex_source, (list, tuple)) else [],
    )
    indicators: list[str] = []
    compose_pkgs = ("androidx.compose", "androidx.navigation.compose")
    for cls in classes:
        cls_name = getattr(cls, "name", cls if isinstance(cls, str) else "")
        for pkg in compose_pkgs:
            if pkg in cls_name:
                indicators.append(f"compose_package:{pkg}")
                break
        if "Composable" in cls_name:
            indicators.append(f"composable_symbol:{cls_name}")
        if len(indicators) >= 10:
            break
    return list(dict.fromkeys(indicators))


def discover_static_screens(
    *,
    project_id: str,
    artifact_id: str,
    manifest: ManifestInfo | None,
    dex_summary: DexSummary | None = None,
    archive_names: list[str] | None = None,
    archive_bytes: bytes | None = None,
) -> tuple[list[ScreenModel], list[ScreenTransition]]:
    """Discover static candidate screens from Manifest components, resources, and DEX."""
    screens: list[ScreenModel] = []
    transitions: list[ScreenTransition] = []
    names = archive_names or []
    compose_indicators = detect_compose_indicators(dex_summary)

    # Extract layouts from archive if bytes are present
    layout_data_map: dict[str, bytes] = {}
    nav_data_list: list[bytes] = []

    if archive_bytes:
        try:
            with zipfile.ZipFile(BytesIO(archive_bytes)) as zf:
                for n in zf.namelist():
                    lower = n.lower()
                    if lower.startswith("res/layout") and lower.endswith(".xml"):
                        base = lower.split("/")[-1].replace(".xml", "")
                        with contextlib.suppress(Exception):
                            layout_data_map[base] = zf.read(n)
                    elif lower.startswith("res/navigation") and lower.endswith(".xml"):
                        with contextlib.suppress(Exception):
                            nav_data_list.append(zf.read(n))
        except Exception as err:
            logger.debug("Failed reading zip archive for UI layout: %s", err)

    # Parse transitions from navigation graphs
    for nav_data in nav_data_list:
        transitions.extend(parse_navigation_graph(nav_data))

    activities = [c for c in (manifest.components if manifest else []) if c.kind == "activity"]

    # If no activities in manifest, check archive layout names as fallback
    if not activities and names:
        layout_bases = [
            n.lower().split("/")[-1].replace(".xml", "")
            for n in names
            if n.lower().startswith("res/layout")
        ]
        for base in layout_bases[:10]:
            sid = f"screen-static-{base}"
            screens.append(
                ScreenModel(
                    screen_id=sid,
                    project_id=project_id,
                    artifact_id=artifact_id,
                    title=base.replace("_", " ").title(),
                    route=ScreenRoute(kind="activity", value=f"com.example.{base.title()}"),
                    state=ScreenState(name="static_candidate", is_runtime=False),
                    regions=_synthesize_default_regions(base),
                    compose_indicators=compose_indicators,
                    is_runtime=False,
                )
            )

    for act in activities:
        simple_name = act.name.split(".")[-1]
        screen_id = f"screen-static-{simple_name.lower()}"
        title = re.sub(r"([A-Z])", r" \1", simple_name).strip()

        # Match potential layout name e.g. activity_main for MainActivity
        slug = re.sub(r"([A-Z])", r"_\1", simple_name).strip("_").lower()
        potential_layout = f"activity_{slug}"
        layout_name = potential_layout if potential_layout in layout_data_map else ""

        regions: list[UIRegion] = []
        if layout_name and layout_name in layout_data_map:
            regions = parse_layout_regions(layout_data_map[layout_name], layout_name)
        elif not regions:
            regions = _synthesize_default_regions(simple_name)

        # Correlate elements
        correlations: list[SourceCorrelation] = []
        for reg in regions:
            correlations.append(
                SourceCorrelation(
                    element_id=reg.region_id,
                    element_type=reg.role,
                    layout_name=layout_name or None,
                    component_class=act.name,
                    confidence=0.85,
                )
            )

        limitations: list[str] = []
        if not layout_name:
            limitations.append("Layout XML not identified; synthesized standard regions")
        if compose_indicators:
            limitations.append("Compose detected; declarative view tree is approximated")

        screens.append(
            ScreenModel(
                screen_id=screen_id,
                project_id=project_id,
                artifact_id=artifact_id,
                title=title,
                route=ScreenRoute(kind="activity", value=act.name),
                state=ScreenState(
                    name="static_candidate",
                    is_runtime=False,
                    parameters={"launcher": act.launcher, "exported": act.effective_exported},
                ),
                regions=regions,
                source_correlations=correlations,
                compose_indicators=compose_indicators,
                limitations=limitations,
                is_runtime=False,
            )
        )

    # Link transitions into screen targets
    for trans in transitions:
        for sc in screens:
            if (
                sc.screen_id == trans.source_screen_id
                and trans.target_screen_id not in sc.transitions
            ):
                sc.transitions.append(trans.target_screen_id)

    return screens, transitions


def _synthesize_default_regions(name: str) -> list[UIRegion]:
    """Synthesize baseline layout regions when no layout XML is directly decodable."""
    return [
        UIRegion(
            region_id="r-01",
            bounds=UIRegionBounds(x=0.0, y=0.0, w=1.0, h=0.08),
            role="toolbar",
            text=name,
            confidence=0.8,
            is_runtime=False,
        ),
        UIRegion(
            region_id="r-02",
            bounds=UIRegionBounds(x=0.05, y=0.12, w=0.90, h=0.70),
            role="container",
            confidence=0.7,
            is_runtime=False,
        ),
        UIRegion(
            region_id="r-03",
            bounds=UIRegionBounds(x=0.10, y=0.85, w=0.80, h=0.08),
            role="button",
            text="Action",
            confidence=0.75,
            is_runtime=False,
        ),
    ]
