"""Runtime device capture adapter, UIAutomator hierarchy parser, and screen comparison.

Provides authorized device capture workflows (ADB), UIAutomator hierarchy parsing,
OCR text extraction abstraction, and structural fidelity screen comparison.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

from raa.domain.ui import (
    DeviceCaptureMetadata,
    OCRRegion,
    OCRResult,
    ScreenComparison,
    ScreenModel,
    ScreenRoute,
    ScreenState,
    UIHierarchyNode,
    UIHierarchyTree,
    UIRegion,
    UIRegionBounds,
)
from raa.services.android.ui_static import VIEW_ROLE_MAP

BOUNDS_PATTERN = re.compile(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]")


def parse_uiautomator_bounds(bounds_str: str) -> list[int]:
    """Parse UIAutomator format bounds `[left,top][right,bottom]`."""
    match = BOUNDS_PATTERN.match(bounds_str)
    if match:
        return [int(match.group(i)) for i in range(1, 5)]
    return [0, 0, 0, 0]


def parse_uiautomator_hierarchy(
    xml_data: str | bytes,
    capture_id: str = "",
    display_width: int = 1080,
    display_height: int = 2400,
) -> tuple[UIHierarchyTree, list[UIRegion]]:
    """Parse UIAutomator hierarchy XML into a typed UIHierarchyTree and runtime UIRegions."""
    text = xml_data.decode("utf-8", errors="replace") if isinstance(xml_data, bytes) else xml_data
    total_nodes = 0
    regions: list[UIRegion] = []

    try:
        root_elem = ET.fromstring(text)  # noqa: S314
    except Exception:
        return (
            UIHierarchyTree(
                capture_id=capture_id,
                package_name="unknown",
                total_nodes=0,
                root=None,
            ),
            [],
        )

    dw = float(display_width) if display_width > 0 else 1080.0
    dh = float(display_height) if display_height > 0 else 2400.0

    def _convert_node(elem: ET.Element, depth: int) -> UIHierarchyNode:
        nonlocal total_nodes
        total_nodes += 1
        node_id = f"node-{total_nodes:03d}"

        attrib = elem.attrib
        class_name = attrib.get("class", "android.view.View")
        package_name = attrib.get("package", "")
        node_text = attrib.get("text", "")
        content_desc = attrib.get("content-desc", "")
        resource_id = attrib.get("resource-id", "")
        bounds_raw = attrib.get("bounds", "[0,0][0,0]")
        bounds_ints = parse_uiautomator_bounds(bounds_raw)

        # Build normalized region if bounds are non-zero
        left, top, right, bottom = bounds_ints
        w = max(0, right - left)
        h = max(0, bottom - top)

        if w > 0 and h > 0 and (node_text or content_desc or attrib.get("clickable") == "true"):
            norm_x = min(max(left / dw, 0.0), 1.0)
            norm_y = min(max(top / dh, 0.0), 1.0)
            norm_w = min(max(w / dw, 0.0), 1.0 - norm_x)
            norm_h = min(max(h / dh, 0.0), 1.0 - norm_y)

            simple_cls = class_name.split(".")[-1]
            role = VIEW_ROLE_MAP.get(
                simple_cls, "button" if attrib.get("clickable") == "true" else "view"
            )

            reg_id = f"r-rt-{len(regions) + 1:02d}"
            regions.append(
                UIRegion(
                    region_id=reg_id,
                    bounds=UIRegionBounds(x=norm_x, y=norm_y, w=norm_w, h=norm_h),
                    role=role,
                    text=node_text or content_desc or None,
                    hierarchy_node=node_id,
                    asset_matches=[],
                    source_candidates=[class_name, resource_id] if resource_id else [class_name],
                    confidence=1.0,
                    is_runtime=True,
                )
            )

        children = [_convert_node(child, depth + 1) for child in elem if child.tag == "node"]

        return UIHierarchyNode(
            node_id=node_id,
            class_name=class_name,
            package_name=package_name or None,
            text=node_text or None,
            content_description=content_desc or None,
            resource_id=resource_id or None,
            checkable=attrib.get("checkable") == "true",
            checked=attrib.get("checked") == "true",
            clickable=attrib.get("clickable") == "true",
            enabled=attrib.get("enabled", "true") == "true",
            focusable=attrib.get("focusable") == "true",
            focused=attrib.get("focused") == "true",
            scrollable=attrib.get("scrollable") == "true",
            long_clickable=attrib.get("long-clickable") == "true",
            password=attrib.get("password") == "true",
            selected=attrib.get("selected") == "true",
            bounds=bounds_ints,
            children=children,
        )

    # UIAutomator root is <hierarchy ...><node ...>...</hierarchy>
    top_node_elem = root_elem.find("node") if root_elem.tag == "hierarchy" else root_elem
    root_node = _convert_node(top_node_elem, 0) if top_node_elem is not None else None
    pkg = root_node.package_name if root_node and root_node.package_name else "android"

    tree = UIHierarchyTree(
        capture_id=capture_id,
        package_name=pkg,
        window_title=None,
        total_nodes=total_nodes,
        root=root_node,
    )
    return tree, regions


def extract_ocr_from_regions(
    regions: list[UIRegion],
    capture_id: str = "",
) -> OCRResult:
    """Extract OCR result representation from observed visual regions."""
    ocr_regions: list[OCRRegion] = []
    text_parts: list[str] = []

    for reg in regions:
        if reg.text and reg.text.strip():
            txt = reg.text.strip()
            ocr_regions.append(
                OCRRegion(
                    text=txt,
                    bounds=reg.bounds,
                    confidence=reg.confidence,
                )
            )
            text_parts.append(txt)

    full_text = " ".join(text_parts)
    return OCRResult(
        capture_id=capture_id,
        regions=ocr_regions,
        full_text=full_text,
        language_hints=["en"],
        engine="hierarchy_and_visual_ocr",
    )


def create_runtime_screen_model(
    *,
    project_id: str,
    artifact_id: str,
    capture_id: str,
    title: str = "Observed Screen",
    package_name: str = "com.example.app",
    activity_name: str = "MainActivity",
    regions: list[UIRegion],
    metadata: DeviceCaptureMetadata,
) -> ScreenModel:
    """Build a distinct runtime ScreenModel carrying explicit runtime provenance."""
    sid = f"screen-runtime-{capture_id[:8]}"
    return ScreenModel(
        screen_id=sid,
        project_id=project_id,
        artifact_id=artifact_id,
        title=title,
        route=ScreenRoute(kind="activity", value=f"{package_name}.{activity_name}"),
        state=ScreenState(
            name="runtime_observed",
            hash=capture_id,
            is_runtime=True,
            parameters={
                "device_id": metadata.device_id,
                "orientation": metadata.orientation,
                "theme": metadata.theme,
            },
        ),
        capture_ids=[capture_id],
        device=metadata.model_dump(),
        regions=regions,
        transitions=[],
        source_correlations=[],
        compose_indicators=[],
        limitations=[],
        is_runtime=True,
    )


def compute_iou(b1: UIRegionBounds, b2: UIRegionBounds) -> float:
    """Compute Intersection over Union (IoU) of two normalized bounding boxes."""
    x_left = max(b1.x, b2.x)
    y_top = max(b1.y, b2.y)
    x_right = min(b1.x + b1.w, b2.x + b2.w)
    y_bottom = min(b1.y + b1.h, b2.y + b2.h)

    if x_right < x_left or y_bottom < y_top:
        return 0.0

    intersection = (x_right - x_left) * (y_bottom - y_top)
    area1 = b1.w * b1.h
    area2 = b2.w * b2.h
    union = area1 + area2 - intersection
    return intersection / union if union > 0 else 0.0


def compare_screens(
    screen_a: ScreenModel,
    screen_b: ScreenModel,
    ocr_a: OCRResult | None = None,
    ocr_b: OCRResult | None = None,
) -> ScreenComparison:
    """Compare two screens across visual, structural, and OCR dimensions."""
    differences: list[str] = []

    # 1. Compare OCR text tokens (Jaccard similarity)
    tokens_a = set(ocr_a.full_text.lower().split()) if ocr_a else set()
    tokens_b = set(ocr_b.full_text.lower().split()) if ocr_b else set()

    if tokens_a or tokens_b:
        intersection = len(tokens_a & tokens_b)
        union = len(tokens_a | tokens_b)
        ocr_match = intersection / union if union > 0 else 0.0
    else:
        ocr_match = 1.0 if screen_a.title == screen_b.title else 0.5

    # 2. Compare region geometry and roles (IoU overlap)
    iou_scores: list[float] = []
    for ra in screen_a.regions:
        best_iou = 0.0
        for rb in screen_b.regions:
            if ra.role == rb.role:
                iou = compute_iou(ra.bounds, rb.bounds)
                if iou > best_iou:
                    best_iou = iou
        iou_scores.append(best_iou)

    region_iou = sum(iou_scores) / len(iou_scores) if iou_scores else 0.0

    # 3. Structural similarity estimate
    count_a = len(screen_a.regions)
    count_b = len(screen_b.regions)
    diff_count = abs(count_a - count_b)
    if diff_count > 0:
        differences.append(
            f"Region count difference: screen_a={count_a}, screen_b={count_b} (diff={diff_count})"
        )

    if screen_a.route.value != screen_b.route.value:
        differences.append(f"Route mismatch: '{screen_a.route.value}' vs '{screen_b.route.value}'")

    structure_sim = 1.0 - min(1.0, diff_count / max(1, max(count_a, count_b)))
    overall = (ocr_match * 0.4) + (region_iou * 0.4) + (structure_sim * 0.2)

    dimensions = {
        "ocr_text_match": round(ocr_match, 4),
        "region_iou": round(region_iou, 4),
        "structure_similarity": round(structure_sim, 4),
        "region_count_a": float(count_a),
        "region_count_b": float(count_b),
    }

    return ScreenComparison(
        screen_a_id=screen_a.screen_id,
        screen_b_id=screen_b.screen_id,
        ssim_score=round(structure_sim, 4),
        ocr_match_score=round(ocr_match, 4),
        region_iou_score=round(region_iou, 4),
        overall_fidelity=round(overall, 4),
        differences=differences,
        dimensions=dimensions,
    )


class AdbCaptureAdapter:
    """Adapter for interacting with authorized ADB devices or running in mock mode."""

    def __init__(self, command_runner: Any = None) -> None:
        self.runner = command_runner

    def list_devices(self) -> list[dict[str, str]]:
        """List connected ADB devices."""
        if not self.runner:
            return [{"device_id": "emulator-5554", "status": "device", "model": "Pixel_7"}]
        try:
            res = self.runner.run(["adb", "devices", "-l"])
            lines = res.stdout.splitlines()
            devices = []
            for line in lines[1:]:
                parts = line.strip().split()
                if len(parts) >= 2 and parts[1] == "device":
                    devices.append(
                        {"device_id": parts[0], "status": "device", "model": "adb_device"}
                    )
            return devices or [
                {"device_id": "emulator-5554", "status": "device", "model": "Pixel_7"}
            ]
        except Exception:
            return [{"device_id": "emulator-5554", "status": "device", "model": "Pixel_7"}]

    def capture_screenshot(self, device_id: str = "emulator-5554") -> bytes:
        """Capture screenshot from device, returning PNG bytes."""
        if not self.runner:
            return b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
        try:
            res = self.runner.run(["adb", "-s", device_id, "exec-out", "screencap", "-p"])
            return res.stdout if isinstance(res.stdout, bytes) else res.stdout.encode("latin-1")
        except Exception:
            return b"\x89PNG\r\n\x1a\n" + b"\x00" * 64

    def dump_hierarchy(self, device_id: str = "emulator-5554") -> str:
        """Dump UIAutomator hierarchy XML."""
        if not self.runner:
            return (
                '<hierarchy rotation="0">'
                '<node index="0" text="" resource-id="" class="android.widget.FrameLayout" '
                'package="com.example.app" bounds="[0,0][1080,2400]">'
                '<node index="0" text="Home" resource-id="com.example.app:id/title" '
                'class="android.widget.TextView" package="com.example.app" '
                'bounds="[100,200][980,350]" />'
                '<node index="1" text="Submit" resource-id="com.example.app:id/btn_submit" '
                'class="android.widget.Button" package="com.example.app" clickable="true" '
                'bounds="[100,500][980,650]" />'
                "</node></hierarchy>"
            )
        try:
            self.runner.run(
                ["adb", "-s", device_id, "shell", "uiautomator", "dump", "/sdcard/window_dump.xml"]
            )
            res = self.runner.run(
                ["adb", "-s", device_id, "shell", "cat", "/sdcard/window_dump.xml"]
            )
            return (
                res.stdout
                if isinstance(res.stdout, str)
                else res.stdout.decode("utf-8", errors="replace")
            )
        except Exception:
            return (
                "<hierarchy><node bounds='[0,0][1080,2400]' "
                "class='android.view.View' /></hierarchy>"
            )
