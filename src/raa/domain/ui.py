"""Domain models for UI reconstruction, screen graphs, UI assets, and runtime capture."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

ScreenRouteKind = Literal[
    "activity", "fragment", "composable", "route", "scene", "dialog", "unknown"
]
UIElementRole = Literal[
    "button",
    "text",
    "image",
    "input",
    "container",
    "card",
    "dialog",
    "nav_bar",
    "list_item",
    "toolbar",
    "tab",
    "view",
]
ScreenCoverageStatus = Literal["visited", "unvisited", "unreachable"]
ScreenTriggerKind = Literal[
    "tap",
    "gesture",
    "intent",
    "deep_link",
    "back",
    "system_event",
    "navigation_action",
]
UITargetPlatform = Literal["compose", "flutter", "react_native", "html"]


class ScreenRoute(BaseModel):
    """Route or component descriptor defining screen entry."""

    kind: ScreenRouteKind = "activity"
    value: str


class ScreenState(BaseModel):
    """State descriptor for a screen snapshot."""

    name: str = "default"
    hash: str = ""
    is_runtime: bool = False
    parameters: dict[str, Any] = Field(default_factory=dict)


class UIRegionBounds(BaseModel):
    """Normalized coordinates in [0.0, 1.0] relative to screen dimensions."""

    x: float = 0.0
    y: float = 0.0
    w: float = 0.0
    h: float = 0.0


class UIRegion(BaseModel):
    """Semantic region identified within a screen."""

    region_id: str
    bounds: UIRegionBounds
    role: str = "view"
    text: str | None = None
    hierarchy_node: str | None = None
    asset_matches: list[str] = Field(default_factory=list)
    source_candidates: list[str] = Field(default_factory=list)
    confidence: float = 1.0
    is_runtime: bool = False


class SourceCorrelation(BaseModel):
    """Correlation linking a UI element to decompiled source or resources."""

    element_id: str
    element_type: str
    resource_id: str | None = None
    layout_name: str | None = None
    component_class: str | None = None
    method_candidate: str | None = None
    evidence_path: str | None = None
    confidence: float = 1.0


class ScreenModel(BaseModel):
    """Reconstructed screen representation with provenance and regions."""

    screen_id: str
    project_id: str
    artifact_id: str
    title: str = ""
    route: ScreenRoute
    state: ScreenState = Field(default_factory=ScreenState)
    capture_ids: list[str] = Field(default_factory=list)
    device: dict[str, Any] | None = None
    regions: list[UIRegion] = Field(default_factory=list)
    transitions: list[str] = Field(default_factory=list)
    source_correlations: list[SourceCorrelation] = Field(default_factory=list)
    compose_indicators: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    is_runtime: bool = False


class UIAsset(BaseModel):
    """One UI resource asset such as a layout, drawable, font, string, or color."""

    id: str
    kind: str
    name: str
    path: str | None = None
    value: Any = None
    configuration: str | None = None


class UIAssetInventory(BaseModel):
    """Inventory of extracted UI assets."""

    assets: list[UIAsset] = Field(default_factory=list)
    total_count: int = 0
    counts_by_kind: dict[str, int] = Field(default_factory=dict)


class UIHierarchyNode(BaseModel):
    """Node in an accessibility or UIAutomator hierarchy tree."""

    node_id: str
    class_name: str
    package_name: str | None = None
    text: str | None = None
    content_description: str | None = None
    resource_id: str | None = None
    checkable: bool = False
    checked: bool = False
    clickable: bool = False
    enabled: bool = True
    focusable: bool = False
    focused: bool = False
    scrollable: bool = False
    long_clickable: bool = False
    password: bool = False
    selected: bool = False
    bounds: list[int] = Field(default_factory=list)
    children: list[UIHierarchyNode] = Field(default_factory=list)


class UIHierarchyTree(BaseModel):
    """Captured UI hierarchy tree."""

    capture_id: str
    package_name: str
    window_title: str | None = None
    total_nodes: int = 0
    root: UIHierarchyNode | None = None


class OCRRegion(BaseModel):
    """Visual text region detected by OCR."""

    text: str
    bounds: UIRegionBounds
    confidence: float = 1.0
    language: str | None = None


class OCRResult(BaseModel):
    """Structured OCR extraction result."""

    capture_id: str
    regions: list[OCRRegion] = Field(default_factory=list)
    full_text: str = ""
    language_hints: list[str] = Field(default_factory=list)
    engine: str = "standard"


class ScreenTransition(BaseModel):
    """Navigation edge between screens with trigger and guard metadata."""

    source_screen_id: str
    target_screen_id: str
    trigger: ScreenTriggerKind = "tap"
    guard: str | None = None
    action_script: str | None = None
    confidence: float = 1.0
    evidence_ids: list[str] = Field(default_factory=list)


class ScreenGraph(BaseModel):
    """Navigable graph of screens and transitions."""

    screens: list[ScreenModel] = Field(default_factory=list)
    transitions: list[ScreenTransition] = Field(default_factory=list)
    start_screen_id: str | None = None
    total_screens: int = 0
    total_transitions: int = 0


class ScreenCoverageItem(BaseModel):
    """Coverage status for an individual screen."""

    screen_id: str
    title: str
    status: ScreenCoverageStatus
    has_runtime_capture: bool
    capture_count: int = 0


class UICoverageReport(BaseModel):
    """Screen discovery and exploration coverage report."""

    discovered_screens: int = 0
    visited_screens: int = 0
    unvisited_screens: int = 0
    unreachable_screens: int = 0
    coverage_percentage: float = 0.0
    screens: list[ScreenCoverageItem] = Field(default_factory=list)


class DeviceCaptureMetadata(BaseModel):
    """Device, OS, display, and scenario metadata for runtime capture."""

    device_id: str
    model: str = "emulator"
    android_version: str = "14"
    sdk_version: int = 34
    abi: str = "x86_64"
    resolution: dict[str, int] = Field(default_factory=lambda: {"width": 1080, "height": 2400})
    density_dpi: int = 420
    orientation: str = "portrait"
    locale: str = "en-US"
    font_scale: float = 1.0
    theme: str = "light"
    timestamp: str = ""
    redacted: bool = False


class ScreenCapture(BaseModel):
    """Single runtime capture record."""

    capture_id: str
    project_id: str
    screen_id: str
    metadata: DeviceCaptureMetadata
    screenshot_path: str | None = None
    hierarchy_tree: UIHierarchyTree | None = None
    ocr_result: OCRResult | None = None
    created_at: str = ""


class ScreenComparison(BaseModel):
    """Comparison metrics between two screens or captures."""

    screen_a_id: str
    screen_b_id: str
    ssim_score: float = 0.0
    ocr_match_score: float = 0.0
    region_iou_score: float = 0.0
    overall_fidelity: float = 0.0
    differences: list[str] = Field(default_factory=list)
    dimensions: dict[str, float] = Field(default_factory=dict)


class UIToCodeResult(BaseModel):
    """Reconstructed code export from screen model."""

    screen_id: str
    target: UITargetPlatform
    code: str
    generated_label: str = "GENERATED BY RAA (NOT ORIGINAL SOURCE)"
    fidelity_report: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    mapped_regions_count: int = 0


class RuntimeScreenCapture(BaseModel):
    """Runtime screen capture containing screenshot path and parsed view hierarchy."""

    screen_id: str
    project_id: str
    artifact_id: str
    device_id: str | None = None
    activity_name: str | None = None
    screenshot_path: str
    bounds_matrix: list[dict[str, Any]] = Field(default_factory=list)
    orientation: str = "portrait"
    resolution: str = "1080x2400"
    captured_at: str = ""


class WebviewInspectionReport(BaseModel):
    """Extraction report for embedded WebViews via Chrome DevTools Protocol."""

    project_id: str
    webview_count: int = 0
    current_url: str = ""
    dom_tree: dict[str, Any] = Field(default_factory=dict)
    computed_tokens: dict[str, Any] = Field(default_factory=dict)
    screenshot_path: str | None = None


class ScreenRedesignSpec(BaseModel):
    """Clean-room mobile screen redesign applying 8pt grid and mobile design system."""

    project_id: str
    screen_id: str
    target_framework: Literal["compose", "react-native", "tailwind"] = "compose"
    theme_mode: Literal["light", "dark", "system"] = "system"
    code: str
    design_tokens: dict[str, Any] = Field(default_factory=dict)
    components_used: list[str] = Field(default_factory=list)
    thumb_zone_elements: list[str] = Field(default_factory=list)
    unresolved_elements: list[str] = Field(default_factory=list)
    generated_at: str = ""


class VisualComparisonReport(BaseModel):
    """Pixel-level and perceptual visual diff between original and redesigned screens."""

    project_id: str
    original_screenshot_path: str
    redesigned_screenshot_path: str
    similarity_score: float = 0.0
    diff_image_path: str | None = None
    layout_conformance: dict[str, Any] = Field(default_factory=dict)
    divergent_regions: list[dict[str, Any]] = Field(default_factory=list)
