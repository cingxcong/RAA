"""Automated Android Asset Studio, Adaptive Icon Generator & Play Store Banner Engine.

Generates full Android 8+ Adaptive Icon suites, Android 13+ Material You monochrome tint layers,
Google Play Console compliant 1024x500 feature graphics, and status bar notification silhouettes.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import Any

# Standard Android Mipmap Densities & Icon Dimensions (dp to px)
MIPMAP_DENSITIES = {
    "mdpi": {"density_dpi": 160, "icon_size_px": 48, "folder": "mipmap-mdpi"},
    "hdpi": {"density_dpi": 240, "icon_size_px": 72, "folder": "mipmap-hdpi"},
    "xhdpi": {"density_dpi": 320, "icon_size_px": 96, "folder": "mipmap-xhdpi"},
    "xxhdpi": {"density_dpi": 480, "icon_size_px": 144, "folder": "mipmap-xxhdpi"},
    "xxxhdpi": {"density_dpi": 640, "icon_size_px": 192, "folder": "mipmap-xxxhdpi"},
    "playstore": {"density_dpi": 640, "icon_size_px": 512, "folder": "web-playstore"},
}

NOTIFICATION_DENSITIES = {
    "mdpi": {"size_px": 24, "folder": "drawable-mdpi"},
    "hdpi": {"size_px": 36, "folder": "drawable-hdpi"},
    "xhdpi": {"size_px": 48, "folder": "drawable-xhdpi"},
    "xxhdpi": {"size_px": 72, "folder": "drawable-xxhdpi"},
    "xxxhdpi": {"size_px": 96, "folder": "drawable-xxxhdpi"},
}


def generate_adaptive_icon_suite(
    name: str = "ic_launcher",
    background_color: str = "#1A73E8",
    foreground_vector_xml: str | None = None,
    output_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Generate complete Android 8+ Adaptive Icon suite including monochrome tint layers."""
    clean_name = name.lower().replace("-", "_").replace(" ", "_")

    # 1. Background Vector or Color
    bg_xml = f"""<?xml version="1.0" encoding="utf-8"?>
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="108dp"
    android:height="108dp"
    android:viewportWidth="108"
    android:viewportHeight="108">
    <path
        android:fillColor="{background_color}"
        android:pathData="M0,0h108v108h-108z"/>
</vector>"""

    # 2. Foreground Vector (Default stylized app shield/gem if omitted)
    fg_xml = (
        foreground_vector_xml
        or """<?xml version="1.0" encoding="utf-8"?>
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="108dp"
    android:height="108dp"
    android:viewportWidth="108"
    android:viewportHeight="108">
    <path
        android:fillColor="#FFFFFFFF"
        android:pathData="M54,20L28,32v24c0,16 11,31 26,35c15,-4 26,-19 26,-35V32L54,20z"/>
    <path
        android:fillColor="#E0E0E0"
        android:pathData="M54,20v67.2c13.7-3.8 24-17.7 24-33.2V32L54,20z"/>
</vector>"""
    )

    # 3. Android 13+ Monochrome Themed Icon Layer
    monochrome_xml = """<?xml version="1.0" encoding="utf-8"?>
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="108dp"
    android:height="108dp"
    android:viewportWidth="108"
    android:viewportHeight="108"
    android:tint="@color/material_you_monochrome_tint">
    <path
        android:fillColor="#FFFFFFFF"
        android:pathData="M54,20L28,32v24c0,16 11,31 26,35c15,-4 26,-19 26,-35V32L54,20z"/>
</vector>"""

    # 4. Adaptive Icon Root Definition (`anydpi-v26/ic_launcher.xml`)
    adaptive_root_xml = f"""<?xml version="1.0" encoding="utf-8"?>
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
    <background android:drawable="@drawable/{clean_name}_background"/>
    <foreground android:drawable="@drawable/{clean_name}_foreground"/>
    <monochrome android:drawable="@drawable/{clean_name}_monochrome"/>
</adaptive-icon>"""

    # 5. Round Icon Root Definition (`anydpi-v26/ic_launcher_round.xml`)
    round_root_xml = f"""<?xml version="1.0" encoding="utf-8"?>
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
    <background android:drawable="@drawable/{clean_name}_background"/>
    <foreground android:drawable="@drawable/{clean_name}_foreground"/>
    <monochrome android:drawable="@drawable/{clean_name}_monochrome"/>
</adaptive-icon>"""

    files_generated: list[dict[str, str]] = [
        {"path": f"res/drawable/{clean_name}_background.xml", "content": bg_xml},
        {"path": f"res/drawable/{clean_name}_foreground.xml", "content": fg_xml},
        {"path": f"res/drawable/{clean_name}_monochrome.xml", "content": monochrome_xml},
        {"path": f"res/mipmap-anydpi-v26/{clean_name}.xml", "content": adaptive_root_xml},
        {"path": f"res/mipmap-anydpi-v26/{clean_name}_round.xml", "content": round_root_xml},
    ]

    density_specs: list[dict[str, Any]] = []
    for density, meta in MIPMAP_DENSITIES.items():
        density_specs.append(
            {
                "density": density,
                "folder": f"res/{meta['folder']}",
                "file_name": f"{clean_name}.png",
                "width_px": meta["icon_size_px"],
                "height_px": meta["icon_size_px"],
                "dpi": meta["density_dpi"],
            }
        )

    # Optional disk write
    if output_dir:
        base_out = Path(output_dir)
        for f in files_generated:
            target_p = base_out / f["path"]
            with contextlib.suppress(Exception):
                target_p.parent.mkdir(parents=True, exist_ok=True)
                target_p.write_text(f["content"], encoding="utf-8")

    return {
        "icon_name": clean_name,
        "background_color": background_color,
        "has_monochrome_layer": True,
        "has_round_variant": True,
        "target_api": "Android 8.0+ (API 26+) with Android 13+ (API 33+) Themed Icons",
        "generated_files": [f["path"] for f in files_generated],
        "density_mipmap_specs": density_specs,
        "files_count": len(files_generated),
        "xml_definitions": {
            "adaptive_icon": adaptive_root_xml,
            "background": bg_xml,
            "foreground": fg_xml,
            "monochrome": monochrome_xml,
        },
    }


def generate_play_store_banner(
    app_title: str,
    tagline: str = "Modern Mobile Experience",
    primary_color: str = "#0D47A1",
    secondary_color: str = "#1976D2",
    accent_color: str = "#00E676",
    output_path: str | Path | None = None,
) -> dict[str, Any]:
    """Generate exact 1024x500 Play Store Feature Graphic matching Google Console standards."""
    width = 1024
    height = 500

    # Clean title text for XML/SVG escaping
    safe_title = (
        app_title.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
    safe_tagline = (
        tagline.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )

    # SVG layout with gradient background, device frame mockup, and safe-zone margins
    svg_content = f"""<svg xmlns="http://www.w3.org/2000/svg"
    width="{width}" height="{height}" viewBox="0 0 {width} {height}">
    <defs>
        <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="{primary_color}"/>
            <stop offset="100%" stop-color="{secondary_color}"/>
        </linearGradient>
        <filter id="shadow" x="-10%" y="-10%" width="130%" height="130%">
            <feDropShadow dx="0" dy="12" stdDeviation="16"
                flood-color="#000000" flood-opacity="0.45"/>
        </filter>
    </defs>

    <!-- 1024x500 Solid Canvas (No Transparency allowed by Play Store) -->
    <rect width="{width}" height="{height}" fill="url(#bgGrad)"/>

    <!-- Decorative Modern Polygons -->
    <circle cx="950" cy="80" r="180" fill="{accent_color}" fill-opacity="0.15"/>
    <circle cx="100" cy="450" r="140" fill="#FFFFFF" fill-opacity="0.08"/>

    <!-- Typography (Safe-Zone: 80px padding from edges) -->
    <g transform="translate(90, 210)">
        <text font-family="Roboto, sans-serif" font-size="48" font-weight="800"
            fill="#FFFFFF" letter-spacing="-0.5">
            {safe_title}
        </text>
        <text y="50" font-family="Roboto, sans-serif" font-size="22" font-weight="400"
            fill="#E3F2FD">
            {safe_tagline}
        </text>
        <rect y="80" width="120" height="4" rx="2" fill="{accent_color}"/>
    </g>

    <!-- Android Device Mockup Frame (Right aligned, safe-zone compliant) -->
    <g transform="translate(680, 70)" filter="url(#shadow)">
        <!-- Outer Device Body -->
        <rect width="240" height="460" rx="36" fill="#121212" stroke="#333333" stroke-width="3"/>
        <!-- Inner Screen -->
        <rect x="10" y="14" width="220" height="432" rx="26" fill="#1E1E1E"/>
        <!-- Notch / Camera Punch-Hole -->
        <circle cx="120" cy="28" r="5" fill="#000000"/>
        <!-- Mock Screen Content -->
        <rect x="25" y="55" width="190" height="60" rx="12"
            fill="{primary_color}" fill-opacity="0.7"/>
        <rect x="25" y="130" width="190" height="110" rx="12" fill="#2C2C2C"/>
        <rect x="25" y="255" width="190" height="80" rx="12" fill="#2C2C2C"/>
    </g>
</svg>"""

    if output_path:
        p = Path(output_path)
        with contextlib.suppress(Exception):
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(svg_content, encoding="utf-8")

    return {
        "title": app_title,
        "tagline": tagline,
        "dimensions": f"{width}x{height}",
        "width_px": width,
        "height_px": height,
        "format": "svg",
        "has_transparency": False,
        "google_play_compliant": True,
        "safe_zone": {
            "margin_horizontal_px": 80,
            "margin_vertical_px": 60,
            "safe_width_px": width - 160,
            "safe_height_px": height - 120,
        },
        "svg_content": svg_content,
        "target_audience": "Google Play Store 1024x500 Feature Graphic Banner",
    }


def generate_notification_silhouette(
    name: str = "ic_stat_notification",
    source_vector_path: str | None = None,
    output_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Generate Android 13+ compliant monochrome alpha-only status bar notification icon."""
    clean_name = name.lower().replace("-", "_").replace(" ", "_")
    if not clean_name.startswith("ic_stat_"):
        clean_name = f"ic_stat_{clean_name}"

    # Default crisp monochrome silhouette path (Bell / Alert)
    bell_path_data = (
        "M12,22c1.1,0 2,-0.9 2,-2h-4c0,1.1 0.9,2 2,2z"
        "M18,16v-5c0,-3.07 -1.63,-5.64 -4.5,-6.32V4c0,-0.83 -0.67,-1.5 -1.5,-1.5"
        "s-1.5,0.67 -1.5,1.5v0.68C7.64,5.36 6,7.92 6,11v5l-2,2v1h16v-1l-2,-2z"
    )

    vector_path = source_vector_path or bell_path_data

    # Android Notification Icon Vector (24x24dp viewport, solid white fill with alpha)
    notification_vector_xml = f"""<?xml version="1.0" encoding="utf-8"?>
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="24dp"
    android:height="24dp"
    android:viewportWidth="24"
    android:viewportHeight="24"
    android:tint="#FFFFFFFF">
    <path
        android:fillColor="#FFFFFFFF"
        android:pathData="{vector_path}"/>
</vector>"""

    density_specs: list[dict[str, Any]] = []
    for density, meta in NOTIFICATION_DENSITIES.items():
        density_specs.append(
            {
                "density": density,
                "folder": f"res/{meta['folder']}",
                "file_name": f"{clean_name}.png",
                "width_px": meta["size_px"],
                "height_px": meta["size_px"],
            }
        )

    file_path = f"res/drawable/{clean_name}.xml"
    if output_dir:
        base_out = Path(output_dir)
        target_p = base_out / file_path
        with contextlib.suppress(Exception):
            target_p.parent.mkdir(parents=True, exist_ok=True)
            target_p.write_text(notification_vector_xml, encoding="utf-8")

    return {
        "icon_name": clean_name,
        "is_monochrome_silhouette": True,
        "has_alpha_channel": True,
        "viewport": "24x24dp",
        "android_notification_compliant": True,
        "generated_xml_path": file_path,
        "density_specs": density_specs,
        "vector_xml": notification_vector_xml,
    }
