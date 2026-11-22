"""Multi-engine inventory and manifest/DEX cross-checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from raa.domain.models import Finding

if TYPE_CHECKING:
    from raa.domain.manifest import ManifestInfo
    from raa.services.android.dex import DexIndex


def cross_check_inventory(
    manifest: ManifestInfo | None,
    dex_index: DexIndex | None,
    *,
    androguard_manifest: dict[str, object] | None = None,
) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    limitations: list[str] = []

    if manifest is not None and dex_index is not None and dex_index.classes:
        known_classes = {klass.name for klass in dex_index.classes}
        package = manifest.package or ""

        for comp in manifest.components:
            name = comp.name
            if name.startswith("."):
                name = f"{package}{name}"
            elif "." not in name and package:
                name = f"{package}.{name}"

            if name not in known_classes and not name.startswith("android."):
                findings.append(
                    Finding(
                        id=f"crosscheck_missing_{comp.kind}_{comp.name}",
                        severity="medium",
                        category="crosscheck",
                        title=f"Declared {comp.kind} missing from DEX",
                        detail=(
                            f"Component '{comp.name}' ({comp.kind}) is declared in "
                            "AndroidManifest.xml but its class definition was not found "
                            "in any indexed DEX file."
                        ),
                    )
                )

    if androguard_manifest is not None:
        pass

    return findings, limitations
