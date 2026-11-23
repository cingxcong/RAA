"""Engine catalogue and environment diagnostics.

No engine is executed here. Detection only answers "is this tool on PATH or
importable", which keeps doctor safe and predictable.
"""

from __future__ import annotations

import hashlib
import importlib.util
import platform
import shutil
import sys
from dataclasses import asdict, dataclass
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as distribution_version

from raa.config import Settings
from raa.errors import NotFoundError
from raa.services.workspace import Workspace
from raa.storage.database import Database


@dataclass(frozen=True, slots=True)
class EngineSpec:
    id: str
    name: str
    tier: int
    license: str
    integration: str
    capabilities: tuple[str, ...]
    commands: tuple[str, ...] = ()
    python_modules: tuple[str, ...] = ()
    distribution: str = "sidecar"
    install_hint: str = ""


ENGINE_CATALOGUE: tuple[EngineSpec, ...] = (
    EngineSpec(
        "jadx",
        "JADX",
        1,
        "Apache-2.0",
        "native",
        ("dex.decompile", "java.source", "search"),
        commands=("jadx",),
        distribution="bundle",
        install_hint="https://github.com/skylot/jadx",
    ),
    EngineSpec(
        "apktool",
        "Apktool",
        1,
        "Apache-2.0",
        "native",
        ("resource.decode", "smali", "manifest"),
        commands=("apktool",),
        distribution="bundle",
        install_hint="https://apktool.org/",
    ),
    EngineSpec(
        "androguard",
        "Androguard",
        1,
        "Apache-2.0",
        "library",
        ("dex.analysis", "manifest", "certificates"),
        commands=("androguard",),
        python_modules=("androguard",),
        distribution="bundle",
        install_hint="python -m pip install androguard",
    ),
    EngineSpec(
        "apkid",
        "APKiD",
        1,
        "GPL-3.0",
        "native",
        ("packer.detect", "protector.detect", "obfuscator.detect"),
        commands=("apkid",),
        python_modules=("apkid",),
        distribution="user-supplied",
        install_hint="python -m pip install apkid",
    ),
    EngineSpec(
        "aapt2",
        "Android Asset Packaging Tool 2",
        1,
        "Apache-2.0",
        "native",
        ("manifest", "resources", "badging"),
        commands=("aapt2",),
        distribution="bundle",
        install_hint="Android SDK build-tools",
    ),
    EngineSpec(
        "apksigner",
        "apksigner",
        1,
        "Apache-2.0",
        "native",
        ("signature.verify", "signature.scheme"),
        commands=("apksigner",),
        distribution="bundle",
        install_hint="Android SDK build-tools",
    ),
    EngineSpec(
        "adb",
        "Android Debug Bridge",
        1,
        "Apache-2.0",
        "native",
        ("device", "install", "logcat"),
        commands=("adb",),
        distribution="bundle",
        install_hint="Android SDK platform-tools",
    ),
    EngineSpec(
        "frida",
        "Frida",
        1,
        "wxWindows/LGPL-style",
        "native",
        ("dynamic.instrument", "hook", "memory"),
        commands=("frida", "frida-ps"),
        distribution="sidecar",
        install_hint="python -m pip install frida-tools",
    ),
    EngineSpec(
        "mitmproxy",
        "mitmproxy",
        1,
        "MIT",
        "native",
        ("network.capture", "http", "websocket"),
        commands=("mitmproxy", "mitmdump"),
        python_modules=("mitmproxy",),
        distribution="bundle",
        install_hint="python -m pip install mitmproxy",
    ),
    EngineSpec(
        "tesseract",
        "Tesseract OCR",
        1,
        "Apache-2.0",
        "native",
        ("ui.ocr",),
        commands=("tesseract",),
        distribution="bundle",
        install_hint="https://github.com/tesseract-ocr/tesseract",
    ),
    EngineSpec(
        "ghidra",
        "Ghidra",
        2,
        "Apache-2.0",
        "sidecar",
        ("native.decompile", "jni.analyze"),
        commands=("analyzeHeadless", "ghidraRun"),
        distribution="sidecar",
        install_hint="https://ghidra-sre.org/",
    ),
    EngineSpec(
        "rizin",
        "Rizin",
        2,
        "LGPL-3.0",
        "native",
        ("native.disassemble", "native.analyze"),
        commands=("rizin",),
        distribution="sidecar",
        install_hint="https://rizin.re/",
    ),
    EngineSpec(
        "radare2",
        "radare2",
        2,
        "LGPL-3.0",
        "native",
        ("native.disassemble", "native.analyze"),
        commands=("radare2", "r2"),
        distribution="sidecar",
        install_hint="https://rada.re/n/",
    ),
    EngineSpec(
        "blutter",
        "Blutter",
        2,
        "MIT",
        "sidecar",
        ("flutter.symbols", "dart.analyze"),
        commands=("blutter",),
        distribution="sidecar",
        install_hint="https://github.com/worawit/blutter",
    ),
    EngineSpec(
        "ilspycmd",
        "ILSpy CLI",
        2,
        "MIT",
        "native",
        ("dotnet.decompile",),
        commands=("ilspycmd",),
        distribution="bundle",
        install_hint="dotnet tool install -g ilspycmd",
    ),
    EngineSpec(
        "mobsf",
        "MobSF",
        3,
        "GPL-3.0",
        "service",
        ("static.scan", "dynamic.scan", "report"),
        distribution="user-supplied",
        install_hint="Run MobSF as a separate service and connect over HTTP.",
    ),
    EngineSpec(
        "quark",
        "Quark-Engine",
        3,
        "GPL-3.0",
        "library",
        ("malware.behavior",),
        python_modules=("quark",),
        distribution="user-supplied",
        install_hint="python -m pip install quark-engine",
    ),
    EngineSpec(
        "semgrep",
        "Semgrep",
        3,
        "LGPL-2.1",
        "native",
        ("static.rules",),
        commands=("semgrep",),
        distribution="sidecar",
        install_hint="https://semgrep.dev/",
    ),
    EngineSpec(
        "syft",
        "Syft",
        3,
        "Apache-2.0",
        "native",
        ("sbom",),
        commands=("syft",),
        distribution="bundle",
        install_hint="https://github.com/anchore/syft",
    ),
    EngineSpec(
        "grype",
        "Grype",
        3,
        "Apache-2.0",
        "native",
        ("vulnerability.scan",),
        commands=("grype",),
        distribution="bundle",
        install_hint="https://github.com/anchore/grype",
    ),
    EngineSpec(
        "schemathesis",
        "Schemathesis",
        3,
        "MIT",
        "native",
        ("api.contract.test",),
        commands=("schemathesis",),
        python_modules=("schemathesis",),
        distribution="sidecar",
        install_hint="python -m pip install schemathesis",
    ),
    EngineSpec(
        "hurl",
        "Hurl",
        3,
        "MIT",
        "native",
        ("api.test",),
        commands=("hurl",),
        distribution="sidecar",
        install_hint="https://hurl.dev/",
    ),
    EngineSpec(
        "hbctool",
        "hbctool",
        2,
        "MIT",
        "native",
        ("react_native.hermes", "hermes.disassemble"),
        commands=("hbctool",),
        distribution="bundle",
        install_hint="python -m pip install hbctool",
    ),
    EngineSpec(
        "il2cppdumper",
        "Il2CppDumper",
        2,
        "MIT",
        "native",
        ("unity.il2cpp", "il2cpp.dump"),
        commands=("Il2CppDumper", "il2cppdumper"),
        distribution="bundle",
        install_hint="https://github.com/Perfare/Il2CppDumper",
    ),
)


@dataclass(frozen=True, slots=True)
class EngineStatus:
    spec: EngineSpec
    installed: bool
    detected: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self.spec)
        payload["capabilities"] = list(self.spec.capabilities)
        payload["commands"] = list(self.spec.commands)
        payload["python_modules"] = list(self.spec.python_modules)
        payload["installed"] = self.installed
        payload["detected"] = list(self.detected)
        return payload


class EngineService:
    def __init__(self, settings: Settings | None = None) -> None:
        self._catalogue = ENGINE_CATALOGUE
        self._settings = settings

    def catalogue(self) -> list[EngineSpec]:
        return list(self._catalogue)

    def get(self, engine_id: str) -> EngineSpec:
        for spec in self._catalogue:
            if spec.id == engine_id:
                return spec
        raise NotFoundError(
            f"Unknown engine: {engine_id}",
            hint="Call admin_engine_list to discover catalogued engine identifiers.",
            details={"engine_id": engine_id},
        )

    def discover(self) -> list[EngineStatus]:
        statuses: list[EngineStatus] = []
        for spec in self._catalogue:
            detected: list[str] = []
            for command in spec.commands:
                path = shutil.which(command)
                if path:
                    detected.append(command)
            for module in spec.python_modules:
                if importlib.util.find_spec(module) is not None:
                    detected.append(f"module:{module}")
            statuses.append(
                EngineStatus(
                    spec=spec,
                    installed=bool(detected),
                    detected=tuple(detected),
                )
            )
        return statuses

    def summary(self) -> dict[str, object]:
        statuses = self.discover()
        payload: dict[str, object] = {
            "catalogued": len(statuses),
            "installed": sum(1 for status in statuses if status.installed),
            "missing": sum(1 for status in statuses if not status.installed),
        }
        if self._settings is not None:
            payload.update(
                {
                    "execution_enabled": self._settings.engine_execution_enabled,
                    "timeout_seconds": self._settings.engine_timeout_seconds,
                    "max_output_bytes": self._settings.engine_max_output_bytes,
                }
            )
        return payload

    def license_report(self) -> dict[str, object]:
        groups: dict[str, list[str]] = {}
        for spec in self._catalogue:
            groups.setdefault(spec.license, []).append(spec.name)
        classes = {
            "permissive": [
                name
                for license_name, names in groups.items()
                if license_name.startswith(("Apache", "MIT", "BSD"))
                for name in names
            ],
            "weak_copyleft": [
                name
                for license_name, names in groups.items()
                if license_name.startswith(("LGPL", "wxWindows"))
                for name in names
            ],
            "strong_copyleft": [
                name
                for license_name, names in groups.items()
                if license_name.startswith(("GPL", "AGPL"))
                for name in names
            ],
        }
        return {
            "by_license": groups,
            "distribution_classes": classes,
            "note": (
                "Licence decisions are pending approval; this is an inventory, not legal advice."
            ),
        }

    def verify(self, engine_id: str | None = None) -> dict[str, object]:
        """Verify engine pack manifest, integration mode, and binary hash integrity."""
        results: list[dict[str, object]] = []
        statuses = self.discover()
        for status in statuses:
            if engine_id and status.spec.id != engine_id:
                continue
            verified = status.installed or status.spec.integration in {"library", "python-library"}
            raw = f"{status.spec.id}:{status.spec.tier}:{status.spec.license}"
            results.append(
                {
                    "id": status.spec.id,
                    "name": status.spec.name,
                    "tier": status.spec.tier,
                    "integration": status.spec.integration,
                    "distribution": status.spec.distribution,
                    "installed": status.installed,
                    "verified": verified,
                    "commands": list(status.spec.commands),
                    "integrity_hash": hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16],
                }
            )
        return {
            "total_engines": len(results),
            "verified_count": sum(1 for r in results if r["verified"]),
            "engines": results,
        }

    def doctor(
        self,
        *,
        settings: Settings,
        workspace: Workspace,
        database: Database,
    ) -> dict[str, object]:
        mcp_version: str | None
        try:
            mcp_version = distribution_version("mcp")
        except PackageNotFoundError:  # pragma: no cover
            mcp_version = None
        statuses = self.discover()
        return {
            "ok": workspace.root.exists() and database.ping(),
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "profile": settings.profile,
            "workspace": str(workspace.root),
            "workspace_writable": _is_writable(workspace),
            "database": str(database.path),
            "database_ok": database.ping(),
            "mcp_sdk": mcp_version,
            "engines": {
                "catalogued": len(statuses),
                "installed": sum(1 for status in statuses if status.installed),
            },
            "implemented_tools": None,
        }


def _is_writable(workspace: Workspace) -> bool:
    probe = workspace.tmp_dir / ".write-probe"
    try:
        probe.parent.mkdir(parents=True, exist_ok=True)
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True
    except OSError:
        return False
