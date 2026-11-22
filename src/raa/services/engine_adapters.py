"""Normalizing adapters for catalogued external engines.

Adapters translate engine-specific command lines and output layouts into the
same bounded dictionary shape. They do not decide whether an engine may run;
that is the :class:`EngineRunner` and settings policy's responsibility.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from raa.errors import EngineExecutionError, NotFoundError, PolicyDeniedError
from raa.services.engine_runner import EngineRunner
from raa.services.workspace import Workspace


class ApktoolAdapter:
    """Decode Smali with Apktool and return one class file."""

    def __init__(self, runner: EngineRunner, workspace: Workspace) -> None:
        self._runner = runner
        self._workspace = workspace

    def decode_smali(
        self,
        artifact_path: Path,
        class_name: str,
        *,
        offset: int = 0,
        limit: int = 100_000,
        max_bytes: int = 1024**2,
    ) -> dict[str, object]:
        spec = self._runner.spec("apktool")
        output_dir = self._runner.create_output_dir("apktool")
        result = self._runner.run(
            spec,
            [
                "d",
                "--no-res",
                "-f",
                "-o",
                str(output_dir),
                str(artifact_path),
            ],
            operation="smali.decode",
        )
        if result.exit_code != 0:
            raise _engine_failure("Apktool", result.exit_code, result.stderr)

        descriptor = _descriptor(class_name)
        relative = f"{descriptor[1:-1]}.smali"
        matches = _find_smali(output_dir, relative)
        if not matches:
            raise NotFoundError(
                f"Smali file not found for class: {class_name}",
                hint=(
                    "Apktool did not emit the expected smali path. Confirm the "
                    "class is present in the artifact and not removed by the engine."
                ),
                details={"class_name": class_name, "expected_path": relative},
            )
        path = matches[0]
        dex_file = _dex_file_for_smali_path(path, output_dir)
        return _read_artifact(
            path=path,
            workspace=self._workspace,
            engine_id=spec.id,
            operation=result.operation,
            duration_ms=result.duration_ms,
            offset=offset,
            limit=limit,
            max_bytes=max_bytes,
            warnings=(
                "Smali is a disassembled representation, not decompiled Java source.",
                "Apktool output is bounded and returned from the workspace engine cache.",
            ),
            dex_file=dex_file,
        )


class JadxAdapter:
    """Decompile one class with JADX and return bounded Java source."""

    def __init__(self, runner: EngineRunner, workspace: Workspace) -> None:
        self._runner = runner
        self._workspace = workspace

    def decompile_class(
        self,
        artifact_path: Path,
        class_name: str,
        *,
        offset: int = 0,
        limit: int = 100_000,
        max_bytes: int = 1024**2,
    ) -> dict[str, object]:
        spec = self._runner.spec("jadx")
        output_dir = self._runner.create_output_dir("jadx")
        result = self._runner.run(
            spec,
            [
                "--single-class",
                _dotted(class_name),
                "-d",
                str(output_dir),
                str(artifact_path),
            ],
            operation="java.decompile",
        )
        if result.exit_code != 0:
            raise _engine_failure("JADX", result.exit_code, result.stderr)

        simple_name = _dotted(class_name).rsplit(".", 1)[-1]
        matches = [
            path
            for path in output_dir.rglob(f"{simple_name}.java")
            if path.is_file() and _within(path, output_dir)
        ]
        if not matches:
            raise NotFoundError(
                f"Decompiled Java file not found for class: {class_name}",
                hint=(
                    "JADX did not emit the expected Java path. Confirm the class "
                    "is present in the artifact and supported by the engine."
                ),
                details={"class_name": class_name, "simple_name": simple_name},
            )
        return _read_artifact(
            path=matches[0],
            workspace=self._workspace,
            engine_id=spec.id,
            operation=result.operation,
            duration_ms=result.duration_ms,
            offset=offset,
            limit=limit,
            max_bytes=max_bytes,
            warnings=(
                "JADX output is decompiled Java, not guaranteed to compile.",
                "The containing class source is returned; method-level isolation is not applied.",
            ),
        )

    def decompile_method(
        self,
        artifact_path: Path,
        class_name: str,
        method_name: str,
        *,
        offset: int = 0,
        limit: int = 100_000,
        max_bytes: int = 1024**2,
    ) -> dict[str, object]:
        class_result = self.decompile_class(
            artifact_path,
            class_name,
            offset=0,
            limit=max_bytes,
            max_bytes=max_bytes,
        )
        full_text = str(class_result["text"])
        method_text, isolated = extract_method_source(full_text, method_name)
        if isolated:
            raw = method_text.encode("utf-8")
            start = max(0, min(offset, len(raw)))
            end = min(start + max(1, limit), max_bytes, len(raw))
            return {
                **class_result,
                "operation": "java.decompile_method",
                "method_name": method_name,
                "method_isolated": True,
                "byte_count": len(raw),
                "offset": start,
                "limit": end - start,
                "truncated": end < len(raw),
                "text": raw[start:end].decode("utf-8", errors="replace"),
                "warnings": [
                    "Method source is isolated from JADX decompiled class.",
                    "JADX output is decompiled Java, not guaranteed to compile.",
                ],
            }
        return {
            **class_result,
            "method_name": method_name,
            "method_isolated": False,
            "warnings": [
                (
                    "Method isolation could not locate the method boundary; "
                    "returning full class source."
                ),
                "JADX output is decompiled Java, not guaranteed to compile.",
            ],
        }


class AndroguardAdapter:
    """Analyze Android manifests and certificates using Androguard."""

    def __init__(self, runner: EngineRunner, workspace: Workspace) -> None:
        self._runner = runner
        self._workspace = workspace

    def analyze_manifest(
        self,
        artifact_path: Path,
    ) -> dict[str, object]:
        spec = self._runner.spec("androguard")
        result = self._runner.run(
            spec,
            ["axml", str(artifact_path)],
            operation="manifest.androguard",
        )
        if result.exit_code != 0:
            raise _engine_failure("Androguard", result.exit_code, result.stderr)

        text = result.stdout.strip()
        return {
            "engine_id": spec.id,
            "operation": result.operation,
            "duration_ms": result.duration_ms,
            "xml_preview": text[:4096],
            "byte_count": len(result.stdout.encode("utf-8")),
            "truncated": len(text) > 4096,
            "warnings": [
                "Androguard output parsed from external engine.",
            ],
        }

    def analyze_certificates(
        self,
        artifact_path: Path,
    ) -> dict[str, object]:
        spec = self._runner.spec("androguard")
        result = self._runner.run(
            spec,
            ["sign", "-a", str(artifact_path)],
            operation="certificate.androguard",
        )
        if result.exit_code != 0:
            raise _engine_failure("Androguard", result.exit_code, result.stderr)

        return {
            "engine_id": spec.id,
            "operation": result.operation,
            "duration_ms": result.duration_ms,
            "output": result.stdout.strip()[:4096],
            "warnings": [
                "Androguard certificate report generated by external engine.",
            ],
        }


class ApkidAdapter:
    """Detect compilers, packers, obfuscators and protectors using APKiD."""

    def __init__(self, runner: EngineRunner, workspace: Workspace) -> None:
        self._runner = runner
        self._workspace = workspace

    def scan(
        self,
        artifact_path: Path,
    ) -> dict[str, object]:
        spec = self._runner.spec("apkid")
        result = self._runner.run(
            spec,
            ["-j", str(artifact_path)],
            operation="packer.apkid",
        )
        if result.exit_code != 0:
            raise _engine_failure("APKiD", result.exit_code, result.stderr)

        try:
            parsed = json.loads(result.stdout)
        except json.JSONDecodeError:
            parsed = {}

        detections: dict[str, list[str]] = {}
        if isinstance(parsed, dict):
            for entry in parsed.values():
                if isinstance(entry, dict):
                    for category, items in entry.items():
                        if isinstance(items, list):
                            detections.setdefault(category, []).extend(items)
                        elif isinstance(items, str):
                            detections.setdefault(category, []).append(items)

        packers = detections.get("packer", [])
        protectors = detections.get("protector", [])
        obfuscators = detections.get("obfuscator", [])
        compilers = detections.get("compiler", [])
        anti_analysis = detections.get("anti_analysis", [])

        findings: list[dict[str, object]] = []
        for p in packers:
            findings.append({"category": "packer", "name": p, "confidence": "derived"})
        for p in protectors:
            findings.append({"category": "protector", "name": p, "confidence": "derived"})
        for o in obfuscators:
            findings.append({"category": "obfuscator", "name": o, "confidence": "derived"})
        for a in anti_analysis:
            findings.append({"category": "anti_analysis", "name": a, "confidence": "derived"})

        return {
            "engine_id": spec.id,
            "operation": result.operation,
            "duration_ms": result.duration_ms,
            "packers": sorted(set(packers)),
            "protectors": sorted(set(protectors)),
            "obfuscators": sorted(set(obfuscators)),
            "compilers": sorted(set(compilers)),
            "anti_analysis": sorted(set(anti_analysis)),
            "findings": findings,
            "total_detections": len(findings),
            "warnings": [
                "APKiD detects static signatures; dynamic anti-tamper may still be present.",
            ],
        }


def extract_method_source(source: str, method_name: str) -> tuple[str, bool]:
    pattern = re.compile(
        rf"(?:^[ \t]*@\w+(?:\([^)]*\))?[ \t]*\r?\n)*"
        rf"^[ \t]*(?:public|protected|private|static|final|native|synchronized|abstract|"
        rf"transient|\s)+[\w<>\[\], ?]+[ \t]+{re.escape(method_name)}[ \t]*\([^;{{]*\)"
        rf"(?:[ \t]*throws[ \t]+[\w., \t]+)?[ \t]*(\{{|;)",
        re.MULTILINE,
    )
    match = pattern.search(source)
    if not match:
        simple_pattern = re.compile(
            rf"^[ \t]*[^\n;{{]*\b{re.escape(method_name)}[ \t]*\([^;{{]*\)"
            rf"(?:[ \t]*throws[ \t]+[\w., \t]+)?[ \t]*(\{{|;)",
            re.MULTILINE,
        )
        match = simple_pattern.search(source)
        if not match:
            return source, False

    start_idx = match.start()
    terminator = match.group(1)
    if terminator == ";":
        return source[start_idx : match.end()].strip(), True

    brace_idx = match.end() - 1
    depth = 0
    in_string = False
    in_char = False
    in_line_comment = False
    in_block_comment = False
    escape = False

    i = brace_idx
    length = len(source)
    while i < length:
        ch = source[i]
        next_ch = source[i + 1] if i + 1 < length else ""

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
        elif in_block_comment:
            if ch == "*" and next_ch == "/":
                in_block_comment = False
                i += 1
        elif in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
        elif in_char:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == "'":
                in_char = False
        else:
            if ch == "/" and next_ch == "/":
                in_line_comment = True
                i += 1
            elif ch == "/" and next_ch == "*":
                in_block_comment = True
                i += 1
            elif ch == '"':
                in_string = True
            elif ch == "'":
                in_char = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return source[start_idx : i + 1].strip(), True
        i += 1

    return source, False


def _engine_failure(engine: str, exit_code: int, stderr: str) -> EngineExecutionError:
    excerpt = stderr.strip()[-500:]
    return EngineExecutionError(
        f"{engine} exited with code {exit_code}.",
        hint=excerpt or "Review the engine diagnostics and artifact container.",
        details={"engine": engine, "exit_code": exit_code, "stderr": excerpt},
    )


def _descriptor(value: str) -> str:
    if value.startswith("L") and value.endswith(";"):
        return value
    return f"L{value.replace('.', '/')};"


def _dotted(value: str) -> str:
    if value.startswith("L") and value.endswith(";"):
        return value[1:-1].replace("/", ".")
    return value


def _find_smali(output_dir: Path, relative: str) -> list[Path]:
    matches: list[Path] = []
    for root_name in ("smali", "smali_classes2", "smali_classes3", "smali_classes4"):
        candidate = output_dir / root_name / relative
        if candidate.is_file() and _within(candidate, output_dir):
            matches.append(candidate)
    if matches:
        return matches
    return [
        path
        for path in output_dir.rglob(Path(relative).name)
        if path.is_file() and _within(path, output_dir)
    ]


def _dex_file_for_smali_path(path: Path, output_dir: Path) -> str | None:
    try:
        first = path.relative_to(output_dir).parts[0]
    except (ValueError, IndexError):
        return None
    if first == "smali":
        return "classes.dex"
    if first.startswith("smali_classes"):
        suffix = first.removeprefix("smali_classes")
        return f"classes{suffix}.dex"
    return None


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise PolicyDeniedError(
            "Engine output escapes its bounded output directory.",
            details={"path": str(path), "root": str(root)},
        ) from exc
    return True


def _read_artifact(
    *,
    path: Path,
    workspace: Workspace,
    engine_id: str,
    operation: str,
    duration_ms: int,
    offset: int,
    limit: int,
    max_bytes: int,
    warnings: tuple[str, ...],
    dex_file: str | None = None,
) -> dict[str, object]:
    raw = path.read_bytes()
    start = max(0, min(offset, len(raw)))
    end = min(start + max(1, limit), max_bytes, len(raw))
    payload: dict[str, object] = {
        "engine_id": engine_id,
        "operation": operation,
        "file_reference": workspace.relative(path),
        "byte_count": len(raw),
        "offset": start,
        "limit": end - start,
        "truncated": end < len(raw),
        "text": raw[start:end].decode("utf-8", errors="replace"),
        "duration_ms": duration_ms,
        "warnings": list(warnings),
    }
    if dex_file is not None:
        payload["dex_file"] = dex_file
    return payload


class BlutterAdapter:
    """Analyze Flutter AOT snapshots using Blutter."""

    def __init__(self, runner: EngineRunner, workspace: Workspace) -> None:
        self._runner = runner
        self._workspace = workspace

    def analyze_aot(self, libapp_path: Path, output_dir: Path) -> dict[str, object]:
        spec = self._runner.spec("blutter")
        result = self._runner.run(
            spec,
            [str(libapp_path), str(output_dir)],
            operation="flutter.symbols",
        )
        if result.exit_code != 0:
            raise _engine_failure("Blutter", result.exit_code, result.stderr)
        return {"output_dir": str(output_dir), "stdout": result.stdout}


class HermesAdapter:
    """Disassemble React Native Hermes bytecode using hbctool or hermes-dec."""

    def __init__(self, runner: EngineRunner, workspace: Workspace) -> None:
        self._runner = runner
        self._workspace = workspace

    def disassemble(self, bundle_path: Path, output_dir: Path) -> dict[str, object]:
        spec = self._runner.spec("hbctool")
        result = self._runner.run(
            spec,
            ["disasm", str(bundle_path), str(output_dir)],
            operation="hermes.disassemble",
        )
        if result.exit_code != 0:
            raise _engine_failure("hbctool", result.exit_code, result.stderr)
        return {"output_dir": str(output_dir), "stdout": result.stdout}


class Il2CppAdapter:
    """Extract metadata and type definitions from Unity IL2CPP using Il2CppDumper."""

    def __init__(self, runner: EngineRunner, workspace: Workspace) -> None:
        self._runner = runner
        self._workspace = workspace

    def dump(
        self, libil2cpp_path: Path, metadata_path: Path, output_dir: Path
    ) -> dict[str, object]:
        spec = self._runner.spec("il2cppdumper")
        result = self._runner.run(
            spec,
            [str(libil2cpp_path), str(metadata_path), str(output_dir)],
            operation="il2cpp.dump",
        )
        if result.exit_code != 0:
            raise _engine_failure("Il2CppDumper", result.exit_code, result.stderr)
        return {"output_dir": str(output_dir), "stdout": result.stdout}


class IlSpyAdapter:
    """Decompile managed .NET / Xamarin assemblies using ILSpy CLI."""

    def __init__(self, runner: EngineRunner, workspace: Workspace) -> None:
        self._runner = runner
        self._workspace = workspace

    def decompile_type(self, assembly_path: Path, type_name: str | None = None) -> str:
        spec = self._runner.spec("ilspycmd")
        args = [str(assembly_path)]
        if type_name:
            args.extend(["-t", type_name])
        result = self._runner.run(
            spec,
            args,
            operation="dotnet.decompile",
        )
        if result.exit_code != 0:
            raise _engine_failure("ILSpy", result.exit_code, result.stderr)
        return result.stdout
