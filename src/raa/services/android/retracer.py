"""ProGuard and R8 mapping file parsing, stack trace retracing, and coverage calculation."""

from __future__ import annotations

import re
from pathlib import Path

from raa.domain.unpacking import (
    ClassMapping,
    FieldMapping,
    MethodMapping,
    RetraceReport,
)
from raa.utils.time import utc_now

# ProGuard/R8 mapping syntax patterns
_CLASS_LINE_RE = re.compile(r"^([a-zA-Z0-9_\.\$]+)\s*->\s*([a-zA-Z0-9_\.\$]+):$")
_METHOD_LINE_RE = re.compile(
    r"^\s*(?:(\d+):(\d+):)?([a-zA-Z0-9_\.\[\]]+)\s+([a-zA-Z0-9_<>$]+)\(([^)]*)\)\s*->\s*([a-zA-Z0-9_<>$]+)$"
)
_FIELD_LINE_RE = re.compile(
    r"^\s*([a-zA-Z0-9_\.\[\]]+)\s+([a-zA-Z0-9_<>$]+)\s*->\s*([a-zA-Z0-9_<>$]+)$"
)

# Stack trace frame pattern: "at a.b.c(Unknown Source:10)" or "at a.b.c.d(Source.java:15)"
_STACK_FRAME_RE = re.compile(r"\bat\s+([a-zA-Z0-9_\.\$]+)\.([a-zA-Z0-9_<>$]+)\(([^:]*):?(\d+)?\)")


class ProguardMapping:
    """Parsed ProGuard/R8 mapping lookup table."""

    def __init__(self) -> None:
        self.classes: dict[str, str] = {}  # obfuscated_class -> original_class
        self.reverse_classes: dict[str, str] = {}  # original_class -> obfuscated_class
        # (obfuscated_class, obfuscated_method) -> list of MethodMapping
        self.methods: dict[tuple[str, str], list[MethodMapping]] = {}
        # (obfuscated_class, obfuscated_field) -> FieldMapping
        self.fields: dict[tuple[str, str], FieldMapping] = {}

        self.class_mappings: list[ClassMapping] = []
        self.method_mappings: list[MethodMapping] = []
        self.field_mappings: list[FieldMapping] = []

    def add_class(self, original: str, obfuscated: str) -> None:
        self.classes[obfuscated] = original
        self.reverse_classes[original] = obfuscated
        self.class_mappings.append(ClassMapping(original=original, obfuscated=obfuscated))

    def add_method(
        self,
        current_class: str,
        original_name: str,
        obfuscated_name: str,
        return_type: str,
        start_line: int | None,
        end_line: int | None,
    ) -> None:
        mapping = MethodMapping(
            class_name=current_class,
            original_name=original_name,
            obfuscated_name=obfuscated_name,
            return_type=return_type,
            start_line=start_line,
            end_line=end_line,
        )
        self.methods.setdefault((current_class, obfuscated_name), []).append(mapping)
        self.method_mappings.append(mapping)

    def add_field(
        self,
        current_class: str,
        original_name: str,
        obfuscated_name: str,
        field_type: str,
    ) -> None:
        mapping = FieldMapping(
            class_name=current_class,
            original_name=original_name,
            obfuscated_name=obfuscated_name,
            field_type=field_type,
        )
        self.fields[(current_class, obfuscated_name)] = mapping
        self.field_mappings.append(mapping)


def parse_mapping_file(mapping_path: Path) -> ProguardMapping:
    """Parse a ProGuard/R8 mapping.txt file into a lookup table."""
    mapping = ProguardMapping()
    if not mapping_path.is_file():
        return mapping

    current_obf_class: str | None = None

    for line in mapping_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # 1. Class line: "original.package.Class -> obf.pkg.C:"
        class_match = _CLASS_LINE_RE.match(line)
        if class_match:
            orig = class_match.group(1)
            obf = class_match.group(2)
            mapping.add_class(orig, obf)
            current_obf_class = obf
            continue

        if not current_obf_class:
            continue

        # 2. Method line: "10:20:void original(int) -> a"
        method_match = _METHOD_LINE_RE.match(line)
        if method_match:
            s_line = int(method_match.group(1)) if method_match.group(1) else None
            e_line = int(method_match.group(2)) if method_match.group(2) else None
            ret = method_match.group(3)
            orig_m = method_match.group(4)
            obf_m = method_match.group(6)
            mapping.add_method(current_obf_class, orig_m, obf_m, ret, s_line, e_line)
            continue

        # 3. Field line: "java.lang.String original -> b"
        field_match = _FIELD_LINE_RE.match(line)
        if field_match:
            f_type = field_match.group(1)
            orig_f = field_match.group(2)
            obf_f = field_match.group(3)
            mapping.add_field(current_obf_class, orig_f, obf_f, f_type)

    return mapping


def retrace_stack_trace(
    mapping: ProguardMapping,
    stack_trace: str,
) -> tuple[str, int, int]:
    """Retrace an obfuscated stack trace string back to original class, method, and line names.

    Returns: (retraced_trace, mapped_count, unmapped_count)
    """
    mapped_count = 0
    unmapped_count = 0
    lines = stack_trace.splitlines()
    retraced_lines: list[str] = []

    for line in lines:
        m = _STACK_FRAME_RE.search(line)
        if not m:
            retraced_lines.append(line)
            continue

        obf_class = m.group(1)
        obf_method = m.group(2)
        source_file = m.group(3)
        line_num = int(m.group(4)) if m.group(4) else None

        orig_class = mapping.classes.get(obf_class)
        if not orig_class:
            unmapped_count += 1
            retraced_lines.append(line)
            continue

        # Try to resolve method
        methods = mapping.methods.get((obf_class, obf_method), [])
        orig_method = obf_method
        if methods:
            if line_num is not None:
                # Match method by line number range
                for mm in methods:
                    if mm.start_line is not None and mm.end_line is not None:
                        if mm.start_line <= line_num <= mm.end_line:
                            orig_method = mm.original_name
                            break
                    elif mm.start_line is not None and line_num >= mm.start_line:
                        orig_method = mm.original_name
                        break
            if orig_method == obf_method:
                orig_method = methods[0].original_name

        class_simple = orig_class.split(".")[-1]
        orig_source = (
            f"{class_simple}.java"
            if not source_file or source_file == "Unknown Source"
            else source_file
        )
        line_str = f":{line_num}" if line_num is not None else ""

        retraced_frame = f"at {orig_class}.{orig_method}({orig_source}{line_str})"
        retraced_line = _STACK_FRAME_RE.sub(retraced_frame, line)
        retraced_lines.append(retraced_line)
        mapped_count += 1

    return "\n".join(retraced_lines), mapped_count, unmapped_count


def execute_retrace(
    mapping_file_path: Path,
    stack_trace: str | None = None,
    total_known_symbols: int | None = None,
) -> RetraceReport:
    """Execute mapping file parsing, stack trace retracing, and retrace coverage calculation."""
    mapping = parse_mapping_file(mapping_file_path)

    total_classes = len(mapping.classes)
    total_methods = len(mapping.method_mappings)
    total_fields = len(mapping.field_mappings)
    total_mapped = total_classes + total_methods + total_fields

    retraced_text: str | None = None
    unmapped_symbols = 0

    if stack_trace:
        retraced_text, mapped_frames, unmapped_frames = retrace_stack_trace(mapping, stack_trace)
        unmapped_symbols = unmapped_frames
        total_eval = mapped_frames + unmapped_frames
        coverage = round((mapped_frames / total_eval) * 100.0, 2) if total_eval > 0 else 100.0
    elif total_known_symbols and total_known_symbols > 0:
        coverage = round(min(100.0, (total_mapped / total_known_symbols) * 100.0), 2)
    else:
        # Default nominal coverage when mapping has entries
        coverage = 100.0 if total_mapped > 0 else 0.0

    return RetraceReport(
        mapping_file=str(mapping_file_path),
        total_classes_mapped=total_classes,
        total_methods_mapped=total_methods,
        total_fields_mapped=total_fields,
        retrace_coverage_percent=coverage,
        retraced_text=retraced_text,
        unmapped_symbols_count=unmapped_symbols,
        processed_at=utc_now(),
    )
