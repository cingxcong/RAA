"""Interactive Symbol Deobfuscation & Propagation Registry.

Manages persistent analyst symbol renames (classes, methods, fields), propagates
renamed identifiers across decompiled source views and call graphs, and exports/imports
standard ProGuard retrace mapping files (mapping.txt).
"""

from __future__ import annotations

import re
from typing import Any


class SymbolRenameRegistry:
    """In-memory and file-backed symbol rename registry for a project."""

    def __init__(self) -> None:
        self.class_mappings: dict[str, str] = {}
        self.method_mappings: dict[str, str] = {}
        self.field_mappings: dict[str, str] = {}

    def add_mapping(self, symbol_type: str, original: str, renamed: str) -> None:
        """Register a symbol rename."""
        if symbol_type == "class":
            self.class_mappings[original] = renamed
        elif symbol_type == "method":
            self.method_mappings[original] = renamed
        elif symbol_type == "field":
            self.field_mappings[original] = renamed
        else:
            raise ValueError(
                f"Unknown symbol_type: {symbol_type}. Must be 'class', 'method', or 'field'."
            )

    def resolve_symbol(self, symbol: str) -> str:
        """Resolve an obfuscated symbol to its renamed identifier if mapped."""
        if symbol in self.class_mappings:
            return self.class_mappings[symbol]
        if symbol in self.method_mappings:
            return self.method_mappings[symbol]
        if symbol in self.field_mappings:
            return self.field_mappings[symbol]
        return symbol

    def apply_to_source(self, source_code: str) -> str:
        """Replace all mapped symbols in source code with their human-readable names."""
        transformed = source_code
        sorted_classes = sorted(
            self.class_mappings.items(), key=lambda kv: len(kv[0]), reverse=True
        )
        for orig, renamed in sorted_classes:
            smali_orig = orig.replace(".", "/")
            smali_renamed = renamed.replace(".", "/")
            transformed = transformed.replace(orig, renamed)
            transformed = transformed.replace(smali_orig, smali_renamed)

        sorted_methods = sorted(
            self.method_mappings.items(), key=lambda kv: len(kv[0]), reverse=True
        )
        for orig, renamed in sorted_methods:
            transformed = transformed.replace(orig, renamed)
            if "." in orig:
                class_part, method_part = orig.rsplit(".", 1)
                renamed_class = self.class_mappings.get(class_part, class_part)
                class_smali = renamed_class.replace(".", "/")
                # Replace smali method invocations: Lclass;->method(
                transformed = transformed.replace(
                    f"L{class_smali};->{method_part}(",
                    f"L{class_smali};->{renamed}(",
                )
                transformed = transformed.replace(
                    f";->{method_part}(",
                    f";->{renamed}(",
                )

        sorted_fields = sorted(self.field_mappings.items(), key=lambda kv: len(kv[0]), reverse=True)
        for orig, renamed in sorted_fields:
            transformed = transformed.replace(orig, renamed)
            if "." in orig:
                class_part, field_part = orig.rsplit(".", 1)
                renamed_class = self.class_mappings.get(class_part, class_part)
                class_smali = renamed_class.replace(".", "/")
                # Replace smali field access: Lclass;->field:
                transformed = transformed.replace(
                    f"L{class_smali};->{field_part}:",
                    f"L{class_smali};->{renamed}:",
                )
                transformed = transformed.replace(
                    f";->{field_part}:",
                    f";->{renamed}:",
                )

        return transformed

    def export_proguard_mapping(self) -> str:
        """Export current mappings in standard ProGuard mapping.txt format."""
        lines = [
            "# RAA Generated ProGuard / Retrace Mapping",
            "# Format: original -> renamed:",
        ]
        for orig, renamed in sorted(self.class_mappings.items()):
            lines.append(f"{renamed} -> {orig}:")
            prefix = f"{orig}."
            for m_orig, m_renamed in sorted(self.method_mappings.items()):
                if m_orig.startswith(prefix):
                    method_name = m_orig[len(prefix) :]
                    lines.append(f"    void {m_renamed}() -> {method_name}")
            for f_orig, f_renamed in sorted(self.field_mappings.items()):
                if f_orig.startswith(prefix):
                    field_name = f_orig[len(prefix) :]
                    lines.append(f"    java.lang.Object {f_renamed} -> {field_name}")

        return "\n".join(lines) + "\n"

    def import_proguard_mapping(self, mapping_content: str) -> int:
        """Import ProGuard mapping.txt rules into registry. Returns count of imported symbols."""
        count = 0
        current_class: str | None = None

        for line in mapping_content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            class_match = re.match(r"^([\w\.\$]+)\s*->\s*([\w\.\$]+):$", line)
            if class_match:
                current_renamed_class = class_match.group(1)
                current_class = class_match.group(2)
                self.class_mappings[current_class] = current_renamed_class
                count += 1
                continue

            if current_class and "->" in line:
                parts = line.split("->")
                left = parts[0].strip().split()
                right = parts[1].strip()
                if len(left) >= 2:
                    member_renamed = left[1].split("(")[0]
                    member_orig = right
                    if "(" in line:
                        self.method_mappings[f"{current_class}.{member_orig}"] = member_renamed
                    else:
                        self.field_mappings[f"{current_class}.{member_orig}"] = member_renamed
                    count += 1

        return count

    def to_dict(self) -> dict[str, Any]:
        """Serialize mappings to dictionary."""
        total = len(self.class_mappings) + len(self.method_mappings) + len(self.field_mappings)
        return {
            "class_mappings": self.class_mappings,
            "method_mappings": self.method_mappings,
            "field_mappings": self.field_mappings,
            "total_mapped": total,
        }
