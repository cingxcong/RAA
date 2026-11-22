"""Deobfuscation transformation engine for Dalvik bytecode and Smali representation."""

from __future__ import annotations

import base64
import re
from pathlib import Path

from raa.domain.unpacking import DeobfuscationResult
from raa.utils.time import utc_now

_REFLECTION_PATTERN = re.compile(
    r'Class\.forName\(\s*"([a-zA-Z0-9_\.\$]+)"\s*\)'
    r'(?:\.getMethod\(\s*"([a-zA-Z0-9_]+)"[^)]*\))?'
)

_BASE64_LITERAL_PATTERN = re.compile(
    r'(?:const-string(?:\/jumbo)?\s+v\d+,\s*|")([A-Za-z0-9+/]{12,}={0,2})"'
)

_OPAQUE_PREDICATE_PATTERN = re.compile(
    r"(?m)(?:^\s*(?:if-eqz\s+v\d+,\s*:\w+\s*\n\s*if-nez\s+v\d+,\s*:\w+)|"
    r"^\s*if-eqz\s+v\d+,\s*:\w+|"
    r"if\s*\(\s*(?:1\s*==\s*0|0\s*==\s*1|false)\s*\)\s*\{[^}]*\})"
)


def _try_b64_decode(text: str) -> str | None:
    try:
        decoded = base64.b64decode(text, validate=True)
        # Check if printable ASCII/UTF-8 string
        s = decoded.decode("utf-8")
        if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in s) and len(s) >= 4:
            return s
    except Exception:
        return None
    return None


def deobfuscate_source(
    source_code: str,
    target_name: str,
    strategy: str = "simplify",
    output_dir: Path | None = None,
) -> DeobfuscationResult:
    """Apply deobfuscation transformations (reflection resolution, string decryption, dead code)."""
    transformed = False
    reflections_resolved = 0
    constants_decrypted = 0
    dead_branches_pruned = 0
    working_text = source_code

    # 1. Reflection Resolution
    if strategy in ("simplify", "reflection_resolve"):
        for m in _REFLECTION_PATTERN.finditer(source_code):
            target_class = m.group(1)
            target_method = m.group(2)
            if target_method:
                comment = (
                    f"/* [RAA DEOBFUSCATION: Resolved reflection -> "
                    f"{target_class}.{target_method}()] */"
                )
            else:
                comment = f"/* [RAA DEOBFUSCATION: Resolved reflection -> {target_class}] */"
            working_text = working_text.replace(m.group(0), f"{m.group(0)} {comment}")
            reflections_resolved += 1
            transformed = True

        # Resolve variable-assigned reflection patterns
        # e.g. clazz = Class.forName; clazz.getMethod
        var_assign_re = re.compile(
            r'([a-zA-Z0-9_]+)\s*=\s*Class\.forName\(\s*"([a-zA-Z0-9_\.\$]+)"\s*\)'
        )
        for vm in var_assign_re.finditer(source_code):
            var_name = vm.group(1)
            cls_name = vm.group(2)
            meth_call_re = re.compile(
                rf'{re.escape(var_name)}\.getMethod\(\s*"([a-zA-Z0-9_]+)"[^)]*\)'
            )
            for mm in meth_call_re.finditer(working_text):
                meth_name = mm.group(1)
                comment = (
                    f"/* [RAA DEOBFUSCATION: Resolved reflection -> {cls_name}.{meth_name}()] */"
                )
                working_text = working_text.replace(mm.group(0), f"{mm.group(0)} {comment}")
                reflections_resolved += 1
                transformed = True

    # 2. String Decryption (Base64 constants inlining)
    if strategy in ("simplify", "string_decrypt"):
        for m in _BASE64_LITERAL_PATTERN.finditer(source_code):
            b64_candidate = m.group(1)
            plain = _try_b64_decode(b64_candidate)
            if plain:
                comment = f'/* [RAA DEOBFUSCATION: Decrypted Base64 -> "{plain}"] */'
                working_text = working_text.replace(
                    f'"{b64_candidate}"', f'"{b64_candidate}" {comment}'
                )
                constants_decrypted += 1
                transformed = True

    # 3. Opaque Predicates & Dead Branch Pruning
    if strategy in ("simplify", "dead_code_prune"):
        dead_matches = list(_OPAQUE_PREDICATE_PATTERN.finditer(working_text))
        for dm in dead_matches:
            matched_code = dm.group(0)
            replacement = "/* [RAA DEOBFUSCATION: Pruned opaque predicate / dead jump] */\n    nop"
            working_text = working_text.replace(matched_code, replacement)
            dead_branches_pruned += 1
            transformed = True

    # Add header banner marking deobfuscated status
    header_banner = (
        "// ============================================================================\n"
        "// RAA DEOBFUSCATED CODE - PROVENANCE WARNING\n"
        "// Transformed by RAA Deobfuscator (strategy: " + strategy + ")\n"
        "// Deobfuscation transforms bytecode semantics. "
        "Never present this output as original source code.\n"
        "// ============================================================================\n\n"
    )
    final_output = header_banner + working_text

    out_file_path: str | None = None
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        safe_name = target_name.replace("/", "_").replace("\\", "_")
        out_file = output_dir / f"deobfuscated_{safe_name}"
        out_file.write_text(final_output, encoding="utf-8")
        out_file_path = str(out_file)

    return DeobfuscationResult(
        target=target_name,
        strategy=strategy,
        transformed=transformed,
        constants_decrypted=constants_decrypted,
        reflections_resolved=reflections_resolved,
        dead_branches_pruned=dead_branches_pruned,
        deobfuscated_file=out_file_path,
        transformed_code=final_output,
        provenance_warning=(
            "Deobfuscation transforms bytecode semantics. "
            "Never present this output as original source code."
        ),
        completed_at=utc_now(),
    )
