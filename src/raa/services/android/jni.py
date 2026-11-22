"""JNI mapping service correlating Java/Kotlin native methods to native library symbols."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from raa.domain.native import JniBinding, JniMappingReport
from raa.services.android.elf import extract_elf_symbols
from raa.services.inspection import read_archive_member

if TYPE_CHECKING:
    from raa.services.android.dex import DexIndex


def escape_jni_identifier(text: str) -> str:
    """Escape an identifier according to JNI symbol rules."""
    return (
        text.replace("_", "_1")
        .replace(";", "_2")
        .replace("[", "_3")
        .replace("/", "_")
        .replace(".", "_")
        .replace("$", "_00024")
    )


def map_jni_methods(
    apk_path: Path,
    dex_index: DexIndex | None,
    native_libraries: list[str],
    *,
    max_native_methods: int = 1000,
) -> JniMappingReport:
    """Map declared native methods in DEX classes to exported ELF symbols."""
    bindings: list[JniBinding] = []
    limitations: list[str] = []

    if dex_index is None:
        return JniMappingReport(
            limitations=["DEX index was not available for JNI mapping."],
        )

    # 1. Collect all declared native methods from DEX
    native_methods: list[tuple[str, str, str]] = []  # (class_name, method_name, descriptor)
    for klass in dex_index.classes:
        for method in klass.methods:
            if method.access_flags & 0x0100:  # ACC_NATIVE
                native_methods.append((klass.name, method.name, method.descriptor))

    if not native_methods:
        return JniMappingReport(
            total_native_methods=0,
            bound_count=0,
            dynamic_count=0,
            unresolved_count=0,
            libraries_searched=native_libraries,
        )

    # 2. Extract symbols from all native libraries
    lib_symbols: dict[str, set[str]] = {}
    libs_with_jni_onload: list[str] = []

    for lib_path in native_libraries:
        try:
            content = read_archive_member(apk_path, lib_path, max_bytes=8 * 1024 * 1024)
            summary = extract_elf_symbols(content, library_name=lib_path)
            symbols = {s.name for s in summary.exported_symbols}
            lib_symbols[lib_path] = symbols
            if summary.has_jni_on_load:
                libs_with_jni_onload.append(lib_path)
        except Exception as exc:
            limitations.append(f"Could not read native library {lib_path}: {exc}")

    # 3. Match each native method against symbols
    bound_count = 0
    dynamic_count = 0
    unresolved_count = 0

    for class_name, method_name, descriptor in native_methods[:max_native_methods]:
        # Formulate expected JNI export name
        escaped_class = escape_jni_identifier(class_name)
        escaped_method = escape_jni_identifier(method_name)
        short_name = f"Java_{escaped_class}_{escaped_method}"

        matched_lib = None
        matched_symbol = None

        for lib_path, symbols in lib_symbols.items():
            if short_name in symbols:
                matched_lib = lib_path
                matched_symbol = short_name
                break
            # Check for overloaded variant if short name not found
            for sym in symbols:
                if sym.startswith(short_name + "__"):
                    matched_lib = lib_path
                    matched_symbol = sym
                    break
            if matched_symbol:
                break

        if matched_symbol:
            bound_count += 1
            bindings.append(
                JniBinding(
                    java_class=class_name,
                    java_method=method_name,
                    descriptor=descriptor,
                    native_symbol=matched_symbol,
                    library=matched_lib,
                    status="bound",
                    notes="Statically bound via exported JNI symbol.",
                )
            )
        elif libs_with_jni_onload:
            dynamic_count += 1
            bindings.append(
                JniBinding(
                    java_class=class_name,
                    java_method=method_name,
                    descriptor=descriptor,
                    native_symbol=None,
                    library=libs_with_jni_onload[0],
                    status="dynamic",
                    notes=(
                        f"No static JNI export found; likely registered dynamically "
                        f"via RegisterNatives in JNI_OnLoad ({libs_with_jni_onload[0]})."
                    ),
                )
            )
        else:
            unresolved_count += 1
            bindings.append(
                JniBinding(
                    java_class=class_name,
                    java_method=method_name,
                    descriptor=descriptor,
                    native_symbol=None,
                    library=None,
                    status="unresolved",
                    notes="No matching native symbol or JNI_OnLoad entry point found.",
                )
            )

    return JniMappingReport(
        bindings=bindings,
        total_native_methods=len(native_methods),
        bound_count=bound_count,
        dynamic_count=dynamic_count,
        unresolved_count=unresolved_count,
        libraries_searched=list(lib_symbols.keys()),
        limitations=limitations,
    )
