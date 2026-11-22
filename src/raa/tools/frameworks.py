"""Framework inspection and adapter tools for Flutter, React Native, Unity, and .NET."""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from raa.errors import NotFoundError
from raa.policy.scopes import ANDROID_PATCH, PROJECT_READ, PROJECT_WRITE, STATIC_READ
from raa.registry.models import (
    CapabilityRegistry,
    ToolAnnotations,
    ToolContext,
    ToolOutcome,
    ToolSpec,
)
from raa.registry.profiles import CORE
from raa.services.android.dex import decode_dex_index
from raa.services.engine_adapters import BlutterAdapter, Il2CppAdapter, IlSpyAdapter
from raa.services.framework_adapters.flutter_reverser import (
    dump_flutter_strings,
    generate_flutter_ssl_bypass,
    inspect_dart_snapshot,
    patch_flutter_engine_proxy,
    patch_flutter_tls,
)
from raa.services.framework_adapters.hermes_reverser import (
    decompile_hermes_bytecode,
    extract_hermes_bundle,
)
from raa.services.framework_adapters.il2cpp_dumper import dump_il2cpp_metadata
from raa.services.framework_inspectors import (
    get_flutter_symbols,
    get_framework_capabilities,
    get_unity_metadata,
    inspect_flutter_assets,
    inspect_react_native_bundle,
    inspect_unity_assets,
    list_dotnet_assemblies,
    list_react_native_modules,
)


class FrameworkCapabilitiesInput(BaseModel):
    framework_id: str | None = Field(
        default=None,
        description="Optional framework identifier (flutter, react_native, unity, xamarin).",
    )


class JobInput(BaseModel):
    project_id: str = Field(min_length=1, description="Target project ID.")
    job_id: str = Field(min_length=1, description="Completed analysis job ID.")


class FlutterListAssetsInput(JobInput):
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class FlutterGetSymbolsInput(JobInput):
    use_engine: bool = Field(
        default=False,
        description="Attempt external engine (Blutter) decompilation when enabled.",
    )


class ReactNativeBundleInput(JobInput):
    bundle_path: str | None = Field(
        default=None,
        description="Optional custom path to JavaScript or Hermes bundle within the APK.",
    )


class ReactNativeModulesInput(JobInput):
    pass


class UnityListAssetsInput(JobInput):
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class UnityGetMetadataInput(JobInput):
    use_engine: bool = Field(
        default=False,
        description="Attempt external engine (Il2CppDumper) analysis when enabled.",
    )


class DotnetListAssembliesInput(JobInput):
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class DotnetGetTypeInput(JobInput):
    assembly_name: str = Field(
        min_length=1,
        description="Name of the assembly file (e.g. 'MyApp.dll').",
    )
    type_name: str | None = Field(
        default=None,
        description="Optional full type name to decompile or inspect.",
    )
    decompile: bool = Field(
        default=False,
        description="Attempt ILSpy C# decompilation when enabled.",
    )


class FlutterPatchTlsInput(BaseModel):
    project_id: str = Field(min_length=1, description="Target project identifier.")
    artifact_id: str = Field(min_length=1, description="Target base Flutter artifact ID.")
    proxy_host: str = Field(default="10.0.2.2", description="Interception proxy hostname or IP.")
    proxy_port: int = Field(default=8080, ge=1, le=65535, description="Interception proxy port.")


class FlutterDumpStringsInput(BaseModel):
    project_id: str = Field(min_length=1, description="Target project identifier.")
    artifact_id: str = Field(min_length=1, description="Target Flutter artifact ID.")


class UnityDumpMetadataInput(BaseModel):
    project_id: str = Field(min_length=1, description="Target project identifier.")
    artifact_id: str = Field(min_length=1, description="Target Unity artifact ID.")


class FlutterDartSnapshotInput(BaseModel):
    snapshot_path: str | None = Field(
        default=None,
        description="Optional path to libapp.so or Dart snapshot file.",
    )
    architecture: str = Field(
        default="arm64",
        description="Target CPU architecture (arm64, armeabi-v7a, x86_64).",
    )


class FlutterSslBypassInput(BaseModel):
    architecture: str = Field(
        default="arm64",
        description="Target architecture for BoringSSL patch (arm64, x86_64).",
    )
    libflutter_path: str | None = Field(
        default=None,
        description="Optional path to libflutter.so binary.",
    )


class FlutterEngineProxyInput(BaseModel):
    libflutter_path: str | None = Field(
        default=None,
        description="Path to libflutter.so to patch.",
    )
    proxy_host: str = Field(
        default="127.0.0.1",
        description="Interception proxy hostname or IP.",
    )
    proxy_port: int = Field(
        default=8080,
        ge=1,
        le=65535,
        description="Interception proxy port.",
    )
    output_path: str | None = Field(
        default=None,
        description="Optional output path for patched libflutter.so.",
    )


class HermesBundleExtractInput(BaseModel):
    bundle_path: str | None = Field(
        default=None,
        description="Path to APK or Hermes bundle file.",
    )


class HermesDecompileInput(BaseModel):
    bundle_path: str | None = Field(
        default=None,
        description="Optional path to Hermes bytecode bundle file.",
    )
    extract_secrets: bool = Field(
        default=True,
        description="Scan decompiled AST for hardcoded API keys, JWT tokens, and credentials.",
    )


class SkipSwiftFrameworkInspectInput(BaseModel):
    """Parameters to inspect Skip Swift transpiler signatures and reconstruct models."""

    apk_path: str | None = Field(default=None, description="Path to target Android APK file.")
    project_id: str | None = Field(default=None, description="Optional target project ID.")
    deobfuscate_models: bool = Field(
        default=True, description="Reconstruct Swift models and SwiftUI view bindings."
    )


def _get_job_context(ctx: ToolContext, project_id: str, job_id: str) -> tuple[Any, Path, list[str]]:
    report = ctx.runtime.analysis.get_report(project_id, job_id)
    artifact = ctx.runtime.artifacts.get_or_raise(report.project_id, report.artifact_id)
    path = ctx.runtime.artifacts.path_for(artifact)
    archive_names: list[str] = list(report.summary.get("archive_names", []))
    if not archive_names and path.is_file():
        try:
            with zipfile.ZipFile(path) as zf:
                archive_names = zf.namelist()
        except Exception:
            archive_names = []
    return report, path, archive_names


async def _framework_get_capabilities(
    ctx: ToolContext, args: FrameworkCapabilitiesInput
) -> ToolOutcome:
    all_caps = get_framework_capabilities()
    if args.framework_id:
        filtered = [c for c in all_caps if c.id == args.framework_id]
        if not filtered:
            raise NotFoundError(
                f"Framework '{args.framework_id}' not found in capabilities catalog."
            )
        return ToolOutcome(data={"capabilities": [c.model_dump(mode="json") for c in filtered]})
    return ToolOutcome(data={"capabilities": [c.model_dump(mode="json") for c in all_caps]})


async def _flutter_list_assets(ctx: ToolContext, args: FlutterListAssetsInput) -> ToolOutcome:
    report, path, archive_names = _get_job_context(ctx, args.project_id, args.job_id)
    summary = inspect_flutter_assets(path, archive_names, max_assets=args.limit + args.offset)
    page = summary.assets[args.offset : args.offset + args.limit]
    return ToolOutcome(
        data={
            "assets": [a.model_dump(mode="json") for a in page],
            "total_count": summary.total_count,
            "count": len(page),
            "font_families": summary.font_families,
            "has_asset_manifest": summary.has_asset_manifest,
            "has_font_manifest": summary.has_font_manifest,
            "manifest_entries": summary.manifest_entries,
        },
        evidence_ids=report.evidence_ids,
    )


async def _flutter_get_symbols(ctx: ToolContext, args: FlutterGetSymbolsInput) -> ToolOutcome:
    report, path, archive_names = _get_job_context(ctx, args.project_id, args.job_id)
    summary = get_flutter_symbols(path, archive_names)
    data = summary.model_dump(mode="json")

    if args.use_engine:
        adapter = BlutterAdapter(ctx.runtime.engine_runner, ctx.runtime.workspace)
        target_app = next((name for name in archive_names if name.endswith("libapp.so")), None)
        if target_app:
            out_dir = ctx.runtime.workspace.tmp_dir / f"blutter_{args.job_id}"
            out_dir.mkdir(parents=True, exist_ok=True)
            res = adapter.analyze_aot(path, out_dir)
            data["engine_output"] = res

    return ToolOutcome(data=data, evidence_ids=report.evidence_ids)


async def _react_native_inspect_bundle(
    ctx: ToolContext, args: ReactNativeBundleInput
) -> ToolOutcome:
    report, path, archive_names = _get_job_context(ctx, args.project_id, args.job_id)
    if args.bundle_path:
        bundle_info = inspect_react_native_bundle(path, [args.bundle_path])
    else:
        bundle_info = inspect_react_native_bundle(path, archive_names)

    if bundle_info is None:
        raise NotFoundError("No React Native JavaScript or Hermes bundle was found in the APK.")

    return ToolOutcome(data=bundle_info.model_dump(mode="json"), evidence_ids=report.evidence_ids)


async def _react_native_list_modules(
    ctx: ToolContext, args: ReactNativeModulesInput
) -> ToolOutcome:
    report = ctx.runtime.analysis.get_report(args.project_id, args.job_id)
    artifact = ctx.runtime.artifacts.get_or_raise(report.project_id, report.artifact_id)
    path = ctx.runtime.artifacts.path_for(artifact)
    dex_index = decode_dex_index(
        path,
        artifact.artifact_type,
        max_bytes=ctx.runtime.settings.max_dex_bytes,
    )
    summary = list_react_native_modules(dex_index)
    return ToolOutcome(data=summary.model_dump(mode="json"), evidence_ids=report.evidence_ids)


async def _unity_list_assets(ctx: ToolContext, args: UnityListAssetsInput) -> ToolOutcome:
    report, path, archive_names = _get_job_context(ctx, args.project_id, args.job_id)
    summary = inspect_unity_assets(path, archive_names)
    data_page = summary.data_files[args.offset : args.offset + args.limit]
    return ToolOutcome(
        data={
            "data_files": data_page,
            "streaming_assets": summary.streaming_assets[: args.limit],
            "has_global_metadata": summary.has_global_metadata,
            "total_count": summary.total_count,
        },
        evidence_ids=report.evidence_ids,
    )


async def _unity_get_metadata(ctx: ToolContext, args: UnityGetMetadataInput) -> ToolOutcome:
    report, path, archive_names = _get_job_context(ctx, args.project_id, args.job_id)
    summary = get_unity_metadata(path, archive_names)
    data = summary.model_dump(mode="json")

    if args.use_engine:
        adapter = Il2CppAdapter(ctx.runtime.engine_runner, ctx.runtime.workspace)
        libil2cpp = next((n for n in archive_names if n.endswith("libil2cpp.so")), None)
        metadata = next((n for n in archive_names if "global-metadata.dat" in n), None)
        if libil2cpp and metadata:
            out_dir = ctx.runtime.workspace.tmp_dir / f"il2cpp_{args.job_id}"
            out_dir.mkdir(parents=True, exist_ok=True)
            res = adapter.dump(path, path, out_dir)
            data["engine_output"] = res

    return ToolOutcome(data=data, evidence_ids=report.evidence_ids)


async def _dotnet_list_assemblies(ctx: ToolContext, args: DotnetListAssembliesInput) -> ToolOutcome:
    report, path, archive_names = _get_job_context(ctx, args.project_id, args.job_id)
    summary = list_dotnet_assemblies(path, archive_names)
    page = summary.assemblies[args.offset : args.offset + args.limit]
    return ToolOutcome(
        data={
            "assemblies": [a.model_dump(mode="json") for a in page],
            "total_count": summary.total_count,
            "runtime": summary.runtime,
            "notes": summary.notes,
        },
        evidence_ids=report.evidence_ids,
    )


async def _dotnet_get_type(ctx: ToolContext, args: DotnetGetTypeInput) -> ToolOutcome:
    report, path, archive_names = _get_job_context(ctx, args.project_id, args.job_id)
    assembly_target = next(
        (
            name
            for name in archive_names
            if name.endswith(args.assembly_name) or name == args.assembly_name
        ),
        None,
    )
    if not assembly_target:
        raise NotFoundError(f"Assembly '{args.assembly_name}' was not found in the APK.")

    data: dict[str, Any] = {
        "assembly_name": args.assembly_name,
        "type_name": args.type_name or "",
        "source": "metadata",
        "decompiled_csharp": None,
    }

    if args.decompile:
        adapter = IlSpyAdapter(ctx.runtime.engine_runner, ctx.runtime.workspace)
        csharp = adapter.decompile_type(path, args.type_name)
        data["source"] = "ilspy"
        data["decompiled_csharp"] = csharp

    return ToolOutcome(data=data, evidence_ids=report.evidence_ids)


async def _flutter_patch_tls(ctx: ToolContext, input_data: FlutterPatchTlsInput) -> ToolOutcome:
    art = ctx.runtime.artifacts.get_or_raise(input_data.project_id, input_data.artifact_id)
    src_path = ctx.runtime.artifacts.path_for(art)
    dst_dir = ctx.runtime.workspace.root / "rebuild" / input_data.project_id
    dst_path = dst_dir / f"reflutter_{input_data.artifact_id}.apk"
    res = patch_flutter_tls(
        apk_path=src_path,
        output_apk_path=dst_path,
        proxy_host=input_data.proxy_host,
        proxy_port=input_data.proxy_port,
    )
    if dst_path.is_file():
        ingest_res = ctx.runtime.artifacts.ingest_path(
            project_id=input_data.project_id, raw_path=str(dst_path)
        )
        res["patched_artifact_id"] = ingest_res.artifact.id
    return ToolOutcome(data=res)


async def _flutter_dump_strings(
    ctx: ToolContext, input_data: FlutterDumpStringsInput
) -> ToolOutcome:
    art = ctx.runtime.artifacts.get_or_raise(input_data.project_id, input_data.artifact_id)
    src_path = ctx.runtime.artifacts.path_for(art)
    res = dump_flutter_strings(src_path)
    return ToolOutcome(data=res)


async def _unity_dump_metadata(ctx: ToolContext, input_data: UnityDumpMetadataInput) -> ToolOutcome:
    art = ctx.runtime.artifacts.get_or_raise(input_data.project_id, input_data.artifact_id)
    src_path = ctx.runtime.artifacts.path_for(art)
    out_dir = ctx.runtime.workspace.root / "unity" / input_data.project_id
    res = dump_il2cpp_metadata(apk_path=src_path, output_dir=out_dir)
    return ToolOutcome(data=res)


async def _flutter_dart_snapshot_inspect(
    ctx: ToolContext, args: FlutterDartSnapshotInput
) -> ToolOutcome:
    res = inspect_dart_snapshot(
        snapshot_bytes_or_path=args.snapshot_path,
        architecture=args.architecture,
    )
    return ToolOutcome(data=res)


async def _flutter_ssl_pinning_bypass_gen(
    ctx: ToolContext, args: FlutterSslBypassInput
) -> ToolOutcome:
    res = generate_flutter_ssl_bypass(
        architecture=args.architecture,
        libflutter_path=args.libflutter_path,
    )
    return ToolOutcome(data=res)


async def _flutter_engine_proxy_patch(
    ctx: ToolContext, args: FlutterEngineProxyInput
) -> ToolOutcome:
    res = patch_flutter_engine_proxy(
        libflutter_path=args.libflutter_path,
        proxy_host=args.proxy_host,
        proxy_port=args.proxy_port,
        output_path=args.output_path,
    )
    return ToolOutcome(data=res)


async def _rn_hermes_bundle_extract(
    ctx: ToolContext, args: HermesBundleExtractInput
) -> ToolOutcome:
    res = extract_hermes_bundle(apk_or_bundle_path=args.bundle_path)
    return ToolOutcome(data=res)


async def _rn_hermes_decompile(ctx: ToolContext, args: HermesDecompileInput) -> ToolOutcome:
    res = decompile_hermes_bytecode(
        bundle_bytes_or_hex=args.bundle_path,
        extract_secrets=args.extract_secrets,
    )
    return ToolOutcome(data=res)


async def _skip_swift_framework_inspect(
    ctx: ToolContext, args: SkipSwiftFrameworkInspectInput
) -> ToolOutcome:
    from raa.services.framework_adapters.skip_swift import inspect_skip_swift_framework

    res = inspect_skip_swift_framework(
        apk_path=args.apk_path,
        project_id=args.project_id,
        deobfuscate_models=args.deobfuscate_models,
    )
    return ToolOutcome(data=res)


def _framework_spec(
    *,
    name: str,
    title: str,
    description: str,
    handler: Any,
    input_model: type[BaseModel],
    scopes: frozenset[str] = frozenset({"project.read", "static.read"}),
    profiles: frozenset[str] = CORE,
    read_only: bool = True,
    idempotent: bool = True,
) -> ToolSpec:
    return ToolSpec(
        name=name,
        title=title,
        description=description,
        input_model=input_model,
        handler=handler,
        family="framework",
        profiles=profiles,
        scopes=scopes,
        annotations=ToolAnnotations(read_only=read_only, idempotent=idempotent),
        cost="fast",
    )


def register(registry: CapabilityRegistry) -> None:
    registry.register(
        _framework_spec(
            name="framework_get_capabilities",
            title="Get framework capabilities",
            description=(
                "Return supported operations, recovery modes, and limits for supported frameworks."
            ),
            handler=_framework_get_capabilities,
            input_model=FrameworkCapabilitiesInput,
            scopes=frozenset(),
        )
    )
    registry.register(
        _framework_spec(
            name="flutter_list_assets",
            title="List Flutter assets",
            description=(
                "List assets declared in flutter_assets, font manifests, and asset mappings."
            ),
            handler=_flutter_list_assets,
            input_model=FlutterListAssetsInput,
        )
    )
    registry.register(
        _framework_spec(
            name="flutter_get_symbols",
            title="Get Flutter Dart symbols",
            description=(
                "Extract Dart snapshot metadata, symbols, and engine version from "
                "libflutter/libapp."
            ),
            handler=_flutter_get_symbols,
            input_model=FlutterGetSymbolsInput,
        )
    )
    registry.register(
        _framework_spec(
            name="react_native_inspect_bundle",
            title="Inspect React Native bundle",
            description=(
                "Inspect React Native bundle for Hermes bytecode header, format "
                "version, and minification."
            ),
            handler=_react_native_inspect_bundle,
            input_model=ReactNativeBundleInput,
        )
    )
    registry.register(
        _framework_spec(
            name="react_native_list_modules",
            title="List React Native modules",
            description=(
                "List React Native NativeModules, TurboModules, and ReactPackages found in DEX."
            ),
            handler=_react_native_list_modules,
            input_model=ReactNativeModulesInput,
        )
    )
    registry.register(
        _framework_spec(
            name="unity_list_assets",
            title="List Unity assets",
            description="List Unity data files, scenes, streaming assets, and metadata files.",
            handler=_unity_list_assets,
            input_model=UnityListAssetsInput,
        )
    )
    registry.register(
        _framework_spec(
            name="unity_get_metadata",
            title="Get Unity IL2CPP metadata",
            description=(
                "Inspect Unity global-metadata.dat header, version, and type definition counts."
            ),
            handler=_unity_get_metadata,
            input_model=UnityGetMetadataInput,
        )
    )
    registry.register(
        _framework_spec(
            name="dotnet_list_assemblies",
            title="List .NET assemblies",
            description="List managed .NET assemblies (DLLs) in Xamarin or .NET MAUI applications.",
            handler=_dotnet_list_assemblies,
            input_model=DotnetListAssembliesInput,
        )
    )
    registry.register(
        _framework_spec(
            name="dotnet_get_type",
            title="Get .NET managed type",
            description="Inspect or decompile a managed .NET type from assemblies using ILSpy.",
            handler=_dotnet_get_type,
            input_model=DotnetGetTypeInput,
        )
    )
    registry.register(
        _framework_spec(
            name="flutter_patch_tls",
            title="Patch Flutter TLS for proxy interception",
            description="Patch libflutter.so inside APK to redirect Dart traffic to proxy.",
            handler=_flutter_patch_tls,
            input_model=FlutterPatchTlsInput,
            scopes=frozenset({ANDROID_PATCH, PROJECT_WRITE}),
        )
    )
    registry.register(
        _framework_spec(
            name="flutter_dump_strings",
            title="Dump Flutter Dart strings and symbols",
            description="Extract embedded Dart strings, classes, and URLs from libapp.so.",
            handler=_flutter_dump_strings,
            input_model=FlutterDumpStringsInput,
            scopes=frozenset({PROJECT_READ, STATIC_READ}),
        )
    )
    registry.register(
        _framework_spec(
            name="unity_dump_metadata",
            title="Dump Unity IL2CPP C# metadata",
            description="Recover C# classes, methods, and string pool using Il2CppDumper pattern.",
            handler=_unity_dump_metadata,
            input_model=UnityDumpMetadataInput,
            scopes=frozenset({PROJECT_READ, STATIC_READ}),
        )
    )
    registry.register(
        _framework_spec(
            name="flutter_dart_snapshot_inspect",
            title="Inspect Flutter Dart AOT snapshot",
            description=(
                "Parse Dart AOT snapshot headers, extract isolate strings, and dump class "
                "hierarchies."
            ),
            handler=_flutter_dart_snapshot_inspect,
            input_model=FlutterDartSnapshotInput,
            profiles=frozenset({"core", "dynamic", "full"}),
            scopes=frozenset(),
        )
    )
    registry.register(
        _framework_spec(
            name="flutter_ssl_pinning_bypass_gen",
            title="Generate Flutter BoringSSL pinning bypass",
            description=(
                "Synthesize targeted Frida hooks and patch bytes for Flutter BoringSSL "
                "certificate verification."
            ),
            handler=_flutter_ssl_pinning_bypass_gen,
            input_model=FlutterSslBypassInput,
            profiles=frozenset({"core", "dynamic", "full"}),
            scopes=frozenset(),
        )
    )
    registry.register(
        _framework_spec(
            name="flutter_engine_proxy_patch",
            title="Patch Flutter engine for proxy routing",
            description=(
                "Patch libflutter.so ELF binary directly to reroute all Dart HTTP/HTTPS "
                "traffic to a proxy."
            ),
            handler=_flutter_engine_proxy_patch,
            input_model=FlutterEngineProxyInput,
            profiles=frozenset({"core", "dynamic", "full"}),
            scopes=frozenset(),
            read_only=False,
            idempotent=False,
        )
    )
    registry.register(
        _framework_spec(
            name="rn_hermes_bundle_extract",
            title="Extract and inspect Hermes bytecode bundle",
            description=(
                "Scan APK assets for React Native Hermes bytecode bundle and extract format "
                "version and counts."
            ),
            handler=_rn_hermes_bundle_extract,
            input_model=HermesBundleExtractInput,
            profiles=frozenset({"core", "full"}),
            scopes=frozenset(),
        )
    )
    registry.register(
        _framework_spec(
            name="rn_hermes_decompile",
            title="Decompile Hermes bytecode to JavaScript AST",
            description=(
                "Disassemble Hermes bytecode into JavaScript AST and scan for secrets, "
                "endpoints, and credentials."
            ),
            handler=_rn_hermes_decompile,
            input_model=HermesDecompileInput,
            profiles=frozenset({"core", "full"}),
            scopes=frozenset(),
        )
    )
    registry.register(
        _framework_spec(
            name="skip_swift_framework_inspect",
            title="Skip Swift Transpiler & SwiftUI Model Reconstructor",
            description=(
                "Detect Skip Swift-to-Android transpiled dual-runtime signatures and reconstruct "
                "original Swift models, SwiftUI state machines, and native bridge endpoints."
            ),
            handler=_skip_swift_framework_inspect,
            input_model=SkipSwiftFrameworkInspectInput,
            profiles=frozenset({"core", "full"}),
            scopes=frozenset(),
        )
    )
