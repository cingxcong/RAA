"""External engine runner, adapter and source-retrieval tests."""

from __future__ import annotations

import os
import sys
import textwrap
from pathlib import Path

import pytest

from raa.config import Settings
from raa.errors import (
    EngineExecutionError,
    EngineTimeoutError,
    EngineUnavailableError,
    NotFoundError,
)
from raa.runtime import Runtime
from raa.services.engine_adapters import (
    AndroguardAdapter,
    ApkidAdapter,
    ApktoolAdapter,
    JadxAdapter,
)
from raa.services.engine_runner import EngineRunner
from raa.services.engines import EngineSpec

_RUNNER_BODY = """
import os
import pathlib
import sys
import time

mode = sys.argv[1]
if mode == "echo":
    print("hello")
    print("warn", file=sys.stderr)
elif mode == "fail":
    print("bad")
    raise SystemExit(3)
elif mode == "sleep":
    time.sleep(10)
elif mode == "big":
    sys.stdout.write("x" * 2048)
    sys.stderr.write("y" * 2048)
elif mode == "env":
    print("secret" if os.environ.get("RAA_API_TOKEN") else "clean")
elif mode == "write":
    target = pathlib.Path(sys.argv[2])
    target.mkdir(parents=True, exist_ok=True)
    (target / "out.txt").write_text("ok", encoding="utf-8")
"""

_APKTOOL_BODY = """
import pathlib
import sys

args = sys.argv[1:]
output = pathlib.Path(args[args.index("-o") + 1])
target = output / "smali" / "com" / "example" / "demo" / "MainActivity.smali"
target.parent.mkdir(parents=True, exist_ok=True)
target.write_text(
    ".class public Lcom/example/demo/MainActivity;\\n"
    ".method public onCreate()V\\n"
    "    return-void\\n"
    ".end method\\n",
    encoding="utf-8",
)
"""

_APKTOOL_FAIL_BODY = """
import sys

print("decode failed", file=sys.stderr)
raise SystemExit(3)
"""

_JADX_BODY = """
import pathlib
import sys

args = sys.argv[1:]
output = pathlib.Path(args[args.index("-d") + 1])
target = output / "sources" / "com" / "example" / "demo" / "MainActivity.java"
target.parent.mkdir(parents=True, exist_ok=True)
target.write_text(
    "public class MainActivity {\\n"
    "    public void onCreate() {\\n"
    "    }\\n"
    "}\\n",
    encoding="utf-8",
)
"""

_ANDROGUARD_BODY = """
import sys
args = sys.argv[1:]
if "axml" in args:
    print('<?xml version="1.0" encoding="utf-8"?><manifest package="com.example.demo"/>')
elif "sign" in args:
    print(
        "Signer 1: CN=Android Debug, O=Android, C=US\\n"
        "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
else:
    print("androguard mock output")
"""

_APKID_BODY = """
import json
import sys
output = {
    sys.argv[-1]: {
        "anti_analysis": [],
        "compiler": ["dexlib 2.x"],
        "obfuscator": ["ProGuard"],
        "packer": [],
        "protector": ["Bangcle"]
    }
}
print(json.dumps(output))
"""

_RUNNER_SPEC = EngineSpec(
    id="runner-test",
    name="Runner test",
    tier=3,
    license="MIT",
    integration="native",
    capabilities=("test",),
    commands=("runner-test",),
)


class FakeEngineEnvironment:
    def __init__(self, settings: Settings, bin_dir: Path, scripts_dir: Path) -> None:
        self.settings = settings
        self.bin_dir = bin_dir
        self.scripts_dir = scripts_dir

    def install(self, name: str, body: str) -> Path:
        script = self.scripts_dir / f"{name}.py"
        script.write_text(textwrap.dedent(body), encoding="utf-8")
        if sys.platform == "win32":
            launcher = self.bin_dir / f"{name}.bat"
            launcher.write_text(
                f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n',
                encoding="utf-8",
            )
        else:
            launcher = self.bin_dir / name
            launcher.write_text(
                f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n',
                encoding="utf-8",
            )
            launcher.chmod(0o755)
        return launcher


@pytest.fixture
def engine_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeEngineEnvironment:
    bin_dir = tmp_path / "bin"
    scripts_dir = tmp_path / "scripts"
    bin_dir.mkdir()
    scripts_dir.mkdir()
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    settings = Settings(
        workspace=tmp_path / "workspace",
        profile="core",
        allowed_input_roots=[tmp_path],
        analysis_timeout_seconds=15,
        engine_execution_enabled=True,
        engine_timeout_seconds=2.0,
        engine_max_output_bytes=1024,
        engine_max_file_bytes=1024,
    )
    return FakeEngineEnvironment(settings, bin_dir, scripts_dir)


@pytest.fixture
def engine_runtime(engine_env: FakeEngineEnvironment) -> Runtime:
    engine_env.install("apktool", _APKTOOL_BODY)
    engine_env.install("jadx", _JADX_BODY)
    engine_env.install("androguard", _ANDROGUARD_BODY)
    engine_env.install("apkid", _APKID_BODY)
    runtime = Runtime(engine_env.settings)
    try:
        yield runtime
    finally:
        runtime.analysis.shutdown()


def _runner(engine_env: FakeEngineEnvironment) -> EngineRunner:
    runtime = Runtime(engine_env.settings)
    try:
        return runtime.engine_runner
    finally:
        runtime.analysis.shutdown()


def test_runner_is_disabled_by_default(tmp_path: Path) -> None:
    settings = Settings(
        workspace=tmp_path / "workspace",
        engine_execution_enabled=False,
    )
    runtime = Runtime(settings)
    try:
        with pytest.raises(EngineUnavailableError):
            runtime.engine_runner.run(
                _RUNNER_SPEC,
                ["echo"],
                operation="test",
            )
    finally:
        runtime.analysis.shutdown()


def test_runner_reports_missing_engine(engine_env: FakeEngineEnvironment) -> None:
    runner = _runner(engine_env)
    with pytest.raises(EngineUnavailableError):
        runner.run(_RUNNER_SPEC, ["echo"], operation="test")


def test_runner_success_and_environment_boundary(engine_env: FakeEngineEnvironment) -> None:
    engine_env.install("runner-test", _RUNNER_BODY)
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setenv("RAA_API_TOKEN", "top-secret")
    try:
        runner = _runner(engine_env)
        result = runner.run(_RUNNER_SPEC, ["echo"], operation="test")
        assert result.exit_code == 0
        assert result.stdout.strip() == "hello"
        assert result.stderr.strip() == "warn"
        assert result.truncated is False

        environment = runner.run(_RUNNER_SPEC, ["env"], operation="test")
        assert environment.stdout.strip() == "clean"
        assert "RAA_API_TOKEN" not in environment.command
    finally:
        monkeypatch.undo()


def test_runner_failure_timeout_and_output_limit(
    engine_env: FakeEngineEnvironment,
) -> None:
    engine_env.install("runner-test", _RUNNER_BODY)
    runner = _runner(engine_env)

    failed = runner.run(_RUNNER_SPEC, ["fail"], operation="test")
    assert failed.exit_code == 3
    assert "bad" in failed.stdout

    with pytest.raises(EngineTimeoutError):
        runner.run(_RUNNER_SPEC, ["sleep"], operation="test", timeout=0.2)

    bounded = runner.run(
        _RUNNER_SPEC,
        ["big"],
        operation="test",
        max_output_bytes=256,
    )
    assert bounded.exit_code == 0
    assert bounded.truncated is True
    assert len(bounded.stdout) == 256
    assert len(bounded.stderr) == 256


def test_apktool_adapter_returns_bounded_smali(engine_runtime: Runtime, apk_path: Path) -> None:
    adapter = ApktoolAdapter(engine_runtime.engine_runner, engine_runtime.workspace)
    payload = adapter.decode_smali(
        apk_path,
        "com.example.demo.MainActivity",
        offset=0,
        limit=60,
        max_bytes=1024,
    )
    assert payload["engine_id"] == "apktool"
    assert payload["dex_file"] == "classes.dex"
    assert ".method" in str(payload["text"])
    assert payload["truncated"] is True
    assert int(payload["byte_count"]) > 60


def test_apktool_adapter_reports_missing_class(engine_runtime: Runtime, apk_path: Path) -> None:
    adapter = ApktoolAdapter(engine_runtime.engine_runner, engine_runtime.workspace)
    with pytest.raises(NotFoundError):
        adapter.decode_smali(apk_path, "com.example.demo.Missing")


def test_apktool_adapter_surfaces_engine_failure(
    engine_runtime: Runtime,
    engine_env: FakeEngineEnvironment,
    apk_path: Path,
) -> None:
    engine_env.install("apktool", _APKTOOL_FAIL_BODY)
    adapter = ApktoolAdapter(engine_runtime.engine_runner, engine_runtime.workspace)
    with pytest.raises(EngineExecutionError):
        adapter.decode_smali(apk_path, "com.example.demo.MainActivity")


def test_jadx_adapter_returns_bounded_java(engine_runtime: Runtime, apk_path: Path) -> None:
    adapter = JadxAdapter(engine_runtime.engine_runner, engine_runtime.workspace)
    payload = adapter.decompile_class(
        apk_path,
        "Lcom/example/demo/MainActivity;",
        offset=0,
        limit=30,
        max_bytes=1024,
    )
    assert payload["engine_id"] == "jadx"
    assert "public class MainActivity" in str(payload["text"])
    assert payload["truncated"] is True


async def _project_and_artifact(runtime: Runtime, path: Path) -> tuple[str, str]:
    project = await runtime.invoke("project_create", {"name": "Engine adapters"})
    ingested = await runtime.invoke(
        "artifact_ingest",
        {"project_id": project.data["id"], "path": str(path)},
    )
    return project.data["id"], ingested.data["id"]


async def _run_analysis(runtime: Runtime, project_id: str, artifact_id: str) -> str:
    started = await runtime.invoke(
        "analysis_start",
        {"project_id": project_id, "artifact_id": artifact_id},
    )
    job = await runtime.analysis.wait(project_id, started.data["id"])
    assert job.status.value == "completed"
    return job.id


async def test_source_get_method_includes_references(
    engine_runtime: Runtime, apk_path: Path
) -> None:
    project_id, artifact_id = await _project_and_artifact(engine_runtime, apk_path)
    job_id = await _run_analysis(engine_runtime, project_id, artifact_id)
    base = {"project_id": project_id, "job_id": job_id}

    method = await engine_runtime.invoke(
        "source_get_method",
        {
            **base,
            "class_name": "com.example.demo.MainActivity",
            "method_name": "helper",
        },
    )
    assert method.data["class"] == "com.example.demo.MainActivity"
    assert method.data["method_descriptors"] == ["(ILjava/lang/String;)Ljava/lang/String;"]
    assert method.data["outgoing_count"] == 2
    assert method.data["incoming_count"] == 1
    assert method.data["source"] is None


async def test_source_get_method_with_jadx_source(engine_runtime: Runtime, apk_path: Path) -> None:
    project_id, artifact_id = await _project_and_artifact(engine_runtime, apk_path)
    job_id = await _run_analysis(engine_runtime, project_id, artifact_id)
    result = await engine_runtime.invoke(
        "source_get_method",
        {
            "project_id": project_id,
            "job_id": job_id,
            "class_name": "com.example.demo.MainActivity",
            "method_name": "onCreate",
            "include_source": True,
            "source_limit": 40,
        },
    )
    assert result.data["include_source"] is True
    source = result.data["source"]
    assert source["engine_id"] == "jadx"
    assert "onCreate" in source["text"]
    assert source["method_isolated"] is True


async def test_source_get_class_with_jadx_source(engine_runtime: Runtime, apk_path: Path) -> None:
    project_id, artifact_id = await _project_and_artifact(engine_runtime, apk_path)
    job_id = await _run_analysis(engine_runtime, project_id, artifact_id)
    result = await engine_runtime.invoke(
        "source_get_class",
        {
            "project_id": project_id,
            "job_id": job_id,
            "class_name": "com.example.demo.MainActivity",
            "include_source": True,
            "source_limit": 50,
        },
    )
    assert result.data["include_source"] is True
    source = result.data["source"]
    assert source["engine_id"] == "jadx"
    assert "public class MainActivity" in source["text"]


def test_androguard_adapter(engine_runtime: Runtime, apk_path: Path) -> None:
    adapter = AndroguardAdapter(engine_runtime.engine_runner, engine_runtime.workspace)
    manifest = adapter.analyze_manifest(apk_path)
    assert manifest["engine_id"] == "androguard"
    assert "package=" in str(manifest["xml_preview"])

    certs = adapter.analyze_certificates(apk_path)
    assert certs["engine_id"] == "androguard"
    assert "Signer 1" in str(certs["output"])


def test_apkid_adapter(engine_runtime: Runtime, apk_path: Path) -> None:
    adapter = ApkidAdapter(engine_runtime.engine_runner, engine_runtime.workspace)
    scan = adapter.scan(apk_path)
    assert scan["engine_id"] == "apkid"
    assert "Bangcle" in scan["protectors"]
    assert "ProGuard" in scan["obfuscators"]
    assert "dexlib 2.x" in scan["compilers"]
    assert scan["total_detections"] == 2


async def test_packer_detect_with_apkid(engine_runtime: Runtime, apk_path: Path) -> None:
    project_id, artifact_id = await _project_and_artifact(engine_runtime, apk_path)
    job_id = await _run_analysis(engine_runtime, project_id, artifact_id)
    result = await engine_runtime.invoke(
        "packer_detect",
        {
            "project_id": project_id,
            "job_id": job_id,
            "include_apkid": True,
        },
    )
    assert "apkid" in result.data
    apkid = result.data["apkid"]
    assert "Bangcle" in apkid["protectors"]


async def test_source_get_smali_requires_engine(runtime: Runtime, apk_path: Path) -> None:
    project_id, artifact_id = await _project_and_artifact(runtime, apk_path)
    job_id = await _run_analysis(runtime, project_id, artifact_id)
    with pytest.raises(EngineUnavailableError):
        await runtime.invoke(
            "source_get_smali",
            {
                "project_id": project_id,
                "job_id": job_id,
                "class_name": "com.example.demo.MainActivity",
            },
        )


async def test_source_get_smali_returns_engine_output(
    engine_runtime: Runtime, apk_path: Path
) -> None:
    project_id, artifact_id = await _project_and_artifact(engine_runtime, apk_path)
    job_id = await _run_analysis(engine_runtime, project_id, artifact_id)
    result = await engine_runtime.invoke(
        "source_get_smali",
        {
            "project_id": project_id,
            "job_id": job_id,
            "class_name": "com.example.demo.MainActivity",
            "limit": 60,
        },
    )
    assert result.data["engine_id"] == "apktool"
    assert ".method" in result.data["text"]
    assert result.data["dex_file"] == "classes.dex"
