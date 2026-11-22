"""Bounded, fail-closed execution of catalogued external engines.

Engines are never discovered from arbitrary user paths. A catalogued engine may
run only when execution is enabled globally, its command resolves through the
process ``PATH``, and its working directory and output directory stay inside
the RAA workspace. The runner never uses a shell and never forwards secrets.
"""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from raa.config import Settings
from raa.errors import (
    EngineTimeoutError,
    EngineUnavailableError,
    NotFoundError,
)
from raa.services.engines import ENGINE_CATALOGUE, EngineSpec
from raa.services.workspace import Workspace


@dataclass(frozen=True, slots=True)
class EngineRunResult:
    """Normalized result of one external engine invocation."""

    engine_id: str
    operation: str
    command: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    truncated: bool
    output_dir: str
    file_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "engine_id": self.engine_id,
            "operation": self.operation,
            "command": list(self.command),
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_ms": self.duration_ms,
            "truncated": self.truncated,
            "output_dir": self.output_dir,
            "file_count": self.file_count,
        }


class EngineRunner:
    """Resolve and run catalogued engines with workspace and output bounds."""

    def __init__(self, settings: Settings, workspace: Workspace) -> None:
        self._settings = settings
        self._workspace = workspace

    @property
    def execution_enabled(self) -> bool:
        return self._settings.engine_execution_enabled

    def spec(self, engine_id: str) -> EngineSpec:
        for spec in ENGINE_CATALOGUE:
            if spec.id == engine_id:
                return spec
        raise NotFoundError(
            f"Unknown engine: {engine_id}",
            hint="Call admin_engine_list to discover catalogued engine identifiers.",
            details={"engine_id": engine_id},
        )

    def resolve(self, spec: EngineSpec) -> str:
        if not spec.commands:
            raise EngineUnavailableError(
                f"Engine '{spec.id}' has no executable command in the catalogue.",
                hint="Library and service engines require a dedicated adapter.",
                details={"engine_id": spec.id},
            )
        command = spec.commands[0]
        resolved = shutil.which(command)
        if resolved is None:
            raise EngineUnavailableError(
                f"Engine '{spec.id}' is not available on PATH.",
                hint=spec.install_hint or f"Install '{command}' or disable the engine.",
                details={"engine_id": spec.id, "command": command},
            )
        return resolved

    def create_output_dir(self, engine_id: str) -> Path:
        safe_id = "".join(
            char if char.isalnum() or char in {"-", "_"} else "_" for char in engine_id
        )
        directory = self._workspace.tmp_dir / "engines" / safe_id / secrets.token_hex(8)
        directory.mkdir(parents=True, exist_ok=False)
        self._workspace.ensure_within(directory, self._workspace.root)
        return directory

    def run(
        self,
        spec: EngineSpec,
        arguments: Sequence[str],
        *,
        operation: str,
        timeout: float | None = None,
        max_output_bytes: int | None = None,
        cwd: Path | None = None,
    ) -> EngineRunResult:
        if not self._settings.engine_execution_enabled:
            raise EngineUnavailableError(
                "External engine execution is disabled.",
                hint=(
                    "Set RAA_ENGINE_EXECUTION_ENABLED=true only after reviewing "
                    "the engine licence, input provenance and workspace policy."
                ),
                details={"engine_id": spec.id, "operation": operation},
            )

        executable = self.resolve(spec)
        effective_timeout = timeout or self._settings.engine_timeout_seconds
        effective_max = max_output_bytes or self._settings.engine_max_output_bytes
        working_dir = cwd or self._workspace.tmp_dir
        self._workspace.ensure_within(working_dir, self._workspace.root)
        output_dir = self.create_output_dir(spec.id)
        command = (executable, *(str(argument) for argument in arguments))
        environment = _safe_environment()
        started = time.perf_counter()

        try:
            with (
                tempfile.TemporaryFile() as stdout_file,
                tempfile.TemporaryFile() as stderr_file,
            ):
                process = subprocess.Popen(
                    command,
                    cwd=str(working_dir),
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    env=environment,
                    shell=False,
                )
                try:
                    exit_code = process.wait(timeout=effective_timeout)
                except subprocess.TimeoutExpired as exc:
                    process.kill()
                    process.wait()
                    raise EngineTimeoutError(
                        f"Engine '{spec.id}' timed out after {effective_timeout:g}s.",
                        hint="Increase RAA_ENGINE_TIMEOUT_SECONDS or narrow the engine operation.",
                        details={
                            "engine_id": spec.id,
                            "operation": operation,
                            "timeout_seconds": effective_timeout,
                        },
                    ) from exc

                stdout_file.seek(0)
                stderr_file.seek(0)
                raw_stdout = stdout_file.read(effective_max + 1)
                raw_stderr = stderr_file.read(effective_max + 1)
        except OSError as exc:
            shutil.rmtree(output_dir, ignore_errors=True)
            raise EngineUnavailableError(
                f"Engine '{spec.id}' could not be started: {exc}",
                hint="Verify the executable permissions and runtime dependencies.",
                details={"engine_id": spec.id, "operation": operation},
            ) from exc

        duration_ms = int((time.perf_counter() - started) * 1000)
        stdout = _decode_bounded(raw_stdout, effective_max)
        stderr = _decode_bounded(raw_stderr, effective_max)
        files = [path for path in output_dir.rglob("*") if path.is_file()]
        return EngineRunResult(
            engine_id=spec.id,
            operation=operation,
            command=command,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
            truncated=len(raw_stdout) > effective_max or len(raw_stderr) > effective_max,
            output_dir=str(output_dir),
            file_count=len(files),
        )


def _decode_bounded(raw: bytes, limit: int) -> str:
    return raw[:limit].decode("utf-8", errors="replace")


def _safe_environment() -> dict[str, str]:
    """Forward only the environment an external engine needs to start.

    Secrets, tokens and RAA settings are deliberately not forwarded.
    """

    allowed = (
        "PATH",
        "Path",
        "SystemRoot",
        "TEMP",
        "TMP",
        "HOME",
        "USERPROFILE",
        "JAVA_HOME",
        "LANG",
        "LC_ALL",
        "PATHEXT",
        "COMSPEC",
    )
    environment: dict[str, str] = {}
    for key in allowed:
        value = os.environ.get(key)
        if value:
            environment[key] = value
    return environment
