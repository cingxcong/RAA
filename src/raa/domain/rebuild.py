"""Domain models for test generation, controlled rebuild, APK patching, and verification."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


class TestFramework(StrEnum):
    PYTEST = "pytest"
    APPIUM = "appium"
    ESPRESSO = "espresso"
    PLAYWRIGHT = "playwright"


class PatchOperation(StrEnum):
    NETWORK_SECURITY_BYPASS = "network_security_bypass"
    SET_DEBUGGABLE = "set_debuggable"
    SET_ALLOW_BACKUP = "set_allow_backup"
    INJECT_FRIDA_GADGET = "inject_frida_gadget"
    CUSTOM_SMALI = "custom_smali"
    PATCH_DEX_STRINGS = "patch_dex_strings"
    PATCH_RESOURCE_STRINGS = "patch_resource_strings"


class TestGenerationReport(BaseModel):
    """Artifact containing generated test scripts derived from observed evidence."""

    test_id: str = Field(description="Unique generated test identifier.")
    project_id: str = Field(description="Target project identifier.")
    artifact_id: str = Field(description="Associated target artifact identifier.")
    framework: TestFramework = Field(description="Target testing framework.")
    test_type: Literal["ui", "api", "integration"] = Field(
        description="Classification of test suite."
    )
    code: str = Field(description="Complete executable source code for the test.")
    entrypoints: list[str] = Field(
        default_factory=list, description="Targeted endpoints or activities."
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class TestExecutionReport(BaseModel):
    """Outcome of running test suites against a target device or mock environment."""

    run_id: str = Field(description="Unique test execution run identifier.")
    test_id: str = Field(description="Executed test suite identifier.")
    status: Literal["passed", "failed", "error"] = Field(description="Overall execution status.")
    total_tests: int = Field(default=0, description="Total number of test cases executed.")
    passed_tests: int = Field(default=0, description="Count of passed test cases.")
    failed_tests: int = Field(default=0, description="Count of failed test cases.")
    duration_ms: float = Field(default=0.0, description="Execution duration in milliseconds.")
    logs: list[str] = Field(default_factory=list, description="Console or logcat outputs captured.")
    executed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class PatchPlan(BaseModel):
    """Specification of an APK modification or rebuild instruction."""

    patch_id: str = Field(description="Unique patch plan identifier.")
    operation: PatchOperation = Field(description="Type of patch operation.")
    target_component: str = Field(description="File or manifest element being modified.")
    parameters: dict[str, Any] = Field(
        default_factory=dict, description="Patch-specific parameters."
    )
    dry_run: bool = Field(
        default=True, description="Whether this plan is simulated without disk writes."
    )
    changes: list[str] = Field(
        default_factory=list, description="Human-readable description of planned edits."
    )


class PatchResult(BaseModel):
    """Outcome of applying a patch plan to an APK container."""

    patch_id: str = Field(description="Executed patch plan identifier.")
    project_id: str = Field(description="Project identifier.")
    base_artifact_id: str = Field(description="Original base artifact identifier.")
    patched_artifact_id: str | None = Field(
        default=None, description="Resulting patched artifact ID."
    )
    success: bool = Field(description="Whether the patch succeeded.")
    dry_run: bool = Field(description="Whether operation was simulated.")
    output_path: str | None = Field(default=None, description="Path to patched APK if written.")
    details: dict[str, Any] = Field(
        default_factory=dict, description="Execution summary or diff details."
    )
    applied_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SignResult(BaseModel):
    """Outcome of signing an APK container with test or custom certificates."""

    project_id: str = Field(description="Project identifier.")
    artifact_id: str = Field(description="Artifact identifier.")
    signed_artifact_id: str = Field(description="Signed artifact identifier.")
    certificate_fingerprint: str = Field(description="SHA-256 fingerprint of the certificate.")
    signature_schemes: list[str] = Field(
        default_factory=lambda: ["v1", "v2"], description="APK signature schemes."
    )
    signed_apk_path: str = Field(description="Absolute path to the signed APK file.")
    signed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class BehaviorVerificationReport(BaseModel):
    """Comparative analysis of application behavior before and after rebuild."""

    verification_id: str = Field(description="Unique verification run identifier.")
    project_id: str = Field(description="Project identifier.")
    base_artifact_id: str = Field(description="Original baseline artifact ID.")
    patched_artifact_id: str = Field(description="Patched comparison artifact ID.")
    divergence_detected: bool = Field(description="Whether behavioral divergence was observed.")
    divergent_behaviors: list[str] = Field(
        default_factory=list, description="Specific behavior changes observed."
    )
    evidence_ids: list[str] = Field(default_factory=list, description="Linked evidence records.")
    verified_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
