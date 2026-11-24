"""Safe, extract-free inspection of Android ZIP containers."""

from __future__ import annotations

import zipfile
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath
from typing import Any

from raa.domain.models import (
    DexFile,
    FrameworkFinding,
    NativeLibrary,
    PackerFinding,
    SignatureInfo,
)
from raa.errors import InvalidArtifactError, LimitExceededError
from raa.services.frameworks import detect_frameworks, detect_packers

SIGNING_BLOCK_MAGIC = b"APK Sig Block 42"
_LIB_PREFIX = "lib/"


@dataclass(frozen=True, slots=True)
class InspectionFinding:
    id: str
    severity: str
    category: str
    title: str
    detail: str
    evidence_key: str


@dataclass(slots=True)
class InspectionResult:
    names: list[str] = field(default_factory=list)
    dex_files: list[DexFile] = field(default_factory=list)
    native_libraries: list[NativeLibrary] = field(default_factory=list)
    abis: list[str] = field(default_factory=list)
    asset_count: int = 0
    encrypted_entries: int = 0
    total_entries: int = 0
    total_uncompressed_bytes: int = 0
    signature: SignatureInfo | None = None
    frameworks: list[FrameworkFinding] = field(default_factory=list)
    packers: list[PackerFinding] = field(default_factory=list)
    findings: list[InspectionFinding] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


def inspect_archive(
    path: Path,
    artifact_type: str,
    *,
    max_entries: int,
    max_uncompressed_bytes: int,
) -> InspectionResult:
    """Inspect central-directory metadata without extracting or executing."""

    if not zipfile.is_zipfile(path):
        raise InvalidArtifactError(
            "Artifact is not a readable ZIP-based Android container.",
            hint="APK, AAB, APKS and XAPK files must be intact ZIP archives.",
        )

    result = InspectionResult()
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > max_entries:
                raise LimitExceededError(
                    "Archive contains too many entries.",
                    hint="Raise RAA_MAX_ARCHIVE_ENTRIES for trusted large packages.",
                    details={"entries": len(infos), "max_entries": max_entries},
                )
            result.total_entries = len(infos)
            seen_native: set[tuple[str, str]] = set()
            for info in infos:
                name = _normalize_name(info.filename)
                _validate_member_name(name)
                if _is_symlink(info):
                    raise InvalidArtifactError(
                        "Archive contains a symbolic link entry.",
                        details={"entry": name},
                    )
                if info.flag_bits & 0x1:
                    result.encrypted_entries += 1
                if info.is_dir():
                    continue

                result.names.append(name)
                result.total_uncompressed_bytes += info.file_size
                if result.total_uncompressed_bytes > max_uncompressed_bytes:
                    raise LimitExceededError(
                        "Archive expands beyond the configured limit.",
                        details={
                            "max_uncompressed_bytes": max_uncompressed_bytes,
                        },
                    )

                base = name.rsplit("/", 1)[-1]
                if fnmatchcase(base, "classes*.dex"):
                    result.dex_files.append(DexFile(name=name, size_bytes=info.file_size))

                if name.startswith(_LIB_PREFIX) and name.endswith(".so"):
                    parts = PurePosixPath(name).parts
                    if len(parts) >= 3 and parts[0] == "lib":
                        abi = parts[1]
                        library = "/".join(parts[2:])
                        if (abi, library) not in seen_native:
                            seen_native.add((abi, library))
                            result.native_libraries.append(
                                NativeLibrary(
                                    abi=abi,
                                    name=library,
                                    size_bytes=info.file_size,
                                )
                            )

                if name.startswith("assets/") and not info.is_dir():
                    result.asset_count += 1

            result.abis = sorted({library.abi for library in result.native_libraries})
    except zipfile.BadZipFile as exc:
        raise InvalidArtifactError("Archive central directory is corrupt.") from exc

    result.signature = _signature_info(path, artifact_type, result.names)
    result.frameworks = detect_frameworks(result.names)
    result.packers = detect_packers(result.names)
    result.findings = _findings(result, artifact_type)
    result.limitations = _limitations(artifact_type)
    return result


def list_archive_members(
    path: Path,
    *,
    pattern: str | None,
    limit: int,
    offset: int,
    max_entries: int,
) -> tuple[list[dict[str, Any]], int]:
    """List archive members with the same safety checks as inspection."""

    if not zipfile.is_zipfile(path):
        raise InvalidArtifactError("Artifact is not a readable ZIP container.")
    lowered_pattern = pattern.lower() if pattern else None
    matches: list[dict[str, Any]] = []
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > max_entries:
                raise LimitExceededError(
                    "Archive contains too many entries.",
                    details={"entries": len(infos), "max_entries": max_entries},
                )
            for info in infos:
                name = _normalize_name(info.filename)
                _validate_member_name(name)
                if info.is_dir():
                    continue
                if lowered_pattern and not fnmatchcase(name.lower(), lowered_pattern):
                    continue
                matches.append(
                    {
                        "name": name,
                        "size_bytes": info.file_size,
                        "compressed_bytes": info.compress_size,
                        "encrypted": bool(info.flag_bits & 0x1),
                    }
                )
    except zipfile.BadZipFile as exc:
        raise InvalidArtifactError("Archive central directory is corrupt.") from exc

    matches.sort(key=lambda item: str(item["name"]))
    return matches[offset : offset + limit], len(matches)


def read_archive_member(path: Path, name: str, *, max_bytes: int) -> bytes:
    """Read one validated archive member with an explicit uncompressed limit."""

    if not zipfile.is_zipfile(path):
        raise InvalidArtifactError("Artifact is not a readable ZIP container.")
    member = _normalize_name(name)
    _validate_member_name(member)
    try:
        with zipfile.ZipFile(path) as archive:
            try:
                info = archive.getinfo(member)
            except KeyError as exc:
                raise InvalidArtifactError(
                    f"Archive does not contain {member}.",
                    details={"entry": member},
                ) from exc
            if info.is_dir():
                raise InvalidArtifactError(
                    "Archive member is a directory.", details={"entry": member}
                )
            if info.flag_bits & 0x1:
                raise InvalidArtifactError(
                    "Archive member is encrypted.",
                    details={"entry": member},
                )
            if info.file_size > max_bytes:
                raise LimitExceededError(
                    "Archive member exceeds the configured extraction limit.",
                    details={"entry": member, "size_bytes": info.file_size, "max_bytes": max_bytes},
                )
            with archive.open(info) as handle:
                data = handle.read(max_bytes + 1)
    except zipfile.BadZipFile as exc:
        raise InvalidArtifactError("Archive central directory is corrupt.") from exc
    if len(data) > max_bytes:
        raise LimitExceededError(
            "Archive member expands beyond the configured extraction limit.",
            details={"entry": member, "max_bytes": max_bytes},
        )
    return data


def _normalize_name(name: str) -> str:
    return name.replace("\\", "/")


def _validate_member_name(name: str) -> None:
    if not name or "\x00" in name:
        raise InvalidArtifactError("Archive contains an invalid entry name.")
    pure = PurePosixPath(name)
    if pure.is_absolute() or ".." in pure.parts:
        raise InvalidArtifactError(
            "Archive contains a path traversal entry.",
            details={"entry": name},
        )
    if len(name) >= 2 and name[1] == ":":
        raise InvalidArtifactError(
            "Archive contains an absolute Windows path entry.",
            details={"entry": name},
        )


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    return ((info.external_attr >> 16) & 0o170000) == 0o120000


def _signature_info(path: Path, artifact_type: str, names: list[str]) -> SignatureInfo:
    certificates = sorted(
        name
        for name in names
        if name.startswith("META-INF/") and name.upper().endswith((".RSA", ".DSA", ".EC"))
    )
    signing_block = _has_apk_signing_block(path)

    if artifact_type == "apk":
        if certificates and signing_block:
            status = "signed_v1_and_v2"
        elif signing_block:
            status = "signed_v2_plus"
        elif certificates:
            status = "signed_v1"
        else:
            status = "unsigned"
    elif certificates:
        status = "signed_v1"
    else:
        status = "unknown"

    notes = [
        "Certificate files are inventoried by filename; certificate contents are not parsed.",
        "APK Signing Block presence is detected but v2/v3/v4 schemes are not distinguished.",
    ]
    if artifact_type in {"aab", "apks", "xapk"}:
        notes.append(
            "Outer-container signing is not the same as module or split signing; "
            "nested verification is a later phase."
        )
    return SignatureInfo(
        v1_certificates=certificates,
        apk_signing_block=signing_block,
        status=status,
        notes=notes,
    )


def _has_apk_signing_block(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            handle.seek(0, 2)
            size = handle.tell()
            handle.seek(max(0, size - 1024 * 1024))
            return SIGNING_BLOCK_MAGIC in handle.read()
    except OSError:
        return False


def _findings(result: InspectionResult, artifact_type: str) -> list[InspectionFinding]:
    findings: list[InspectionFinding] = []
    if result.signature is None:
        return findings

    if artifact_type == "apk" and result.signature.status == "unsigned":
        findings.append(
            InspectionFinding(
                id="finding_signature_absent",
                severity="medium",
                category="signature",
                title="APK is not signed",
                detail="No v1 certificate and no APK Signing Block were detected.",
                evidence_key="signature",
            )
        )
    if result.signature.status == "signed_v1":
        findings.append(
            InspectionFinding(
                id="finding_signature_v1_only",
                severity="low",
                category="signature",
                title="Only legacy v1 signing was detected",
                detail="The APK has v1 certificate files but no APK Signing Block.",
                evidence_key="signature",
            )
        )
    if result.packers:
        findings.append(
            InspectionFinding(
                id="finding_packer_markers",
                severity="medium",
                category="packer",
                title="Packer or protector markers detected",
                detail=(
                    "Filename markers suggest the app may be packed; confirm with "
                    "APKiD or an authorized runtime dump."
                ),
                evidence_key="packers",
            )
        )
    if artifact_type in {"apk", "aab"} and not result.dex_files:
        findings.append(
            InspectionFinding(
                id="finding_no_dex",
                severity="medium",
                category="code",
                title="No DEX files detected",
                detail="The package has no classes*.dex files at a recognizable location.",
                evidence_key="dex",
            )
        )
    if result.native_libraries:
        findings.append(
            InspectionFinding(
                id="finding_native_libraries",
                severity="info",
                category="native",
                title="Native libraries are present",
                detail=(
                    f"{len(result.native_libraries)} native libraries across "
                    f"{len(result.abis)} ABI(s)."
                ),
                evidence_key="native",
            )
        )
    if result.asset_count > 5000:
        findings.append(
            InspectionFinding(
                id="finding_large_assets",
                severity="info",
                category="assets",
                title="Large asset inventory",
                detail=f"{result.asset_count} asset files were found.",
                evidence_key="container",
            )
        )
    if result.encrypted_entries:
        findings.append(
            InspectionFinding(
                id="finding_encrypted_entries",
                severity="medium",
                category="container",
                title="Encrypted archive entries",
                detail=f"{result.encrypted_entries} entries are encrypted.",
                evidence_key="container",
            )
        )
    return findings


def _limitations(artifact_type: str) -> list[str]:
    limitations = [
        "Binary AndroidManifest.xml is inventoried but not parsed in this build.",
        "No code, resource, API or UI analysis is performed by the built-in scanner.",
        (
            "Framework and packer detection uses filename markers and can miss "
            "renamed or encrypted assets."
        ),
        "No runtime observation or device execution was performed.",
        "Signatures are not cryptographically verified in this build.",
    ]
    if artifact_type in {"aab", "apks", "xapk"}:
        limitations.append(
            "Nested modules and split APK contents are not independently analyzed in this build."
        )
    return limitations
