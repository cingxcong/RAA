"""Dump completeness verification and DEX structural integrity checking service."""

from __future__ import annotations

import hashlib
import struct
import zlib
from pathlib import Path

from raa.domain.unpacking import (
    CompletenessStatus,
    DexHeaderSummary,
    UnpackVerificationReport,
)
from raa.utils.time import utc_now

_VALID_MAGICS = {
    b"dex\n035\x00": "035",
    b"dex\n037\x00": "037",
    b"dex\n038\x00": "038",
    b"dex\n039\x00": "039",
}


def verify_dex_dump(file_path: Path) -> UnpackVerificationReport:
    """Verify structural integrity, checksums, class completeness, and stub ratio of a DEX dump."""
    if not file_path.is_file():
        return UnpackVerificationReport(
            file_path=str(file_path),
            sha256="",
            file_size=0,
            status=CompletenessStatus.CORRUPTED,
            issues=["DEX file does not exist."],
        )

    dex_bytes = file_path.read_bytes()
    file_size = len(dex_bytes)
    sha256 = hashlib.sha256(dex_bytes).hexdigest()
    issues: list[str] = []

    if file_size < 0x70:
        return UnpackVerificationReport(
            file_path=str(file_path),
            sha256=sha256,
            file_size=file_size,
            status=CompletenessStatus.CORRUPTED,
            issues=[f"File too small for valid DEX header ({file_size} bytes)."],
        )

    magic = dex_bytes[:8]
    if magic not in _VALID_MAGICS:
        return UnpackVerificationReport(
            file_path=str(file_path),
            sha256=sha256,
            file_size=file_size,
            status=CompletenessStatus.CORRUPTED,
            issues=[f"Invalid DEX magic: {magic!r}."],
        )

    version_str = _VALID_MAGICS[magic]

    # Parse standard DEX header
    (
        expected_checksum,
        expected_sha1,
        hdr_file_size,
        hdr_size,
        endian_tag,
        _link_size,
        _link_off,
        _map_off,
        string_ids_size,
        _string_ids_off,
        type_ids_size,
        _type_ids_off,
        proto_ids_size,
        _proto_ids_off,
        field_ids_size,
        _field_ids_off,
        method_ids_size,
        _method_ids_off,
        class_defs_size,
        class_defs_off,
        data_size,
        data_off,
    ) = struct.unpack("<I20s20I", dex_bytes[8:112])

    header = DexHeaderSummary(
        magic=magic.decode("latin1", errors="replace"),
        version=version_str,
        checksum=expected_checksum,
        signature_sha1=expected_sha1.hex(),
        file_size=hdr_file_size,
        header_size=hdr_size,
        endian_tag=endian_tag,
        string_ids_size=string_ids_size,
        type_ids_size=type_ids_size,
        proto_ids_size=proto_ids_size,
        field_ids_size=field_ids_size,
        method_ids_size=method_ids_size,
        class_defs_size=class_defs_size,
        data_size=data_size,
        data_off=data_off,
    )

    # 1. Checksum validation (Adler32 from offset 12 to EOF)
    actual_adler = zlib.adler32(dex_bytes[12:])
    checksum_valid = actual_adler == expected_checksum
    if not checksum_valid:
        issues.append(
            f"Adler32 checksum mismatch: expected 0x{expected_checksum:08x}, "
            f"computed 0x{actual_adler:08x}."
        )

    # 2. SHA-1 signature validation (SHA-1 from offset 32 to EOF)
    actual_sha1 = hashlib.sha1(dex_bytes[32:]).digest()  # noqa: S324
    signature_valid = actual_sha1 == expected_sha1
    if not signature_valid:
        issues.append("SHA-1 signature mismatch in DEX header.")

    # 3. File size check
    if file_size < hdr_file_size:
        issues.append(
            f"DEX payload is truncated: header states {hdr_file_size} bytes, "
            f"actual is {file_size} bytes."
        )

    # 4. Class definitions inspection (detect real class data vs stubs)
    class_count = class_defs_size
    stub_classes = 0
    real_code_classes = 0

    if class_defs_size > 0 and class_defs_off + (class_defs_size * 32) <= file_size:
        for i in range(class_defs_size):
            offset = class_defs_off + (i * 32)
            # class_def structure:
            # class_idx (4), access_flags (4), superclass_idx (4), interfaces_off (4),
            # source_file_idx (4), annotations_off (4), class_data_off (4), static_values_off (4)
            cdata_off = int.from_bytes(dex_bytes[offset + 24 : offset + 28], byteorder="little")
            if cdata_off == 0:
                stub_classes += 1
            else:
                real_code_classes += 1
    elif class_defs_size > 0:
        issues.append("Class definitions table exceeds file boundary.")

    # Classify overall status
    if file_size < hdr_file_size:
        status = CompletenessStatus.PARTIAL
    elif class_count > 0 and stub_classes == class_count:
        status = CompletenessStatus.STUB_ONLY
        issues.append("All class definitions are empty shell stubs with no method data.")
    elif real_code_classes > 0 and (checksum_valid or file_size == hdr_file_size):
        status = CompletenessStatus.COMPLETE
    elif real_code_classes > 0:
        status = CompletenessStatus.PARTIAL
    else:
        status = CompletenessStatus.CORRUPTED

    return UnpackVerificationReport(
        file_path=str(file_path),
        sha256=sha256,
        file_size=file_size,
        status=status,
        header=header,
        checksum_valid=checksum_valid,
        signature_valid=signature_valid,
        class_count=class_count,
        method_count=method_ids_size,
        real_code_classes=real_code_classes,
        stub_classes=stub_classes,
        issues=issues,
        reanalyzed=False,
        verified_at=utc_now(),
    )
