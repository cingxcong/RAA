"""Static payload extraction service carving embedded DEX and archive containers."""

from __future__ import annotations

import contextlib
import hashlib
import zipfile
from pathlib import Path

from raa.domain.unpacking import (
    ExtractedPayload,
    PayloadKind,
    UnpackExtractionReport,
)
from raa.utils.ids import new_id
from raa.utils.time import utc_now

_DEX_MAGICS = (
    b"dex\n035\x00",
    b"dex\n037\x00",
    b"dex\n038\x00",
    b"dex\n039\x00",
)
_ZIP_MAGIC = b"PK\x03\x04"


def extract_static_payloads(
    apk_path: Path,
    output_dir: Path,
    artifact_id: str = "art_default",
) -> UnpackExtractionReport:
    """Scan APK assets and resources to extract embedded, hidden, or nested DEX/ZIP payloads."""
    output_dir.mkdir(parents=True, exist_ok=True)
    payloads: list[ExtractedPayload] = []
    errors: list[str] = []

    if not apk_path.is_file():
        return UnpackExtractionReport(
            artifact_id=artifact_id,
            total_payloads_found=0,
            payloads=[],
            errors=["Target APK file not found."],
        )

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for entry_name in zf.namelist():
                # Skip standard top-level DEX files (already indexed)
                if entry_name.startswith("classes") and entry_name.endswith(".dex"):
                    continue

                with contextlib.suppress(Exception):
                    raw_data = zf.read(entry_name)
                    if len(raw_data) < 32:
                        continue

                    # 1. Direct embedded DEX search
                    for magic in _DEX_MAGICS:
                        idx = raw_data.find(magic)
                        if idx != -1:
                            # Carve DEX from magic onwards if size is available in header
                            carved = raw_data[idx:]
                            if len(carved) >= 0x24:
                                dex_size = int.from_bytes(carved[0x20:0x24], byteorder="little")
                                if 0x70 <= dex_size <= len(carved):
                                    dex_bytes = carved[:dex_size]
                                else:
                                    dex_bytes = carved
                            else:
                                dex_bytes = carved

                            sha256 = hashlib.sha256(dex_bytes).hexdigest()
                            safe_name = entry_name.replace("/", "_").replace("\\", "_")
                            out_file = output_dir / f"extracted_{safe_name}.dex"
                            out_file.write_bytes(dex_bytes)

                            payloads.append(
                                ExtractedPayload(
                                    payload_id=new_id("payload"),
                                    source_path=entry_name,
                                    output_path=str(out_file),
                                    kind=PayloadKind.DEX,
                                    size_bytes=len(dex_bytes),
                                    sha256=sha256,
                                    extraction_method="magic_carve_dex",
                                )
                            )
                            break

                    # 2. Direct embedded ZIP/JAR search in assets
                    if entry_name.startswith("assets/") and raw_data.startswith(_ZIP_MAGIC):
                        sha256 = hashlib.sha256(raw_data).hexdigest()
                        safe_name = entry_name.replace("/", "_").replace("\\", "_")
                        out_file = output_dir / f"extracted_{safe_name}.zip"
                        out_file.write_bytes(raw_data)

                        payloads.append(
                            ExtractedPayload(
                                payload_id=new_id("payload"),
                                source_path=entry_name,
                                output_path=str(out_file),
                                kind=PayloadKind.ZIP,
                                size_bytes=len(raw_data),
                                sha256=sha256,
                                extraction_method="nested_zip_extract",
                            )
                        )

                    # 3. Simple XOR-obfuscated DEX test on .dat/.mp3/.bin files in assets
                    if entry_name.startswith("assets/") and entry_name.endswith(
                        (".dat", ".bin", ".mp3", ".png")
                    ):
                        for xor_key in (0xFF, 0x55, 0xAA, 0x12):
                            test_head = bytes(b ^ xor_key for b in raw_data[:8])
                            if any(test_head.startswith(m) for m in _DEX_MAGICS):
                                deobf_bytes = bytes(b ^ xor_key for b in raw_data)
                                sha256 = hashlib.sha256(deobf_bytes).hexdigest()
                                safe_name = entry_name.replace("/", "_")
                                out_file = output_dir / f"deobf_xor_{safe_name}.dex"
                                out_file.write_bytes(deobf_bytes)

                                payloads.append(
                                    ExtractedPayload(
                                        payload_id=new_id("payload"),
                                        source_path=entry_name,
                                        output_path=str(out_file),
                                        kind=PayloadKind.DEX,
                                        size_bytes=len(deobf_bytes),
                                        sha256=sha256,
                                        extraction_method=f"xor_key_0x{xor_key:02x}",
                                    )
                                )
                                break
    except Exception as exc:
        errors.append(str(exc))

    return UnpackExtractionReport(
        artifact_id=artifact_id,
        total_payloads_found=len(payloads),
        payloads=payloads,
        errors=errors,
        extracted_at=utc_now(),
    )
