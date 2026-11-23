"""Pure-Python Native APK Signature Scheme v2 and v3 Block Builder and Verifier.

Implements the official Android APK Signing Block format (APK Sig Block 42),
supporting:
- APK Signature Scheme v2 (ID 0x7109871a)
- APK Signature Scheme v3 (ID 0xf05368c0)

Zero external tool dependency (does not require external apksigner or Android SDK).
Uses RFC-compliant cryptographic primitives (RSA-SHA256, Merkle 1MB chunked digests,
and X.509 DER certificates).
"""

from __future__ import annotations

import datetime
import hashlib
import struct
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key
from cryptography.x509.oid import NameOID

APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
APK_SIGNATURE_SCHEME_V2_BLOCK_ID = 0x7109871A
APK_SIGNATURE_SCHEME_V3_BLOCK_ID = 0xF05368C0

CHUNK_SIZE_BYTES = 1048576  # 1 MB
SIG_ALG_SHA256 = 0x0103


def generate_debug_credentials() -> tuple[rsa.RSAPrivateKey, bytes, bytes, str]:
    """Generate deterministic or standard RSA 2048-bit debug key and X.509 DER certificate.

    Returns:
        (private_key, cert_der, pub_key_der, cert_fingerprint_hex)
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Android Debug"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Android"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ]
    )
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    cert_der = cert.public_bytes(Encoding.DER)
    pub_der = key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    cert_fp = hashlib.sha256(cert_der).hexdigest()
    return key, cert_der, pub_der, cert_fp


def find_eocd(apk_bytes: bytes) -> tuple[int, int, int]:
    """Find the End of Central Directory (EOCD) record."""
    max_search = min(len(apk_bytes), 65535 + 22)
    search_buf = apk_bytes[-max_search:]

    eocd_idx = search_buf.rfind(b"\x50\x4b\x05\x06")
    if eocd_idx < 0:
        raise ValueError("No ZIP End of Central Directory (EOCD) record found")

    eocd_offset = len(apk_bytes) - max_search + eocd_idx
    if len(apk_bytes) < eocd_offset + 20:
        raise ValueError("Malformed EOCD record")

    cd_size = struct.unpack("<I", apk_bytes[eocd_offset + 12 : eocd_offset + 16])[0]
    cd_offset = struct.unpack("<I", apk_bytes[eocd_offset + 16 : eocd_offset + 20])[0]

    return eocd_offset, cd_offset, cd_size


def find_apk_signing_block(
    apk_bytes: bytes,
    cd_offset: int,
) -> tuple[int, bytes] | None:
    """Find the APK Signing Block immediately preceding the Central Directory."""
    if cd_offset < 24:
        return None

    footer = apk_bytes[cd_offset - 24 : cd_offset]
    magic = footer[8:24]
    if magic != APK_SIG_BLOCK_MAGIC:
        return None

    block_size = struct.unpack("<Q", footer[:8])[0]
    block_offset = cd_offset - block_size - 8
    if block_offset < 0:
        return None

    header_size = struct.unpack("<Q", apk_bytes[block_offset : block_offset + 8])[0]
    if header_size != block_size:
        return None

    return block_offset, apk_bytes[block_offset:cd_offset]


def compute_apk_digest(
    apk_bytes: bytes,
    signing_block_offset: int,
    cd_offset: int,
    cd_size: int,
    eocd_offset: int,
) -> bytes:
    """Compute official Android 1MB chunked SHA-256 digest across 3 sections.

    Section 1: [0, signing_block_offset)
    Section 2: Central Directory [cd_offset, cd_offset + cd_size)
    Section 3: EOCD with Central Directory offset pointing to signing_block_offset
    """
    eocd_modified = bytearray(apk_bytes[eocd_offset:])
    struct.pack_into("<I", eocd_modified, 16, signing_block_offset)

    sections = [
        apk_bytes[0:signing_block_offset],
        apk_bytes[cd_offset : cd_offset + cd_size],
        bytes(eocd_modified),
    ]

    total_chunks = sum((len(sec) + CHUNK_SIZE_BYTES - 1) // CHUNK_SIZE_BYTES for sec in sections)
    chunk_digests: list[bytes] = []
    for section in sections:
        for i in range(0, len(section), CHUNK_SIZE_BYTES):
            chunk = section[i : i + CHUNK_SIZE_BYTES]
            # Android chunk digest prefix: 0xa5 followed by uint32(len(chunk))
            chunk_digests.append(
                hashlib.sha256(b"\xa5" + struct.pack("<I", len(chunk)) + chunk).digest()
            )

    # Root digest prefix: 0x5a followed by uint32(total_chunks)
    root_hasher = hashlib.sha256()
    root_hasher.update(b"\x5a" + struct.pack("<I", total_chunks))
    for cd in chunk_digests:
        root_hasher.update(cd)
    return root_hasher.digest()


def build_scheme_block(
    scheme_id: int,
    root_digest: bytes,
    cert_der: bytes,
    key: rsa.RSAPrivateKey,
    pub_der: bytes,
) -> bytes:
    """Build a valid v2 or v3 signature scheme payload using RSA cryptographic signatures."""
    # 1. Digests block: sequence of len-prefixed digest entries
    digest_payload = struct.pack("<II", SIG_ALG_SHA256, len(root_digest)) + root_digest
    digest_entry = struct.pack("<I", len(digest_payload)) + digest_payload
    digests_block = struct.pack("<I", len(digest_entry)) + digest_entry

    # 2. Certificates block: sequence of len-prefixed X.509 DER certificates
    certs_entry = struct.pack("<I", len(cert_der)) + cert_der
    certs_block = struct.pack("<I", len(certs_entry)) + certs_entry

    # 3. Additional attributes block: sequence of len-prefixed ID-value pairs
    attrs_block = struct.pack("<I", 0)

    # 4. Signed data:
    # In v2: digests + certificates + additional attributes
    # In v3: digests + certificates + min_sdk + max_sdk + additional attributes
    if scheme_id == APK_SIGNATURE_SCHEME_V3_BLOCK_ID:
        min_sdk = 24
        max_sdk = 2147483647
        signed_data = (
            digests_block + certs_block + struct.pack("<II", min_sdk, max_sdk) + attrs_block
        )
    else:
        signed_data = digests_block + certs_block + attrs_block

    signed_data_block = struct.pack("<I", len(signed_data)) + signed_data

    # 5. Signatures: sequence of len-prefixed signature entries over signed_data
    sig_raw = key.sign(signed_data, padding.PKCS1v15(), hashes.SHA256())
    sig_payload = struct.pack("<II", SIG_ALG_SHA256, len(sig_raw)) + sig_raw
    sig_entry = struct.pack("<I", len(sig_payload)) + sig_payload
    signatures_block = struct.pack("<I", len(sig_entry)) + sig_entry

    # 6. Public key: len-prefixed SubjectPublicKeyInfo DER
    public_key_block = struct.pack("<I", len(pub_der)) + pub_der

    # 7. Signer block:
    # In v2: signed_data_block + signatures_block + public_key_block
    # In v3: signed_data_block + min_sdk + max_sdk + signatures_block + public_key_block
    if scheme_id == APK_SIGNATURE_SCHEME_V3_BLOCK_ID:
        signer_data = (
            signed_data_block
            + struct.pack("<II", min_sdk, max_sdk)
            + signatures_block
            + public_key_block
        )
    else:
        signer_data = signed_data_block + signatures_block + public_key_block

    signer_entry = struct.pack("<I", len(signer_data)) + signer_data
    signers_block = struct.pack("<I", len(signer_entry)) + signer_entry
    return signers_block


def build_apk_signing_block(entries: list[tuple[int, bytes]]) -> bytes:
    """Pack key-value ID pairs into the APK Signing Block format."""
    pairs_data = bytearray()
    for block_id, value in entries:
        pair_len = 4 + len(value)
        pairs_data.extend(struct.pack("<QI", pair_len, block_id))
        pairs_data.extend(value)

    block_size = len(pairs_data) + 24
    block = bytearray()
    block.extend(struct.pack("<Q", block_size))
    block.extend(pairs_data)
    block.extend(struct.pack("<Q", block_size))
    block.extend(APK_SIG_BLOCK_MAGIC)
    return bytes(block)


def sign_apk_v2v3(
    apk_bytes: bytes,
    include_v2: bool = True,
    include_v3: bool = True,
    key: rsa.RSAPrivateKey | None = None,
    cert_der: bytes | None = None,
    pub_der: bytes | None = None,
) -> bytes:
    """Sign an APK in-place with native APK Signature Scheme v2 and/or v3."""
    eocd_offset, cd_offset, cd_size = find_eocd(apk_bytes)

    existing = find_apk_signing_block(apk_bytes, cd_offset)
    if existing:
        block_off, _ = existing
        apk_bytes = apk_bytes[:block_off] + apk_bytes[cd_offset:]
        eocd_offset, cd_offset, cd_size = find_eocd(apk_bytes)

    if key is None or cert_der is None or pub_der is None:
        key, cert_der, pub_der, _ = generate_debug_credentials()

    signing_block_offset = cd_offset
    root_digest = compute_apk_digest(
        apk_bytes,
        signing_block_offset=signing_block_offset,
        cd_offset=cd_offset,
        cd_size=cd_size,
        eocd_offset=eocd_offset,
    )

    entries: list[tuple[int, bytes]] = []
    if include_v2:
        v2_data = build_scheme_block(
            APK_SIGNATURE_SCHEME_V2_BLOCK_ID, root_digest, cert_der, key, pub_der
        )
        entries.append((APK_SIGNATURE_SCHEME_V2_BLOCK_ID, v2_data))
    if include_v3:
        v3_data = build_scheme_block(
            APK_SIGNATURE_SCHEME_V3_BLOCK_ID, root_digest, cert_der, key, pub_der
        )
        entries.append((APK_SIGNATURE_SCHEME_V3_BLOCK_ID, v3_data))

    signing_block = build_apk_signing_block(entries)

    new_cd_offset = cd_offset + len(signing_block)
    modified_eocd = bytearray(apk_bytes[eocd_offset:])
    struct.pack_into("<I", modified_eocd, 16, new_cd_offset)

    signed_apk = (
        apk_bytes[:cd_offset]
        + signing_block
        + apk_bytes[cd_offset:eocd_offset]
        + bytes(modified_eocd)
    )

    return signed_apk


def verify_apk_v2v3_signatures(apk_bytes: bytes) -> dict[str, Any]:
    """Parse and cryptographically verify APK Signing Block, checking v2 and v3 schemes."""
    try:
        eocd_offset, cd_offset, cd_size = find_eocd(apk_bytes)
    except Exception as exc:
        return {"has_signing_block": False, "verified": False, "error": str(exc)}

    signing_block_info = find_apk_signing_block(apk_bytes, cd_offset)
    if not signing_block_info:
        return {
            "has_signing_block": False,
            "v2_signed": False,
            "v3_signed": False,
            "schemes_found": [],
            "verified": False,
        }

    block_offset, block_bytes = signing_block_info
    pos = 8
    end = len(block_bytes) - 24
    schemes_found: list[str] = []
    v2_found = False
    v3_found = False
    all_verified = True

    # Compute expected Merkle root digest
    expected_root_digest = compute_apk_digest(
        apk_bytes,
        signing_block_offset=block_offset,
        cd_offset=cd_offset,
        cd_size=cd_size,
        eocd_offset=eocd_offset,
    )

    while pos < end:
        if pos + 12 > end:
            break
        pair_len, block_id = struct.unpack("<QI", block_bytes[pos : pos + 12])
        val = block_bytes[pos + 12 : pos + 8 + pair_len]
        pos += 8 + pair_len

        if block_id in (APK_SIGNATURE_SCHEME_V2_BLOCK_ID, APK_SIGNATURE_SCHEME_V3_BLOCK_ID):
            scheme_name = "v2" if block_id == APK_SIGNATURE_SCHEME_V2_BLOCK_ID else "v3"
            schemes_found.append(scheme_name)
            if scheme_name == "v2":
                v2_found = True
            else:
                v3_found = True

            # Verify signer block
            try:
                if len(val) < 8:
                    all_verified = False
                    continue
                _signers_len = struct.unpack("<I", val[:4])[0]
                signer_entry_len = struct.unpack("<I", val[4:8])[0]
                signer_data = val[8 : 8 + signer_entry_len]

                # Parse signed_data
                sd_len = struct.unpack("<I", signer_data[:4])[0]
                signed_data = signer_data[4 : 4 + sd_len]

                # Parse digests
                d_len = struct.unpack("<I", signed_data[:4])[0]
                d_block = signed_data[4 : 4 + d_len]
                d_entry_len = struct.unpack("<I", d_block[:4])[0]
                d_entry = d_block[4 : 4 + d_entry_len]
                _d_alg, d_sz = struct.unpack("<II", d_entry[:8])
                claimed_digest = d_entry[8 : 8 + d_sz]

                if claimed_digest != expected_root_digest:
                    all_verified = False

                # Parse signatures & public key
                idx = 4 + sd_len
                if block_id == APK_SIGNATURE_SCHEME_V3_BLOCK_ID:
                    idx += 8  # skip min_sdk and max_sdk
                sigs_len = struct.unpack("<I", signer_data[idx : idx + 4])[0]
                sigs_block = signer_data[idx + 4 : idx + 4 + sigs_len]
                idx += 4 + sigs_len
                pub_len = struct.unpack("<I", signer_data[idx : idx + 4])[0]
                pub_bytes = signer_data[idx + 4 : idx + 4 + pub_len]

                s_entry_len = struct.unpack("<I", sigs_block[:4])[0]
                s_entry = sigs_block[4 : 4 + s_entry_len]
                _s_alg, s_sz = struct.unpack("<II", s_entry[:8])
                sig_bytes = s_entry[8 : 8 + s_sz]

                pub = load_der_public_key(pub_bytes)
                pub.verify(sig_bytes, signed_data, padding.PKCS1v15(), hashes.SHA256())
            except Exception:
                all_verified = False

    return {
        "has_signing_block": True,
        "signing_block_offset": block_offset,
        "signing_block_size": len(block_bytes),
        "v2_signed": v2_found,
        "v3_signed": v3_found,
        "schemes_found": schemes_found,
        "verified": (v2_found or v3_found) and all_verified,
    }
