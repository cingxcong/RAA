"""Domain models for Phase 8: Obfuscation, native, unpacking, and deobfuscation."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from raa.utils.time import utc_now


class PackerKind(StrEnum):
    """Known commercial or open-source packer categories."""

    JIAGU = "jiagu"
    TENCENT_LEGU = "tencent_legu"
    BANGCLE = "bangcle"
    SECNEO = "secneo"
    BAIDU = "baidu"
    ALI = "ali"
    QIHOO_360 = "qihoo_360"
    MEDUSA = "medusa"
    IJIAMI = "ijiami"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class ProtectorKind(StrEnum):
    """Commercial application hardening and protector frameworks."""

    DEXGUARD = "dexguard"
    ARXAN = "arxan"
    APPROTECT = "approtect"
    VERIMATRIX = "verimatrix"
    PROGUARD = "proguard"
    R8 = "r8"
    ALLATORI = "allatori"
    DASHO = "dasho"
    STRINGER = "stringer"
    UNKNOWN = "unknown"


class AntiAnalysisKind(StrEnum):
    """Categories of anti-analysis and integrity defenses."""

    ROOT_DETECTION = "root_detection"
    EMULATOR_DETECTION = "emulator_detection"
    DEBUGGER_DETECTION = "debugger_detection"
    HOOK_DETECTION = "hook_detection"
    INTEGRITY_CHECK = "integrity_check"
    SIGNATURE_CHECK = "signature_check"


class CompletenessStatus(StrEnum):
    """Integrity and completeness classification of a dumped/extracted DEX."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    CORRUPTED = "corrupted"
    STUB_ONLY = "stub_only"


class PayloadKind(StrEnum):
    """Kind of extracted hidden or encrypted payload."""

    DEX = "dex"
    ZIP = "zip"
    SO = "so"
    ENCRYPTED_BLOB = "encrypted_blob"
    UNKNOWN = "unknown"


# --- Detection Models ---


class PackerFinding(BaseModel):
    """Identified packer or protector signature finding."""

    category: str = "packer"  # packer, protector, obfuscator, compiler
    name: str
    confidence: str = "high"  # exact, high, medium, heuristic
    indicators: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)


class AntiAnalysisFinding(BaseModel):
    """Detected anti-analysis mechanism observed in bytecode, manifest, or native libs."""

    kind: AntiAnalysisKind
    name: str
    description: str
    location: str  # class, method, native lib, or manifest tag
    evidence_ids: list[str] = Field(default_factory=list)


class PackerDetectionReport(BaseModel):
    """Complete packer, protector, obfuscator, and anti-analysis detection report."""

    artifact_id: str
    is_packed: bool = False
    packers: list[PackerFinding] = Field(default_factory=list)
    protectors: list[PackerFinding] = Field(default_factory=list)
    obfuscators: list[PackerFinding] = Field(default_factory=list)
    compilers: list[PackerFinding] = Field(default_factory=list)
    anti_analysis: list[AntiAnalysisFinding] = Field(default_factory=list)
    entropy_score: float = 0.0
    scanned_at: datetime = Field(default_factory=utc_now)


# --- Payload Extraction Models ---


class ExtractedPayload(BaseModel):
    """Record of an extracted hidden, nested, or decrypted payload."""

    payload_id: str
    source_path: str
    output_path: str
    kind: PayloadKind
    size_bytes: int
    sha256: str
    extracted_at: datetime = Field(default_factory=utc_now)
    extraction_method: str = "magic_carve"
    evidence_ids: list[str] = Field(default_factory=list)


class UnpackExtractionReport(BaseModel):
    """Result of static payload extraction scanning."""

    project_id: str = ""
    artifact_id: str
    total_payloads_found: int = 0
    payloads: list[ExtractedPayload] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    extracted_at: datetime = Field(default_factory=utc_now)


# --- Verification Models ---


class DexHeaderSummary(BaseModel):
    """Parsed DEX header structural summary."""

    magic: str
    version: str
    checksum: int
    signature_sha1: str
    file_size: int
    header_size: int
    endian_tag: int
    string_ids_size: int
    type_ids_size: int
    proto_ids_size: int
    field_ids_size: int
    method_ids_size: int
    class_defs_size: int
    data_size: int
    data_off: int


class UnpackVerificationReport(BaseModel):
    """Completeness, integrity, and class/method statistics for dumped/extracted DEX."""

    file_path: str
    sha256: str
    file_size: int
    status: CompletenessStatus
    header: DexHeaderSummary | None = None
    checksum_valid: bool = False
    signature_valid: bool = False
    class_count: int = 0
    method_count: int = 0
    real_code_classes: int = 0
    stub_classes: int = 0
    issues: list[str] = Field(default_factory=list)
    reanalyzed: bool = False
    reanalyzed_artifact_id: str | None = None
    verified_at: datetime = Field(default_factory=utc_now)


# --- Deobfuscation Models ---


class DeobfuscationResult(BaseModel):
    """Outcome of Dalvik/bytecode deobfuscation transformation."""

    target: str
    strategy: str  # reflection_resolve, string_decrypt, dead_code_prune, simplify
    transformed: bool = False
    constants_decrypted: int = 0
    reflections_resolved: int = 0
    dead_branches_pruned: int = 0
    deobfuscated_file: str | None = None
    transformed_code: str | None = None
    provenance_warning: str = (
        "Deobfuscation transforms bytecode semantics. "
        "Never present this output as original source code."
    )
    evidence_ids: list[str] = Field(default_factory=list)
    completed_at: datetime = Field(default_factory=utc_now)


# --- Retrace Models ---


class ClassMapping(BaseModel):
    """Single class ProGuard/R8 mapping definition."""

    original: str
    obfuscated: str


class MethodMapping(BaseModel):
    """Single method ProGuard/R8 mapping definition."""

    class_name: str
    original_name: str
    obfuscated_name: str
    return_type: str = "void"
    start_line: int | None = None
    end_line: int | None = None


class FieldMapping(BaseModel):
    """Single field ProGuard/R8 mapping definition."""

    class_name: str
    original_name: str
    obfuscated_name: str
    field_type: str = ""


class RetraceReport(BaseModel):
    """Result of parsing mapping files and translating symbols or stack traces."""

    mapping_file: str
    total_classes_mapped: int = 0
    total_methods_mapped: int = 0
    total_fields_mapped: int = 0
    retrace_coverage_percent: float = 0.0
    retraced_text: str | None = None
    unmapped_symbols_count: int = 0
    processed_at: datetime = Field(default_factory=utc_now)


# --- Native Inventory Models ---


class NativeLibrarySummary(BaseModel):
    """Metadata, ELF properties, and JNI linkages for a native shared object."""

    library_name: str
    abi: str
    size_bytes: int
    sha256: str
    architecture: str
    machine: str
    bitness: int
    endianness: str
    dependencies: list[str] = Field(default_factory=list)
    exported_symbols_count: int = 0
    imported_symbols_count: int = 0
    has_jni_on_load: bool = False
    jni_symbols: list[str] = Field(default_factory=list)


class NativeInventoryReport(BaseModel):
    """Multi-ABI native library inventory across an APK container."""

    artifact_id: str
    total_libraries: int = 0
    abis_present: list[str] = Field(default_factory=list)
    libraries: list[NativeLibrarySummary] = Field(default_factory=list)
    inspected_at: datetime = Field(default_factory=utc_now)
