"""Bounded, dependency-free DEX metadata indexing.

The indexer reads the DEX header, string/type/proto/field/method identifier
tables and class definitions. It records declared members and access flags but
does not decode bytecode, annotations, debug info or resources. Every read is
bounds-checked and every table is capped.
"""

from __future__ import annotations

import hashlib
import struct
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path

from raa.domain.dex import (
    DexClassDetail,
    DexClassInfo,
    DexFileSummary,
    DexMemberInfo,
    DexReferenceInfo,
    DexSummary,
    ReferenceKind,
)
from raa.errors import InvalidArtifactError, LimitExceededError, UnsupportedError

_HEADER_SIZE = 0x70
_ENDIAN_CONSTANT = 0x12345678
_NO_INDEX = 0xFFFFFFFF
_MAX_STRING_RAW_BYTES = 1024 * 1024

_CLASS_FLAGS: tuple[tuple[int, str], ...] = (
    (0x0001, "public"),
    (0x0010, "final"),
    (0x0200, "interface"),
    (0x0400, "abstract"),
    (0x1000, "synthetic"),
    (0x2000, "annotation"),
    (0x4000, "enum"),
)
_FIELD_FLAGS: tuple[tuple[int, str], ...] = (
    (0x0001, "public"),
    (0x0002, "private"),
    (0x0004, "protected"),
    (0x0008, "static"),
    (0x0010, "final"),
    (0x0040, "volatile"),
    (0x0080, "transient"),
    (0x1000, "synthetic"),
    (0x4000, "enum"),
)
_METHOD_FLAGS: tuple[tuple[int, str], ...] = (
    (0x0001, "public"),
    (0x0002, "private"),
    (0x0004, "protected"),
    (0x0008, "static"),
    (0x0010, "final"),
    (0x0020, "synchronized"),
    (0x0040, "bridge"),
    (0x0080, "varargs"),
    (0x0100, "native"),
    (0x0200, "interface"),
    (0x0400, "abstract"),
    (0x0800, "strict"),
    (0x1000, "synthetic"),
    (0x10000, "constructor"),
    (0x20000, "declared_synchronized"),
)


_METHOD_CALL_OPS = frozenset((*range(0x6E, 0x73), *range(0x74, 0x79), 0xFA, 0xFB))
_FIELD_ACCESS_OPS = frozenset((*range(0x52, 0x60), *range(0x60, 0x6E)))
_STRING_REFERENCE_21C = frozenset({0x1A})
_STRING_REFERENCE_31C = frozenset({0x1B})
_TYPE_REFERENCE_OPS = frozenset({0x1C, 0x1F, 0x20, 0x22, 0x23, 0x24, 0x25})


def _width_table() -> dict[int, int]:
    widths: dict[int, int] = {}

    def assign(start: int, end: int, width: int) -> None:
        for opcode in range(start, end + 1):
            widths[opcode] = width

    assign(0x00, 0x01, 1)
    assign(0x02, 0x02, 2)
    assign(0x03, 0x03, 3)
    assign(0x04, 0x04, 1)
    assign(0x05, 0x05, 2)
    assign(0x06, 0x06, 3)
    assign(0x07, 0x07, 1)
    assign(0x08, 0x08, 2)
    assign(0x09, 0x09, 3)
    assign(0x0A, 0x0E, 1)
    assign(0x0F, 0x11, 1)
    assign(0x12, 0x12, 1)
    assign(0x13, 0x13, 2)
    assign(0x14, 0x14, 3)
    assign(0x15, 0x16, 2)
    assign(0x17, 0x17, 3)
    assign(0x18, 0x18, 5)
    assign(0x19, 0x19, 2)
    assign(0x1A, 0x1A, 2)
    assign(0x1B, 0x1B, 3)
    assign(0x1C, 0x1C, 2)
    assign(0x1D, 0x1E, 1)
    assign(0x1F, 0x1F, 2)
    assign(0x20, 0x20, 2)
    assign(0x21, 0x21, 1)
    assign(0x22, 0x22, 2)
    assign(0x23, 0x23, 2)
    assign(0x24, 0x26, 3)
    assign(0x27, 0x27, 1)
    assign(0x28, 0x28, 1)
    assign(0x29, 0x29, 2)
    assign(0x2A, 0x2C, 3)
    assign(0x2D, 0x31, 2)
    assign(0x32, 0x3D, 2)
    assign(0x44, 0x51, 2)
    assign(0x52, 0x5F, 2)
    assign(0x60, 0x6D, 2)
    assign(0x6E, 0x72, 3)
    assign(0x74, 0x78, 3)
    assign(0x7B, 0x8F, 1)
    assign(0x90, 0xAF, 2)
    assign(0xB0, 0xCF, 1)
    assign(0xD0, 0xD7, 2)
    assign(0xD8, 0xE2, 2)
    assign(0xFA, 0xFB, 4)
    assign(0xFC, 0xFD, 3)
    assign(0xFE, 0xFF, 2)
    return widths


_WIDTHS = _width_table()


@dataclass(frozen=True, slots=True)
class ParsedField:
    name: str
    descriptor: str
    access_flags: int

    @property
    def info(self) -> DexMemberInfo:
        return DexMemberInfo(
            name=self.name,
            descriptor=self.descriptor,
            access_flags=self.access_flags,
            access=access_labels(self.access_flags, "field"),
            static=bool(self.access_flags & 0x0008),
        )


@dataclass(frozen=True, slots=True)
class ParsedMethod:
    name: str
    descriptor: str
    access_flags: int
    code_offset: int | None = None

    @property
    def info(self) -> DexMemberInfo:
        return DexMemberInfo(
            name=self.name,
            descriptor=self.descriptor,
            access_flags=self.access_flags,
            access=access_labels(self.access_flags, "method"),
            static=bool(self.access_flags & 0x0008),
            has_code=self.code_offset is not None,
        )


@dataclass(frozen=True, slots=True)
class ParsedReference:
    kind: ReferenceKind
    from_class: str
    from_method: str
    from_descriptor: str
    target: str
    target_class: str | None
    target_name: str | None
    target_descriptor: str | None
    value: str | None
    opcode: int
    offset: int
    dex_file: str

    @property
    def info(self) -> DexReferenceInfo:
        return DexReferenceInfo(
            kind=self.kind,
            from_class=self.from_class,
            from_method=self.from_method,
            from_descriptor=self.from_descriptor,
            target=self.target,
            target_class=self.target_class,
            target_name=self.target_name,
            target_descriptor=self.target_descriptor,
            value=self.value,
            opcode=self.opcode,
            offset=self.offset,
            dex_file=self.dex_file,
        )


@dataclass(slots=True)
class ParsedClass:
    name: str
    descriptor: str
    access_flags: int
    superclass: str | None
    interfaces: list[str]
    source_file: str | None
    dex_file: str
    fields: list[ParsedField] = field(default_factory=list)
    methods: list[ParsedMethod] = field(default_factory=list)

    def info(self) -> DexClassInfo:
        return DexClassInfo(
            name=self.name,
            descriptor=self.descriptor,
            access_flags=self.access_flags,
            access=access_labels(self.access_flags, "class"),
            superclass=self.superclass,
            interfaces=list(self.interfaces),
            source_file=self.source_file,
            dex_file=self.dex_file,
            field_count=len(self.fields),
            method_count=len(self.methods),
        )

    def detail(self, *, offset: int, limit: int) -> DexClassDetail:
        methods = self.methods[offset : offset + limit]
        fields = self.fields[offset : offset + limit]
        info = self.info().model_dump()
        info["field_count"] = len(fields)
        info["method_count"] = len(methods)
        return DexClassDetail(
            **info,
            fields=[item.info for item in fields],
            methods=[item.info for item in methods],
            field_total=len(self.fields),
            method_total=len(self.methods),
            truncated=(len(self.fields) > offset + limit or len(self.methods) > offset + limit),
        )


@dataclass(slots=True)
class ParsedDex:
    name: str
    size_bytes: int
    version: str | None
    checksum: str | None
    checksum_valid: bool | None
    signature_valid: bool | None
    strings: list[str]
    classes: list[ParsedClass]
    references: list[ParsedReference] = field(default_factory=list)
    reference_warnings: list[str] = field(default_factory=list)
    error: str | None = None

    def summary(self) -> DexFileSummary:
        return DexFileSummary(
            name=self.name,
            size_bytes=self.size_bytes,
            version=self.version,
            checksum=self.checksum,
            checksum_valid=self.checksum_valid,
            signature_valid=self.signature_valid,
            class_count=len(self.classes),
            method_count=sum(len(item.methods) for item in self.classes),
            field_count=sum(len(item.fields) for item in self.classes),
            string_count=len(self.strings),
            error=self.error,
        )


@dataclass(slots=True)
class DexIndex:
    files: list[ParsedDex] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    @property
    def classes(self) -> list[ParsedClass]:
        return [item for dex in self.files for item in dex.classes]

    @property
    def errors(self) -> list[tuple[str, str]]:
        return [(dex.name, dex.error) for dex in self.files if dex.error]

    @property
    def references(self) -> list[ParsedReference]:
        return [reference for dex in self.files for reference in dex.references]

    def summary(self) -> DexSummary:
        limitations = list(self.limitations)
        for name, error in self.errors:
            limitations.append(f"DEX file {name} could not be indexed: {error}")
        for dex in self.files:
            limitations.extend(dex.reference_warnings)
        return DexSummary(
            file_count=len(self.files),
            class_count=sum(len(dex.classes) for dex in self.files),
            method_count=sum(len(item.methods) for dex in self.files for item in dex.classes),
            field_count=sum(len(item.fields) for dex in self.files for item in dex.classes),
            string_count=sum(len(dex.strings) for dex in self.files),
            multi_dex=len(self.files) > 1,
            files=[dex.summary() for dex in self.files],
            limitations=limitations,
        )


class _Cursor:
    """Bounds-checked cursor for DEX structures."""

    __slots__ = ("_data", "_end", "_label", "_pos")

    def __init__(self, data: bytes, offset: int, end: int, label: str) -> None:
        if offset < 0 or end < offset or end > len(data):
            raise InvalidArtifactError(f"Invalid DEX bounds in {label}.")
        self._data = data
        self._pos = offset
        self._end = end
        self._label = label

    @property
    def position(self) -> int:
        return self._pos

    def _check(self, size: int) -> None:
        if size < 0 or self._pos + size > self._end:
            raise InvalidArtifactError(
                f"Truncated DEX while reading {self._label}.",
                details={"offset": self._pos, "required": size},
            )

    def u1(self) -> int:
        self._check(1)
        value = self._data[self._pos]
        self._pos += 1
        return value

    def u2(self) -> int:
        self._check(2)
        value = int(struct.unpack_from("<H", self._data, self._pos)[0])
        self._pos += 2
        return value

    def u4(self) -> int:
        self._check(4)
        value = int(struct.unpack_from("<I", self._data, self._pos)[0])
        self._pos += 4
        return value

    def uleb128(self) -> int:
        result = 0
        for shift in range(0, 35, 7):
            byte = self.u1()
            result |= (byte & 0x7F) << shift
            if not byte & 0x80:
                if result > 0xFFFFFFFF:
                    raise InvalidArtifactError("DEX LEB128 value exceeds 32 bits.")
                return result
        raise InvalidArtifactError("DEX LEB128 value is too long.")


def decode_dex_index(
    path: Path,
    artifact_type: str,
    *,
    max_bytes: int,
    max_strings: int = 300_000,
    max_classes: int = 50_000,
    max_members: int = 500_000,
    include_references: bool = False,
    max_instruction_units: int = 500_000,
    max_references: int = 200_000,
) -> DexIndex:
    """Index every root-level ``classes*.dex`` file in an APK."""

    if artifact_type != "apk":
        raise UnsupportedError(
            f"DEX indexing is implemented for APK containers, not {artifact_type}.",
            hint="Use an APK, or unpack split/module containers before indexing.",
            details={"artifact_type": artifact_type},
        )
    if not zipfile.is_zipfile(path):
        raise InvalidArtifactError("Artifact is not a readable ZIP container.")

    index = DexIndex(
        limitations=[
            "DEX indexing is metadata-only; method bodies are not disassembled.",
            (
                "Only root-level classes*.dex files are indexed; split or nested DEX "
                "files are not merged."
            ),
        ]
    )
    with zipfile.ZipFile(path) as archive:
        names = sorted(
            (info.filename for info in archive.infolist() if _is_dex_name(info.filename)),
            key=_dex_sort_key,
        )
    if not names:
        index.limitations.append("No root-level classes.dex file was found.")
    for name in names:
        try:
            from raa.services.inspection import read_archive_member

            data = read_archive_member(path, name, max_bytes=max_bytes)
            index.files.append(
                parse_dex(
                    data,
                    name=name,
                    max_strings=max_strings,
                    max_classes=max_classes,
                    max_members=max_members,
                    include_references=include_references,
                    max_instruction_units=max_instruction_units,
                    max_references=max_references,
                )
            )
        except (InvalidArtifactError, LimitExceededError, UnsupportedError) as exc:
            index.files.append(
                ParsedDex(
                    name=name,
                    size_bytes=0,
                    version=None,
                    checksum=None,
                    checksum_valid=None,
                    signature_valid=None,
                    strings=[],
                    classes=[],
                    error=f"{exc.code}: {exc.message}",
                )
            )
    return index


def _is_dex_name(name: str) -> bool:
    if "/" in name or not name.startswith("classes") or not name.endswith(".dex"):
        return False
    suffix = name[len("classes") : -len(".dex")]
    return suffix == "" or suffix.isdigit()


def _dex_sort_key(name: str) -> tuple[int, str]:
    suffix = name[len("classes") : -len(".dex")]
    if suffix == "":
        return (1, name)
    return (int(suffix), name)


def parse_dex(
    data: bytes,
    *,
    name: str = "classes.dex",
    max_strings: int = 300_000,
    max_classes: int = 50_000,
    max_members: int = 500_000,
    include_references: bool = False,
    max_instruction_units: int = 500_000,
    max_references: int = 200_000,
) -> ParsedDex:
    """Decode one DEX file's identifier and class-definition tables."""

    if len(data) < _HEADER_SIZE:
        raise InvalidArtifactError("DEX file is smaller than its header.")
    magic = data[:8]
    if magic.startswith(b"cdex"):
        raise UnsupportedError(
            "Compact DEX (cdex) is not supported by the built-in indexer.",
            details={"file": name},
        )
    if not magic.startswith(b"dex\n") or magic[7] != 0:
        raise InvalidArtifactError(
            "File does not start with a DEX magic value.",
            details={"file": name},
        )
    version = magic[4:7].decode("ascii", errors="replace")
    file_size = struct.unpack_from("<I", data, 0x20)[0]
    header_size = struct.unpack_from("<I", data, 0x24)[0]
    if header_size < _HEADER_SIZE or header_size > file_size or file_size > len(data):
        raise InvalidArtifactError(
            "DEX header size or file size is invalid.",
            details={"file": name, "header_size": header_size, "file_size": file_size},
        )
    endian = struct.unpack_from("<I", data, 0x28)[0]
    if endian != _ENDIAN_CONSTANT:
        raise InvalidArtifactError(
            "DEX endian tag is not supported.",
            details={"file": name, "endian_tag": f"0x{endian:08x}"},
        )
    declared_checksum = struct.unpack_from("<I", data, 0x08)[0]
    checksum_valid = (zlib.adler32(data[0x0C:file_size]) & 0xFFFFFFFF) == declared_checksum
    # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
    signature_valid = (
        hashlib.sha1(data[0x20:file_size], usedforsecurity=False).digest() == data[0x0C:0x20]
    )

    string_count, string_off = _table(data, file_size, 0x38, name, "string")
    type_count, type_off = _table(data, file_size, 0x40, name, "type")
    proto_count, proto_off = _table(data, file_size, 0x48, name, "proto")
    field_count, field_off = _table(data, file_size, 0x50, name, "field")
    method_count, method_off = _table(data, file_size, 0x58, name, "method")
    class_count, class_off = _table(data, file_size, 0x60, name, "class")

    for label, count, limit in (
        ("string", string_count, max_strings),
        ("type", type_count, max_strings),
        ("proto", proto_count, max_members),
        ("field", field_count, max_members),
        ("method", method_count, max_members),
        ("class", class_count, max_classes),
    ):
        if count > limit:
            raise LimitExceededError(
                f"DEX {label} table exceeds the configured limit.",
                details={"file": name, "count": count, "limit": limit},
            )

    strings = _parse_strings(data, file_size, string_count, string_off, name)
    types = _parse_types(data, file_size, type_count, type_off, strings, name)
    protocol_descriptors = _parse_protos(
        data, file_size, proto_count, proto_off, types, max_members, name
    )
    field_ids = _parse_field_ids(data, file_size, field_count, field_off, types, strings, name)
    method_ids = _parse_method_ids(
        data,
        file_size,
        method_count,
        method_off,
        types,
        protocol_descriptors,
        strings,
        name,
    )
    classes = _parse_classes(
        data,
        file_size,
        class_count,
        class_off,
        types,
        strings,
        field_ids,
        method_ids,
        max_members,
        name,
    )
    references: list[ParsedReference] = []
    reference_warnings: list[str] = []
    if include_references:
        references, reference_warnings = _parse_references(
            data,
            file_size,
            classes,
            types,
            strings,
            field_ids,
            method_ids,
            max_instruction_units=max_instruction_units,
            max_references=max_references,
        )
    return ParsedDex(
        name=name,
        size_bytes=len(data),
        version=version,
        checksum=f"{declared_checksum:08x}",
        checksum_valid=checksum_valid,
        signature_valid=signature_valid,
        strings=strings,
        classes=classes,
        references=references,
        reference_warnings=reference_warnings,
    )


def _table(
    data: bytes,
    file_size: int,
    offset: int,
    name: str,
    label: str,
) -> tuple[int, int]:
    count = struct.unpack_from("<I", data, offset)[0]
    start = struct.unpack_from("<I", data, offset + 4)[0]
    if count == 0:
        return 0, 0
    if start > file_size:
        raise InvalidArtifactError(
            f"DEX {label} table offset is outside the file.",
            details={"file": name, "offset": start},
        )
    return count, start


def _parse_strings(
    data: bytes,
    file_size: int,
    count: int,
    offset: int,
    name: str,
) -> list[str]:
    if count and offset + count * 4 > file_size:
        raise InvalidArtifactError(
            "DEX string identifier table is truncated.",
            details={"file": name},
        )
    strings: list[str] = []
    for index in range(count):
        string_off = struct.unpack_from("<I", data, offset + index * 4)[0]
        if string_off >= file_size:
            raise InvalidArtifactError(
                "DEX string data offset is outside the file.",
                details={"file": name, "index": index},
            )
        strings.append(_read_mutf8(data, string_off, file_size, name, index))
    return strings


def _read_mutf8(
    data: bytes,
    offset: int,
    end: int,
    name: str,
    index: int,
) -> str:
    cursor = _Cursor(data, offset, end, "DEX string data")
    utf16_length = cursor.uleb128()
    raw = bytearray()
    while True:
        if cursor.position >= end:
            raise InvalidArtifactError(
                "DEX string data is not NUL-terminated.",
                details={"file": name, "index": index},
            )
        byte = cursor.u1()
        if byte == 0:
            break
        raw.append(byte)
        if len(raw) > _MAX_STRING_RAW_BYTES:
            raise LimitExceededError(
                "DEX string exceeds the configured raw byte limit.",
                details={"file": name, "index": index},
            )
    value = _decode_mutf8(bytes(raw), name, index)
    if _utf16_units(value) != utf16_length:
        raise InvalidArtifactError(
            "DEX string length does not match its declared UTF-16 length.",
            details={"file": name, "index": index},
        )
    return value


def _decode_mutf8(raw: bytes, name: str, index: int) -> str:
    units: list[int] = []
    position = 0
    while position < len(raw):
        byte = raw[position]
        if byte < 0x80:
            units.append(byte)
            position += 1
            continue
        if byte & 0xE0 == 0xC0:
            if position + 1 >= len(raw) or raw[position + 1] & 0xC0 != 0x80:
                raise InvalidArtifactError(
                    "DEX string contains invalid modified UTF-8.",
                    details={"file": name, "index": index},
                )
            units.append(((byte & 0x1F) << 6) | (raw[position + 1] & 0x3F))
            position += 2
            continue
        if byte & 0xF0 == 0xE0:
            if (
                position + 2 >= len(raw)
                or raw[position + 1] & 0xC0 != 0x80
                or raw[position + 2] & 0xC0 != 0x80
            ):
                raise InvalidArtifactError(
                    "DEX string contains invalid modified UTF-8.",
                    details={"file": name, "index": index},
                )
            units.append(
                ((byte & 0x0F) << 12)
                | ((raw[position + 1] & 0x3F) << 6)
                | (raw[position + 2] & 0x3F)
            )
            position += 3
            continue
        raise InvalidArtifactError(
            "DEX string contains invalid modified UTF-8.",
            details={"file": name, "index": index},
        )

    chars: list[str] = []
    position = 0
    while position < len(units):
        unit = units[position]
        if 0xD800 <= unit <= 0xDBFF and position + 1 < len(units):
            low = units[position + 1]
            if 0xDC00 <= low <= 0xDFFF:
                chars.append(chr(0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00)))
                position += 2
                continue
        chars.append(chr(unit))
        position += 1
    return "".join(chars)


def _utf16_units(value: str) -> int:
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _parse_types(
    data: bytes,
    file_size: int,
    count: int,
    offset: int,
    strings: list[str],
    name: str,
) -> list[str]:
    if count and offset + count * 4 > file_size:
        raise InvalidArtifactError(
            "DEX type identifier table is truncated.",
            details={"file": name},
        )
    types: list[str] = []
    for index in range(count):
        string_index = struct.unpack_from("<I", data, offset + index * 4)[0]
        if string_index >= len(strings):
            raise InvalidArtifactError(
                "DEX type descriptor index is out of range.",
                details={"file": name, "index": index},
            )
        types.append(strings[string_index])
    return types


def _parse_protos(
    data: bytes,
    file_size: int,
    count: int,
    offset: int,
    types: list[str],
    max_members: int,
    name: str,
) -> list[str]:
    if count and offset + count * 12 > file_size:
        raise InvalidArtifactError(
            "DEX prototype identifier table is truncated.",
            details={"file": name},
        )
    descriptors: list[str] = []
    for index in range(count):
        base = offset + index * 12
        _ = struct.unpack_from("<I", data, base)[0]
        return_index = struct.unpack_from("<I", data, base + 4)[0]
        parameters_off = struct.unpack_from("<I", data, base + 8)[0]
        if return_index >= len(types):
            raise InvalidArtifactError(
                "DEX prototype return type is out of range.",
                details={"file": name, "index": index},
            )
        parameters = _parse_type_list(
            data,
            file_size,
            parameters_off,
            types,
            max_members,
            name,
        )
        descriptors.append(f"({''.join(parameters)}){types[return_index]}")
    return descriptors


def _parse_type_list(
    data: bytes,
    file_size: int,
    offset: int,
    types: list[str],
    max_members: int,
    name: str,
) -> list[str]:
    if offset == 0:
        return []
    if offset + 4 > file_size:
        raise InvalidArtifactError(
            "DEX type list is outside the file.",
            details={"file": name, "offset": offset},
        )
    count = struct.unpack_from("<I", data, offset)[0]
    if count > max_members:
        raise LimitExceededError(
            "DEX type list exceeds the configured member limit.",
            details={"file": name, "count": count},
        )
    required = offset + 4 + count * 2
    if required > file_size:
        raise InvalidArtifactError(
            "DEX type list is truncated.",
            details={"file": name, "offset": offset},
        )
    values: list[str] = []
    for index in range(count):
        type_index = struct.unpack_from("<H", data, offset + 4 + index * 2)[0]
        if type_index >= len(types):
            raise InvalidArtifactError(
                "DEX type list entry is out of range.",
                details={"file": name, "index": index},
            )
        values.append(types[type_index])
    return values


def _parse_field_ids(
    data: bytes,
    file_size: int,
    count: int,
    offset: int,
    types: list[str],
    strings: list[str],
    name: str,
) -> list[tuple[str, str, str]]:
    if count and offset + count * 8 > file_size:
        raise InvalidArtifactError(
            "DEX field identifier table is truncated.",
            details={"file": name},
        )
    fields: list[tuple[str, str, str]] = []
    for index in range(count):
        base = offset + index * 8
        class_index = struct.unpack_from("<H", data, base)[0]
        type_index = struct.unpack_from("<H", data, base + 2)[0]
        name_index = struct.unpack_from("<I", data, base + 4)[0]
        if class_index >= len(types) or type_index >= len(types):
            raise InvalidArtifactError(
                "DEX field type index is out of range.",
                details={"file": name, "index": index},
            )
        if name_index >= len(strings):
            raise InvalidArtifactError(
                "DEX field name index is out of range.",
                details={"file": name, "index": index},
            )
        fields.append((types[class_index], strings[name_index], types[type_index]))
    return fields


def _parse_method_ids(
    data: bytes,
    file_size: int,
    count: int,
    offset: int,
    types: list[str],
    proto_descriptors: list[str],
    strings: list[str],
    name: str,
) -> list[tuple[str, str, str]]:
    if count and offset + count * 8 > file_size:
        raise InvalidArtifactError(
            "DEX method identifier table is truncated.",
            details={"file": name},
        )
    methods: list[tuple[str, str, str]] = []
    for index in range(count):
        base = offset + index * 8
        class_index = struct.unpack_from("<H", data, base)[0]
        proto_index = struct.unpack_from("<H", data, base + 2)[0]
        name_index = struct.unpack_from("<I", data, base + 4)[0]
        if class_index >= len(types):
            raise InvalidArtifactError(
                "DEX method class index is out of range.",
                details={"file": name, "index": index},
            )
        if proto_index >= len(proto_descriptors):
            raise InvalidArtifactError(
                "DEX method prototype index is out of range.",
                details={"file": name, "index": index},
            )
        if name_index >= len(strings):
            raise InvalidArtifactError(
                "DEX method name index is out of range.",
                details={"file": name, "index": index},
            )
        methods.append(
            (
                types[class_index],
                strings[name_index],
                proto_descriptors[proto_index],
            )
        )
    return methods


def _parse_classes(
    data: bytes,
    file_size: int,
    count: int,
    offset: int,
    types: list[str],
    strings: list[str],
    field_ids: list[tuple[str, str, str]],
    method_ids: list[tuple[str, str, str]],
    max_members: int,
    name: str,
) -> list[ParsedClass]:
    if count and offset + count * 32 > file_size:
        raise InvalidArtifactError(
            "DEX class definition table is truncated.",
            details={"file": name},
        )

    classes: list[ParsedClass] = []
    member_budget = 0
    for index in range(count):
        base = offset + index * 32
        class_index = struct.unpack_from("<I", data, base)[0]
        access_flags = struct.unpack_from("<I", data, base + 4)[0]
        superclass_index = struct.unpack_from("<I", data, base + 8)[0]
        interfaces_off = struct.unpack_from("<I", data, base + 12)[0]
        source_file_index = struct.unpack_from("<I", data, base + 16)[0]
        class_data_off = struct.unpack_from("<I", data, base + 24)[0]
        if class_index >= len(types):
            raise InvalidArtifactError(
                "DEX class type index is out of range.",
                details={"file": name, "index": index},
            )
        if superclass_index != _NO_INDEX and superclass_index >= len(types):
            raise InvalidArtifactError(
                "DEX superclass index is out of range.",
                details={"file": name, "index": index},
            )
        if source_file_index != _NO_INDEX and source_file_index >= len(strings):
            raise InvalidArtifactError(
                "DEX source file index is out of range.",
                details={"file": name, "index": index},
            )
        interfaces = _parse_type_list(
            data,
            file_size,
            interfaces_off,
            types,
            max_members,
            name,
        )
        fields, methods = _parse_class_data(
            data,
            file_size,
            class_data_off,
            field_ids,
            method_ids,
            max_members,
            name,
        )
        member_budget += len(fields) + len(methods)
        if member_budget > max_members:
            raise LimitExceededError(
                "DEX class members exceed the configured limit.",
                details={"file": name, "limit": max_members},
            )
        descriptor = types[class_index]
        classes.append(
            ParsedClass(
                name=display_name(descriptor),
                descriptor=descriptor,
                access_flags=access_flags,
                superclass=(
                    display_name(types[superclass_index]) if superclass_index != _NO_INDEX else None
                ),
                interfaces=[display_name(item) for item in interfaces],
                source_file=(
                    strings[source_file_index] if source_file_index != _NO_INDEX else None
                ),
                dex_file=name,
                fields=fields,
                methods=methods,
            )
        )
    return classes


def _parse_class_data(
    data: bytes,
    file_size: int,
    offset: int,
    field_ids: list[tuple[str, str, str]],
    method_ids: list[tuple[str, str, str]],
    max_members: int,
    name: str,
) -> tuple[list[ParsedField], list[ParsedMethod]]:
    if offset == 0:
        return [], []
    cursor = _Cursor(data, offset, file_size, "DEX class data")
    static_count = cursor.uleb128()
    instance_count = cursor.uleb128()
    direct_count = cursor.uleb128()
    virtual_count = cursor.uleb128()
    total = static_count + instance_count + direct_count + virtual_count
    if total > max_members:
        raise LimitExceededError(
            "DEX class data exceeds the configured member limit.",
            details={"file": name, "count": total, "limit": max_members},
        )

    fields: list[ParsedField] = []
    for count in (static_count, instance_count):
        field_index = 0
        for _ in range(count):
            field_index += cursor.uleb128()
            access_flags = cursor.uleb128()
            if field_index >= len(field_ids):
                raise InvalidArtifactError(
                    "DEX field index is out of range.",
                    details={"file": name, "index": field_index},
                )
            _, field_name, field_type = field_ids[field_index]
            fields.append(
                ParsedField(
                    name=field_name,
                    descriptor=field_type,
                    access_flags=access_flags,
                )
            )

    methods: list[ParsedMethod] = []
    for count in (direct_count, virtual_count):
        method_index = 0
        for _ in range(count):
            method_index += cursor.uleb128()
            access_flags = cursor.uleb128()
            code_offset = cursor.uleb128()
            if method_index >= len(method_ids):
                raise InvalidArtifactError(
                    "DEX method index is out of range.",
                    details={"file": name, "index": method_index},
                )
            _, method_name, descriptor = method_ids[method_index]
            methods.append(
                ParsedMethod(
                    name=method_name,
                    descriptor=descriptor,
                    access_flags=access_flags,
                    code_offset=code_offset or None,
                )
            )
    return fields, methods


def _parse_references(
    data: bytes,
    file_size: int,
    classes: list[ParsedClass],
    types: list[str],
    strings: list[str],
    field_ids: list[tuple[str, str, str]],
    method_ids: list[tuple[str, str, str]],
    *,
    max_instruction_units: int,
    max_references: int,
) -> tuple[list[ParsedReference], list[str]]:
    references: list[ParsedReference] = []
    warnings: list[str] = []
    for klass in classes:
        for method in klass.methods:
            if method.code_offset is None:
                continue
            label = f"{klass.name}#{method.name}{method.descriptor}"
            try:
                found = _parse_code_references(
                    data,
                    file_size,
                    method.code_offset,
                    klass,
                    method,
                    types,
                    strings,
                    field_ids,
                    method_ids,
                    max_instruction_units=max_instruction_units,
                )
            except (InvalidArtifactError, LimitExceededError) as exc:
                warnings.append(f"{label} could not be scanned: {exc.message}")
                continue
            remaining = max_references - len(references)
            if len(found) > remaining:
                references.extend(found[:remaining])
                warnings.append(
                    "Reference indexing stopped at the configured limit of "
                    f"{max_references} references."
                )
                return references, warnings
            references.extend(found)
    return references, warnings


def _parse_code_references(
    data: bytes,
    file_size: int,
    offset: int,
    klass: ParsedClass,
    method: ParsedMethod,
    types: list[str],
    strings: list[str],
    field_ids: list[tuple[str, str, str]],
    method_ids: list[tuple[str, str, str]],
    *,
    max_instruction_units: int,
) -> list[ParsedReference]:
    if offset + 16 > file_size:
        raise InvalidArtifactError("DEX code item is outside the file.")
    insns_size = struct.unpack_from("<I", data, offset + 12)[0]
    if insns_size == 0:
        return []
    if insns_size > max_instruction_units:
        raise LimitExceededError(
            "DEX method code exceeds the configured instruction limit.",
            details={"method": method.name, "count": insns_size, "limit": max_instruction_units},
        )
    start = offset + 16
    if start + insns_size * 2 > file_size:
        raise InvalidArtifactError("DEX code item instructions are truncated.")
    units = struct.unpack_from(f"<{insns_size}H", data, start)

    references: list[ParsedReference] = []
    cursor = 0
    while cursor < insns_size:
        reference = _reference_at(
            units,
            cursor,
            klass=klass,
            method=method,
            types=types,
            strings=strings,
            field_ids=field_ids,
            method_ids=method_ids,
            dex_file=klass.dex_file,
        )
        if reference is not None:
            references.append(reference)
        width = _instruction_units(units, cursor)
        if width < 1 or cursor + width > insns_size:
            raise InvalidArtifactError(
                "DEX instruction stream is truncated.",
                details={"method": method.name, "offset": cursor, "width": width},
            )
        cursor += width
    return references


def _reference_at(
    units: tuple[int, ...],
    cursor: int,
    *,
    klass: ParsedClass,
    method: ParsedMethod,
    types: list[str],
    strings: list[str],
    field_ids: list[tuple[str, str, str]],
    method_ids: list[tuple[str, str, str]],
    dex_file: str,
) -> ParsedReference | None:
    opcode = units[cursor] & 0xFF

    def make(
        kind: ReferenceKind,
        target: str,
        target_class: str | None,
        target_name: str | None,
        target_descriptor: str | None,
        value: str | None,
    ) -> ParsedReference:
        return ParsedReference(
            kind=kind,
            from_class=klass.name,
            from_method=method.name,
            from_descriptor=method.descriptor,
            target=target,
            target_class=target_class,
            target_name=target_name,
            target_descriptor=target_descriptor,
            value=value,
            opcode=opcode,
            offset=cursor,
            dex_file=dex_file,
        )

    if opcode in _METHOD_CALL_OPS:
        index = units[cursor + 1]
        if index >= len(method_ids):
            raise InvalidArtifactError(
                "DEX method reference index is out of range.",
                details={"method": method.name, "index": index},
            )
        class_descriptor, name, descriptor = method_ids[index]
        target_class = display_name(class_descriptor)
        return make(
            "method_call",
            f"{target_class}#{name}{descriptor}",
            target_class,
            name,
            descriptor,
            None,
        )

    if opcode in _FIELD_ACCESS_OPS:
        index = units[cursor + 1]
        if index >= len(field_ids):
            raise InvalidArtifactError(
                "DEX field reference index is out of range.",
                details={"method": method.name, "index": index},
            )
        class_descriptor, name, descriptor = field_ids[index]
        target_class = display_name(class_descriptor)
        return make(
            "field_access",
            f"{target_class}#{name}:{descriptor}",
            target_class,
            name,
            descriptor,
            None,
        )

    if opcode in _STRING_REFERENCE_21C or opcode in _STRING_REFERENCE_31C:
        index = units[cursor + 1]
        if opcode in _STRING_REFERENCE_31C:
            index |= units[cursor + 2] << 16
        if index >= len(strings):
            raise InvalidArtifactError(
                "DEX string reference index is out of range.",
                details={"method": method.name, "index": index},
            )
        value = strings[index]
        return make("string_reference", value, None, None, None, value)

    if opcode in _TYPE_REFERENCE_OPS:
        index = units[cursor + 1]
        if index >= len(types):
            raise InvalidArtifactError(
                "DEX type reference index is out of range.",
                details={"method": method.name, "index": index},
            )
        descriptor = types[index]
        return make(
            "type_reference",
            display_name(descriptor),
            None,
            None,
            descriptor,
            None,
        )

    return None


def _instruction_units(units: tuple[int, ...], cursor: int) -> int:
    unit = units[cursor]
    if unit == 0x0100:
        if cursor + 1 >= len(units):
            raise InvalidArtifactError("Truncated packed-switch payload.")
        return 4 + 2 * units[cursor + 1]
    if unit == 0x0200:
        if cursor + 1 >= len(units):
            raise InvalidArtifactError("Truncated sparse-switch payload.")
        return 2 + 4 * units[cursor + 1]
    if unit == 0x0300:
        if cursor + 3 >= len(units):
            raise InvalidArtifactError("Truncated fill-array-data payload.")
        element_width = units[cursor + 1]
        size = units[cursor + 2] | (units[cursor + 3] << 16)
        return 4 + ((size * element_width + 3) // 4) * 2
    opcode = unit & 0xFF
    width = _WIDTHS.get(opcode)
    if width is None:
        raise InvalidArtifactError(
            f"Unsupported Dalvik opcode 0x{opcode:02x}.",
            details={"offset": cursor},
        )
    return width


def display_name(descriptor: str) -> str:
    if descriptor.startswith("L") and descriptor.endswith(";"):
        return descriptor[1:-1].replace("/", ".")
    return descriptor


def access_labels(flags: int, kind: str) -> list[str]:
    table = {
        "class": _CLASS_FLAGS,
        "field": _FIELD_FLAGS,
        "method": _METHOD_FLAGS,
    }[kind]
    return [label for bit, label in table if flags & bit]
