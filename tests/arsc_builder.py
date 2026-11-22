"""Synthetic ``resources.arsc`` fixtures.

The builder emits the binary table format documented in AOSP
``ResourceTypes.h``. It is intentionally small and declarative so tests can
exercise packages, type configurations, complex styles and file references
without shipping a real APK.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

_RES_STRING_POOL_TYPE = 0x0001
_RES_TABLE_TYPE = 0x0002
_RES_TABLE_PACKAGE_TYPE = 0x0200
_RES_TABLE_TYPE_TYPE = 0x0201
_RES_TABLE_TYPE_SPEC_TYPE = 0x0202

_UTF8_FLAG = 0x100

_TYPE_REFERENCE = 0x01
_TYPE_STRING = 0x03
_TYPE_DIMENSION = 0x05
_TYPE_INT_BOOLEAN = 0x12
_TYPE_INT_COLOR_ARGB8 = 0x1C

_ENTRY_FLAG_COMPLEX = 0x0001

_DEFAULT_CONFIG = struct.pack("<I", 64) + bytes(60)
_FRENCH_CONFIG = struct.pack("<I", 64) + struct.pack("<HH", 0, 0) + b"fr" + b"FR" + bytes(52)
_HDpi_CONFIG = (
    struct.pack("<I", 64)
    + struct.pack("<HH", 0, 0)
    + bytes(4)
    + bytes(2)
    + struct.pack("<H", 240)
    + bytes(48)
)


@dataclass(frozen=True, slots=True)
class SimpleEntry:
    """One resource entry with a direct value."""

    index: int
    key: str
    value_type: int
    data: int


@dataclass(frozen=True, slots=True)
class ComplexEntry:
    """One resource entry with a map, such as a style or array."""

    index: int
    key: str
    maps: tuple[tuple[int, int, int], ...] = ()
    parent: int = 0


EntrySpec = SimpleEntry | ComplexEntry


@dataclass(slots=True)
class ResourceTypeSpec:
    """One ``ResTable_type`` chunk and its entries."""

    type_id: int
    name: str
    entries: list[EntrySpec]
    config: bytes = _DEFAULT_CONFIG
    flags: int = 0


@dataclass(slots=True)
class ResourceTableSpec:
    package_id: int = 0x7F
    package_name: str = "com.example.demo"
    strings: list[str] = field(default_factory=list)
    types: list[ResourceTypeSpec] = field(default_factory=list)


def string_pool(strings: list[str], *, utf8: bool = True) -> bytes:
    """Encode a ``ResStringPool`` chunk."""

    offsets: list[int] = []
    payload = bytearray()
    for value in strings:
        offsets.append(len(payload))
        if utf8:
            encoded = value.encode("utf-8")
            payload += _utf8_length(len(value.encode("utf-16-le")) // 2)
            payload += _utf8_length(len(encoded))
            payload += encoded + b"\x00"
        else:
            encoded = value.encode("utf-16-le")
            payload += struct.pack("<H", len(encoded) // 2)
            payload += encoded + b"\x00\x00"
    header_size = 28
    strings_start = header_size + len(offsets) * 4
    size = strings_start + len(payload)
    padding = (-size) % 4
    return (
        struct.pack("<HHI", _RES_STRING_POOL_TYPE, header_size, size + padding)
        + struct.pack(
            "<IIIII",
            len(strings),
            0,
            _UTF8_FLAG if utf8 else 0,
            strings_start,
            0,
        )
        + b"".join(struct.pack("<I", offset) for offset in offsets)
        + bytes(payload)
        + bytes(padding)
    )


def build_resource_table(
    spec: ResourceTableSpec,
    *,
    utf8_strings: bool = True,
) -> bytes:
    """Encode a complete ``ResTable`` chunk from a declarative spec."""

    type_strings: list[str] = []
    for item in spec.types:
        if item.type_id > len(type_strings):
            type_strings.extend(["?"] * (item.type_id - len(type_strings)))
        if type_strings[item.type_id - 1] == "?":
            type_strings[item.type_id - 1] = item.name
    key_names: list[str] = []
    for item in spec.types:
        for entry in item.entries:
            if entry.key not in key_names:
                key_names.append(entry.key)

    type_pool = string_pool(type_strings, utf8=utf8_strings)
    key_pool = string_pool(key_names, utf8=utf8_strings)
    package_header_size = 288
    type_pool_offset = package_header_size
    key_pool_offset = type_pool_offset + len(type_pool)

    body = bytearray()
    body += type_pool
    body += key_pool
    entry_counts: dict[int, int] = {}
    for item in spec.types:
        entry_counts[item.type_id] = max(
            entry_counts.get(item.type_id, 0),
            max((entry.index for entry in item.entries), default=-1) + 1,
        )
    for type_id, entry_count in entry_counts.items():
        body += _type_spec(type_id, entry_count)
    for item in spec.types:
        body += _type_chunk(item, _key_index(key_names, item))

    package_size = package_header_size + len(body)
    encoded_name = spec.package_name.encode("utf-16-le")[:254]
    package = (
        struct.pack(
            "<HHII",
            _RES_TABLE_PACKAGE_TYPE,
            package_header_size,
            package_size,
            spec.package_id,
        )
        + encoded_name.ljust(256, b"\x00")
        + struct.pack(
            "<IIIII",
            type_pool_offset,
            len(type_strings),
            key_pool_offset,
            len(key_names),
            0,
        )
        + bytes(body)
    )

    global_pool = string_pool(spec.strings, utf8=utf8_strings)
    table_size = 12 + len(global_pool) + len(package)
    return struct.pack("<HHII", _RES_TABLE_TYPE, 12, table_size, 1) + global_pool + package


def build_sample_resource_table(
    *,
    utf8_strings: bool = True,
) -> bytes:
    """A representative table used by the analysis and tool tests."""

    string_entries = [
        SimpleEntry(0, "app_name", _TYPE_STRING, 0),
        SimpleEntry(1, "title", _TYPE_STRING, 1),
        SimpleEntry(2, "main_layout", _TYPE_REFERENCE, 0x7F020000),
        SimpleEntry(3, "optional", _TYPE_INT_BOOLEAN, 1),
    ]
    french_entries = [
        SimpleEntry(0, "app_name", _TYPE_STRING, 1),
        SimpleEntry(1, "title", _TYPE_STRING, 0),
    ]
    hdpi_entries = [SimpleEntry(0, "app_name", _TYPE_STRING, 1)]
    layout_entries = [SimpleEntry(0, "main", _TYPE_STRING, 2)]
    color_entries = [SimpleEntry(0, "accent", _TYPE_INT_COLOR_ARGB8, 0xFF3366CC)]
    style_maps = (
        (0x01010098, _TYPE_REFERENCE, 0x7F030000),
        (0x01010036, _TYPE_DIMENSION, (8 << 8) | 0x01),
        (0x0101000E, _TYPE_INT_BOOLEAN, 1),
    )
    style_entries = [ComplexEntry(0, "AppTheme", style_maps)]
    bool_entries = [SimpleEntry(0, "enabled", _TYPE_INT_BOOLEAN, 1)]
    integer_entries = [SimpleEntry(0, "max_retries", 0x10, 5)]
    dimen_entries = [SimpleEntry(0, "margin", _TYPE_DIMENSION, (16 << 8) | 0x01)]

    spec = ResourceTableSpec(
        strings=[
            "Demo App",
            "Bienvenue",
            "res/layout/main.xml",
            "res/drawable/icon.png",
        ],
        types=[
            ResourceTypeSpec(1, "string", list(string_entries)),
            ResourceTypeSpec(1, "string", list(french_entries), config=_FRENCH_CONFIG),
            ResourceTypeSpec(1, "string", list(hdpi_entries), config=_HDpi_CONFIG),
            ResourceTypeSpec(2, "layout", list(layout_entries)),
            ResourceTypeSpec(3, "color", list(color_entries)),
            ResourceTypeSpec(4, "style", list(style_entries)),
            ResourceTypeSpec(5, "bool", list(bool_entries)),
            ResourceTypeSpec(6, "integer", list(integer_entries)),
            ResourceTypeSpec(7, "dimen", list(dimen_entries)),
        ],
    )
    return build_resource_table(spec, utf8_strings=utf8_strings)


def _type_spec(type_id: int, entry_count: int) -> bytes:
    size = 16 + entry_count * 4
    return struct.pack(
        "<HHIBBHI",
        _RES_TABLE_TYPE_SPEC_TYPE,
        16,
        size,
        type_id,
        0,
        0,
        entry_count,
    ) + bytes(entry_count * 4)


def _type_chunk(
    spec: ResourceTypeSpec,
    key_index: dict[str, int],
) -> bytes:
    header_size = 20 + len(spec.config)
    if spec.flags & 0x01:
        entry_count = len(spec.entries)
        offsets = bytearray()
        data = bytearray()
        for entry in sorted(spec.entries, key=lambda item: item.index):
            offsets += struct.pack("<HH", entry.index, len(data) // 4)
            data += _entry(entry, key_index)
    elif spec.flags & 0x02:
        entry_count = max((entry.index for entry in spec.entries), default=-1) + 1
        offsets = bytearray(b"\xff\xff" * entry_count)
        data = bytearray()
        for entry in sorted(spec.entries, key=lambda item: item.index):
            struct.pack_into("<H", offsets, entry.index * 2, len(data) // 4)
            data += _entry(entry, key_index)
    else:
        entry_count = max((entry.index for entry in spec.entries), default=-1) + 1
        offsets = bytearray(b"\xff\xff\xff\xff" * entry_count)
        data = bytearray()
        for entry in sorted(spec.entries, key=lambda item: item.index):
            struct.pack_into("<I", offsets, entry.index * 4, len(data))
            data += _entry(entry, key_index)
    entries_start = header_size + len(offsets)
    padding = (-entries_start) % 4
    entries_start += padding
    size = entries_start + len(data)
    size += (-size) % 4
    return (
        struct.pack(
            "<HHIBBHII",
            _RES_TABLE_TYPE_TYPE,
            header_size,
            size,
            spec.type_id,
            spec.flags,
            0,
            entry_count,
            entries_start,
        )
        + spec.config
        + bytes(offsets)
        + bytes(padding)
        + bytes(data)
        + bytes(size - entries_start - len(data))
    )


def _entry(entry: EntrySpec, key_index: dict[str, int]) -> bytes:
    index = key_index[entry.key]
    if isinstance(entry, SimpleEntry):
        return struct.pack("<HHI", 8, 0, index) + _value(entry.value_type, entry.data)
    maps = b"".join(
        struct.pack("<I", name) + _value(value_type, data) for name, value_type, data in entry.maps
    )
    return (
        struct.pack(
            "<HHIII",
            16,
            _ENTRY_FLAG_COMPLEX,
            index,
            entry.parent,
            len(entry.maps),
        )
        + maps
    )


def _value(value_type: int, data: int) -> bytes:
    return struct.pack("<HBBI", 8, 0, value_type, data)


def _key_index(key_names: list[str], spec: ResourceTypeSpec) -> dict[str, int]:
    return {entry.key: key_names.index(entry.key) for entry in spec.entries}


def _utf8_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    return bytes([0x80 | (length >> 8), length & 0xFF])
