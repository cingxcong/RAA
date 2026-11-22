"""Bounded Android ``resources.arsc`` decoding.

Only the standard library is used. The decoder indexes packages, types, entry
names and simple values, and skips compact entries that this build does not yet
understand. Every read is bounds-checked and entry/config counts are capped.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from raa.domain.resources import (
    ResourceMapInfo,
    ResourceSummary,
    ResourceTypeSummary,
    ResourceValueInfo,
    ResourceVariantInfo,
)
from raa.errors import InvalidArtifactError, LimitExceededError, UnsupportedError
from raa.services.android.axml import BinaryReader, parse_string_pool
from raa.services.inspection import read_archive_member

RESOURCES_MEMBER = "resources.arsc"

RES_STRING_POOL_TYPE = 0x0001
RES_TABLE_TYPE = 0x0002
RES_TABLE_PACKAGE_TYPE = 0x0200
RES_TABLE_TYPE_TYPE = 0x0201
RES_TABLE_TYPE_SPEC_TYPE = 0x0202

_TYPE_NULL = 0x00
_TYPE_REFERENCE = 0x01
_TYPE_ATTRIBUTE = 0x02
_TYPE_STRING = 0x03
_TYPE_FLOAT = 0x04
_TYPE_DIMENSION = 0x05
_TYPE_FRACTION = 0x06
_TYPE_DYNAMIC_REFERENCE = 0x07
_TYPE_DYNAMIC_ATTRIBUTE = 0x08
_TYPE_INT_DEC = 0x10
_TYPE_INT_HEX = 0x11
_TYPE_INT_BOOLEAN = 0x12
_TYPE_INT_COLOR_ARGB8 = 0x1C
_TYPE_INT_COLOR_RGB8 = 0x1D
_TYPE_INT_COLOR_ARGB4 = 0x1E
_TYPE_INT_COLOR_RGB4 = 0x1F

_ENTRY_FLAG_COMPLEX = 0x0001
_ENTRY_FLAG_COMPACT = 0x0008

_TYPE_FLAG_SPARSE = 0x01
_TYPE_FLAG_OFFSET16 = 0x02

_VALUE_TYPE_NAMES = {
    _TYPE_NULL: "null",
    _TYPE_REFERENCE: "reference",
    _TYPE_ATTRIBUTE: "attribute",
    _TYPE_STRING: "string",
    _TYPE_FLOAT: "float",
    _TYPE_DIMENSION: "dimension",
    _TYPE_FRACTION: "fraction",
    _TYPE_DYNAMIC_REFERENCE: "dynamic_reference",
    _TYPE_DYNAMIC_ATTRIBUTE: "dynamic_attribute",
    _TYPE_INT_DEC: "int",
    _TYPE_INT_HEX: "hex",
    _TYPE_INT_BOOLEAN: "boolean",
    _TYPE_INT_COLOR_ARGB8: "color",
    _TYPE_INT_COLOR_RGB8: "color",
    _TYPE_INT_COLOR_ARGB4: "color",
    _TYPE_INT_COLOR_RGB4: "color",
}

_DIMENSION_UNITS = ("px", "dp", "sp", "pt", "in", "mm")
_FRACTION_UNITS = ("%", "%p")
_RADIX_MULTIPLIERS = (0.00390625, 3.051758e-05, 1.192093e-07, 4.656613e-10)
_DENSITY_NAMES = {
    120: "ldpi",
    160: "mdpi",
    213: "tvdpi",
    240: "hdpi",
    320: "xhdpi",
    480: "xxhdpi",
    640: "xxxhdpi",
    0xFFFE: "anydpi",
    0xFFFF: "nodpi",
}

_MAX_MAPS_PER_ENTRY = 512


@dataclass(frozen=True, slots=True)
class ParsedValue:
    value_type: int
    data: int
    value: str | int | float | bool | None

    def to_info(self) -> ResourceValueInfo:
        return ResourceValueInfo(
            type=_VALUE_TYPE_NAMES.get(self.value_type, f"0x{self.value_type:02x}"),
            data=self.data,
            value=self.value,
        )


@dataclass(frozen=True, slots=True)
class ParsedMap:
    name_resource_id: int
    value: ParsedValue


@dataclass(slots=True)
class ParsedResourceEntry:
    resource_id: int
    package: str
    type: str
    name: str
    entry_index: int
    config: str
    is_default: bool
    complex: bool
    value: ParsedValue | None = None
    parent_resource_id: int | None = None
    map_count: int = 0
    maps: list[ParsedMap] = field(default_factory=list)
    maps_truncated: bool = False

    def variant_info(self) -> ResourceVariantInfo:
        return ResourceVariantInfo(
            resource_id=_format_resource_id(self.resource_id),
            package=self.package,
            type=self.type,
            name=self.name,
            entry_index=self.entry_index,
            config=self.config,
            is_default=self.is_default,
            complex=self.complex,
            value=self.value.to_info() if self.value is not None else None,
            parent=(
                _format_resource_id(self.parent_resource_id)
                if self.parent_resource_id is not None
                else None
            ),
            map_count=self.map_count,
            maps=[
                ResourceMapInfo(
                    name=_format_resource_id(item.name_resource_id),
                    value=item.value.to_info(),
                )
                for item in self.maps
            ],
            maps_truncated=self.maps_truncated,
            file_reference=_file_reference(self.value),
        )


@dataclass(slots=True)
class ParsedResourceTable:
    packages: list[str]
    entries: list[ParsedResourceEntry]
    skipped_compact_entries: int
    skipped_unsupported_chunks: int
    limitations: list[str]

    def summary(self) -> ResourceSummary:
        by_type: dict[str, _TypeStats] = {}
        resource_ids: set[int] = set()
        configs: set[str] = set()
        for entry in self.entries:
            resource_ids.add(entry.resource_id)
            configs.add(entry.config)
            stats = by_type.setdefault(entry.type, _TypeStats())
            stats.ids.add(entry.resource_id)
            stats.configs.add(entry.config)
            stats.values += 1
            if entry.is_default:
                stats.defaults += 1

        types = [
            ResourceTypeSummary(
                type=name,
                entry_count=len(stats.ids),
                value_count=stats.values,
                default_count=stats.defaults,
                config_count=len(stats.configs),
            )
            for name, stats in sorted(by_type.items())
        ]
        return ResourceSummary(
            packages=self.packages,
            entry_count=len(resource_ids),
            value_count=len(self.entries),
            config_count=len(configs),
            types=types,
            skipped_compact_entries=self.skipped_compact_entries,
            skipped_unsupported_chunks=self.skipped_unsupported_chunks,
            limitations=list(self.limitations),
        )


@dataclass(slots=True)
class _TypeStats:
    ids: set[int] = field(default_factory=set)
    configs: set[str] = field(default_factory=set)
    values: int = 0
    defaults: int = 0


@dataclass(slots=True)
class _Budget:
    max_entries: int
    max_configs: int
    max_map_entries: int
    entries: int = 0
    configs: int = 0
    maps: int = 0
    compact_entries: int = 0


def read_resource_table(path: Path, artifact_type: str, *, max_bytes: int) -> bytes:
    """Read the resource table from an APK-family artifact."""

    if artifact_type == "apk":
        return read_archive_member(path, RESOURCES_MEMBER, max_bytes=max_bytes)
    if artifact_type == "aab":
        raise UnsupportedError(
            "AAB resources use protobuf encoding, not resources.arsc.",
            hint="Analyze a derived base APK, or wait for the AAB protobuf decoder.",
        )
    if artifact_type in {"apks", "xapk"}:
        raise UnsupportedError(
            "Split packages keep resource tables inside nested APKs.",
            hint="Ingest the base APK, or wait for nested split resource merging.",
        )
    raise UnsupportedError(f"Resource decoding is not implemented for {artifact_type} containers.")


def decode_resource_table(
    path: Path,
    artifact_type: str,
    *,
    max_bytes: int,
    max_entries: int = 200_000,
    max_strings: int = 500_000,
    max_configs: int = 10_000,
    max_map_entries: int = 100_000,
) -> ParsedResourceTable:
    data = read_resource_table(path, artifact_type, max_bytes=max_bytes)
    return parse_resource_table(
        data,
        max_entries=max_entries,
        max_strings=max_strings,
        max_configs=max_configs,
        max_map_entries=max_map_entries,
    )


def parse_resource_table(
    data: bytes,
    *,
    max_entries: int = 200_000,
    max_strings: int = 500_000,
    max_configs: int = 10_000,
    max_map_entries: int = 100_000,
) -> ParsedResourceTable:
    """Decode ``resources.arsc`` into a bounded resource index."""

    if len(data) < 12:
        raise InvalidArtifactError("Android resource table is too short.")
    header = BinaryReader(data, 0, len(data), "resource table header")
    chunk_type = header.u16()
    header_size = header.u16()
    chunk_size = header.u32()
    if chunk_type != RES_TABLE_TYPE:
        raise InvalidArtifactError(
            "File is not an Android resource table.",
            details={"chunk_type": chunk_type},
        )
    if header_size < 12 or chunk_size < header_size or chunk_size > len(data):
        raise InvalidArtifactError("Android resource table has an invalid header.")
    package_count = header.u32()
    budget = _Budget(
        max_entries=max_entries,
        max_configs=max_configs,
        max_map_entries=max_map_entries,
    )
    limitations: list[str] = [
        "Resource references are reported as IDs and are not resolved across packages.",
        "Resource file paths are returned as strings; files are not extracted.",
    ]
    global_strings: list[str] = []
    packages: list[str] = []
    entries: list[ParsedResourceEntry] = []
    skipped_unsupported = 0
    position = header_size
    while position + 8 <= chunk_size:
        chunk = BinaryReader(data, position, chunk_size, "resource chunk header")
        node_type = chunk.u16()
        node_header_size = chunk.u16()
        node_size = chunk.u32()
        if (
            node_header_size < 8
            or node_size < node_header_size
            or position + node_size > chunk_size
        ):
            raise InvalidArtifactError(
                "Android resource table has an invalid chunk.",
                details={"offset": position, "chunk_type": node_type},
            )
        if node_type == RES_STRING_POOL_TYPE:
            global_strings = parse_string_pool(
                data,
                position,
                node_header_size,
                node_size,
                max_strings=max_strings,
            )
        elif node_type == RES_TABLE_PACKAGE_TYPE:
            package_name, package_entries, package_limitations = _parse_package(
                data,
                position,
                node_header_size,
                node_size,
                global_strings,
                budget,
                max_strings,
            )
            packages.append(package_name)
            entries.extend(package_entries)
            limitations.extend(package_limitations)
        elif node_type not in {RES_TABLE_TYPE_TYPE, RES_TABLE_TYPE_SPEC_TYPE}:
            skipped_unsupported += 1
        position += node_size

    if not packages:
        raise InvalidArtifactError("Android resource table contains no packages.")
    if package_count and len(packages) != package_count:
        limitations.append(
            f"Resource table declares {package_count} package(s) but {len(packages)} were decoded."
        )
    if skipped_unsupported:
        limitations.append(f"{skipped_unsupported} unsupported resource chunk(s) were skipped.")
    if budget.compact_entries:
        noun = "entry was" if budget.compact_entries == 1 else "entries were"
        limitations.append(f"{budget.compact_entries} compact resource {noun} skipped.")
    return ParsedResourceTable(
        packages=packages,
        entries=entries,
        skipped_compact_entries=budget.compact_entries,
        skipped_unsupported_chunks=skipped_unsupported,
        limitations=limitations,
    )


def _parse_package(
    data: bytes,
    start: int,
    header_size: int,
    size: int,
    global_strings: list[str],
    budget: _Budget,
    max_strings: int,
) -> tuple[str, list[ParsedResourceEntry], list[str]]:
    if header_size < 284:
        raise InvalidArtifactError("Android resource package header is too short.")
    end = start + size
    reader = BinaryReader(data, start + 8, end, "resource package")
    package_id = reader.u32()
    raw_name = reader.read(256)
    package_name = raw_name.decode("utf-16-le", errors="replace").split("\x00", 1)[0]
    if not package_name:
        package_name = f"package_0x{package_id:02x}"
    type_strings_offset = reader.u32()
    reader.u32()  # lastPublicType
    key_strings_offset = reader.u32()
    reader.u32()  # lastPublicKey
    type_id_offset = reader.u32() if header_size >= 288 else 0

    type_strings = _parse_pool_at(
        data,
        start,
        end,
        type_strings_offset,
        "resource type strings",
        max_strings,
    )
    key_strings = _parse_pool_at(
        data,
        start,
        end,
        key_strings_offset,
        "resource key strings",
        max_strings,
    )
    if not type_strings:
        raise InvalidArtifactError("Android resource package has no type string pool.")
    if not key_strings:
        raise InvalidArtifactError("Android resource package has no key string pool.")

    entries: list[ParsedResourceEntry] = []
    limitations: list[str] = []
    position = start + header_size
    while position + 8 <= end:
        chunk = BinaryReader(data, position, end, "resource package chunk")
        node_type = chunk.u16()
        node_header_size = chunk.u16()
        node_size = chunk.u32()
        if node_header_size < 8 or node_size < node_header_size or position + node_size > end:
            raise InvalidArtifactError(
                "Android resource package has an invalid chunk.",
                details={"offset": position, "chunk_type": node_type},
            )
        if node_type == RES_TABLE_TYPE_TYPE:
            entries.extend(
                _parse_type(
                    data,
                    position,
                    node_header_size,
                    node_size,
                    package_id,
                    package_name,
                    type_id_offset,
                    type_strings,
                    key_strings,
                    global_strings,
                    budget,
                    limitations,
                )
            )
        position += node_size
    return package_name, entries, limitations


def _parse_pool_at(
    data: bytes,
    start: int,
    end: int,
    offset: int,
    label: str,
    max_strings: int,
) -> list[str]:
    absolute = start + offset
    if absolute < start or absolute + 8 > end:
        raise InvalidArtifactError(f"Android {label} offset is out of bounds.")
    reader = BinaryReader(data, absolute, end, label)
    chunk_type = reader.u16()
    header_size = reader.u16()
    size = reader.u32()
    if chunk_type != RES_STRING_POOL_TYPE:
        raise InvalidArtifactError(
            f"Android {label} does not point to a string pool.",
            details={"chunk_type": chunk_type},
        )
    if header_size < 28 or size < header_size or absolute + size > end:
        raise InvalidArtifactError(f"Android {label} chunk is invalid.")
    return parse_string_pool(
        data,
        absolute,
        header_size,
        size,
        max_strings=max_strings,
    )


def _parse_type(
    data: bytes,
    start: int,
    header_size: int,
    size: int,
    package_id: int,
    package_name: str,
    type_id_offset: int,
    type_strings: list[str],
    key_strings: list[str],
    global_strings: list[str],
    budget: _Budget,
    limitations: list[str],
) -> list[ParsedResourceEntry]:
    if header_size < 20 or size < 20:
        raise InvalidArtifactError("Android resource type chunk is too short.")
    end = start + size
    reader = BinaryReader(data, start + 8, end, "resource type")
    type_id = reader.u8()
    flags = reader.u8()
    reader.u16()  # reserved
    entry_count = reader.u32()
    entries_start = reader.u32()
    config_size = reader.u32()
    if type_id == 0:
        raise InvalidArtifactError("Android resource type ID 0 is invalid.")
    if config_size < 4 or 20 + config_size > header_size:
        raise InvalidArtifactError("Android resource configuration size is invalid.")
    if entries_start < header_size or entries_start > size:
        raise InvalidArtifactError("Android resource entry data offset is invalid.")

    budget.configs += 1
    if budget.configs > budget.max_configs:
        raise LimitExceededError(
            "Android resource table has too many configurations.",
            details={"max_configs": budget.max_configs},
        )

    config_bytes = data[start + 20 : start + header_size]
    config_label, is_default = _config_label(config_bytes)
    type_name = (
        type_strings[type_id - 1] if 0 <= type_id - 1 < len(type_strings) else f"type_{type_id}"
    )
    if type_name.startswith("type_"):
        limitations.append(
            f"Resource type ID {type_id} has no readable type name; a synthetic name is used."
        )
    effective_type_id = (type_id + type_id_offset) & 0xFF

    offset_table = start + header_size
    data_start = start + entries_start
    entries: list[ParsedResourceEntry] = []

    if flags & _TYPE_FLAG_SPARSE:
        table_size = entry_count * 4
        if offset_table + table_size > data_start:
            raise InvalidArtifactError("Android sparse resource table is truncated.")
        for index in range(entry_count):
            item = BinaryReader(data, offset_table + index * 4, data_start, "sparse entry")
            entry_index = item.u16()
            entry_offset = item.u16() * 4
            entry = _parse_entry(
                data,
                data_start + entry_offset,
                end,
                package_id,
                package_name,
                effective_type_id,
                type_name,
                key_strings,
                global_strings,
                entry_index,
                config_label,
                is_default,
                budget,
            )
            if entry is not None:
                entries.append(entry)
    elif flags & _TYPE_FLAG_OFFSET16:
        table_size = entry_count * 2
        if offset_table + table_size > data_start:
            raise InvalidArtifactError("Android 16-bit resource offset table is truncated.")
        for entry_index in range(entry_count):
            offset = _u16_at(data, offset_table + entry_index * 2)
            if offset == 0xFFFF:
                continue
            entry = _parse_entry(
                data,
                data_start + offset * 4,
                end,
                package_id,
                package_name,
                effective_type_id,
                type_name,
                key_strings,
                global_strings,
                entry_index,
                config_label,
                is_default,
                budget,
            )
            if entry is not None:
                entries.append(entry)
    else:
        table_size = entry_count * 4
        if offset_table + table_size > data_start:
            raise InvalidArtifactError("Android resource offset table is truncated.")
        for entry_index in range(entry_count):
            offset = _u32_at(data, offset_table + entry_index * 4)
            if offset == 0xFFFFFFFF:
                continue
            entry = _parse_entry(
                data,
                data_start + offset,
                end,
                package_id,
                package_name,
                effective_type_id,
                type_name,
                key_strings,
                global_strings,
                entry_index,
                config_label,
                is_default,
                budget,
            )
            if entry is not None:
                entries.append(entry)
    return entries


def _parse_entry(
    data: bytes,
    offset: int,
    end: int,
    package_id: int,
    package_name: str,
    type_id: int,
    type_name: str,
    key_strings: list[str],
    global_strings: list[str],
    entry_index: int,
    config: str,
    is_default: bool,
    budget: _Budget,
) -> ParsedResourceEntry | None:
    if offset < 0 or offset + 4 > end:
        raise InvalidArtifactError("Android resource entry is out of bounds.")
    budget.entries += 1
    if budget.entries > budget.max_entries:
        raise LimitExceededError(
            "Android resource table has too many entries.",
            details={"max_entries": budget.max_entries},
        )
    reader = BinaryReader(data, offset, end, "resource entry")
    entry_size = reader.u16()
    entry_flags = reader.u16()
    if entry_flags & _ENTRY_FLAG_COMPACT:
        budget.compact_entries += 1
        return None
    if offset + 8 > end:
        raise InvalidArtifactError("Android resource entry is truncated.")
    key_index = reader.u32()
    if key_index >= len(key_strings):
        raise InvalidArtifactError(
            "Android resource entry references an invalid key string.",
            details={"key_index": key_index, "count": len(key_strings)},
        )
    key_name = key_strings[key_index]
    if not key_name:
        raise InvalidArtifactError("Android resource entry has an empty key name.")
    resource_id = (package_id << 24) | (type_id << 16) | entry_index

    if entry_flags & _ENTRY_FLAG_COMPLEX:
        if entry_size < 16 or offset + 16 > end:
            raise InvalidArtifactError("Android complex resource entry is truncated.")
        map_reader = BinaryReader(data, offset + 8, end, "resource map entry")
        parent = map_reader.u32()
        map_count = map_reader.u32()
        if map_count > budget.max_map_entries:
            raise LimitExceededError(
                "Android complex resource entry has too many map values.",
                details={"map_count": map_count, "max_map_entries": budget.max_map_entries},
            )
        stored = min(map_count, _MAX_MAPS_PER_ENTRY)
        budget.maps += stored
        if budget.maps > budget.max_map_entries:
            raise LimitExceededError(
                "Android resource table has too many map values.",
                details={"max_map_entries": budget.max_map_entries},
            )
        maps: list[ParsedMap] = []
        for index in range(stored):
            map_offset = offset + 16 + index * 12
            if map_offset + 12 > end:
                raise InvalidArtifactError("Android resource map is truncated.")
            item = BinaryReader(data, map_offset, end, "resource map")
            name_resource_id = item.u32()
            maps.append(
                ParsedMap(
                    name_resource_id=name_resource_id,
                    value=_read_value(data, map_offset + 4, end, global_strings),
                )
            )
        return ParsedResourceEntry(
            resource_id=resource_id,
            package=package_name,
            type=type_name,
            name=key_name,
            entry_index=entry_index,
            config=config,
            is_default=is_default,
            complex=True,
            parent_resource_id=parent or None,
            map_count=map_count,
            maps=maps,
            maps_truncated=stored < map_count,
        )

    if entry_size < 8 or offset + entry_size + 8 > end:
        raise InvalidArtifactError("Android simple resource entry is truncated.")
    value = _read_value(data, offset + entry_size, end, global_strings)
    return ParsedResourceEntry(
        resource_id=resource_id,
        package=package_name,
        type=type_name,
        name=key_name,
        entry_index=entry_index,
        config=config,
        is_default=is_default,
        complex=False,
        value=value,
    )


def _read_value(data: bytes, offset: int, end: int, strings: list[str]) -> ParsedValue:
    if offset < 0 or offset + 8 > end:
        raise InvalidArtifactError("Android resource value is out of bounds.")
    reader = BinaryReader(data, offset, end, "resource value")
    value_size = reader.u16()
    reader.u8()  # res0
    value_type = reader.u8()
    value_data = reader.u32()
    if value_size < 8:
        raise InvalidArtifactError("Android resource value size is invalid.")
    return _decode_value(value_type, value_data, strings)


def _decode_value(value_type: int, data: int, strings: list[str]) -> ParsedValue:
    if value_type == _TYPE_STRING:
        if data >= len(strings):
            raise InvalidArtifactError(
                "Android resource value references an invalid string.",
                details={"index": data, "count": len(strings)},
            )
        return ParsedValue(value_type=value_type, data=data, value=strings[data])
    if value_type == _TYPE_INT_BOOLEAN:
        return ParsedValue(value_type=value_type, data=data, value=data != 0)
    if value_type in {_TYPE_INT_DEC, _TYPE_INT_HEX}:
        return ParsedValue(value_type=value_type, data=data, value=data)
    if value_type == _TYPE_FLOAT:
        return ParsedValue(
            value_type=value_type,
            data=data,
            value=float(struct.unpack("<f", struct.pack("<I", data))[0]),
        )
    if value_type == _TYPE_REFERENCE:
        return ParsedValue(value_type=value_type, data=data, value=f"@0x{data:08x}")
    if value_type == _TYPE_DYNAMIC_REFERENCE:
        return ParsedValue(value_type=value_type, data=data, value=f"@dynamic/0x{data:08x}")
    if value_type == _TYPE_ATTRIBUTE:
        return ParsedValue(value_type=value_type, data=data, value=f"?0x{data:08x}")
    if value_type == _TYPE_DYNAMIC_ATTRIBUTE:
        return ParsedValue(value_type=value_type, data=data, value=f"?dynamic/0x{data:08x}")
    if value_type == _TYPE_DIMENSION:
        unit_index = data & 0xF
        unit = _DIMENSION_UNITS[unit_index] if unit_index < len(_DIMENSION_UNITS) else ""
        return ParsedValue(
            value_type=value_type,
            data=data,
            value=f"{_complex_value(data):g}{unit}",
        )
    if value_type == _TYPE_FRACTION:
        unit = _FRACTION_UNITS[data & 0xF] if data & 0xF < len(_FRACTION_UNITS) else "%"
        return ParsedValue(
            value_type=value_type,
            data=data,
            value=f"{_complex_value(data):g}{unit}",
        )
    if _TYPE_INT_COLOR_ARGB8 <= value_type <= _TYPE_INT_COLOR_RGB4:
        digits = {
            _TYPE_INT_COLOR_ARGB8: 8,
            _TYPE_INT_COLOR_RGB8: 6,
            _TYPE_INT_COLOR_ARGB4: 4,
            _TYPE_INT_COLOR_RGB4: 3,
        }[value_type]
        return ParsedValue(
            value_type=value_type,
            data=data,
            value=f"#{data:0{digits}x}",
        )
    if value_type == _TYPE_NULL:
        return ParsedValue(value_type=value_type, data=data, value=None)
    return ParsedValue(value_type=value_type, data=data, value=None)


def _complex_value(data: int) -> float:
    mantissa = (data >> 8) & 0xFFFFFF
    if mantissa & 0x800000:
        mantissa -= 0x1000000
    radix = (data >> 4) & 0x3
    return float(mantissa << 8) * _RADIX_MULTIPLIERS[radix]


def _config_label(config: bytes) -> tuple[str, bool]:
    """Return a readable label and whether this is the default configuration."""

    if len(config) < 4:
        return "default", True
    config_size = int(struct.unpack_from("<I", config, 0)[0])
    body_size = min(max(config_size, 4), len(config))
    body = config[4:body_size]
    if not any(body):
        return "default", True

    tokens: list[str] = []

    def u16(offset: int) -> int:
        return int(struct.unpack_from("<H", config, offset)[0]) if offset + 2 <= body_size else 0

    def u8(offset: int) -> int:
        return int(config[offset]) if offset < body_size else 0

    mcc = u16(4)
    mnc = u16(6)
    if mcc:
        tokens.append(f"mcc{mcc}")
    if mnc:
        tokens.append(f"mnc{mnc}")
    language = config[8:10].rstrip(b"\x00").decode("ascii", errors="ignore")
    country = config[10:12].rstrip(b"\x00").decode("ascii", errors="ignore")
    if language:
        tokens.append(language)
    if country:
        tokens.append(f"r{country}")
    orientation = u8(12)
    if orientation in {1, 2, 3}:
        tokens.append(("port", "land", "square")[orientation - 1])
    density = u16(14)
    if density:
        tokens.append(_DENSITY_NAMES.get(density, f"{density}dpi"))
    sdk = u16(24)
    if sdk:
        tokens.append(f"v{sdk}")
    screen_layout = u8(28)
    size_bits = screen_layout & 0x0F
    if size_bits in {1, 2, 3, 4}:
        tokens.append(("small", "normal", "large", "xlarge")[size_bits - 1])
    ui_mode = u8(29)
    if ui_mode & 0x30 == 0x20:
        tokens.append("night")
    smallest_width = u16(30)
    if smallest_width:
        tokens.append(f"sw{smallest_width}dp")
    width_dp = u16(32)
    height_dp = u16(34)
    if width_dp:
        tokens.append(f"w{width_dp}dp")
    if height_dp:
        tokens.append(f"h{height_dp}dp")
    script = config[36:40].rstrip(b"\x00").decode("ascii", errors="ignore")
    variant = config[40:48].rstrip(b"\x00").decode("ascii", errors="ignore")
    if script:
        tokens.append(script)
    if variant:
        tokens.append(variant)

    if not tokens:
        tokens.append(f"config_{body[:8].hex()}")
    return "-".join(tokens), False


def _file_reference(value: ParsedValue | None) -> str | None:
    if value is None or value.value_type != _TYPE_STRING:
        return None
    if isinstance(value.value, str) and value.value.startswith(("res/", "assets/")):
        return value.value
    return None


def _format_resource_id(resource_id: int) -> str:
    return f"0x{resource_id:08x}"


def _u16_at(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise InvalidArtifactError("Android resource table read is out of bounds.")
    return int(struct.unpack_from("<H", data, offset)[0])


def _u32_at(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise InvalidArtifactError("Android resource table read is out of bounds.")
    return int(struct.unpack_from("<I", data, offset)[0])
