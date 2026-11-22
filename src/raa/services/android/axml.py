"""Android resource types and binary XML decoding.

This module intentionally depends only on the standard library. It decodes the
subset of AXML used by manifests, layouts and resource files, with explicit size
checks so a malformed artifact cannot crash or exhaust the worker.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

from raa.errors import InvalidArtifactError, LimitExceededError

ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android"

RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_RESOURCE_MAP_TYPE = 0x0180

_NO_INDEX = 0xFFFFFFFF
_UTF8_FLAG = 0x100

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

# Resource IDs for attributes used by manifests. Raw names are normally present
# in the string pool; this table is a fallback for stripped or renamed pools.
ANDROID_ATTRIBUTE_NAMES: dict[int, str] = {
    0x01010000: "theme",
    0x01010001: "label",
    0x01010002: "icon",
    0x01010003: "name",
    0x01010006: "permission",
    0x01010007: "readPermission",
    0x01010008: "writePermission",
    0x01010009: "protectionLevel",
    0x0101000E: "enabled",
    0x0101000F: "debuggable",
    0x01010010: "exported",
    0x01010011: "process",
    0x01010018: "authorities",
    0x0101001B: "grantUriPermissions",
    0x0101001C: "priority",
    0x01010020: "description",
    0x01010024: "value",
    0x01010025: "resource",
    0x01010026: "mimeType",
    0x01010027: "scheme",
    0x01010028: "host",
    0x01010029: "port",
    0x0101002A: "path",
    0x0101002B: "pathPrefix",
    0x0101002C: "pathPattern",
    0x01010202: "targetActivity",
    0x0101020C: "minSdkVersion",
    0x0101021B: "versionCode",
    0x0101021C: "versionName",
    0x01010270: "targetSdkVersion",
    0x01010271: "maxSdkVersion",
    0x01010272: "testOnly",
    0x01010280: "allowBackup",
    0x010104EA: "extractNativeLibs",
    0x010104EB: "fullBackupContent",
    0x010104EC: "usesCleartextTraffic",
    0x010104EE: "autoVerify",
    0x01010527: "networkSecurityConfig",
    0x01010572: "compileSdkVersion",
    0x01010573: "compileSdkVersionCodename",
    0x01010603: "requestLegacyExternalStorage",
    0x01010604: "dataExtractionRules",
    0x0101060B: "usesPermissionFlags",
}

AttributeValue = str | int | float | bool | None


@dataclass(frozen=True, slots=True)
class XmlAttribute:
    """One decoded element attribute."""

    namespace: str | None
    name: str
    resource_id: int | None
    value: AttributeValue
    raw_value: str | None
    value_type: str

    @property
    def qualified_name(self) -> str:
        if self.namespace == ANDROID_NAMESPACE:
            return f"android:{self.name}"
        return self.name


@dataclass(slots=True)
class XmlElement:
    """A decoded element with ordered attributes and children."""

    name: str
    attributes: list[XmlAttribute] = field(default_factory=list)
    children: list[XmlElement] = field(default_factory=list)
    line: int | None = None

    def attribute(self, name: str) -> XmlAttribute | None:
        """Find an attribute, preferring the Android namespace."""

        for attribute in self.attributes:
            if attribute.name == name and attribute.namespace == ANDROID_NAMESPACE:
                return attribute
        for attribute in self.attributes:
            if attribute.name == name and attribute.namespace is None:
                return attribute
        for attribute in self.attributes:
            if attribute.name == name:
                return attribute
        return None

    def value(self, name: str, default: Any = None) -> Any:
        attribute = self.attribute(name)
        if attribute is None:
            return default
        return attribute.value

    def find(self, name: str) -> XmlElement | None:
        for child in self.children:
            if child.name == name:
                return child
        return None

    def findall(self, name: str) -> list[XmlElement]:
        return [child for child in self.children if child.name == name]


@dataclass(frozen=True, slots=True)
class XmlDocument:
    root: XmlElement
    element_count: int


class BinaryReader:
    """Small bounds-checked little-endian reader."""

    __slots__ = ("_data", "_end", "_label", "_pos")

    def __init__(self, data: bytes, offset: int, end: int, label: str) -> None:
        if offset < 0 or end < offset or end > len(data):
            raise InvalidArtifactError(f"Invalid binary XML bounds in {label}.")
        self._data = data
        self._pos = offset
        self._end = end
        self._label = label

    @property
    def position(self) -> int:
        return self._pos

    @property
    def remaining(self) -> int:
        return self._end - self._pos

    def _check(self, size: int) -> None:
        if size < 0 or self._pos + size > self._end:
            raise InvalidArtifactError(
                f"Truncated binary XML while reading {self._label}.",
                details={"offset": self._pos, "required": size},
            )

    def u8(self) -> int:
        self._check(1)
        value = self._data[self._pos]
        self._pos += 1
        return value

    def u16(self) -> int:
        self._check(2)
        value = int(struct.unpack_from("<H", self._data, self._pos)[0])
        self._pos += 2
        return value

    def u32(self) -> int:
        self._check(4)
        value = int(struct.unpack_from("<I", self._data, self._pos)[0])
        self._pos += 4
        return value

    def read(self, size: int) -> bytes:
        self._check(size)
        value = self._data[self._pos : self._pos + size]
        self._pos += size
        return value

    def skip(self, size: int) -> None:
        self._check(size)
        self._pos += size


def parse_binary_xml(
    data: bytes,
    *,
    max_elements: int = 100_000,
    max_depth: int = 256,
    max_strings: int = 200_000,
) -> XmlDocument:
    """Decode Android binary XML into an element tree."""

    if len(data) < 8:
        raise InvalidArtifactError("Android binary XML is too short.")
    header = BinaryReader(data, 0, len(data), "XML header")
    chunk_type = header.u16()
    header_size = header.u16()
    chunk_size = header.u32()
    if chunk_type != RES_XML_TYPE:
        raise InvalidArtifactError(
            "File is not Android binary XML.",
            details={"chunk_type": chunk_type},
        )
    if header_size < 8 or chunk_size < header_size or chunk_size > len(data):
        raise InvalidArtifactError("Android binary XML has an invalid root chunk.")

    strings: list[str] = []
    resource_ids: list[int] = []
    stack: list[XmlElement] = []
    root: XmlElement | None = None
    element_count = 0
    position = header_size
    while position + 8 <= chunk_size:
        chunk = BinaryReader(data, position, chunk_size, "chunk header")
        node_type = chunk.u16()
        node_header_size = chunk.u16()
        node_size = chunk.u32()
        if (
            node_header_size < 8
            or node_size < node_header_size
            or position + node_size > chunk_size
        ):
            raise InvalidArtifactError(
                "Android binary XML has an invalid chunk.",
                details={"offset": position, "chunk_type": node_type},
            )

        if node_type == RES_STRING_POOL_TYPE:
            strings = parse_string_pool(
                data,
                position,
                node_header_size,
                node_size,
                max_strings=max_strings,
            )
        elif node_type == RES_XML_RESOURCE_MAP_TYPE:
            resource_ids = _parse_resource_map(data, position, node_header_size, node_size)
        elif node_type == RES_XML_START_NAMESPACE_TYPE:
            _parse_namespace(data, position, node_header_size, node_size, strings)
        elif node_type == RES_XML_END_NAMESPACE_TYPE:
            pass
        elif node_type == RES_XML_START_ELEMENT_TYPE:
            element = _parse_start_element(
                data,
                position,
                node_header_size,
                node_size,
                strings,
                resource_ids,
            )
            element_count += 1
            if element_count > max_elements:
                raise LimitExceededError(
                    "Android binary XML has too many elements.",
                    details={"max_elements": max_elements},
                )
            if stack:
                stack[-1].children.append(element)
            elif root is None:
                root = element
            else:
                raise InvalidArtifactError("Android binary XML has multiple root elements.")
            stack.append(element)
            if len(stack) > max_depth:
                raise LimitExceededError(
                    "Android binary XML nesting is too deep.",
                    details={"max_depth": max_depth},
                )
        elif node_type == RES_XML_END_ELEMENT_TYPE:
            if not stack:
                raise InvalidArtifactError("Android binary XML has an unmatched end element.")
            ending = _parse_end_element(data, position, node_header_size, node_size, strings)
            open_element = stack.pop()
            if ending != open_element.name:
                raise InvalidArtifactError(
                    "Android binary XML has mismatched element names.",
                    details={"open": open_element.name, "close": ending},
                )
        elif node_type == RES_XML_CDATA_TYPE:
            pass
        position += node_size

    if root is None:
        raise InvalidArtifactError("Android binary XML contains no root element.")
    if stack:
        raise InvalidArtifactError("Android binary XML has unclosed elements.")
    return XmlDocument(root=root, element_count=element_count)


def parse_string_pool(
    data: bytes,
    start: int,
    header_size: int,
    size: int,
    *,
    max_strings: int,
) -> list[str]:
    """Decode a resource string pool chunk at an absolute file offset."""

    if header_size < 28:
        raise InvalidArtifactError("Android string pool header is too short.")
    end = start + size
    reader = BinaryReader(data, start + 8, end, "string pool header")
    count = reader.u32()
    style_count = reader.u32()
    flags = reader.u32()
    strings_start = reader.u32()
    reader.u32()  # stylesStart
    if count > max_strings:
        raise LimitExceededError(
            "Android string pool contains too many strings.",
            details={"count": count, "max_strings": max_strings},
        )
    if count + style_count and header_size + (count + style_count) * 4 > size:
        raise InvalidArtifactError("Android string pool offset table is truncated.")
    if strings_start < header_size + (count + style_count) * 4 or start + strings_start > end:
        raise InvalidArtifactError("Android string pool data offset is invalid.")
    utf8 = bool(flags & _UTF8_FLAG)
    strings: list[str] = []
    for index in range(count):
        offset = _u32_at(data, start + header_size + index * 4)
        absolute = start + strings_start + offset
        if absolute >= end:
            raise InvalidArtifactError(
                "Android string pool contains an out-of-range string offset.",
                details={"index": index},
            )
        if utf8:
            strings.append(_decode_utf8_string(data, absolute, end))
        else:
            strings.append(_decode_utf16_string(data, absolute, end))
    return strings


def _parse_resource_map(data: bytes, start: int, header_size: int, size: int) -> list[int]:
    if header_size < 8 or size < header_size:
        raise InvalidArtifactError("Android resource map chunk is truncated.")
    count = (size - header_size) // 4
    return [_u32_at(data, start + header_size + index * 4) for index in range(count)]


def _parse_namespace(
    data: bytes,
    start: int,
    header_size: int,
    size: int,
    strings: list[str],
) -> tuple[str | None, str | None]:
    if header_size < 16 or size < header_size + 8:
        raise InvalidArtifactError("Android namespace chunk is truncated.")
    reader = BinaryReader(data, start + header_size, start + size, "namespace")
    prefix_index = reader.u32()
    uri_index = reader.u32()
    return _optional_string(strings, prefix_index), _optional_string(strings, uri_index)


def _parse_start_element(
    data: bytes,
    start: int,
    header_size: int,
    size: int,
    strings: list[str],
    resource_ids: list[int],
) -> XmlElement:
    if header_size < 16 or size < header_size + 20:
        raise InvalidArtifactError("Android start-element chunk is truncated.")
    reader = BinaryReader(data, start + 8, start + size, "start element")
    line = reader.u32()
    reader.u32()  # comment
    namespace_index = reader.u32()
    name_index = reader.u32()
    attribute_start = reader.u16()
    attribute_size = reader.u16()
    attribute_count = reader.u16()
    reader.u16()  # idIndex
    reader.u16()  # classIndex
    reader.u16()  # styleIndex
    if attribute_size < 20 or attribute_start < 20:
        raise InvalidArtifactError("Android element has an invalid attribute layout.")
    attribute_base = start + header_size + attribute_start
    if attribute_count and attribute_base + attribute_count * attribute_size > start + size:
        raise InvalidArtifactError("Android element attributes are truncated.")
    name = _required_string(strings, name_index)
    _optional_string(strings, namespace_index)
    attributes: list[XmlAttribute] = []
    for index in range(attribute_count):
        offset = attribute_base + index * attribute_size
        attribute_reader = BinaryReader(data, offset, start + size, "attribute")
        attribute_namespace = _optional_string(strings, attribute_reader.u32())
        raw_name_index = attribute_reader.u32()
        raw_value_index = attribute_reader.u32()
        typed_size = attribute_reader.u16()
        attribute_reader.u8()  # res0
        value_type = attribute_reader.u8()
        value_data = attribute_reader.u32()
        if typed_size < 8:
            raise InvalidArtifactError("Android attribute typed value is truncated.")
        resource_id = (
            resource_ids[raw_name_index]
            if raw_name_index < len(resource_ids) and resource_ids[raw_name_index]
            else None
        )
        name_value = _optional_string(strings, raw_name_index)
        if not name_value and resource_id is not None:
            name_value = ANDROID_ATTRIBUTE_NAMES.get(resource_id)
        if not name_value:
            raise InvalidArtifactError(
                "Android attribute has no readable name.",
                details={"index": index},
            )
        raw_value = _optional_string(strings, raw_value_index)
        value = _decode_value(
            value_type,
            value_data,
            strings,
            raw_value=raw_value,
            label=name_value,
        )
        attributes.append(
            XmlAttribute(
                namespace=attribute_namespace,
                name=name_value,
                resource_id=resource_id,
                value=value,
                raw_value=raw_value,
                value_type=_VALUE_TYPE_NAMES.get(value_type, f"0x{value_type:02x}"),
            )
        )
    return XmlElement(
        name=name,
        attributes=attributes,
        children=[],
        line=line,
    )


def _parse_end_element(
    data: bytes,
    start: int,
    header_size: int,
    size: int,
    strings: list[str],
) -> str:
    if header_size < 16 or size < header_size + 8:
        raise InvalidArtifactError("Android end-element chunk is truncated.")
    reader = BinaryReader(data, start + header_size, start + size, "end element")
    reader.u32()  # namespace
    name_index = reader.u32()
    return _required_string(strings, name_index)


def _decode_value(
    value_type: int,
    data: int,
    strings: list[str],
    *,
    raw_value: str | None,
    label: str,
) -> AttributeValue:
    if value_type == _TYPE_NULL:
        return None
    if value_type == _TYPE_STRING:
        if data >= len(strings):
            raise InvalidArtifactError(
                "Android attribute references an invalid string.",
                details={"attribute": label, "index": data},
            )
        return strings[data]
    if value_type == _TYPE_INT_BOOLEAN:
        return data != 0
    if value_type == _TYPE_INT_DEC:
        return data
    if value_type == _TYPE_INT_HEX:
        return data
    if value_type == _TYPE_REFERENCE:
        return f"@0x{data:08x}"
    if value_type == _TYPE_DYNAMIC_REFERENCE:
        return f"@dynamic/0x{data:08x}"
    if value_type == _TYPE_ATTRIBUTE:
        return f"?0x{data:08x}"
    if value_type == _TYPE_DYNAMIC_ATTRIBUTE:
        return f"?dynamic/0x{data:08x}"
    if value_type == _TYPE_FLOAT:
        return float(struct.unpack("<f", struct.pack("<I", data))[0])
    if value_type in {_TYPE_DIMENSION, _TYPE_FRACTION}:
        return f"0x{data:08x}"
    if _TYPE_INT_COLOR_ARGB8 <= value_type <= _TYPE_INT_COLOR_RGB4:
        return f"#{data:08x}"
    if raw_value is not None:
        return raw_value
    return data


def _decode_utf8_string(data: bytes, offset: int, end: int) -> str:
    utf16_length, offset = _decode_utf8_length(data, offset, end)
    byte_length, offset = _decode_utf8_length(data, offset, end)
    if offset + byte_length > end:
        raise InvalidArtifactError("Android UTF-8 string is truncated.")
    try:
        value = data[offset : offset + byte_length].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidArtifactError("Android UTF-8 string is not valid UTF-8.") from exc
    # The UTF-16 length is advisory; it is retained here to document the format.
    _ = utf16_length
    return value


def _decode_utf8_length(data: bytes, offset: int, end: int) -> tuple[int, int]:
    if offset >= end:
        raise InvalidArtifactError("Android UTF-8 string length is truncated.")
    first = data[offset]
    if first & 0x80:
        if offset + 1 >= end:
            raise InvalidArtifactError("Android UTF-8 string length is truncated.")
        return ((first & 0x7F) << 8) | data[offset + 1], offset + 2
    return first, offset + 1


def _decode_utf16_string(data: bytes, offset: int, end: int) -> str:
    if offset + 2 > end:
        raise InvalidArtifactError("Android UTF-16 string length is truncated.")
    length = struct.unpack_from("<H", data, offset)[0]
    offset += 2
    if length & 0x8000:
        if offset + 2 > end:
            raise InvalidArtifactError("Android UTF-16 string length is truncated.")
        low = struct.unpack_from("<H", data, offset)[0]
        length = ((length & 0x7FFF) << 16) | low
        offset += 2
    byte_length = length * 2
    if offset + byte_length > end:
        raise InvalidArtifactError("Android UTF-16 string is truncated.")
    try:
        return data[offset : offset + byte_length].decode("utf-16-le")
    except UnicodeDecodeError as exc:
        raise InvalidArtifactError("Android UTF-16 string is not valid UTF-16.") from exc


def _optional_string(strings: list[str], index: int) -> str | None:
    if index == _NO_INDEX:
        return None
    return _required_string(strings, index)


def _required_string(strings: list[str], index: int) -> str:
    if index >= len(strings):
        raise InvalidArtifactError(
            "Android binary XML references an invalid string index.",
            details={"index": index, "count": len(strings)},
        )
    return strings[index]


def _u32_at(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise InvalidArtifactError("Android binary XML read is out of bounds.")
    return int(struct.unpack_from("<I", data, offset)[0])
