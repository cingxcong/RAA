"""Build small, valid Android binary XML documents for tests."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android"
_NO_INDEX = 0xFFFFFFFF

_RES_STRING_POOL_TYPE = 0x0001
_RES_XML_TYPE = 0x0003
_RES_XML_START_NAMESPACE_TYPE = 0x0100
_RES_XML_END_NAMESPACE_TYPE = 0x0101
_RES_XML_START_ELEMENT_TYPE = 0x0102
_RES_XML_END_ELEMENT_TYPE = 0x0103
_RES_XML_RESOURCE_MAP_TYPE = 0x0180
_UTF8_FLAG = 0x100

_RESOURCE_IDS = {
    "theme": 0x01010000,
    "label": 0x01010001,
    "icon": 0x01010002,
    "name": 0x01010003,
    "permission": 0x01010006,
    "readPermission": 0x01010007,
    "writePermission": 0x01010008,
    "protectionLevel": 0x01010009,
    "enabled": 0x0101000E,
    "debuggable": 0x0101000F,
    "exported": 0x01010010,
    "process": 0x01010011,
    "authorities": 0x01010018,
    "grantUriPermissions": 0x0101001B,
    "priority": 0x0101001C,
    "description": 0x01010020,
    "mimeType": 0x01010026,
    "scheme": 0x01010027,
    "host": 0x01010028,
    "port": 0x01010029,
    "path": 0x0101002A,
    "pathPrefix": 0x0101002B,
    "pathPattern": 0x0101002C,
    "targetActivity": 0x01010202,
    "minSdkVersion": 0x0101020C,
    "versionCode": 0x0101021B,
    "versionName": 0x0101021C,
    "targetSdkVersion": 0x01010270,
    "maxSdkVersion": 0x01010271,
    "testOnly": 0x01010272,
    "allowBackup": 0x01010280,
    "extractNativeLibs": 0x010104EA,
    "fullBackupContent": 0x010104EB,
    "usesCleartextTraffic": 0x010104EC,
    "autoVerify": 0x010104EE,
    "networkSecurityConfig": 0x01010527,
    "compileSdkVersion": 0x01010572,
    "compileSdkVersionCodename": 0x01010573,
    "requestLegacyExternalStorage": 0x01010603,
    "dataExtractionRules": 0x01010604,
    "usesPermissionFlags": 0x0101060B,
}


@dataclass(frozen=True, slots=True)
class Attr:
    name: str
    value: Any
    namespace: str | None = ANDROID_NAMESPACE
    resource_id: int | None = None


@dataclass(slots=True)
class Node:
    name: str
    attrs: list[Attr] = field(default_factory=list)
    children: list[Node] = field(default_factory=list)
    namespace: str | None = None


def android(name: str, value: Any) -> Attr:
    return Attr(name=name, value=value)


def plain(name: str, value: Any) -> Attr:
    return Attr(name=name, value=value, namespace=None)


def sample_manifest_node() -> Node:
    return Node(
        "manifest",
        [
            plain("package", "com.example.demo"),
            android("versionCode", 42),
            android("versionName", "1.2.3"),
            android("compileSdkVersion", 34),
        ],
        [
            Node(
                "uses-sdk",
                [android("minSdkVersion", 23), android("targetSdkVersion", 33)],
            ),
            Node(
                "uses-permission",
                [android("name", "android.permission.INTERNET")],
            ),
            Node(
                "uses-permission",
                [android("name", "android.permission.CAMERA")],
            ),
            Node(
                "permission",
                [
                    android("name", "com.example.demo.permission.CUSTOM"),
                    android("protectionLevel", "signature"),
                ],
            ),
            Node(
                "uses-feature",
                [android("name", "android.hardware.camera"), android("required", False)],
            ),
            Node(
                "application",
                [
                    android("label", "@string/app_name"),
                    android("icon", "@mipmap/ic_launcher"),
                    android("theme", "@style/AppTheme"),
                    android("debuggable", True),
                    android("allowBackup", True),
                    android("usesCleartextTraffic", True),
                    android("networkSecurityConfig", "@xml/network_security_config"),
                ],
                [
                    Node(
                        "activity",
                        [android("name", ".MainActivity"), android("exported", True)],
                        [
                            Node(
                                "intent-filter",
                                [android("autoVerify", False)],
                                [
                                    Node(
                                        "action",
                                        [android("name", "android.intent.action.MAIN")],
                                    ),
                                    Node(
                                        "category",
                                        [android("name", "android.intent.category.LAUNCHER")],
                                    ),
                                ],
                            )
                        ],
                    ),
                    Node(
                        "activity",
                        [android("name", ".DeepLinkActivity"), android("exported", True)],
                        [
                            Node(
                                "intent-filter",
                                [android("autoVerify", True)],
                                [
                                    Node(
                                        "action",
                                        [android("name", "android.intent.action.VIEW")],
                                    ),
                                    Node(
                                        "category",
                                        [android("name", "android.intent.category.BROWSABLE")],
                                    ),
                                    Node(
                                        "data",
                                        [
                                            android("scheme", "https"),
                                            android("host", "example.com"),
                                            android("pathPrefix", "/app"),
                                        ],
                                    ),
                                ],
                            )
                        ],
                    ),
                    Node(
                        "activity",
                        [android("name", ".LegacyActivity")],
                        [
                            Node(
                                "intent-filter",
                                [],
                                [
                                    Node(
                                        "action",
                                        [android("name", "android.intent.action.SEND")],
                                    ),
                                    Node(
                                        "category",
                                        [android("name", "android.intent.category.DEFAULT")],
                                    ),
                                ],
                            )
                        ],
                    ),
                    Node(
                        "activity",
                        [
                            android("name", ".ProtectedActivity"),
                            android("exported", True),
                            android("permission", "com.example.demo.permission.CUSTOM"),
                        ],
                    ),
                    Node(
                        "activity-alias",
                        [
                            android("name", ".AliasActivity"),
                            android("targetActivity", ".MainActivity"),
                            android("exported", False),
                        ],
                    ),
                    Node(
                        "service",
                        [
                            android("name", ".SyncService"),
                            android("exported", False),
                            android("permission", "com.example.demo.permission.CUSTOM"),
                        ],
                    ),
                    Node(
                        "receiver",
                        [android("name", ".BootReceiver"), android("exported", True)],
                    ),
                    Node(
                        "provider",
                        [
                            android("name", ".FileProvider"),
                            android("authorities", "com.example.demo.files"),
                            android("exported", False),
                            android("grantUriPermissions", True),
                        ],
                    ),
                ],
            ),
        ],
    )


def build_sample_manifest(*, utf8: bool = True) -> bytes:
    return encode_binary_xml(sample_manifest_node(), utf8=utf8)


def encode_binary_xml(root: Node, *, utf8: bool = True) -> bytes:
    nodes = list(_walk(root))
    pool = _StringPool()
    pool.add("android")
    pool.add(ANDROID_NAMESPACE)
    for node in nodes:
        if node.namespace:
            pool.add(node.namespace)
        pool.add(node.name)
        for attr in node.attrs:
            if attr.namespace:
                pool.add(attr.namespace)
            pool.add(attr.name)
            if isinstance(attr.value, str):
                pool.add(attr.value)

    resource_ids = [0] * len(pool.values)
    for node in nodes:
        for attr in node.attrs:
            resource_id = attr.resource_id or (
                _RESOURCE_IDS.get(attr.name) if attr.namespace == ANDROID_NAMESPACE else None
            )
            if resource_id:
                resource_ids[pool.index[attr.name]] = resource_id

    chunks = [
        _string_pool_chunk(pool.values, utf8=utf8),
        _resource_map_chunk(resource_ids),
        _namespace_chunk(
            _RES_XML_START_NAMESPACE_TYPE, pool.index["android"], pool.index[ANDROID_NAMESPACE]
        ),
        _element_chunks(root, pool),
        _namespace_chunk(
            _RES_XML_END_NAMESPACE_TYPE, pool.index["android"], pool.index[ANDROID_NAMESPACE]
        ),
    ]
    body = b"".join(chunks)
    return struct.pack("<HHI", _RES_XML_TYPE, 8, 8 + len(body)) + body


def _walk(node: Node) -> Any:
    yield node
    for child in node.children:
        yield from _walk(child)


class _StringPool:
    def __init__(self) -> None:
        self.values: list[str] = []
        self.index: dict[str, int] = {}

    def add(self, value: str) -> int:
        if value not in self.index:
            self.index[value] = len(self.values)
            self.values.append(value)
        return self.index[value]


def _string_pool_chunk(strings: list[str], *, utf8: bool) -> bytes:
    encoded: list[bytes] = []
    offsets: list[int] = []
    cursor = 0
    for value in strings:
        offsets.append(cursor)
        if utf8:
            raw = value.encode("utf-8")
            utf16_length = len(value.encode("utf-16-le")) // 2
            chunk = _encode_length8(utf16_length) + _encode_length8(len(raw)) + raw + b"\x00"
        else:
            raw = value.encode("utf-16-le")
            chunk = _encode_length16(len(raw) // 2) + raw + b"\x00\x00"
        encoded.append(chunk)
        cursor += len(chunk)
    data = b"".join(encoded)
    header_size = 28
    strings_start = header_size + 4 * len(strings)
    body = struct.pack("<IIIII", len(strings), 0, _UTF8_FLAG if utf8 else 0, strings_start, 0)
    offset_bytes = b"".join(struct.pack("<I", offset) for offset in offsets)
    payload = body + offset_bytes + data
    size = 8 + len(payload)
    size += (-size) % 4
    padding = b"\x00" * (size - 8 - len(payload))
    return struct.pack("<HHI", _RES_STRING_POOL_TYPE, header_size, size) + payload + padding


def _resource_map_chunk(resource_ids: list[int]) -> bytes:
    payload = b"".join(struct.pack("<I", value) for value in resource_ids)
    return struct.pack("<HHI", _RES_XML_RESOURCE_MAP_TYPE, 8, 8 + len(payload)) + payload


def _namespace_chunk(chunk_type: int, prefix_index: int, uri_index: int) -> bytes:
    payload = struct.pack("<IIII", 1, _NO_INDEX, prefix_index, uri_index)
    return struct.pack("<HHI", chunk_type, 16, 8 + len(payload)) + payload


def _element_chunks(root: Node, pool: _StringPool) -> bytes:
    chunks: list[bytes] = []
    _append_element(root, pool, chunks)
    return b"".join(chunks)


def _append_element(node: Node, pool: _StringPool, chunks: list[bytes]) -> None:
    attributes = b"".join(_attribute_record(attr, pool) for attr in node.attrs)
    name_index = pool.index[node.name]
    namespace_index = pool.index[node.namespace] if node.namespace else _NO_INDEX
    payload = (
        struct.pack(
            "<IIIIHHHHHH",
            1,
            _NO_INDEX,
            namespace_index,
            name_index,
            20,
            20,
            len(node.attrs),
            0,
            0,
            0,
        )
        + attributes
    )
    chunks.append(struct.pack("<HHI", _RES_XML_START_ELEMENT_TYPE, 16, 8 + len(payload)) + payload)
    for child in node.children:
        _append_element(child, pool, chunks)
    end_payload = struct.pack("<IIII", 1, _NO_INDEX, namespace_index, name_index)
    chunks.append(
        struct.pack("<HHI", _RES_XML_END_ELEMENT_TYPE, 16, 8 + len(end_payload)) + end_payload
    )


def _attribute_record(attr: Attr, pool: _StringPool) -> bytes:
    namespace_index = pool.index[attr.namespace] if attr.namespace else _NO_INDEX
    name_index = pool.index[attr.name]
    value_type, data, raw_index = _encode_value(attr.value, pool)
    return struct.pack(
        "<IIIHBBI",
        namespace_index,
        name_index,
        raw_index,
        8,
        0,
        value_type,
        data,
    )


def _encode_value(value: Any, pool: _StringPool) -> tuple[int, int, int]:
    if value is None:
        return 0x00, 0, _NO_INDEX
    if isinstance(value, bool):
        return 0x12, 0xFFFFFFFF if value else 0, _NO_INDEX
    if isinstance(value, int):
        return 0x10, value, _NO_INDEX
    if isinstance(value, float):
        data = struct.unpack("<I", struct.pack("<f", value))[0]
        return 0x04, data, _NO_INDEX
    if isinstance(value, str):
        index = pool.index[value]
        return 0x03, index, index
    raise TypeError(f"Unsupported attribute value: {value!r}")


def _encode_length8(value: int) -> bytes:
    if value > 0x7FFF:
        raise ValueError("string length is too large")
    if value > 0x7F:
        return bytes([0x80 | (value >> 8), value & 0xFF])
    return bytes([value])


def _encode_length16(value: int) -> bytes:
    if value > 0x7FFFFFFF:
        raise ValueError("string length is too large")
    if value > 0x7FFF:
        return struct.pack("<HH", 0x8000 | (value >> 16), value & 0xFFFF)
    return struct.pack("<H", value)
