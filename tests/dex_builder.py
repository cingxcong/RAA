"""Synthetic DEX builder used by tests.

The builder emits valid headers, identifier tables, class definitions, class
data and optional code items. It is deliberately small and deterministic; it
exists to exercise metadata indexing, not to produce runnable bytecode.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from collections.abc import Sequence
from dataclasses import dataclass

_NO_INDEX = 0xFFFFFFFF
_METHOD_OPS = frozenset((*range(0x6E, 0x73), *range(0x74, 0x79), 0xFA, 0xFB))
_FIELD_OPS = frozenset((*range(0x52, 0x60), *range(0x60, 0x6E)))
_STRING_OPS = frozenset({0x1A, 0x1B})
_TYPE_OPS = frozenset({0x1C, 0x1F, 0x20, 0x22, 0x23, 0x24, 0x25})


@dataclass(frozen=True)
class DexFieldSpec:
    name: str
    type: str
    access_flags: int = 0x1


@dataclass(frozen=True)
class DexInsn:
    """One symbolic instruction.

    ``target`` is a method reference, field reference, type descriptor or
    string value. ``units`` can be used for raw instructions that do not need
    table resolution.
    """

    opcode: int
    target: str | None = None
    units: tuple[int, ...] = ()


@dataclass(frozen=True)
class DexMethodSpec:
    name: str
    params: tuple[str, ...] = ()
    returns: str = "V"
    access_flags: int = 0x1
    code: bool = True
    instructions: tuple[DexInsn, ...] = ()


@dataclass(frozen=True)
class DexClassSpec:
    name: str
    superclass: str | None = "Ljava/lang/Object;"
    interfaces: tuple[str, ...] = ()
    source_file: str | None = None
    access_flags: int = 0x1
    fields: tuple[DexFieldSpec, ...] = ()
    methods: tuple[DexMethodSpec, ...] = ()


def build_sample_dex() -> bytes:
    return build_dex(
        [
            DexClassSpec(
                name="Lcom/example/demo/MainActivity;",
                superclass="Landroid/app/Activity;",
                interfaces=("Lcom/example/demo/ClickListener;",),
                source_file="MainActivity.java",
                fields=(
                    DexFieldSpec("TAG", "Ljava/lang/String;", 0x19),
                    DexFieldSpec("count", "I", 0x2),
                ),
                methods=(
                    DexMethodSpec(
                        "<init>",
                        (),
                        "V",
                        0x10001,
                        instructions=(
                            DexInsn(
                                0x71,
                                "Lcom/example/demo/MainActivity;->"
                                "helper(ILjava/lang/String;)Ljava/lang/String;",
                            ),
                            DexInsn(0x1A, "demo-start"),
                        ),
                    ),
                    DexMethodSpec(
                        "onCreate",
                        ("Landroid/os/Bundle;",),
                        "V",
                        0x1,
                        instructions=(
                            DexInsn(0x22, "Lcom/example/demo/ClickListener;"),
                            DexInsn(0x1A, "demo-start"),
                        ),
                    ),
                    DexMethodSpec(
                        "helper",
                        ("I", "Ljava/lang/String;"),
                        "Ljava/lang/String;",
                        0x9,
                        instructions=(
                            DexInsn(
                                0x62,
                                "Lcom/example/demo/MainActivity;->TAG:Ljava/lang/String;",
                            ),
                            DexInsn(0x1C, "Ljava/lang/String;"),
                        ),
                    ),
                ),
            ),
            DexClassSpec(
                name="Lcom/example/demo/ClickListener;",
                superclass=None,
                source_file="ClickListener.java",
                access_flags=0x0601,
                methods=(
                    DexMethodSpec(
                        "onClick",
                        ("Landroid/view/View;",),
                        "V",
                        0x401,
                        instructions=(DexInsn(0x22, "Lcom/example/demo/MainActivity;"),),
                    ),
                ),
            ),
        ],
        extra_strings=("demo-start",),
    )


def build_sample_dex2() -> bytes:
    return build_dex(
        [
            DexClassSpec(
                name="Lcom/example/demo/network/ApiClient;",
                superclass="Ljava/lang/Object;",
                source_file="ApiClient.java",
                fields=(DexFieldSpec("BASE_URL", "Ljava/lang/String;", 0x19),),
                methods=(
                    DexMethodSpec("<init>", (), "V", 0x10001),
                    DexMethodSpec(
                        "fetch",
                        ("Ljava/lang/String;",),
                        "Ljava/lang/String;",
                        0x1,
                        instructions=(
                            DexInsn(0x1A, "https://api.example.com/v1"),
                            DexInsn(0x1C, "Ljava/lang/String;"),
                        ),
                    ),
                ),
            )
        ],
        extra_strings=("https://api.example.com/v1",),
    )


def build_dex(
    classes: Sequence[DexClassSpec],
    *,
    extra_strings: Sequence[str] = (),
    version: bytes = b"035",
) -> bytes:
    """Build one DEX file from class specifications."""

    class_specs = sorted(classes, key=lambda item: item.name)
    strings = _collect_strings(class_specs, extra_strings)
    string_index = {value: index for index, value in enumerate(strings)}

    type_descriptors = sorted(
        {
            descriptor
            for spec in class_specs
            for descriptor in (
                spec.name,
                *((spec.superclass,) if spec.superclass else ()),
                *spec.interfaces,
                *(field.type for field in spec.fields),
                *(param for method in spec.methods for param in method.params),
                *(method.returns for method in spec.methods),
            )
        },
        key=lambda value: string_index[value],
    )
    type_index = {value: index for index, value in enumerate(type_descriptors)}

    proto_specs = sorted(
        {(method.returns, method.params) for spec in class_specs for method in spec.methods},
        key=lambda item: (
            type_index[item[0]],
            tuple(type_index[param] for param in item[1]),
        ),
    )
    proto_index = {value: index for index, value in enumerate(proto_specs)}

    field_records = sorted(
        {
            (spec.name, field.name, field.type, field.access_flags)
            for spec in class_specs
            for field in spec.fields
        },
        key=lambda item: (
            type_index[item[0]],
            string_index[item[1]],
            type_index[item[2]],
        ),
    )
    field_index = {
        (class_name, name, type_name): index
        for index, (class_name, name, type_name, _flags) in enumerate(field_records)
    }

    method_records = sorted(
        {
            (
                spec.name,
                method.name,
                f"({''.join(method.params)}){method.returns}",
                method.access_flags,
                method.code,
            )
            for spec in class_specs
            for method in spec.methods
        },
        key=lambda item: (
            type_index[item[0]],
            string_index[item[1]],
            _method_proto_index(item, proto_index),
        ),
    )
    method_index = {
        (class_name, name, descriptor): index
        for index, (class_name, name, descriptor, _flags, _code) in enumerate(method_records)
    }
    method_specs = {
        (spec.name, method.name, f"({''.join(method.params)}){method.returns}"): method
        for spec in class_specs
        for method in spec.methods
    }

    # Header and identifier tables are laid out before the data section.
    string_ids_off = 0x70
    type_ids_off = string_ids_off + len(strings) * 4
    proto_ids_off = type_ids_off + len(type_descriptors) * 4
    field_ids_off = proto_ids_off + len(proto_specs) * 12
    method_ids_off = field_ids_off + len(field_records) * 8
    class_defs_off = method_ids_off + len(method_records) * 8
    data_start = _align4(class_defs_off + len(class_specs) * 32)

    data = bytearray()

    def append(blob: bytes, *, align: bool = False) -> int:
        if align:
            data.extend(b"\x00" * (-(data_start + len(data)) % 4))
        offset = data_start + len(data)
        data.extend(blob)
        return offset

    string_offsets: list[int] = []
    string_data_start = data_start + len(data)
    for value in strings:
        string_offsets.append(append(_uleb(len(value)) + value.encode("utf-8") + b"\x00"))

    type_list_offsets: dict[tuple[str, ...], int] = {}
    type_list_start = data_start + len(data)
    for params in sorted(
        {method.params for spec in class_specs for method in spec.methods if method.params}
        | {spec.interfaces for spec in class_specs if spec.interfaces},
        key=lambda item: tuple(type_index[value] for value in item),
    ):
        blob = _type_list(type_index[value] for value in params)
        type_list_offsets[params] = append(blob, align=True)

    code_offsets: dict[tuple[str, str, str], int] = {}
    code_start = data_start + len(data)
    for class_name, name, descriptor, _flags, has_code in method_records:
        if not has_code:
            continue
        spec = method_specs[(class_name, name, descriptor)]
        code_offsets[(class_name, name, descriptor)] = append(
            _code_item(
                spec.instructions,
                string_index=string_index,
                type_index=type_index,
                field_index=field_index,
                method_index=method_index,
            ),
            align=True,
        )

    class_data_offsets: dict[str, int] = {}
    class_data_start = data_start + len(data)
    for spec in class_specs:
        if not spec.fields and not spec.methods:
            continue
        blob = _class_data(
            spec,
            field_index,
            method_index,
            code_offsets,
        )
        class_data_offsets[spec.name] = append(blob, align=True)

    map_off = data_start + len(data)
    map_entries: list[tuple[int, int, int]] = [
        (0x0000, 1, 0),
        (0x0001, len(strings), string_ids_off),
        (0x0002, len(type_descriptors), type_ids_off),
        (0x0003, len(proto_specs), proto_ids_off),
        (0x0004, len(field_records), field_ids_off),
        (0x0005, len(method_records), method_ids_off),
        (0x0006, len(class_specs), class_defs_off),
    ]
    if strings:
        map_entries.append((0x2002, len(strings), string_data_start))
    if type_list_offsets:
        map_entries.append((0x1001, len(type_list_offsets), type_list_start))
    if code_offsets:
        map_entries.append((0x2001, len(code_offsets), code_start))
    if class_data_offsets:
        map_entries.append((0x2000, len(class_data_offsets), class_data_start))
    map_entries.append((0x1000, 1, map_off))
    map_entries.sort(key=lambda item: item[2])
    data.extend(struct.pack("<I", len(map_entries)))
    for kind, size, offset in map_entries:
        data.extend(struct.pack("<HHII", kind, 0, size, offset))

    file_size = data_start + len(data)
    output = bytearray(file_size)
    output[0:8] = b"dex\n" + version + b"\x00"
    struct.pack_into("<I", output, 0x20, file_size)
    struct.pack_into("<I", output, 0x24, 0x70)
    struct.pack_into("<I", output, 0x28, 0x12345678)
    struct.pack_into("<I", output, 0x2C, 0)  # link_size
    struct.pack_into("<I", output, 0x30, 0)  # link_off
    struct.pack_into("<I", output, 0x34, map_off)
    struct.pack_into("<I", output, 0x38, len(strings))
    struct.pack_into("<I", output, 0x3C, string_ids_off if strings else 0)
    struct.pack_into("<I", output, 0x40, len(type_descriptors))
    struct.pack_into("<I", output, 0x44, type_ids_off if type_descriptors else 0)
    struct.pack_into("<I", output, 0x48, len(proto_specs))
    struct.pack_into("<I", output, 0x4C, proto_ids_off if proto_specs else 0)
    struct.pack_into("<I", output, 0x50, len(field_records))
    struct.pack_into("<I", output, 0x54, field_ids_off if field_records else 0)
    struct.pack_into("<I", output, 0x58, len(method_records))
    struct.pack_into("<I", output, 0x5C, method_ids_off if method_records else 0)
    struct.pack_into("<I", output, 0x60, len(class_specs))
    struct.pack_into("<I", output, 0x64, class_defs_off if class_specs else 0)
    struct.pack_into("<I", output, 0x68, len(data))
    struct.pack_into("<I", output, 0x6C, data_start)

    for index, offset in enumerate(string_offsets):
        struct.pack_into("<I", output, string_ids_off + index * 4, offset)
    for index, descriptor in enumerate(type_descriptors):
        struct.pack_into("<I", output, type_ids_off + index * 4, string_index[descriptor])
    for index, (returns, params) in enumerate(proto_specs):
        base = proto_ids_off + index * 12
        struct.pack_into("<I", output, base, string_index[_shorty(returns, params)])
        struct.pack_into("<I", output, base + 4, type_index[returns])
        struct.pack_into(
            "<I",
            output,
            base + 8,
            type_list_offsets[params] if params else 0,
        )
    for index, (class_name, name, type_name, _flags) in enumerate(field_records):
        base = field_ids_off + index * 8
        struct.pack_into("<H", output, base, type_index[class_name])
        struct.pack_into("<H", output, base + 2, type_index[type_name])
        struct.pack_into("<I", output, base + 4, string_index[name])
    for index, (class_name, name, descriptor, _flags, _code) in enumerate(method_records):
        base = method_ids_off + index * 8
        struct.pack_into("<H", output, base, type_index[class_name])
        struct.pack_into(
            "<H",
            output,
            base + 2,
            proto_index[_descriptor_parts(descriptor)],
        )
        struct.pack_into("<I", output, base + 4, string_index[name])

    for index, spec in enumerate(class_specs):
        base = class_defs_off + index * 32
        struct.pack_into("<I", output, base, type_index[spec.name])
        struct.pack_into("<I", output, base + 4, spec.access_flags)
        struct.pack_into(
            "<I",
            output,
            base + 8,
            type_index[spec.superclass] if spec.superclass else _NO_INDEX,
        )
        struct.pack_into(
            "<I",
            output,
            base + 12,
            type_list_offsets[spec.interfaces] if spec.interfaces else 0,
        )
        struct.pack_into(
            "<I",
            output,
            base + 16,
            string_index[spec.source_file] if spec.source_file else _NO_INDEX,
        )
        struct.pack_into("<I", output, base + 20, 0)  # annotations_off
        struct.pack_into("<I", output, base + 24, class_data_offsets.get(spec.name, 0))
        struct.pack_into("<I", output, base + 28, 0)  # static_values_off

    output[data_start:] = data
    # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
    signature = hashlib.sha1(output[0x20:], usedforsecurity=False).digest()
    output[0x0C:0x20] = signature
    checksum = zlib.adler32(output[0x0C:]) & 0xFFFFFFFF
    struct.pack_into("<I", output, 0x08, checksum)
    return bytes(output)


def _collect_strings(
    classes: Sequence[DexClassSpec],
    extra_strings: Sequence[str],
) -> list[str]:
    values: set[str] = set(extra_strings)
    for spec in classes:
        values.add(spec.name)
        if spec.superclass:
            values.add(spec.superclass)
        values.update(spec.interfaces)
        if spec.source_file:
            values.add(spec.source_file)
        for field in spec.fields:
            values.add(field.name)
            values.add(field.type)
        for method in spec.methods:
            values.add(method.name)
            values.add(method.returns)
            values.update(method.params)
            values.add(_shorty(method.returns, method.params))
            for instruction in method.instructions:
                if instruction.target is not None:
                    _collect_instruction_strings(
                        instruction.opcode,
                        instruction.target,
                        values,
                    )
    return sorted(values)


def _collect_instruction_strings(
    opcode: int,
    target: str,
    values: set[str],
) -> None:
    if opcode in _METHOD_OPS:
        class_name, name, descriptor = _parse_method_target(target)
        returns, params = _descriptor_parts(descriptor)
        values.add(class_name)
        values.add(name)
        values.add(returns)
        values.update(params)
        values.add(_shorty(returns, params))
        return
    if opcode in _FIELD_OPS:
        class_name, name, type_name = _parse_field_target(target)
        values.update((class_name, name, type_name))
        return
    values.add(target)


def _shorty(returns: str, params: Sequence[str]) -> str:
    return _shorty_char(returns) + "".join(_shorty_char(item) for item in params)


def _shorty_char(descriptor: str) -> str:
    if descriptor.startswith("["):
        return "L"
    if descriptor.startswith("L"):
        return "L"
    return descriptor


def _descriptor_parts(descriptor: str) -> tuple[str, tuple[str, ...]]:
    closing = descriptor.index(")")
    returns = descriptor[closing + 1 :]
    body = descriptor[1:closing]
    params: list[str] = []
    index = 0
    while index < len(body):
        start = index
        while body[index] == "[":
            index += 1
        if body[index] == "L":
            index = body.index(";", index) + 1
        else:
            index += 1
        params.append(body[start:index])
    return returns, tuple(params)


def _method_proto_index(
    record: tuple[str, str, str, int, bool],
    proto_index: dict[tuple[str, tuple[str, ...]], int],
) -> int:
    returns, params = _descriptor_parts(record[2])
    return proto_index[(returns, params)]


def _class_data(
    spec: DexClassSpec,
    field_index: dict[tuple[str, str, str], int],
    method_index: dict[tuple[str, str, str], int],
    code_offsets: dict[tuple[str, str, str], int],
) -> bytes:
    static_fields = sorted(
        (
            (field_index[(spec.name, field.name, field.type)], field.access_flags)
            for field in spec.fields
            if field.access_flags & 0x0008
        ),
        key=lambda item: item[0],
    )
    instance_fields = sorted(
        (
            (field_index[(spec.name, field.name, field.type)], field.access_flags)
            for field in spec.fields
            if not field.access_flags & 0x0008
        ),
        key=lambda item: item[0],
    )

    method_rows = []
    for method in spec.methods:
        descriptor = f"({''.join(method.params)}){method.returns}"
        direct = bool(method.access_flags & (0x0002 | 0x0008)) or method.name in {
            "<init>",
            "<clinit>",
        }
        method_rows.append(
            (
                method_index[(spec.name, method.name, descriptor)],
                method.access_flags,
                code_offsets.get((spec.name, method.name, descriptor), 0) if method.code else 0,
                direct,
            )
        )
    direct_methods = sorted((row for row in method_rows if row[3]), key=lambda item: item[0])
    virtual_methods = sorted((row for row in method_rows if not row[3]), key=lambda item: item[0])

    output = bytearray()
    output += _uleb(len(static_fields))
    output += _uleb(len(instance_fields))
    output += _uleb(len(direct_methods))
    output += _uleb(len(virtual_methods))
    for group in (static_fields, instance_fields):
        previous = 0
        for index, access_flags in group:
            output += _uleb(index - previous)
            output += _uleb(access_flags)
            previous = index
    for group in (direct_methods, virtual_methods):
        previous = 0
        for index, access_flags, code_offset, _direct in group:
            output += _uleb(index - previous)
            output += _uleb(access_flags)
            output += _uleb(code_offset)
            previous = index
    return bytes(output)


def _type_list(indices: Sequence[int]) -> bytes:
    values = list(indices)
    blob = bytearray(struct.pack("<I", len(values)))
    for value in values:
        blob += struct.pack("<H", value)
    if len(blob) % 4:
        blob += b"\x00" * (4 - len(blob) % 4)
    return bytes(blob)


def _parse_method_target(target: str) -> tuple[str, str, str]:
    class_name, rest = target.split("->", 1)
    name, descriptor = rest.split("(", 1)
    return class_name, name, f"({descriptor}"


def _parse_field_target(target: str) -> tuple[str, str, str]:
    class_name, rest = target.split("->", 1)
    name, type_name = rest.split(":", 1)
    return class_name, name, type_name


def _encode_insn(
    instruction: DexInsn,
    *,
    string_index: dict[str, int],
    type_index: dict[str, int],
    field_index: dict[tuple[str, str, str], int],
    method_index: dict[tuple[str, str, str], int],
) -> tuple[int, ...]:
    if instruction.units:
        return instruction.units
    opcode = instruction.opcode
    if instruction.target is None:
        return (opcode,)
    if opcode in _METHOD_OPS:
        index = method_index[_parse_method_target(instruction.target)]
        return (opcode, index, 0, 0) if opcode in {0xFA, 0xFB} else (opcode, index, 0)
    if opcode in _FIELD_OPS:
        index = field_index[_parse_field_target(instruction.target)]
        return (opcode, index)
    if opcode == 0x1B:
        index = string_index[instruction.target]
        return (opcode, index & 0xFFFF, index >> 16)
    if opcode in _STRING_OPS:
        return (opcode, string_index[instruction.target])
    if opcode in _TYPE_OPS:
        index = type_index[instruction.target]
        return (opcode, index, 0) if opcode in {0x24, 0x25} else (opcode, index)
    raise ValueError(f"Unsupported symbolic opcode 0x{opcode:02x}")


def _code_item(
    instructions: Sequence[DexInsn],
    *,
    string_index: dict[str, int],
    type_index: dict[str, int],
    field_index: dict[tuple[str, str, str], int],
    method_index: dict[tuple[str, str, str], int],
) -> bytes:
    units: list[int] = []
    for instruction in instructions:
        units.extend(
            _encode_insn(
                instruction,
                string_index=string_index,
                type_index=type_index,
                field_index=field_index,
                method_index=method_index,
            )
        )
    if not units or (units[-1] & 0xFF) not in {0x0E, 0x0F, 0x10, 0x11}:
        units.append(0x000E)
    return struct.pack("<HHHHII", 1, 0, 0, 0, 0, len(units)) + struct.pack(
        f"<{len(units)}H", *units
    )


def _uleb(value: int) -> bytes:
    output = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
        output.append(byte)
        if not value:
            return bytes(output)


def _align4(value: int) -> int:
    return (value + 3) & ~3
