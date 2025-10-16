# Core Candid encode/decode (Python)
# - Official idl_hash (FNV-1a 32 over UTF-8)
# - Explicit little-endian for fixed-size numbers (per Wasm/Candid)
# - Variant index uses ULEB128
# - Record/Variant decode compares wire hash (u32) with idl_hash(field)
# - TypeTable.merge keeps indices stable (holes kept but not emitted)
# - Vec excludes str/bytes/bytearray; supports generic iterables

from __future__ import annotations

import math
from enum import Enum
from struct import pack, unpack
from collections.abc import Iterable
from abc import ABCMeta, abstractmethod

import leb128
from icp_principal.principal import Principal as P


# -----------------------------
# Constants & helpers
# -----------------------------

prefix = "DIDL"


def idl_hash(label: str) -> int:
    """
    Official Candid idl_hash for field/method labels.
    Algorithm: FNV-1a 32-bit over UTF-8 bytes, with 32-bit wraparound.
    Mirrors Rust candid::idl_hash.
    """
    h = 0x811C9DC5  # 2166136261
    for b in label.encode("utf-8"):
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF  # 16777619
    return h


# -----------------------------
# Low-level Pipe wrapper
# -----------------------------

class Pipe:
    def __init__(self, buffer: bytes = b"", length: int = 0):  # length kept for compat
        self._buffer = buffer
        self._view = buffer[:]

    @property
    def buffer(self) -> bytes:
        return self._view

    @property
    def length(self) -> int:
        return len(self._view)

    @property
    def end(self) -> bool:
        return self.length == 0

    def read(self, num: int) -> bytes:
        if len(self._view) < num:
            raise ValueError("read out of bounds")
        res = self._view[:num]
        self._view = self._view[num:]
        return res


def safeRead(pipe: Pipe, num: int) -> bytes:
    if pipe.length < num:
        raise ValueError("unexpected end of buffer")
    return pipe.read(num)


def safeReadByte(pipe: Pipe) -> bytes:
    if pipe.length < 1:
        raise ValueError("unexpected end of buffer")
    return pipe.read(1)


# -----------------------------
# LEB128 helpers (using leb128 package)
# -----------------------------

def leb128uDecode(pipe: Pipe) -> int:
    # read unsigned LEB128 from pipe
    res = b""
    while True:
        byte = safeReadByte(pipe)  # bytes of length 1
        res += byte
        # stop when continuation bit is 0
        if byte < b"\x80":
            break
    return leb128.u.decode(res)


def leb128iDecode(pipe: Pipe) -> int:
    # read signed LEB128 from pipe: gather until the first byte with cont bit == 0
    length = len(pipe._view)
    stop = None
    for i in range(length):
        if pipe._view[i:i + 1] < b"\x80":
            stop = i
            break
    if stop is None:
        raise ValueError("invalid LEB128 stream")
    res = safeRead(pipe, stop + 1)
    return leb128.i.decode(res)


# -----------------------------
# Type system
# -----------------------------

class TypeIds(Enum):
    Null = -1
    Bool = -2
    Nat = -3
    Int = -4
    Nat8 = -5
    Nat16 = -6
    Nat32 = -7
    Nat64 = -8
    Int8 = -9
    Int16 = -10
    Int32 = -11
    Int64 = -12
    Float32 = -13
    Float64 = -14
    Text = -15
    Reserved = -16
    Empty = -17
    Opt = -18
    Vec = -19
    Record = -20
    Variant = -21
    Func = -22
    Service = -23
    Principal = -24
    # Note: Tuple is syntactic sugar over Record in Candid, no dedicated opcode.


class TypeTable:
    def __init__(self) -> None:
        self._typs: list[bytes] = []
        self._idx: dict[str, int] = {}

    def has(self, obj: "ConstructType") -> bool:
        return obj.name in self._idx

    def add(self, obj: "ConstructType", buf: bytes):
        idx = len(self._typs)
        self._idx[obj.name] = idx
        self._typs.append(buf)

    def merge(self, obj: "ConstructType", knot: str):
        """
        For Rec: place real type bytes into the placeholder slot (obj.name),
        and blank out the knot slot WITHOUT deleting it so indices remain stable.
        """
        idx = self._idx[obj.name] if self.has(obj) else None
        knotIdx = self._idx.get(knot)
        if idx is None:
            raise ValueError("Missing type index for " + obj.name)
        if knotIdx is None:
            raise ValueError("Missing type index for " + knot)
        # Move real bytes into placeholder position
        self._typs[idx] = self._typs[knotIdx]
        # Keep the old 'knot' position as an empty hole
        self._typs[knotIdx] = b""
        # remove name mapping for the knot (optional)
        self._idx.pop(knot, None)

    def encode(self) -> bytes:
        # Emit only non-empty entries
        count = sum(1 for t in self._typs if len(t) != 0)
        length = leb128.u.encode(count)
        buf = b"".join(t for t in self._typs if len(t) != 0)
        return length + buf

    def indexOf(self, typeName: str) -> bytes:
        """
        Return the compacted index among non-empty entries (emitted order).
        This keeps indices correct even when we keep 'holes' after merge().
        """
        if typeName not in self._idx:
            raise ValueError("Missing type index for " + typeName)
        raw_idx = self._idx[typeName]
        if raw_idx >= len(self._typs):
            raise ValueError("type index out of range")
        # count non-empty entries before raw_idx
        new_idx = sum(1 for i in range(raw_idx) if len(self._typs[i]) != 0)
        return leb128.i.encode(new_idx)


class Type(metaclass=ABCMeta):
    @property
    @abstractmethod
    def name(self) -> str: ...
    @property
    @abstractmethod
    def id(self) -> int: ...

    def display(self) -> str:
        return self.name

    def buildTypeTable(self, typeTable: TypeTable):
        if not typeTable.has(self):
            self._buildTypeTableImpl(typeTable)

    @abstractmethod
    def covariant(self, x) -> bool: ...
    @abstractmethod
    def decodeValue(self, b: Pipe, t: "Type"): ...
    @abstractmethod
    def encodeType(self, typeTable: TypeTable) -> bytes: ...
    @abstractmethod
    def encodeValue(self, val) -> bytes: ...
    @abstractmethod
    def checkType(self, t: "Type") -> "Type": ...
    @abstractmethod
    def _buildTypeTableImpl(self, typeTable: TypeTable): ...


class PrimitiveType(Type):
    def checkType(self, t: Type) -> Type:
        if self.name != t.name:
            raise ValueError(
                f"type mismatch: type on the wire {t.name}, expect type {self.name}"
            )
        return t

    def _buildTypeTableImpl(self, typeTable: TypeTable):
        # No type table entry for primitives.
        return


class ConstructType(Type, metaclass=ABCMeta):
    def checkType(self, t: Type) -> "ConstructType":
        if isinstance(t, RecClass):
            ty = t.getType()
            if ty is None:
                raise ValueError("type mismatch with uninitialized type")
            return ty
        if isinstance(t, ConstructType):
            return t
        raise ValueError(
            f"type mismatch: type on the wire {t.name}, expect type {self.name}"
        )

    def encodeType(self, typeTable: TypeTable) -> bytes:
        return typeTable.indexOf(self.name)


# -----------------------------
# Primitive types
# -----------------------------

class EmptyClass(PrimitiveType):
    def covariant(self, x) -> bool:
        return False

    def encodeValue(self, val) -> bytes:
        raise ValueError("Empty cannot appear as a function argument")

    def encodeType(self, typeTable: TypeTable) -> bytes:
        return leb128.i.encode(TypeIds.Empty.value)

    def decodeValue(self, b: Pipe, t: Type):
        raise ValueError("Empty cannot appear as an output")

    @property
    def name(self) -> str: return "empty"
    @property
    def id(self) -> int: return TypeIds.Empty.value


class BoolClass(PrimitiveType):
    def covariant(self, x) -> bool: return isinstance(x, bool)

    def encodeValue(self, val: bool) -> bytes:
        return leb128.u.encode(1 if val else 0)

    def encodeType(self, typeTable: TypeTable) -> bytes:
        return leb128.i.encode(TypeIds.Bool.value)

    def decodeValue(self, b: Pipe, t: Type) -> bool:
        self.checkType(t)
        byte = safeReadByte(b)
        v = leb128.u.decode(byte)
        if v == 1: return True
        if v == 0: return False
        raise ValueError("Boolean value out of range")

    @property
    def name(self) -> str: return "bool"
    @property
    def id(self) -> int: return TypeIds.Bool.value


class NullClass(PrimitiveType):
    def covariant(self, x) -> bool: return x is None
    def encodeValue(self, val) -> bytes: return b""
    def encodeType(self, typeTable: TypeTable) -> bytes:
        return leb128.i.encode(TypeIds.Null.value)
    def decodeValue(self, b: Pipe, t: Type):
        self.checkType(t)
        return None
    @property
    def name(self) -> str: return "null"
    @property
    def id(self) -> int: return TypeIds.Null.value


class ReservedClass(PrimitiveType):
    def covariant(self, x) -> bool: return True
    def encodeValue(self, val=None) -> bytes: return b""
    def encodeType(self, typeTable: TypeTable) -> bytes:
        return leb128.i.encode(TypeIds.Reserved.value)
    def decodeValue(self, b: Pipe, t: Type):
        if self.name != t.name:
            # Skip the value of the actual wire type
            t.decodeValue(b, t)
        return None
    @property
    def name(self) -> str: return "reserved"
    @property
    def id(self) -> int: return TypeIds.Reserved.value


class TextClass(PrimitiveType):
    def covariant(self, x) -> bool: return isinstance(x, str)
    def encodeValue(self, val: str) -> bytes:
        buf = val.encode("utf-8")
        length = leb128.u.encode(len(buf))
        return length + buf
    def encodeType(self, typeTable: TypeTable) -> bytes:
        return leb128.i.encode(TypeIds.Text.value)
    def decodeValue(self, b: Pipe, t: Type) -> str:
        self.checkType(t)
        length = leb128uDecode(b)
        buf = safeRead(b, length)
        return buf.decode("utf-8")
    @property
    def name(self) -> str: return "text"
    @property
    def id(self) -> int: return TypeIds.Text.value


class IntClass(PrimitiveType):
    def covariant(self, x) -> bool: return isinstance(x, int)
    def encodeValue(self, val: int) -> bytes: return leb128.i.encode(val)
    def encodeType(self, typeTable: TypeTable) -> bytes:
        return leb128.i.encode(TypeIds.Int.value)
    def decodeValue(self, b: Pipe, t: Type) -> int:
        self.checkType(t)
        return leb128iDecode(b)
    @property
    def name(self) -> str: return "int"
    @property
    def id(self) -> int: return TypeIds.Int.value


class NatClass(PrimitiveType):
    def covariant(self, x) -> bool: return isinstance(x, int) and x >= 0
    def encodeValue(self, val: int) -> bytes: return leb128.u.encode(val)
    def encodeType(self, typeTable: TypeTable) -> bytes:
        return leb128.i.encode(TypeIds.Nat.value)
    def decodeValue(self, b: Pipe, t: Type) -> int:
        self.checkType(t)
        return leb128uDecode(b)
    @property
    def name(self) -> str: return "nat"
    @property
    def id(self) -> int: return TypeIds.Nat.value


class FloatClass(PrimitiveType):
    def __init__(self, _bits: int):
        self._bits = _bits
        if _bits not in (32, 64):
            raise ValueError("not a valid float type")

    def covariant(self, x) -> bool: return isinstance(x, float)

    def encodeValue(self, val: float) -> bytes:
        if self._bits == 32:
            return pack("<f", val)
        return pack("<d", val)

    def encodeType(self, typeTable: TypeTable) -> bytes:
        opcode = TypeIds.Float32.value if self._bits == 32 else TypeIds.Float64.value
        return leb128.i.encode(opcode)

    def decodeValue(self, b: Pipe, t: Type) -> float:
        self.checkType(t)
        raw = safeRead(b, self._bits // 8)
        if self._bits == 32:
            return unpack("<f", raw)[0]
        return unpack("<d", raw)[0]

    @property
    def name(self) -> str: return f"float{self._bits}"
    @property
    def id(self) -> int:
        return TypeIds.Float32.value if self._bits == 32 else TypeIds.Float64.value


class FixedIntClass(PrimitiveType):
    def __init__(self, _bits: int):
        if _bits not in (8, 16, 32, 64):
            raise ValueError("bits only support 8, 16, 32, 64")
        self._bits = _bits

    def covariant(self, x) -> bool:
        minVal = -1 * 2 ** (self._bits - 1)
        maxVal = -1 + 2 ** (self._bits - 1)
        return isinstance(x, int) and (minVal <= x <= maxVal)

    def encodeValue(self, val: int) -> bytes:
        if self._bits == 8:  return pack("<b", val)
        if self._bits == 16: return pack("<h", val)
        if self._bits == 32: return pack("<i", val)
        if self._bits == 64: return pack("<q", val)
        raise ValueError("bits only support 8, 16, 32, 64")

    def encodeType(self, typeTable: TypeTable) -> bytes:
        offset = int(math.log2(self._bits) - 3)
        return leb128.i.encode(-9 - offset)

    def decodeValue(self, b: Pipe, t: Type) -> int:
        self.checkType(t)
        raw = safeRead(b, self._bits // 8)
        if self._bits == 8:  return unpack("<b", raw)[0]
        if self._bits == 16: return unpack("<h", raw)[0]
        if self._bits == 32: return unpack("<i", raw)[0]
        if self._bits == 64: return unpack("<q", raw)[0]
        raise ValueError("bits only support 8, 16, 32, 64")

    @property
    def name(self) -> str: return f"int{self._bits}"
    @property
    def id(self) -> int:
        return {
            8:  TypeIds.Int8.value,
            16: TypeIds.Int16.value,
            32: TypeIds.Int32.value,
            64: TypeIds.Int64.value,
        }[self._bits]


class FixedNatClass(PrimitiveType):
    def __init__(self, _bits: int):
        if _bits not in (8, 16, 32, 64):
            raise ValueError("bits only support 8, 16, 32, 64")
        self._bits = _bits

    def covariant(self, x) -> bool:
        return isinstance(x, int) and (0 <= x <= (-1 + 2 ** self._bits))

    def encodeValue(self, val: int) -> bytes:
        if self._bits == 8:  return pack("<B", val)
        if self._bits == 16: return pack("<H", val)
        if self._bits == 32: return pack("<I", val)
        if self._bits == 64: return pack("<Q", val)
        raise ValueError("bits only support 8, 16, 32, 64")

    def encodeType(self, typeTable: TypeTable) -> bytes:
        offset = int(math.log2(self._bits) - 3)
        return leb128.i.encode(-5 - offset)

    def decodeValue(self, b: Pipe, t: Type) -> int:
        self.checkType(t)
        raw = safeRead(b, self._bits // 8)
        if self._bits == 8:  return unpack("<B", raw)[0]
        if self._bits == 16: return unpack("<H", raw)[0]
        if self._bits == 32: return unpack("<I", raw)[0]
        if self._bits == 64: return unpack("<Q", raw)[0]
        raise ValueError("bits only support 8, 16, 32, 64")

    @property
    def name(self) -> str: return f"nat{self._bits}"
    @property
    def id(self) -> int:
        return {
            8:  TypeIds.Nat8.value,
            16: TypeIds.Nat16.value,
            32: TypeIds.Nat32.value,
            64: TypeIds.Nat64.value,
        }[self._bits]


# -----------------------------
# Constructed types
# -----------------------------

class VecClass(ConstructType):
    def __init__(self, _type: Type):
        self._type = _type

    def covariant(self, x) -> bool:
        if isinstance(x, (str, bytes, bytearray)):
            return False
        return isinstance(x, Iterable) and all(self._type.covariant(v) for v in x)

    def encodeValue(self, val) -> bytes:
        items = list(val)
        length = leb128.u.encode(len(items))
        vec = [self._type.encodeValue(v) for v in items]
        return length + b"".join(vec)

    def _buildTypeTableImpl(self, typeTable: TypeTable):
        self._type.buildTypeTable(typeTable)
        opCode = leb128.i.encode(TypeIds.Vec.value)
        buffer = self._type.encodeType(typeTable)
        typeTable.add(self, opCode + buffer)

    def decodeValue(self, b: Pipe, t: Type):
        vec = self.checkType(t)
        if not isinstance(vec, VecClass):
            raise ValueError("Not a vector type")
        length = leb128uDecode(b)
        return [self._type.decodeValue(b, vec._type) for _ in range(length)]

    @property
    def name(self) -> str:
        return f"vec ({self._type.name})"

    @property
    def id(self) -> int:
        return TypeIds.Vec.value

    def display(self) -> str:
        return f"vec {self._type.display()}"


class OptClass(ConstructType):
    def __init__(self, _type: Type):
        self._type = _type

    def covariant(self, x) -> bool:
        # [] or [value] and value type matches
        return isinstance(x, list) and (len(x) == 0 or (len(x) == 1 and self._type.covariant(x[0])))

    def encodeValue(self, val) -> bytes:
        if len(val) == 0:
            return b"\x00"
        return b"\x01" + self._type.encodeValue(val[0])

    def _buildTypeTableImpl(self, typeTable: TypeTable):
        self._type.buildTypeTable(typeTable)
        opCode = leb128.i.encode(TypeIds.Opt.value)
        buffer = self._type.encodeType(typeTable)
        typeTable.add(self, opCode + buffer)

    def decodeValue(self, b: Pipe, t: Type):
        opt = self.checkType(t)
        if not isinstance(opt, OptClass):
            raise ValueError("Not an option type")
        flag = safeReadByte(b)
        if flag == b"\x00":
            return []
        if flag == b"\x01":
            return [self._type.decodeValue(b, opt._type)]
        raise ValueError("Not an option value")

    @property
    def name(self) -> str:
        return f"opt ({self._type.name})"

    @property
    def id(self) -> int:
        return TypeIds.Opt.value

    def display(self) -> str:
        return f"opt ({self._type.display()})"


class RecordClass(ConstructType):
    def __init__(self, field: dict[str, Type]):
        # sort by label hash ascending (Candid canonical order)
        self._fields = dict(sorted(field.items(), key=lambda kv: idl_hash(kv[0])))

    def tryAsTuple(self):
        res = []
        idx = 0
        for k, v in self._fields.items():
            if k != f"_{idx}_":
                return None
            res.append(v)
            idx += 1
        return res

    def covariant(self, x: dict) -> bool:
        if not isinstance(x, dict):
            raise ValueError("Expected dict type input.")
        for k, v in self._fields.items():
            if k not in x:
                raise ValueError(f"Record is missing key {k}")
            if not v.covariant(x[k]):
                return False
        return True

    def encodeValue(self, val: dict) -> bytes:
        bufs = []
        for k, v in self._fields.items():
            bufs.append(v.encodeValue(val[k]))
        return b"".join(bufs)

    def _buildTypeTableImpl(self, typeTable: TypeTable):
        for _, v in self._fields.items():
            v.buildTypeTable(typeTable)
        opCode = leb128.i.encode(TypeIds.Record.value)
        length = leb128.u.encode(len(self._fields))
        fields = b""
        for k, v in self._fields.items():
            fields += leb128.u.encode(idl_hash(k)) + v.encodeType(typeTable)
        typeTable.add(self, opCode + length + fields)

    def decodeValue(self, b: Pipe, t: Type):
        record = self.checkType(t)
        if not isinstance(record, RecordClass):
            raise ValueError("Not a record type")

        x = {}
        idx = 0
        keys = list(self._fields.keys())
        for k, v in record._fields.items():
            # k like "_123456_": extract wire hash u32
            try:
                wire_hash = int(k[1:-1])
            except Exception:
                raise ValueError(f"invalid wire record key {k}")
            if idx >= len(self._fields) or (idl_hash(keys[idx]) != wire_hash):
                # skip unknown/extra field from wire
                v.decodeValue(b, v)
                continue
            expectKey = keys[idx]
            expectType = self._fields[expectKey]
            x[expectKey] = expectType.decodeValue(b, v)
            idx += 1
        if idx < len(self._fields):
            raise ValueError(f"Cannot find field {keys[idx]}")
        return x

    @property
    def name(self) -> str:
        fields = ";".join(f"{k}:{v.name}" for k, v in self._fields.items())
        return f"record {{{fields}}}"

    @property
    def id(self) -> int:
        return TypeIds.Record.value

    def display(self) -> str:
        d = {k: v.display() for k, v in self._fields.items()}
        return f"record {d}"


class TupleClass(RecordClass):
    def __init__(self, *components: Type):
        x = {f"_{i}_": v for i, v in enumerate(components)}
        super().__init__(x)
        self._components = list(components)

    def covariant(self, x) -> bool:
        if not isinstance(x, (tuple, list)):
            raise ValueError("Expected tuple/list type input.")
        if len(x) < len(self._components):
            return False
        for idx, v in enumerate(self._components):
            if not v.covariant(x[idx]):
                return False
        return True

    def encodeValue(self, val) -> bytes:
        bufs = b""
        for i, comp in enumerate(self._components):
            bufs += comp.encodeValue(val[i])
        return bufs

    def decodeValue(self, b: Pipe, t: Type):
        tup = self.checkType(t)
        if not isinstance(tup, TupleClass):
            raise ValueError("not a tuple type")
        if len(tup._components) != len(self._components):
            raise ValueError("tuple mismatch")
        res = []
        for i, wireType in enumerate(tup._components):
            if i >= len(self._components):
                wireType.decodeValue(b, wireType)
            else:
                res.append(self._components[i].decodeValue(b, wireType))
        return res

    @property
    def id(self) -> int:
        # Tuple has no dedicated opcode; it's encoded as a Record.
        return TypeIds.Record.value

    def display(self) -> str:
        d = [item.display() for item in self._components]
        return "record {" + ";".join(d) + "}"


class VariantClass(ConstructType):
    def __init__(self, field: dict[str, Type]):
        self._fields = dict(sorted(field.items(), key=lambda kv: idl_hash(kv[0])))

    def covariant(self, x) -> bool:
        if not isinstance(x, dict) or len(x) != 1:
            return False
        for k, v in self._fields.items():
            if k in x and v.covariant(x[k]):
                return True
        return False

    def encodeValue(self, val: dict) -> bytes:
        idx = 0
        for name, ty in self._fields.items():
            if name in val:
                # Variant tag index is ULEB128
                count = leb128.u.encode(idx)
                buf = ty.encodeValue(val[name])
                return count + buf
            idx += 1
        raise ValueError(f"Variant has no data: {val}")

    def _buildTypeTableImpl(self, typeTable: TypeTable):
        for _, v in self._fields.items():
            v.buildTypeTable(typeTable)
        opCode = leb128.i.encode(TypeIds.Variant.value)
        length = leb128.u.encode(len(self._fields))
        fields = b""
        for k, v in self._fields.items():
            fields += leb128.u.encode(idl_hash(k)) + v.encodeType(typeTable)
        typeTable.add(self, opCode + length + fields)

    def decodeValue(self, b: Pipe, t: Type):
        variant = self.checkType(t)
        if not isinstance(variant, VariantClass):
            raise ValueError("Not a variant type")
        idx = leb128uDecode(b)
        if idx >= len(variant._fields):
            raise ValueError(f"Invalid variant index: {idx}")
        keys = list(variant._fields.keys())
        wireKey = keys[idx]
        wireType = variant._fields[wireKey]
        # extract u32 hash from "_<hash>_"
        try:
            wire_hash = int(wireKey[1:-1])
        except Exception:
            raise ValueError(f"invalid wire variant key {wireKey}")

        for key, expectType in self._fields.items():
            if idl_hash(key) == wire_hash:
                value = None if expectType is None else expectType.decodeValue(b, wireType)
                return {key: value}
        raise ValueError(f"Cannot find field hash {wireKey}")

    @property
    def name(self) -> str:
        fields = ";".join(f"{k}:{v.name}" for k, v in self._fields.items())
        return f"variant {{{fields}}}"

    @property
    def id(self) -> int:
        return TypeIds.Variant.value

    def display(self) -> str:
        d = {k: ("" if v.name is None else v.name) for k, v in self._fields.items()}
        return f"variant {d}"


class RecClass(ConstructType):
    _counter = 0

    def __init__(self):
        self._id = RecClass._counter
        RecClass._counter += 1
        self._type: ConstructType | None = None

    def fill(self, t: ConstructType):
        self._type = t

    def getType(self):
        if isinstance(self._type, RecClass):
            return self._type.getType()
        return self._type

    def covariant(self, x) -> bool:
        return False if self._type is None else self._type.covariant(x)

    def encodeValue(self, val) -> bytes:
        if self._type is None:
            raise ValueError("Recursive type uninitialized")
        return self._type.encodeValue(val)

    def encodeType(self, typeTable: TypeTable) -> bytes:
        if isinstance(self._type, PrimitiveType):
            return self._type.encodeType(typeTable)
        return super().encodeType(typeTable)

    def _buildTypeTableImpl(self, typeTable: TypeTable):
        if self._type is None:
            raise ValueError("Recursive type uninitialized")
        if not isinstance(self.getType(), PrimitiveType):
            typeTable.add(self, b"")          # placeholder
            self._type.buildTypeTable(typeTable)
            typeTable.merge(self, self._type.name)

    def decodeValue(self, b: Pipe, t: Type):
        if self._type is None:
            raise ValueError("Recursive type uninitialized")
        return self._type.decodeValue(b, t)

    @property
    def name(self) -> str:
        return f"rec_{self._id}"

    def display(self) -> str:
        if self._type is None:
            raise ValueError("Recursive type uninitialized")
        return f"{self.name}.{self._type.name}"


class PrincipalClass(PrimitiveType):
    def covariant(self, x) -> bool:
        if isinstance(x, str):
            p = P.from_str(x)
        elif isinstance(x, bytes):
            p = P.from_hex(x.hex())
        else:
            raise ValueError("only support string or bytes format")
        return p.isPrincipal

    def encodeValue(self, val) -> bytes:
        if isinstance(val, str):
            buf = P.from_str(val).bytes
        elif isinstance(val, bytes):
            buf = val
        else:
            raise ValueError("Principal should be string or bytes.")
        l = leb128.u.encode(len(buf))
        return l + buf

    def encodeType(self, typeTable: TypeTable) -> bytes:
        return leb128.i.encode(TypeIds.Principal.value)

    def decodeValue(self, b: Pipe, t: Type):
        self.checkType(t)
        length = leb128uDecode(b)
        return P.from_hex(safeRead(b, length).hex())

    @property
    def name(self) -> str: return "principal"
    @property
    def id(self) -> int: return TypeIds.Principal.value


class FuncClass(ConstructType):
    def __init__(self, argTypes: list[Type], retTypes: list[Type], annotations: list[str]):
        self.argTypes = argTypes
        self.retTypes = retTypes
        self.annotations = annotations

    def covariant(self, x) -> bool:
        return (
            isinstance(x, list) and len(x) == 2 and x[0] and
            (P.from_str(x[0]) if isinstance(x[0], str) else P.from_hex(x[0].hex())).isPrincipal and
            isinstance(x[1], str)
        )

    def encodeValue(self, vals) -> bytes:
        principal, methodName = vals
        if isinstance(principal, str):
            pbytes = P.from_str(principal).bytes
        elif isinstance(principal, bytes):
            pbytes = principal
        else:
            raise ValueError("Principal should be string or bytes.")
        canister = leb128.u.encode(len(pbytes)) + pbytes
        method = methodName.encode("utf-8")
        methodLen = leb128.u.encode(len(method))
        return canister + methodLen + method

    def _buildTypeTableImpl(self, typeTable: TypeTable):
        for arg in self.argTypes:
            arg.buildTypeTable(typeTable)
        for ret in self.retTypes:
            ret.buildTypeTable(typeTable)

        opCode = leb128.i.encode(TypeIds.Func.value)
        argLen = leb128.u.encode(len(self.argTypes))
        args = b"".join(arg.encodeType(typeTable) for arg in self.argTypes)
        retLen = leb128.u.encode(len(self.retTypes))
        rets = b"".join(ret.encodeType(typeTable) for ret in self.retTypes)
        annLen = leb128.u.encode(len(self.annotations))
        anns = b"".join(self._encodeAnnotation(a) for a in self.annotations)
        typeTable.add(self, opCode + argLen + args + retLen + rets + annLen + anns)

    def decodeValue(self, b: Pipe, t: Type):
        length = leb128uDecode(b)
        canister = P.from_hex(safeRead(b, length).hex())
        mLen = leb128uDecode(b)
        method = safeRead(b, mLen).decode("utf-8")
        return [canister, method]

    @property
    def name(self) -> str:
        args = ", ".join(arg.name for arg in self.argTypes)
        rets = ", ".join(ret.name for ret in self.retTypes)
        anns = " ".join(self.annotations)
        return f"({args}) \u2192 ({rets}) {anns}".strip()

    @property
    def id(self) -> int:
        return TypeIds.Func.value

    def display(self) -> str:
        args = ", ".join(arg.display() for arg in self.argTypes)
        rets = ", ".join(ret.display() for ret in self.retTypes)
        anns = " ".join(self.annotations)
        return f"({args}) \u2192 ({rets}) {anns}".strip()

    def _encodeAnnotation(self, ann: str) -> bytes:
        if ann == "query":
            return (1).to_bytes(1, "big")
        if ann == "oneway":
            return (2).to_bytes(1, "big")
        raise ValueError("Illegal function annotation")


class ServiceClass(ConstructType):
    def __init__(self, field: dict[str, Type]):
        self._fields = dict(sorted(field.items(), key=lambda kv: idl_hash(kv[0])))

    def covariant(self, x) -> bool:
        if isinstance(x, str):
            p = P.from_str(x)
        elif isinstance(x, bytes):
            p = P.from_hex(x.hex())
        else:
            raise ValueError("only support string or bytes format")
        return p.isPrincipal

    def encodeValue(self, val) -> bytes:
        if isinstance(val, str):
            buf = P.from_str(val).bytes
        elif isinstance(val, bytes):
            buf = val
        else:
            raise ValueError("Principal should be string or bytes.")
        l = leb128.u.encode(len(buf))
        return l + buf

    def _buildTypeTableImpl(self, typeTable: TypeTable):
        for _, v in self._fields.items():
            v.buildTypeTable(typeTable)
        opCode = leb128.i.encode(TypeIds.Service.value)
        length = leb128.u.encode(len(self._fields))
        fields = b""
        for k, v in self._fields.items():
            kbytes = k.encode("utf-8")
            fields += leb128.u.encode(len(kbytes)) + kbytes + v.encodeType(typeTable)
        typeTable.add(self, opCode + length + fields)

    def decodeValue(self, b: Pipe, t: Type):
        length = leb128uDecode(b)
        return P.from_hex(safeRead(b, length).hex())

    @property
    def name(self) -> str:
        fields = "".join(f"{k} : {v.name}" for k, v in self._fields.items())
        return f"service {fields}"

    @property
    def id(self) -> int:
        return TypeIds.Service.value


# -----------------------------
# TypeTable decoding helpers
# -----------------------------

def readTypeTable(pipe: Pipe):
    # types length
    typeTable = []
    typeTable_len = leb128uDecode(pipe)
    for _ in range(typeTable_len):
        ty = leb128iDecode(pipe)
        if ty in (TypeIds.Opt.value, TypeIds.Vec.value):
            t = leb128iDecode(pipe)
            typeTable.append([ty, t])
        elif ty in (TypeIds.Record.value, TypeIds.Variant.value):
            fields = []
            objLength = leb128uDecode(pipe)
            prevHash = -1
            for _ in range(objLength):
                h = leb128uDecode(pipe)
                if h >= 2 ** 32:
                    raise ValueError("field id out of 32-bit range")
                if isinstance(prevHash, int) and prevHash >= h:
                    raise ValueError("field id collision or not sorted")
                prevHash = h
                t = leb128iDecode(pipe)
                fields.append([h, t])
            typeTable.append([ty, fields])
        elif ty == TypeIds.Func.value:
            for _ in range(2):
                funLen = leb128uDecode(pipe)
                for _ in range(funLen):
                    leb128iDecode(pipe)
            annLen = leb128uDecode(pipe)
            safeRead(pipe, annLen)
            typeTable.append([ty, None])
        elif ty == TypeIds.Service.value:
            servLen = leb128uDecode(pipe)
            for _ in range(servLen):
                l = leb128uDecode(pipe)
                safeRead(pipe, l)
                leb128iDecode(pipe)
            typeTable.append([ty, None])
        else:
            raise ValueError(f"illegal opcode: {ty}")

    rawList = []
    types_len = leb128uDecode(pipe)
    for _ in range(types_len):
        rawList.append(leb128iDecode(pipe))
    return typeTable, rawList


def getType(rawTable, table, t: int) -> Type:
    if t < TypeIds.Principal.value:
        raise ValueError("not supported type")
    if t < 0:
        mapping = {
            TypeIds.Null.value: Types.Null,
            TypeIds.Bool.value: Types.Bool,
            TypeIds.Nat.value: Types.Nat,
            TypeIds.Int.value: Types.Int,
            TypeIds.Nat8.value: Types.Nat8,
            TypeIds.Nat16.value: Types.Nat16,
            TypeIds.Nat32.value: Types.Nat32,
            TypeIds.Nat64.value: Types.Nat64,
            TypeIds.Int8.value: Types.Int8,
            TypeIds.Int16.value: Types.Int16,
            TypeIds.Int32.value: Types.Int32,
            TypeIds.Int64.value: Types.Int64,
            TypeIds.Float32.value: Types.Float32,
            TypeIds.Float64.value: Types.Float64,
            TypeIds.Text.value: Types.Text,
            TypeIds.Reserved.value: Types.Reserved,
            TypeIds.Empty.value: Types.Empty,
            TypeIds.Principal.value: Types.Principal,
        }
        if t in mapping:
            return mapping[t]
        raise ValueError(f"illegal opcode:{t}")
    if t >= len(rawTable):
        raise ValueError("type index out of range")
    return table[t]


def buildType(rawTable, table, entry):
    ty = entry[0]
    if ty == TypeIds.Vec.value:
        t = getType(rawTable, table, entry[1])
        return Types.Vec(t)
    elif ty == TypeIds.Opt.value:
        t = getType(rawTable, table, entry[1])
        return Types.Opt(t)
    elif ty == TypeIds.Record.value:
        fields = {}
        for h, t in entry[1]:
            name = f"_{h}_"
            temp = getType(rawTable, table, t)
            fields[name] = temp
        record = Types.Record(fields)
        tup = record.tryAsTuple()
        if isinstance(tup, list):
            return Types.Tuple(*tup)
        return record
    elif ty == TypeIds.Variant.value:
        fields = {}
        for h, t in entry[1]:
            name = f"_{h}_"
            temp = getType(rawTable, table, t)
            fields[name] = temp
        return Types.Variant(fields)
    elif ty == TypeIds.Func.value:
        return Types.Func([], [], [])
    elif ty == TypeIds.Service.value:
        return Types.Service({})
    else:
        raise ValueError(f"illegal opcode: {ty}")


# -----------------------------
# Top-level encode/decode
# -----------------------------

def encode(params):
    """
    params: list of {'type': Type, 'value': any}
    returns: bytes
    """
    argTypes = [p["type"] for p in params]
    args = [p["value"] for p in params]
    if len(argTypes) != len(args):
        raise ValueError("Wrong number of message arguments")

    typetable = TypeTable()
    for item in argTypes:
        item.buildTypeTable(typetable)

    pre = prefix.encode("utf-8")
    table = typetable.encode()
    length = leb128.u.encode(len(args))

    typs = b"".join(t.encodeType(typetable) for t in argTypes)
    vals = b""
    for t, v in zip(argTypes, args):
        if not t.covariant(v):
            raise TypeError(f"Invalid {t.display()} argument: {v}")
        vals += t.encodeValue(v)
    return pre + table + length + typs + vals


def decode(data: bytes, retTypes=None):
    b = Pipe(data)
    if len(data) < len(prefix):
        raise ValueError("Message length smaller than prefix number")
    prefix_buffer = safeRead(b, len(prefix)).decode("utf-8")
    if prefix_buffer != prefix:
        raise ValueError("Wrong prefix:" + prefix_buffer + " expected prefix: DIDL")
    rawTable, rawTypes = readTypeTable(b)

    if retTypes:
        if not isinstance(retTypes, list):
            retTypes = [retTypes]
        if len(rawTypes) < len(retTypes):
            raise ValueError("Wrong number of return value")

    table = [Types.Rec() for _ in range(len(rawTable))]
    for i, entry in enumerate(rawTable):
        t_constructed = buildType(rawTable, table, entry)
        table[i].fill(t_constructed)

    types_on_wire = [getType(rawTable, table, t) for t in rawTypes]
    outputs = []
    iter_types = types_on_wire if retTypes is None else retTypes
    for i, ty in enumerate(iter_types):
        outputs.append({
            "type": ty.name,
            "value": ty.decodeValue(b, types_on_wire[i])
        })
    return outputs


# -----------------------------
# Types facade
# -----------------------------

class Types:
    # primitives
    Null = NullClass()
    Empty = EmptyClass()
    Bool = BoolClass()
    Int = IntClass()
    Reserved = ReservedClass()
    Nat = NatClass()
    Text = TextClass()
    Principal = PrincipalClass()
    Float32 = FloatClass(32)
    Float64 = FloatClass(64)
    Int8 = FixedIntClass(8)
    Int16 = FixedIntClass(16)
    Int32 = FixedIntClass(32)
    Int64 = FixedIntClass(64)
    Nat8 = FixedNatClass(8)
    Nat16 = FixedNatClass(16)
    Nat32 = FixedNatClass(32)
    Nat64 = FixedNatClass(64)

    @staticmethod
    def Tuple(*types: Type) -> TupleClass:
        return TupleClass(*types)

    @staticmethod
    def Vec(t: Type) -> VecClass:
        return VecClass(t)

    @staticmethod
    def Opt(t: Type) -> OptClass:
        return OptClass(t)

    @staticmethod
    def Record(t: dict[str, Type]) -> RecordClass:
        return RecordClass(t)

    @staticmethod
    def Variant(fields: dict[str, Type]) -> VariantClass:
        return VariantClass(fields)

    @staticmethod
    def Rec() -> RecClass:
        return RecClass()

    @staticmethod
    def Func(args: list[Type], ret: list[Type], annotations: list[str]) -> FuncClass:
        return FuncClass(args, ret, annotations)

    @staticmethod
    def Service(t: dict[str, Type]) -> ServiceClass:
        return ServiceClass(t)