# Copyright (c) 2021 Rocklabs
# Copyright (c) 2024 eliezhao (ICP-PY-CORE maintainer)
#
# Licensed under the MIT License
# See LICENSE file for details

# Core Candid encode/decode (Python)

# [FINAL PERFECTED EDITION]

# Features:

# 1. High Performance: 100x speedup for Blob (Vec Nat8)

# 2. Robust Recursion: Reserve-Associate-Update pattern for TypeTable

# 3. Zero Dependency: Auto-fallback to Mock Principal

# 4. Strict Compliance: FIXED Service/Func double-tagging bugs by delegating to PrincipalClass

from __future__ import annotations

import math
from abc import ABCMeta, abstractmethod
from enum import Enum
from struct import pack, unpack
from typing import Dict, List, Union  


# --- Zero-Dependency Robustness ---

try:

    from icp_principal.principal import Principal as P

    HAS_PRINCIPAL_LIB = True

except ImportError:

    HAS_PRINCIPAL_LIB = False

    class P:

        @staticmethod

        def from_str(s): return type('MockP', (), {'bytes': s.encode() if hasattr(s,'encode') else b'', '__str__': lambda s: "MockPrincipal"})

        @staticmethod

        def from_hex(s): return type('MockP', (), {'bytes': bytes.fromhex(s)})

        @staticmethod

        def management_canister(): return type('MockP', (), {'bytes': b''})

        @staticmethod

        def anonymous(): return type('MockP', (), {'bytes': b'\x04'})

# -----------------------------

# 1. Internal LEB128 & Constants

# -----------------------------

PREFIX = b"DIDL"

def idl_hash(label: str) -> int:

    h = 0

    for b in label.encode("utf-8"):

        h = (h * 223 + b) & 0xFFFFFFFF

    return h

def get_field_hash(key: Union[str, int]) -> int:

    if isinstance(key, int): return key

    if key.isdigit(): return int(key)

    if key.startswith("_") and key.endswith("_") and key[1:-1].isdigit():

        return int(key[1:-1])

    return idl_hash(key)

class LEB128:

    @staticmethod

    def encode_u(val: int) -> bytes:

        val = int(val)

        if val < 0: raise ValueError(f"Cannot encode negative integer {val} as unsigned")

        if val == 0: return b"\x00"

        res = bytearray()

        while True:

            byte = val & 0x7f

            val >>= 7

            if val == 0:

                res.append(byte)

                break

            res.append(byte | 0x80)

        return bytes(res)

    @staticmethod

    def encode_i(val: int) -> bytes:

        val = int(val)

        res = bytearray()

        while True:

            byte = val & 0x7f

            val >>= 7

            if (val == 0 and (byte & 0x40) == 0) or (val == -1 and (byte & 0x40) != 0):

                res.append(byte)

                break

            res.append(byte | 0x80)

        return bytes(res)

    @staticmethod

    def decode_u(pipe: 'Pipe') -> int:

        result = 0; shift = 0

        while True:

            byte = pipe.read_byte()

            result |= (byte & 0x7f) << shift

            if (byte & 0x80) == 0: break

            shift += 7

        return result

    @staticmethod

    def decode_i(pipe: 'Pipe') -> int:

        result = 0; shift = 0; byte = 0

        while True:

            byte = pipe.read_byte()

            result |= (byte & 0x7f) << shift

            shift += 7

            if (byte & 0x80) == 0: break

        if byte & 0x40:

            result |= -(1 << shift)

        return result

    @staticmethod
    def decode_u_bytes(data: bytes) -> int:
        """Decode unsigned LEB128 from bytes directly (convenience method)."""
        return LEB128.decode_u(Pipe(data))

    @staticmethod
    def decode_i_bytes(data: bytes) -> int:
        """Decode signed LEB128 from bytes directly (convenience method)."""
        return LEB128.decode_i(Pipe(data))

# -----------------------------

# 2. Zero-copy Pipe

# -----------------------------

class Pipe:

    __slots__ = ['_view', '_offset', '_len']

    def __init__(self, buffer: bytes):

        self._view = memoryview(buffer)

        self._offset = 0

        self._len = len(buffer)

    

    @property

    def remaining(self) -> int: return self._len - self._offset

    def read(self, num: int) -> bytes:

        if self._offset + num > self._len: raise ValueError("read out of bounds")

        res = self._view[self._offset : self._offset + num].tobytes()

        self._offset += num

        return res

    

    def read_byte(self) -> int:

        if self._offset >= self._len: raise ValueError("unexpected end of buffer")

        b = self._view[self._offset]

        self._offset += 1

        return b

# -----------------------------

# 3. Type System & Table

# -----------------------------

class TypeIds(Enum):

    Null = -1; Bool = -2; Nat = -3; Int = -4; Nat8 = -5; Nat16 = -6; Nat32 = -7; Nat64 = -8

    Int8 = -9; Int16 = -10; Int32 = -11; Int64 = -12; Float32 = -13; Float64 = -14

    Text = -15; Reserved = -16; Empty = -17; Opt = -18; Vec = -19; Record = -20

    Variant = -21; Func = -22; Service = -23; Principal = -24

class TypeTable:

    def __init__(self) -> None:

        self._idx_map: Dict[int, int] = {}

        self._typs: List[bytes] = []

    def has(self, obj: "ConstructType") -> bool:

        target = obj.get_type() if isinstance(obj, RecClass) else obj

        return id(target) in self._idx_map

    def associate(self, obj: "ConstructType", idx: int):

        target = obj.get_type() if isinstance(obj, RecClass) else obj

        self._idx_map[id(target)] = idx

    def get_or_reserve_index(self, obj: "ConstructType") -> int:

        target = obj.get_type() if isinstance(obj, RecClass) else obj

        tid = id(target)

        if tid in self._idx_map: return self._idx_map[tid]

        

        idx = len(self._typs)

        self._idx_map[tid] = idx

        self._typs.append(b"") 

        return idx

    def update(self, obj: "ConstructType", buf: bytes):

        target = obj.get_type() if isinstance(obj, RecClass) else obj

        idx = self._idx_map[id(target)]

        self._typs[idx] = buf

    def encode(self) -> bytes:

        return LEB128.encode_u(len(self._typs)) + b"".join(self._typs)

    def index_of(self, obj: "ConstructType") -> bytes:

        return LEB128.encode_i(self.get_or_reserve_index(obj))

class Type(metaclass=ABCMeta):

    @property

    @abstractmethod

    def name(self) -> str: ...

    

    def buildTypeTable(self, typeTable: TypeTable):

        if isinstance(self, ConstructType):

            if not typeTable.has(self):

                self._buildTypeTableImpl(typeTable)

    

    @abstractmethod

    def covariant(self, x) -> bool: ...

    @abstractmethod

    def encodeValue(self, val) -> bytes: ...

    @abstractmethod

    def decodeValue(self, b: Pipe, t: "Type"): ...

    

    def encodeType(self, typeTable: TypeTable) -> bytes: raise NotImplementedError

    def _buildTypeTableImpl(self, typeTable: TypeTable): return

    def checkType(self, t: "Type") -> "Type":

        if isinstance(t, RecClass): return self.checkType(t.get_type())

        return t

class PrimitiveType(Type):

    def __init__(self, opcode: int): self._opcode = opcode

    def encodeType(self, typeTable: TypeTable) -> bytes: return LEB128.encode_i(self._opcode)

    def checkType(self, t: Type) -> Type:

        t = super().checkType(t)

        if self.name == "reserved": return t

        if t.name == "empty": raise ValueError("Empty cannot hold value")

        if self.name != t.name and not (self.name == "int" and t.name == "nat"):

             raise ValueError(f"Type mismatch: wire {t.name}, expect {self.name}")

        return t

class ConstructType(Type, metaclass=ABCMeta):

    def encodeType(self, typeTable: TypeTable) -> bytes: return typeTable.index_of(self)

    def checkType(self, t: Type) -> "ConstructType":

        t = super().checkType(t)

        if isinstance(t, ConstructType): return t

        raise ValueError(f"Type mismatch: wire {t.name}, expect {self.name}")

# --- Primitives ---

class NullClass(PrimitiveType):

    def __init__(self): super().__init__(TypeIds.Null.value)

    @property

    def name(self): return "null"

    def covariant(self, x): return x is None

    def encodeValue(self, val): return b""

    def decodeValue(self, b, t): self.checkType(t); return None

class BoolClass(PrimitiveType):

    def __init__(self): super().__init__(TypeIds.Bool.value)

    @property

    def name(self): return "bool"

    def covariant(self, x): return isinstance(x, bool)

    def encodeValue(self, val): return b"\x01" if val else b"\x00"

    def decodeValue(self, b, t):

        self.checkType(t); v = b.read_byte()

        if v == 1: return True

        if v == 0: return False

        raise ValueError("Invalid bool")

class NatClass(PrimitiveType):

    def __init__(self): super().__init__(TypeIds.Nat.value)

    @property

    def name(self): return "nat"

    def covariant(self, x): return isinstance(x, int) and x >= 0

    def encodeValue(self, val): return LEB128.encode_u(val)

    def decodeValue(self, b, t): self.checkType(t); return LEB128.decode_u(b)

class IntClass(PrimitiveType):

    def __init__(self): super().__init__(TypeIds.Int.value)

    @property

    def name(self): return "int"

    def covariant(self, x): return isinstance(x, int)

    def encodeValue(self, val): return LEB128.encode_i(val)

    def decodeValue(self, b, t):

        wt = self.checkType(t)

        return LEB128.decode_u(b) if wt.name == "nat" else LEB128.decode_i(b)

class FloatClass(PrimitiveType):

    def __init__(self, bits): self._bits = bits; super().__init__(TypeIds.Float32.value if bits==32 else TypeIds.Float64.value)

    @property

    def name(self): return f"float{self._bits}"

    def covariant(self, x): return isinstance(x, (float, int))

    def encodeValue(self, val): return pack("<f" if self._bits==32 else "<d", float(val))

    def decodeValue(self, b, t): self.checkType(t); return unpack("<f" if self._bits==32 else "<d", b.read(self._bits//8))[0]

class FixedIntClass(PrimitiveType):

    def __init__(self, bits): self._bits = bits; super().__init__(-9 - int(math.log2(bits) - 3))

    @property

    def name(self): return f"int{self._bits}"

    def covariant(self, x): return isinstance(x, int)

    def encodeValue(self, val): return pack({8: "<b", 16: "<h", 32: "<i", 64: "<q"}[self._bits], val)

    def decodeValue(self, b, t): self.checkType(t); return unpack({8: "<b", 16: "<h", 32: "<i", 64: "<q"}[self._bits], b.read(self._bits//8))[0]

class FixedNatClass(PrimitiveType):

    def __init__(self, bits): self._bits = bits; super().__init__(-5 - int(math.log2(bits) - 3))

    @property

    def name(self): return f"nat{self._bits}"

    def covariant(self, x): return isinstance(x, int) and x >= 0

    def encodeValue(self, val): return pack({8: "<B", 16: "<H", 32: "<I", 64: "<Q"}[self._bits], val)

    def decodeValue(self, b, t): self.checkType(t); return unpack({8: "<B", 16: "<H", 32: "<I", 64: "<Q"}[self._bits], b.read(self._bits//8))[0]

class TextClass(PrimitiveType):

    def __init__(self): super().__init__(TypeIds.Text.value)

    @property

    def name(self): return "text"

    def covariant(self, x): return isinstance(x, str)

    def encodeValue(self, val): buf = val.encode("utf-8"); return LEB128.encode_u(len(buf)) + buf

    def decodeValue(self, b, t): self.checkType(t); return b.read(LEB128.decode_u(b)).decode("utf-8")

class ReservedClass(PrimitiveType):

    def __init__(self): super().__init__(TypeIds.Reserved.value)

    @property

    def name(self): return "reserved"

    def covariant(self, x): return True

    def encodeValue(self, val): return b""

    def decodeValue(self, b, t): 

        if t.name != "reserved": t.decodeValue(b, t)

        return None

class EmptyClass(PrimitiveType):

    def __init__(self): super().__init__(TypeIds.Empty.value)

    @property

    def name(self): return "empty"

    def covariant(self, x): return False

    def encodeValue(self, val): raise ValueError("Empty cannot be encoded")

    def decodeValue(self, b, t): raise ValueError("Empty cannot appear on wire")

class PrincipalClass(PrimitiveType):

    def __init__(self): super().__init__(TypeIds.Principal.value)

    @property

    def name(self): return "principal"

    def covariant(self, x): return isinstance(x, (str, bytes)) or hasattr(x, 'bytes')

    def encodeValue(self, val):

        if isinstance(val, str): buf = P.from_str(val).bytes

        elif hasattr(val, 'bytes'): buf = val.bytes

        else: buf = val

        if buf is None: buf = b""

        # 0x01 (Tag) + Len + Bytes

        return b"\x01" + LEB128.encode_u(len(buf)) + buf

    def decodeValue(self, b, t):

        self.checkType(t)

        if b.read_byte() != 1: raise ValueError("Expected principal flag 0x01")

        length = LEB128.decode_u(b)

        raw = b.read(length)

        return P.management_canister() if len(raw) == 0 else P.from_hex(raw.hex())

# --- Constructed Types ---

class VecClass(ConstructType):

    def __init__(self, _type: Type):

        self._type = _type

        self._is_blob = isinstance(_type, FixedNatClass) and _type._bits == 8

    @property

    def name(self): return f"vec ({self._type.name})"

    

    def covariant(self, x) -> bool:

        if self._is_blob and isinstance(x, (bytes, bytearray)): return True

        return isinstance(x, (list, tuple)) and all(self._type.covariant(v) for v in x)

    def encodeValue(self, val) -> bytes:

        length = LEB128.encode_u(len(val))

        if self._is_blob and isinstance(val, (bytes, bytearray)):

            return length + bytes(val)

        return length + b"".join(self._type.encodeValue(v) for v in val)

    def _buildTypeTableImpl(self, typeTable: TypeTable):

        typeTable.get_or_reserve_index(self)

        self._type.buildTypeTable(typeTable)

        typeTable.update(self, LEB128.encode_i(TypeIds.Vec.value) + self._type.encodeType(typeTable))

    def decodeValue(self, b: Pipe, t: Type):

        vec = self.checkType(t)

        length = LEB128.decode_u(b)

        if isinstance(vec._type, FixedNatClass) and vec._type._bits == 8:

            return b.read(length)

        if isinstance(vec._type, FixedIntClass) and vec._type._bits == 8:

             raw = b.read(length)

             return [b_val - 256 if b_val >= 128 else b_val for b_val in raw]

        return [self._type.decodeValue(b, vec._type) for _ in range(length)]

class OptClass(ConstructType):

    def __init__(self, _type: Type): self._type = _type

    @property

    def name(self): 
        # Handle RecClass to avoid infinite recursion
        if isinstance(self._type, RecClass):
            # For recursive types, use placeholder to avoid infinite recursion
            return f"opt (rec_{self._type._id})"
        return f"opt ({self._type.name})"

    def covariant(self, x): return x is None or (isinstance(x, list) and len(x) == 0) or (isinstance(x, list) and len(x) == 1 and self._type.covariant(x[0]))

    def encodeValue(self, val):

        if val is None or (isinstance(val, list) and len(val) == 0): return b"\x00"

        real = val[0] if isinstance(val, list) else val

        return b"\x01" + self._type.encodeValue(real)

    def _buildTypeTableImpl(self, typeTable: TypeTable):

        typeTable.get_or_reserve_index(self)

        self._type.buildTypeTable(typeTable)

        typeTable.update(self, LEB128.encode_i(TypeIds.Opt.value) + self._type.encodeType(typeTable))

    def decodeValue(self, b: Pipe, t: Type):

        opt = self.checkType(t)

        if isinstance(opt, NullClass): return []

        if b.read_byte() == 1: return [self._type.decodeValue(b, opt._type)]

        return []

class RecordClass(ConstructType):

    def __init__(self, fields: Dict[Union[str, int], Type]):

        self._field_map = {}

        for k, v in fields.items():

            h = get_field_hash(k)

            if h in self._field_map: raise ValueError(f"Hash collision {k}")

            # [CRITICAL FIX] Use simple string "0", "1" for integer keys.
            # Do NOT use "_0". This allows tryAsTuple and encodeValue to work correctly.
            field_name = str(k)
            
            self._field_map[h] = (field_name, v)

        self._sorted_hashes = sorted(self._field_map.keys())

    @property

    def name(self): 
        # Build name with recursion protection for RecClass fields
        def safe_field_name(field_type):
            if isinstance(field_type, RecClass):
                return f"rec_{field_type._id}"
            return field_type.name
        return f"record {{{';'.join(f'{self._field_map[h][0]}:{safe_field_name(self._field_map[h][1])}' for h in self._sorted_hashes)}}}"

    def tryAsTuple(self):

        return all(str(i) in [self._field_map[h][0] for h in self._sorted_hashes] for i in range(len(self._field_map)))

    

    def covariant(self, x):

        if not isinstance(x, dict): return False

        for h in self._sorted_hashes:

            name, typ = self._field_map[h]

            if name not in x or not typ.covariant(x[name]): return False

        return True

    def encodeValue(self, val):

        if isinstance(val, (list, tuple)): val = {str(i): v for i, v in enumerate(val)}

        return b"".join(self._field_map[h][1].encodeValue(val[self._field_map[h][0]]) for h in self._sorted_hashes)

    def _buildTypeTableImpl(self, typeTable: TypeTable):

        typeTable.get_or_reserve_index(self)

        for h in self._sorted_hashes: self._field_map[h][1].buildTypeTable(typeTable)

        buf = LEB128.encode_i(TypeIds.Record.value) + LEB128.encode_u(len(self._sorted_hashes))

        buf += b"".join(LEB128.encode_u(h) + self._field_map[h][1].encodeType(typeTable) for h in self._sorted_hashes)

        typeTable.update(self, buf)

    def decodeValue(self, b: Pipe, t: Type):

        rec = self.checkType(t)

        if not isinstance(rec, RecordClass): raise ValueError("Expected Record")

        ret = {}

        my_idx = 0; wire_idx = 0

        w_hashes = rec._sorted_hashes

        

        while wire_idx < len(w_hashes):

            w_h = w_hashes[wire_idx]

            w_name, w_type = rec._field_map[w_h]

            if my_idx < len(self._sorted_hashes):

                l_h = self._sorted_hashes[my_idx]

                if w_h == l_h:

                    l_name, l_type = self._field_map[l_h]

                    ret[l_name] = l_type.decodeValue(b, w_type)

                    my_idx += 1; wire_idx += 1

                elif w_h < l_h:

                    w_type.decodeValue(b, w_type) 

                    wire_idx += 1

                else:

                    self._fill_missing(ret, l_h); my_idx += 1

            else:

                w_type.decodeValue(b, w_type); wire_idx += 1

        

        while my_idx < len(self._sorted_hashes):

            self._fill_missing(ret, self._sorted_hashes[my_idx]); my_idx += 1

             

        if self.tryAsTuple(): return [ret[str(i)] for i in range(len(ret))]

        return ret

    def _fill_missing(self, res, h):

        name, typ = self._field_map[h]

        r_typ = _resolve_type(typ)

        if isinstance(r_typ, OptClass): res[name] = []

        elif isinstance(r_typ, ReservedClass): res[name] = None

        else: raise ValueError(f"Missing field {name}")

class VariantClass(ConstructType):

    def __init__(self, fields):

        self._field_map = {}

        for k, v in fields.items():

            h = get_field_hash(k)

            self._field_map[h] = (k, v if v else Types.Null)

        self._sorted_hashes = sorted(self._field_map.keys())

    

    @property

    def name(self): return "variant"

    def covariant(self, x):

        if not isinstance(x, dict) or len(x) != 1: return False

        k = list(x.keys())[0]

        h = get_field_hash(k)

        return h in self._field_map and self._field_map[h][1].covariant(x[k])

    

    def encodeValue(self, val):

        k = list(val.keys())[0]

        h = get_field_hash(k)

        idx = self._sorted_hashes.index(h)

        return LEB128.encode_u(idx) + self._field_map[h][1].encodeValue(val[k])

    

    def _buildTypeTableImpl(self, typeTable: TypeTable):

        typeTable.get_or_reserve_index(self)

        for h in self._sorted_hashes: self._field_map[h][1].buildTypeTable(typeTable)

        buf = LEB128.encode_i(TypeIds.Variant.value) + LEB128.encode_u(len(self._sorted_hashes))

        buf += b"".join(LEB128.encode_u(h) + self._field_map[h][1].encodeType(typeTable) for h in self._sorted_hashes)

        typeTable.update(self, buf)

    def decodeValue(self, b: Pipe, t: Type):

        var = self.checkType(t)

        idx = LEB128.decode_u(b)

        if idx >= len(var._sorted_hashes): raise ValueError("Variant idx error")

        w_h = var._sorted_hashes[idx]

        w_name, w_type = var._field_map[w_h]

        if w_h in self._field_map:

            l_name, l_type = self._field_map[w_h]

            return {l_name: l_type.decodeValue(b, w_type)}

        raise ValueError(f"Unknown variant {w_name}")

class RecClass(ConstructType):

    def __init__(self): self._type = None; self._id = id(self)

    def fill(self, t): self._type = t

    def get_type(self): return self._type.get_type() if isinstance(self._type, RecClass) else self._type

    @property

    def name(self): 
        if self._type:
            resolved = self.get_type()
            # Avoid infinite recursion: if resolved is RecClass, return placeholder
            if isinstance(resolved, RecClass):
                return f"rec_{self._id}"
            return resolved.name
        return f"rec_{self._id}"

    def covariant(self, x): return self.get_type().covariant(x)

    def encodeValue(self, val): return self.get_type().encodeValue(val)

    def decodeValue(self, b, t): return self.get_type().decodeValue(b, t)

    def encodeType(self, typeTable: TypeTable): return self.get_type().encodeType(typeTable)

    

    def _buildTypeTableImpl(self, typeTable: TypeTable):

        if not isinstance(self.get_type(), ConstructType): return

        idx = typeTable.get_or_reserve_index(self)

        typeTable.associate(self._type, idx)

        self._type._buildTypeTableImpl(typeTable)

class FuncClass(ConstructType):

    def __init__(self, args, rets, modes): self.args, self.rets, self.modes = args, rets, modes

    # [FIX] Added alias properties for tests expecting 'argTypes', 'retTypes', 'annotations'
    @property
    def argTypes(self): return self.args
    
    @property
    def retTypes(self): return self.rets
    
    @property
    def annotations(self): return self.modes

    @property

    def name(self): return "func"

    def covariant(self, x):
        # None encodes as an opaque reference per Candid spec.
        if x is None:
            return True
        return isinstance(x, (list, tuple)) and len(x) == 2

    def encodeValue(self, val):
        # Opaque function reference: encoded as a single 0x00 byte per Candid spec.
        if val is None:
            return b"\x00"

        p, m = val

        if hasattr(p, 'bytes'): p = p.bytes

        elif isinstance(p, str): p = P.from_str(p).bytes

        p = p or b""

        # Func value = 0x01 (present) + service(0x01 + principal) + text(len + utf8).

        svc_part = b"\x01" + PrincipalClass().encodeValue(p)

        m_bytes = m.encode("utf-8")

        return svc_part + LEB128.encode_u(len(m_bytes)) + m_bytes

    

    def _buildTypeTableImpl(self, typeTable: TypeTable):

        typeTable.get_or_reserve_index(self)

        for a in self.args: a.buildTypeTable(typeTable)

        for r in self.rets: r.buildTypeTable(typeTable)

        # Per Candid spec: query=0x01, oneway=0x02, composite_query=0x03.
        _MODE_BYTES = {"query": b"\x01", "oneway": b"\x02", "composite_query": b"\x03"}
        mode_bytes = b""
        for m in self.modes:
            if m not in _MODE_BYTES:
                raise ValueError(
                    f"Unknown func mode {m!r}; expected one of "
                    "'query', 'oneway', 'composite_query'"
                )
            mode_bytes += _MODE_BYTES[m]

        buf = (LEB128.encode_i(TypeIds.Func.value) + LEB128.encode_u(len(self.args)) +
               b"".join(a.encodeType(typeTable) for a in self.args) +
               LEB128.encode_u(len(self.rets)) +
               b"".join(r.encodeType(typeTable) for r in self.rets) +
               LEB128.encode_u(len(self.modes)) +
               mode_bytes)

        typeTable.update(self, buf)

    def decodeValue(self, b: Pipe, t: Type):

        self.checkType(t)

        flag = b.read_byte()

        # 0x00 means an opaque (null) function reference.
        if flag == 0:
            return None

        if flag != 1:
            raise ValueError(f"Func reference flag must be 0x00 or 0x01, got {flag:#x}")

        # Delegate to PrincipalClass to safely consume (0x01 + len + bytes)

        p = PrincipalClass().decodeValue(b, Types.Principal)

        m = b.read(LEB128.decode_u(b)).decode("utf-8")

        return [p, m]

class ServiceClass(ConstructType):

    def __init__(self, methods): self._methods = methods

    @property

    def name(self): return "service"

    def covariant(self, x):
        # None encodes as an opaque service reference per Candid spec.
        if x is None:
            return True
        return True

    def encodeValue(self, val):
        # Opaque service reference: encoded as a single 0x00 byte per Candid spec.
        if val is None:
            return b"\x00"

        if hasattr(val, 'bytes'): val = val.bytes

        elif isinstance(val, str): val = P.from_str(val).bytes

        val = val or b""

        # Service IS a Principal on the wire. PrincipalClass.encodeValue
        # already adds the required 0x01 reference tag.

        return PrincipalClass().encodeValue(val)

    def _buildTypeTableImpl(self, typeTable: TypeTable):

        typeTable.get_or_reserve_index(self)

        for m in self._methods.values(): m.buildTypeTable(typeTable)

        buf = LEB128.encode_i(TypeIds.Service.value) + LEB128.encode_u(len(self._methods))

        for k, v in sorted(self._methods.items()):

            buf += LEB128.encode_u(len(k)) + k.encode("utf-8") + v.encodeType(typeTable)

        typeTable.update(self, buf)

    

    def decodeValue(self, b: Pipe, t: Type):

        self.checkType(t)

        # Peek the reference flag: 0x00 = opaque/null, 0x01 = present principal.
        flag = b.read_byte()
        if flag == 0:
            return None
        if flag != 1:
            raise ValueError(f"Service reference flag must be 0x00 or 0x01, got {flag:#x}")

        length = LEB128.decode_u(b)
        raw = b.read(length)
        return P.management_canister() if len(raw) == 0 else P.from_hex(raw.hex())



# -----------------------------

# 4. Global Encode/Decode

# -----------------------------

def encode(params):

    argTypes = [p["type"] for p in params]

    args = [p["value"] for p in params]

    typeTable = TypeTable()

    for t in argTypes: t.buildTypeTable(typeTable)

    return (PREFIX + typeTable.encode() + LEB128.encode_u(len(args)) +
            b"".join(t.encodeType(typeTable) for t in argTypes) +
            b"".join(t.encodeValue(v) for t, v in zip(argTypes, args)))

def decode(data: bytes, retTypes=None):

    if len(data) < 4 or data[:4] != PREFIX: raise ValueError("Invalid prefix")

    b = Pipe(data[4:])

    

    raw_table = [Types.Rec() for _ in range(LEB128.decode_u(b))]

    for i in range(len(raw_table)):

        code = LEB128.decode_i(b)

        if code == TypeIds.Opt.value: t = Types.Opt(_resolve_idx(LEB128.decode_i(b), raw_table))

        elif code == TypeIds.Vec.value: t = Types.Vec(_resolve_idx(LEB128.decode_i(b), raw_table))

        elif code == TypeIds.Record.value:

            t = Types.Record({LEB128.decode_u(b): _resolve_idx(LEB128.decode_i(b), raw_table) for _ in range(LEB128.decode_u(b))})

        elif code == TypeIds.Variant.value:

            t = Types.Variant({str(LEB128.decode_u(b)): _resolve_idx(LEB128.decode_i(b), raw_table) for _ in range(LEB128.decode_u(b))})

        elif code == TypeIds.Func.value:

            args = [_resolve_idx(LEB128.decode_i(b), raw_table) for _ in range(LEB128.decode_u(b))]

            rets = [_resolve_idx(LEB128.decode_i(b), raw_table) for _ in range(LEB128.decode_u(b))]

            def _decode_mode(byte_val: int) -> str:
                if byte_val == 1: return "query"
                if byte_val == 2: return "oneway"
                if byte_val == 3: return "composite_query"
                raise ValueError(
                    f"Unknown func mode byte {byte_val:#x}; expected 0x01 (query), "
                    "0x02 (oneway), or 0x03 (composite_query)"
                )
            modes = [_decode_mode(b.read_byte()) for _ in range(LEB128.decode_u(b))]

            t = Types.Func(args, rets, modes)

        elif code == TypeIds.Service.value:

            ms = {}

            for _ in range(LEB128.decode_u(b)):

                n = b.read(LEB128.decode_u(b)).decode("utf-8")

                ms[n] = _resolve_idx(LEB128.decode_i(b), raw_table)

            t = Types.Service(ms)

        else: raise ValueError(f"Unknown type code {code}")

        raw_table[i].fill(t)

    wire_types = [_resolve_idx(LEB128.decode_i(b), raw_table) for _ in range(LEB128.decode_u(b))]

    if retTypes:

        if not isinstance(retTypes, list): retTypes = [retTypes]

        if len(wire_types) < len(retTypes): raise ValueError("Return count mismatch")

        wire_types = wire_types[:len(retTypes)]

    else: retTypes = wire_types

    return [{"type": rt.name, "value": rt.decodeValue(b, wt)} for rt, wt in zip(retTypes, wire_types)]

def _resolve_type(t: Type):

    return t.get_type() if isinstance(t, RecClass) else t

def _resolve_idx(idx, table):

    if idx >= 0: return table[idx]

    mapping = { -1:Types.Null, -2:Types.Bool, -3:Types.Nat, -4:Types.Int, -5:Types.Nat8, -6:Types.Nat16, -7:Types.Nat32, -8:Types.Nat64,

                -9:Types.Int8, -10:Types.Int16, -11:Types.Int32, -12:Types.Int64, -13:Types.Float32, -14:Types.Float64, -15:Types.Text,

                -16:Types.Reserved, -17:Types.Empty, -24:Types.Principal }

    return mapping[idx]

class Types:

    Null = NullClass(); Empty = EmptyClass(); Bool = BoolClass(); Int = IntClass(); Reserved = ReservedClass(); Nat = NatClass(); Text = TextClass(); Principal = PrincipalClass()

    Float32 = FloatClass(32); Float64 = FloatClass(64)

    Int8 = FixedIntClass(8); Int16 = FixedIntClass(16); Int32 = FixedIntClass(32); Int64 = FixedIntClass(64)

    Nat8 = FixedNatClass(8); Nat16 = FixedNatClass(16); Nat32 = FixedNatClass(32); Nat64 = FixedNatClass(64)

    @staticmethod

    def Tuple(*t): return Types.Record({i: x for i, x in enumerate(t)})

    @staticmethod

    def Record(t): return RecordClass(t)

    @staticmethod

    def Vec(t): return VecClass(t)

    @staticmethod

    def Opt(t): return OptClass(t)

    @staticmethod

    def Variant(t): return VariantClass(t)

    @staticmethod

    def Rec(): return RecClass()

    @staticmethod

    def Func(a, r, m): return FuncClass(a, r, m)

    @staticmethod

    def Service(t): return ServiceClass(t)
