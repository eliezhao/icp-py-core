# Copyright (c) 2021 Rocklabs
# Copyright (c) 2024 eliezhao (ICP-PY-CORE maintainer)
#
# Licensed under the MIT License
# See LICENSE file for details

import json

try:
    # First try: import from icp_candid package (development/local build)
    from . import _ic_candid_core as ic_candid_parser
except ImportError:
    try:
        # Second try: import from top-level package (when installed via PyPI wheel)
        # The ic_candid_parser wheel installs as _ic_candid_core package
        # because it's a separate PyPI package and cannot install into icp_candid namespace
        from _ic_candid_core import _ic_candid_core as ic_candid_parser
    except ImportError:
        try:
            # Third try: alternative direct import
            import _ic_candid_core._ic_candid_core as ic_candid_parser
        except ImportError:
            ic_candid_parser = None

from .candid import Types

class DIDLoader:

    def __init__(self):

        self.type_env = {}

    def load_did_source(self, did_content: str):

        # [FIX] Check against None instead of globals() dict
        if ic_candid_parser is None:

             raise ImportError("Rust extension '_ic_candid_core' not found. Please install the package.")

             

        try:

            json_str = ic_candid_parser.parse_did(did_content)

        except ValueError as e:

            raise ValueError(f"DID Parse Error: {e}")

            

        data = json.loads(json_str)

        self.type_env = {}

        

        # 1. Pre-declare Recursive Types

        if 'env' in data:

            for entry in data['env']:

                self.type_env[entry['name']] = Types.Rec()

        

        # 2. Fill Types

        if 'env' in data:

            for entry in data['env']:

                # [Actual Format] Rust parser returns 'datatype' field (actual transmission format)

                def_node = entry.get('datatype')

                if def_node:

                    self.type_env[entry['name']].fill(self._parse_json_type(def_node))

        init_args = []

        actor_data = data.get('actor') or {}

        if 'init' in actor_data and actor_data['init']:

            init_args = [self._parse_json_type(t) for t in actor_data['init']]

        methods = {}

        for m in actor_data.get('methods', []):

            methods[m['name']] = Types.Func(

                [self._parse_json_type(t) for t in m['args']],

                [self._parse_json_type(t) for t in m['rets']],

                m['modes']

            )

        # Fallback: when actor is null (e.g. service : () -> TypeName in some parser versions),
        # use the last Service-typed entry in env as the actor interface (Motoko-style DID).
        if not methods and data.get('env'):

            for entry in reversed(data['env']):

                def_node = entry.get('datatype')

                if isinstance(def_node, dict) and def_node.get('type') == 'Service':

                    for m in def_node.get('value') or []:

                        methods[m['name']] = Types.Func(

                            [self._parse_json_type(t) for t in m.get('args', [])],

                            [self._parse_json_type(t) for t in m.get('rets', [])],

                            m.get('modes') or []

                        )

                    break

        return {

            "arguments": init_args,

            "methods": methods

        }

    def _parse_json_type(self, t_node):

        # Handle string primitives (if any)
        if isinstance(t_node, str): return self._prim(t_node)

        # [Actual Format] Rust parser returns {"type": "Prim", "value": "text"} format
        # This is the actual transmission format from Rust extension
        if not isinstance(t_node, dict) or 'type' not in t_node:
            raise ValueError(f"Unexpected JSON type format: {t_node}. Expected {{'type': ..., ...}}")
        
        tag = t_node['type']
        
        # [SPEC] According to Candid spec, Principal is a primitive type.
        # However, in Rust parser implementation, Principal is a unit variant,
        # which serde serializes as {"type": "Principal"} without "value" field.
        # This is consistent with serde's default behavior for unit variants.
        # We handle Principal specially here to match the actual implementation.
        if tag == 'Principal':
            return Types.Principal
        
        # Other types require 'value' field
        if 'value' not in t_node:
            raise ValueError(f"Unexpected JSON type format: {t_node}. Expected {{'type': ..., 'value': ...}}")
        
        val = t_node['value']

        if tag == 'Prim': return self._prim(val)

        

        elif tag == 'Opt': return Types.Opt(self._parse_json_type(val))

        elif tag == 'Vec': return Types.Vec(self._parse_json_type(val))

        elif tag == 'Record':
            fields = {}
            
            # [Actual Format] Rust parser returns Record as array: {"type": "Record", "value": [["key", type], ...]}
            # This is the actual transmission format from Rust extension
            if not isinstance(val, list):
                raise ValueError(f"Unexpected Record format: expected array, got {type(val).__name__}")
            
            for item in val:
                if not isinstance(item, list) or len(item) != 2:
                    raise ValueError(f"Unexpected Record item format: expected [key, type], got {item}")
                k, v = item
                # Correctly handle integer keys for Tuples
                key = int(k) if isinstance(k, str) and k.isdigit() else k
                fields[key] = self._parse_json_type(v)

            return Types.Record(fields)

        elif tag == 'Variant':
            fields = {}
            
            # [Actual Format] Rust parser returns Variant as array: {"type": "Variant", "value": [["key", type], ...]}
            # This is the actual transmission format from Rust extension
            if not isinstance(val, list):
                raise ValueError(f"Unexpected Variant format: expected array, got {type(val).__name__}")
            
            for item in val:
                if not isinstance(item, list) or len(item) != 2:
                    raise ValueError(f"Unexpected Variant item format: expected [key, type], got {item}")
                k, v = item
                key = int(k) if isinstance(k, str) and k.isdigit() else k
                fields[key] = (self._parse_json_type(v) if v else None)

            return Types.Variant(fields)

        elif tag == 'Id':

            return self.type_env.get(val) or Types.Rec()

        elif tag == 'Func':

             return Types.Func(

                 [self._parse_json_type(x) for x in val['args']],

                 [self._parse_json_type(x) for x in val['rets']],

                 val['modes']

             )

        elif tag == 'Service': return Types.Service({})

        # Fallback for unknown tags (likely primitive or error)
        return self._prim(tag)

    def _prim(self, t):

        m = {'nat': Types.Nat, 'int': Types.Int, 'text': Types.Text, 'bool': Types.Bool, 'null': Types.Null, 'float64': Types.Float64, 'float32': Types.Float32, 'nat8': Types.Nat8, 'nat16': Types.Nat16, 'nat32': Types.Nat32, 'nat64': Types.Nat64, 'int8': Types.Int8, 'int16': Types.Int16, 'int32': Types.Int32, 'int64': Types.Int64, 'principal': Types.Principal, 'empty': Types.Empty, 'reserved': Types.Reserved}

        return m.get(t.lower(), Types.Null)
