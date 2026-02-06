# Copyright (c) 2021 Rocklabs
# Copyright (c) 2024 eliezhao (ICP-PY-CORE maintainer)
#
# Licensed under the MIT License
# See LICENSE file for details

from icp_candid.did_loader import DIDLoader
from icp_principal import Principal

class Canister:
    def __init__(self, agent, canister_id, candid_str=None, auto_fetch_candid=False):
        """
        Initialize a Canister instance.

        Args:
            agent: Agent instance for interacting with IC
            canister_id: Canister ID (can be a string or Principal object)
            candid_str: Optional Candid interface definition string. If provided, local definition will be used first.
            auto_fetch_candid: If True and candid_str is None, automatically fetch Candid interface from IC.
                               If False (default), no auto-fetch; candid_str=None leaves no methods bound (backward compatible).
        """
        self.agent = agent
        self.canister_id = canister_id
        self.candid_str = candid_str
        self.methods = {}
        self.actor = None
        self.init_args = []  # Store init arguments (for Canister deployment)

        # If local candid_str is provided, use local definition first
        if candid_str:
            self._parse_did_with_retry(candid_str)
        elif auto_fetch_candid:
            # If no local candid_str provided, try to automatically fetch from IC
            fetched_candid = self._fetch_candid_from_ic()
            if fetched_candid:
                self.candid_str = fetched_candid
                self._parse_did_with_retry(fetched_candid)
            else:
                raise ValueError(
                    f"Failed to fetch Candid interface definition from canister {canister_id}. "
                    "Please ensure the canister is deployed and contains public candid:service metadata, "
                    "or manually provide the candid_str parameter."
                )
        # else: candid_str=None and auto_fetch_candid=False -> no methods (backward compatible)
    
    def _fetch_candid_from_ic(self):
        """
        Fetch Candid interface definition from Internet Computer for the canister.
        
        First tries to fetch public metadata (candid:service), then falls back to private metadata (candid) if failed.
        Returns None if both attempts fail.
        
        Returns:
            Candid interface definition string, or None if fetch fails.
        """
        # Ensure canister_id is a Principal object
        if isinstance(self.canister_id, str):
            canister_principal = Principal.from_str(self.canister_id)
        elif isinstance(self.canister_id, Principal):
            canister_principal = self.canister_id
        else:
            # Try to convert to Principal
            try:
                canister_principal = Principal(self.canister_id)
            except Exception:
                raise ValueError(f"Invalid canister_id: {self.canister_id}")
        
        canister_id_bytes = canister_principal.bytes
        
        # Convert Principal to string for read_state_raw (it expects string or Principal, but certificate validation needs string)
        canister_id_str = canister_principal.to_str() if hasattr(canister_principal, 'to_str') else str(self.canister_id)
        if isinstance(self.canister_id, str):
            canister_id_str = self.canister_id
        
        # First try to fetch public metadata (candid:service)
        # Anyone can read this, no authentication required
        public_path = [
            b"canister",
            canister_id_bytes,
            b"metadata",
            b"candid:service"
        ]
        
        try:
            certificate = self.agent.read_state_raw(
                canister_id_str,
                [public_path],
                verify_certificate=False  # Disable verification for Candid fetch (read-only operation)
            )
            candid_bytes = certificate.lookup(public_path)
            if candid_bytes:
                candid_str = candid_bytes.decode('utf-8')
                return candid_str
        except Exception:
            # Public metadata doesn't exist or read failed, continue to try private metadata
            pass
        
        # If public metadata doesn't exist, try to fetch private metadata (candid)
        # This requires controller identity and may fail
        private_path = [
            b"canister",
            canister_id_bytes,
            b"metadata",
            b"candid"
        ]
        
        try:
            certificate = self.agent.read_state_raw(
                canister_id_str,
                [private_path],
                verify_certificate=False  # Disable verification for Candid fetch (read-only operation)
            )
            candid_bytes = certificate.lookup(private_path)
            if candid_bytes:
                candid_str = candid_bytes.decode('utf-8')
                return candid_str
        except Exception:
            # Private metadata also doesn't exist or insufficient permissions
            pass
        
        # Both attempts failed
        return None

    def _parse_did_with_retry(self, did_content):
        """
        Parse DID content using the new DIDLoader.
        """
        self._parse_did(did_content)

    def _parse_did(self, did):
        """
        Parse DID content using DIDLoader and build service interface.
        """
        loader = DIDLoader()
        result = loader.load_did_source(did)
        
        if result is None:
            raise ValueError("DID content does not contain a service definition")
        
        # result is a dictionary format: {"arguments": [...], "methods": {...}}
        # Store init arguments (for Canister deployment)
        self.init_args = result.get("arguments", [])
        
        # methods dictionary contains method name to FuncClass mapping
        methods_dict = result.get("methods", {})
        if not methods_dict:
            raise ValueError("DID content does not contain any methods")
        
        # Store methods dictionary as actor (for backward compatibility)
        self.actor = methods_dict
        
        # Dynamically bind methods to Canister instance (sync and async)
        for name, method_type in methods_dict.items():
            self.methods[name] = method_type
            setattr(self, name, self._create_method(name, method_type))
            setattr(self, f"{name}_async", self._create_async_method(name, method_type))

    def _create_method(self, name, method_type):
        """
        Create dynamic method. method_type is a Types.Func object.
        """
        def method(*args, **kwargs):
            # 1. Get argument types and return types
            # method_type is a FuncClass object with argTypes and retTypes attributes
            arg_types = method_type.argTypes
            ret_types = method_type.retTypes
            
            # 2. Extract control parameters from kwargs BEFORE processing them as method arguments
            # verify_certificate is a control parameter for agent.update(), not a method argument
            # Default to True to match Agent.update() default behavior for security
            verify_certificate = kwargs.pop('verify_certificate', True)
            timeout = kwargs.pop('timeout', None)
            
            # 3. Handle kwargs: if kwargs are provided and no args, convert kwargs to a single record argument
            # This allows calling methods like: method(field1=val1, field2=val2) for single-record methods
            if kwargs and not args and len(arg_types) == 1:
                # Single record parameter: kwargs can be used directly
                args = (kwargs,)
            elif kwargs:
                # If both args and kwargs are provided, kwargs are ignored (use args)
                # This is intentional: Candid methods typically use positional args with dict values
                pass
            
            # 4. Validate argument count
            if len(args) != len(arg_types):
                raise TypeError(
                    f"{name}() takes {len(arg_types)} argument(s) but {len(args)} were given"
                )
            
            # 5. Construct parameter list conforming to encode requirements
            processed_args = []
            for i, val in enumerate(args):
                if i < len(arg_types):
                    processed_args.append({'type': arg_types[i], 'value': val})
            
            # 6. Determine if it's a Query or Update call
            # annotations is a list, e.g. ['query'] or []
            annotations = method_type.annotations
            is_query = 'query' in annotations

            # 7. Execute network request using Agent's high-level query/update methods
            # These methods automatically encode args and decode return values
            if is_query:
                query_kwargs = dict(
                    arg=processed_args if processed_args else None,
                    return_type=ret_types,
                )
                if timeout is not None:
                    query_kwargs['timeout'] = timeout
                res = self.agent.query(
                    self.canister_id,
                    name,
                    **query_kwargs,
                )
            else:
                # verify_certificate was already extracted in step 2
                update_kwargs = dict(
                    arg=processed_args if processed_args else None,
                    return_type=ret_types,
                    verify_certificate=verify_certificate,
                )
                if timeout is not None:
                    update_kwargs['timeout'] = timeout
                res = self.agent.update(
                    self.canister_id,
                    name,
                    **update_kwargs,
                )
            
            # 7. Return the result (already decoded by query/update methods)
            return res
            
        return method

    def _create_async_method(self, name, method_type):
        """
        Create async method that calls agent.query_async() or agent.update_async().
        Same parameter handling as _create_method.
        """
        async def async_method(*args, **kwargs):
            arg_types = method_type.argTypes
            ret_types = method_type.retTypes
            verify_certificate = kwargs.pop('verify_certificate', True)
            timeout = kwargs.pop('timeout', None)

            if kwargs and not args and len(arg_types) == 1:
                args = (kwargs,)
            elif kwargs:
                pass

            if len(args) != len(arg_types):
                raise TypeError(
                    f"{name}() takes {len(arg_types)} argument(s) but {len(args)} were given"
                )

            processed_args = []
            for i, val in enumerate(args):
                if i < len(arg_types):
                    processed_args.append({'type': arg_types[i], 'value': val})

            annotations = method_type.annotations
            is_query = 'query' in annotations

            if is_query:
                query_kwargs = dict(
                    arg=processed_args if processed_args else None,
                    return_type=ret_types,
                )
                if timeout is not None:
                    query_kwargs['timeout'] = timeout
                res = await self.agent.query_async(
                    self.canister_id,
                    name,
                    **query_kwargs,
                )
            else:
                update_kwargs = dict(
                    arg=processed_args if processed_args else None,
                    return_type=ret_types,
                    verify_certificate=verify_certificate,
                )
                if timeout is not None:
                    update_kwargs['timeout'] = timeout
                res = await self.agent.update_async(
                    self.canister_id,
                    name,
                    **update_kwargs,
                )

            return res

        return async_method

    def __getattr__(self, name):
        if name in self.methods:
            # Use object.__getattribute__ to avoid infinite recursion
            return object.__getattribute__(self, name)
        # Support async method lookup: {method_name}_async
        if name.endswith('_async') and name[:-6] in self.methods:
            return object.__getattribute__(self, name)
        raise AttributeError(f"'Canister' object has no attribute '{name}'")