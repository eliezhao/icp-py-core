# Copyright (c) 2021 Rocklabs
# Copyright (c) 2024 eliezhao (ICP-PY-CORE maintainer)
#
# Licensed under the MIT License
# See LICENSE file for details

# src/icp_core/__init__.py
"""
Unified facade for icp-py-core.

Developers can import common APIs from this single entrypoint, e.g.:
    from icp_core import (
        Agent, Client,
        Canister, Ledger, Governance, Management, CyclesWallet,
        Identity, DelegateIdentity,
        Principal, Certificate,
        encode, decode, Types,
    )
"""

# --- errors (import first, no dependencies) ---
from icp_core.errors import (
    ICError,
    TransportError,
    SecurityError,
    SignatureVerificationFailed,
    LookupPathMissing,
    PayloadEncodingError,
    ReplicaReject,
    IngressExpiryError,
    CertificateVerificationError,
    NodeKeyNotFoundError,
    ReplicaSignatureVerificationFailed,
)

# Lazy imports to avoid circular dependencies
_agent = None
_client = None
_canister = None
_ledger = None
_governance = None
_management = None
_cycles_wallet = None
_identity = None
_principal = None
_certificate = None
_candid = None

def __getattr__(name):
    """Lazy import to avoid circular dependencies."""
    global _agent, _client, _canister, _ledger, _governance, _management
    global _cycles_wallet, _identity, _principal, _certificate, _candid
    
    if name == "Agent":
        if _agent is None:
            from icp_agent.agent import Agent as _Agent
            _agent = _Agent
        return _agent
    elif name == "Client":
        if _client is None:
            from icp_agent.client import Client as _Client
            _client = _Client
        return _client
    elif name == "Canister":
        if _canister is None:
            from icp_canister.canister import Canister as _Canister
            _canister = _Canister
        return _canister
    elif name == "Ledger":
        if _ledger is None:
            from icp_canister.ledger import Ledger as _Ledger
            _ledger = _Ledger
        return _ledger
    elif name == "Governance":
        if _governance is None:
            from icp_canister.governance import Governance as _Governance
            _governance = _Governance
        return _governance
    elif name == "Management":
        if _management is None:
            from icp_canister.management import Management as _Management
            _management = _Management
        return _management
    elif name == "CyclesWallet":
        if _cycles_wallet is None:
            from icp_canister.cycles_wallet import CyclesWallet as _CyclesWallet
            _cycles_wallet = _CyclesWallet
        return _cycles_wallet
    elif name == "Identity":
        if _identity is None:
            from icp_identity.identity import Identity as _Identity
            _identity = _Identity
        return _identity
    elif name == "DelegateIdentity":
        if _identity is None:
            from icp_identity.identity import Identity as _Identity, DelegateIdentity as _DelegateIdentity
            _identity = _Identity
            globals()["DelegateIdentity"] = _DelegateIdentity
        return globals().get("DelegateIdentity")
    elif name == "Principal":
        if _principal is None:
            from icp_principal.principal import Principal as _Principal
            _principal = _Principal
        return _principal
    elif name == "Certificate":
        if _certificate is None:
            from icp_certificate.certificate import Certificate as _Certificate
            _certificate = _Certificate
        return _certificate
    elif name in ("encode", "decode", "Types"):
        if _candid is None:
            from icp_candid.candid import encode as _encode, decode as _decode, Types as _Types
            _candid = True
            globals()["encode"] = _encode
            globals()["decode"] = _decode
            globals()["Types"] = _Types
        if name == "encode":
            return globals()["encode"]
        elif name == "decode":
            return globals()["decode"]
        elif name == "Types":
            return globals()["Types"]
    
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    "Agent", "Client",
    "Canister", "Ledger", "Governance", "Management", "CyclesWallet",
    "Identity", "DelegateIdentity",
    "encode", "decode", "Types",
    "Principal",
    "Certificate",
    # Errors
    "ICError",
    "TransportError",
    "SecurityError",
    "SignatureVerificationFailed",
    "LookupPathMissing",
    "PayloadEncodingError",
    "ReplicaReject",
    "IngressExpiryError",
    "CertificateVerificationError",
    "NodeKeyNotFoundError",
    "ReplicaSignatureVerificationFailed",
]
