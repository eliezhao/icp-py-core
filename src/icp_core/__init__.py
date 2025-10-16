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

# --- agent & client & system state ---
from icp_agent.agent import Agent
from icp_agent.client import Client

# --- canister family ---
from icp_canister.canister import Canister
from icp_canister.ledger import Ledger
from icp_canister.governance import Governance
from icp_canister.management import Management
from icp_canister.cycles_wallet import CyclesWallet

# --- identity ---
from icp_identity.identity import Identity, DelegateIdentity

# --- candid ---
from icp_candid.candid import encode, decode, Types

# --- principal ---
from icp_principal.principal import Principal

# --- certificate ---
from icp_certificate.certificate import Certificate

__all__ = [
    "Agent", "Client",
    "Canister", "Ledger", "Governance", "Management", "CyclesWallet",
    "Identity", "DelegateIdentity",
    "encode", "decode", "Types",
    "Principal",
    "Certificate",
]