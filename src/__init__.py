# src/icp/__init__.py
"""
Unified facade for icp-py-core.

Developers can import common APIs from this single entrypoint, e.g.:
    from icp import Agent, Client, Identity, encode, decode, Types, Principal, Certificate
"""

# --- agent & client & canister ---
from icp_agent.agent import Agent
from icp_agent.client import Client
from icp_canister.canister import Canister

# --- identity ---
from icp_identity.identity import Identity, DelegateIdentity

# --- candid ---
from icp_candid.candid import encode, decode, Types

# --- principal ---
from icp_principal.principal import Principal

# --- certificate ---
from icp_certificate.certificate import Certificate

__all__ = [
    # agent/canister
    "Agent", "Client", "Canister",
    # identity
    "Identity", "DelegateIdentity",
    # candid
    "encode", "decode", "Types",
    # principal
    "Principal",
    # certificate
    "Certificate",
]