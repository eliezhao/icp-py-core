# Copyright (c) 2021 Rocklabs
# Copyright (c) 2024 eliezhao (ICP-PY-CORE maintainer)
#
# Licensed under the MIT License
# See LICENSE file for details

import cbor2

from icp_agent import Agent
from icp_principal import Principal


def time(agent: Agent, canister_id: str) -> int:
    certificate = agent.read_state_raw(canister_id, [["time".encode()]])
    # lookup_time() already decodes the ULEB128 'time' leaf into an int.
    # Decoding it again (via bytes(int)) would allocate a multi-exabyte buffer
    # and raise MemoryError, so just return the decoded value directly.
    return certificate.lookup_time()

def subnet_public_key(agent: Agent, canister_id: str, subnet_id: str) -> str:
    path = ["subnet".encode(), Principal.from_str(subnet_id).bytes, "public_key".encode()]
    certificate = agent.read_state_raw(canister_id, [path])
    pubkey = certificate.lookup(path)
    return pubkey.hex()

def subnet_public_key_direct(agent: Agent, subnet_id: str) -> str:
    """
    Get subnet public key directly using subnet read_state endpoint.
    This is more efficient than using canister read_state when you only need subnet data.
    """
    path = ["subnet".encode(), Principal.from_str(subnet_id).bytes, "public_key".encode()]
    certificate = agent.read_state_subnet_raw(subnet_id, [path])
    pubkey = certificate.lookup(path)
    return pubkey.hex()

def subnet_canister_ranges(agent: Agent, canister_id: str, subnet_id: str) -> list[list[Principal]]:
    path = ["subnet".encode(), Principal.from_str(subnet_id).bytes, "canister_ranges".encode()]
    certificate = agent.read_state_raw(canister_id, [path])
    ranges = certificate.lookup(path)
    return list(
        map(lambda range_item: 
            list(map(Principal, range_item)),  
        cbor2.loads(ranges))
        )

def subnet_canister_ranges_direct(agent: Agent, subnet_id: str) -> list[list[Principal]]:
    """
    Get subnet canister ranges directly using subnet read_state endpoint.
    This is more efficient than using canister read_state when you only need subnet data.
    """
    path = ["subnet".encode(), Principal.from_str(subnet_id).bytes, "canister_ranges".encode()]
    certificate = agent.read_state_subnet_raw(subnet_id, [path])
    ranges = certificate.lookup(path)
    return list(
        map(lambda range_item: 
            list(map(Principal, range_item)),  
        cbor2.loads(ranges))
        )

def canister_module_hash(agent: Agent, canister_id: str) -> str:
    path = ["canister".encode(), Principal.from_str(canister_id).bytes, "module_hash".encode()]
    certificate = agent.read_state_raw(canister_id, [path])
    module_hash = certificate.lookup(path)
    return module_hash.hex()

def canister_controllers(agent: Agent, canister_id: str) -> list[Principal]:
    path = ["canister".encode(), Principal.from_str(canister_id).bytes, "controllers".encode()]
    certificate = agent.read_state_raw(canister_id, [path])
    controllers = certificate.lookup(path)
    return list(map(Principal, cbor2.loads(controllers)))