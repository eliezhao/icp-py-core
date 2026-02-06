#!/usr/bin/env python3
"""
Capture raw query response from IC (including optional 'signatures' field).
Run from repo root: python scripts/capture_query_response.py
Output can be used to add real response shapes to test_query_signature_verification.
"""
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from icp_agent.agent import Agent, sign_request
from icp_agent.client import Client
from icp_identity import Identity
from icp_principal import Principal
from icp_candid.candid import encode

CANISTER_ID = "wcrzb-2qaaa-aaaap-qhpgq-cai"

def main():
    client = Client(url="https://ic0.app")
    identity = Identity(anonymous=True)
    agent = Agent(identity, client)

    req = {
        "request_type": "query",
        "sender": identity.sender().bytes,
        "canister_id": Principal.from_str(CANISTER_ID).bytes,
        "method_name": "get",
        "arg": encode([]),
        "ingress_expiry": agent.get_expiry_date(),
    }
    request_id, signed_cbor = sign_request(req, identity)
    result = agent.query_endpoint(CANISTER_ID, signed_cbor)

    # Serialize for inspection (bytes as hex for JSON-safety)
    def sanitize(obj):
        if isinstance(obj, dict):
            return {k: sanitize(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [sanitize(x) for x in obj]
        if isinstance(obj, bytes):
            return {"__bytes_hex": obj.hex(), "__len": len(obj)}
        if isinstance(obj, int) and (obj < -2**53 or obj > 2**53):
            return {"__bigint": str(obj)}
        return obj

    out = sanitize(result)
    print("Raw query response keys:", list(result.keys()))
    print("Has 'signatures':", "signatures" in result)
    if "signatures" in result:
        sigs = result["signatures"]
        print("Number of signatures:", len(sigs) if isinstance(sigs, list) else "N/A")
        if isinstance(sigs, list) and len(sigs) > 0:
            print("First signature keys:", list(sigs[0].keys()) if isinstance(sigs[0], dict) else type(sigs[0]))
    print()
    print("Request ID (hex):", request_id.hex())
    print()
    print("Full response (sanitized):")
    print(json.dumps(out, indent=2, default=str))

    # Save fixture for tests (bytes/bigint as JSON-serializable)
    fixture = {
        "request_id_hex": request_id.hex(),
        "canister_id": CANISTER_ID,
        "response": out,
    }
    fixture_path = os.path.join(os.path.dirname(__file__), "..", "tests", "fixtures", "query_response_with_signature.json")
    os.makedirs(os.path.dirname(fixture_path), exist_ok=True)
    with open(fixture_path, "w") as f:
        json.dump(fixture, f, indent=2, default=str)
    print()
    print("Fixture written to:", fixture_path)

if __name__ == "__main__":
    main()
