"""
Example demonstrating query and update calls to a simple counter canister.

This example shows how to:
- Query the current counter value (query call)
- Set a new counter value (update call)
- Use both Canister wrapper and Agent methods directly

Canister ID: wcrzb-2qaaa-aaaap-qhpgq-cai
Candid Interface:
  service : {
    get : () -> (nat) query;
    set : (nat) -> (nat)
  }
"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from icp_agent import Agent, Client
from icp_identity import Identity
from icp_canister import Canister
from icp_candid import Types
from helpers import get_result_value, print_section, handle_exception

# Configuration
CANISTER_ID = "wcrzb-2qaaa-aaaap-qhpgq-cai"

# Candid interface definition
COUNTER_DID = """
service : {
  get : () -> (nat) query;
  set : (nat) -> (nat)
}
"""


def main():
    """Main function demonstrating counter canister interactions."""
    print("=" * 60)
    print("Simple Counter Canister Example")
    print("=" * 60)
    
    # Connect to IC mainnet
    try:
        client = Client(url="https://ic0.app")
        identity = Identity(anonymous=True)
        agent = Agent(identity, client)
        print("[+] Connected to IC mainnet")
    except Exception as e:
        handle_exception("Network connection", e)
        return

    # Initialize Counter canister
    try:
        counter = Canister(agent, CANISTER_ID, COUNTER_DID)
        print(f"[+] Counter canister initialized: {CANISTER_ID}")
    except Exception as e:
        handle_exception("Counter canister initialization", e)
        return

    # Example 1: Query call - Get current value
    print_section("[1] Query Call: Get Current Counter Value")
    try:
        result = counter.get()
        current_value = get_result_value(result)
        if current_value is not None:
            print(f"[+] Current counter value: {current_value}")
    except Exception as e:
        handle_exception("Query counter value", e)

    # Example 2: Update call - Set a new value using Canister wrapper
    print_section("[2] Update Call: Set Counter Value to 42")
    print("[!] Note: Using verify_certificate=True (requires blst)")
    try:
        new_value = 42
        result = counter.set(new_value, verify_certificate=True)
        returned_value = get_result_value(result)
        if returned_value is not None:
            print(f"[+] Set value: {new_value}")
            print(f"[+] Returned value: {returned_value}")
    except Exception as e:
        handle_exception("Set counter value", e)

    # Example 3: Query call - Verify the value was set
    print_section("[3] Query Call: Verify Counter Value After Set")
    try:
        result = counter.get()
        current_value = get_result_value(result)
        if current_value is not None:
            print(f"[+] Current counter value: {current_value}")
    except Exception as e:
        handle_exception("Query counter value", e)

    # Example 4: Update call - Set another value using Agent directly
    print_section("[4] Update Call: Set Counter Value to 100 (using Agent directly)")
    try:
        another_value = 100
        result = agent.update(
            CANISTER_ID,
            "set",
            [{'type': Types.Nat, 'value': another_value}],
            return_type=[Types.Nat],
            verify_certificate=True
        )
        returned_value = get_result_value(result)
        if returned_value is not None:
            print(f"[+] Set value: {another_value}")
            print(f"[+] Returned value: {returned_value}")
    except Exception as e:
        handle_exception("Set counter value", e)

    # Example 5: Query call - Final check
    print_section("[5] Query Call: Final Counter Value")
    try:
        result = counter.get()
        final_value = get_result_value(result)
        if final_value is not None:
            print(f"[+] Final counter value: {final_value}")
    except Exception as e:
        handle_exception("Query counter value", e)

    print("\n" + "=" * 60)
    print("Example completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
