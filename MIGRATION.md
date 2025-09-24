# Migration Guide: `ic-py` → `icp-py-core`

This document helps you migrate from the original **ic-py** to **icp-py-core**.

---

## 1. Package Renaming & Layout

**Old (ic-py):**
- Single top-level package `ic`
- Mixed modules (agent, identity, candid, etc.) under `ic/`

**New (icp-py-core):**
- Split into focused subpackages under `src/`:
  - `icp_agent`: Agent & HTTP client
  - `icp_canister`: High-level canister wrappers
  - `icp_candid`: Candid encode/decode + parser
  - `icp_identity`: Ed25519 / Secp256k1 identities
  - `icp_principal`: Principal utilities
  - `icp_certificate`: Certificate verification
  - `icp_utils`: constants/utilities
  - `icp`: **aggregate facade** (optional, re-exports common APIs)

You can either import per subpackage, or use the `icp` facade for convenience.

---

## 2. Import Mapping

| Old import                               | New import (subpackage)                        | New import (facade)                     |
|------------------------------------------|------------------------------------------------|-----------------------------------------|
| `from ic.agent import Agent`             | `from icp_agent import Agent`                  | `from icp import Agent`                 |
| `from ic.client import Client`           | `from icp_agent import Client`                 | `from icp import Client`                |
| `from ic.canister import Canister`       | `from icp_canister import Canister`            | `from icp import Canister`              |
| `from ic.identity import Identity`       | `from icp_identity import Identity`            | `from icp import Identity`              |
| `from ic.principal import Principal`     | `from icp_principal import Principal`          | `from icp import Principal`             |
| `from ic.candid import encode`           | `from icp_candid import encode, decode, Types` | `from icp import encode, decode, Types` |
| `from ic.certificate import Certificate` | `from icp_certificate import Certificate`      | `from icp import Certificate`           |

---

## 3. Endpoint Changes

- **Update calls** moved from legacy `/api/v2/.../call` to **BN v3** `/api/v3/canister/.../call`.
- Ensure your environment allows access to boundary nodes exposing v3 endpoints.

---

## 4. Certificate Verification (Optional but Recommended)

- New flag on update flow:
```python
agent.update_raw(..., verify_certificate=True)
```
•	Requires installing the official blst binding from source (not on PyPI). See README for step-by-step installation.
•	If verify_certificate=False (default), update replies are not BLS-verified (useful for prototyping).
