# Migration Guide: `ic-py` → `icp-py-core`

This guide helps you migrate from **ic-py** to the modular **icp-py-core**.

---

## 1) Package Layout

**Old (`ic-py`)**
- One top-level package: `ic` (agent, identity, candid, etc. all mixed)

**New (`icp-py-core`)**
- Split into focused subpackages under `src/`:
  - `icp_agent` — Agent & HTTP client
  - `icp_candid` — Candid encode/decode & types
  - `icp_identity` — Ed25519 / Delegation identities
  - `icp_principal` — Principal utilities
  - `icp_certificate` — Certificate verification
  - `icp_core` — **facade** (re-exports common APIs)

> The facade you should import from is **`icp_core`** (not `icp`).  
> It currently re-exports: `Agent`, `Client`, `Identity`, `DelegateIdentity`,  
> `encode`, `decode`, `Types`, `Principal`, `Certificate`.

---

## 2) Import Mapping

| Old import (`ic-py`)                      | New import (subpackage)                            | New import (**facade**)                         |
|------------------------------------------|----------------------------------------------------|------------------------------------------------|
| `from ic.agent import Agent`             | `from icp_agent import Agent`                      | `from icp_core import Agent`                    |
| `from ic.client import Client`           | `from icp_agent import Client`                     | `from icp_core import Client`                   |
| `from ic.identity import Identity`       | `from icp_identity import Identity`                | `from icp_core import Identity`                 |
| *(n/a)* `DelegateIdentity`               | `from icp_identity import DelegateIdentity`        | `from icp_core import DelegateIdentity`         |
| `from ic.candid import encode`           | `from icp_candid import encode, decode, Types`     | `from icp_core import encode, decode, Types`    |
| `from ic.principal import Principal`     | `from icp_principal import Principal`              | `from icp_core import Principal`                |
| `from ic.certificate import Certificate` | `from icp_certificate import Certificate`          | `from icp_core import Certificate`              |

**Example**

```python
# Before (ic-py)
from ic.agent import Agent
from ic.identity import Identity
from ic.candid import encode

# After (icp-py-core) – subpackages
from icp_agent import Agent, Client
from icp_identity import Identity
from icp_candid import encode

# After (icp-py-core) – facade
from icp_core import Agent, Client, Identity, encode
```

---

## 3) HTTP Endpoints

- Update calls use **Boundary Node v3**:
  - `/api/v3/canister/<canister_id>/call`
- Queries & read_state remain on v2:
  - `/api/v2/canister/<canister_id>/query`
  - `/api/v2/canister/<canister_id>/read_state`

Ensure your boundary node supports **v3** for updates.

---

## 4) Agent API

Both **high-level** and **low-level** methods are available:

- High-level:
  - `Agent.query(canister_id, method_name, arg=None, *, return_type=None, effective_canister_id=None)`
  - `Agent.update(canister_id, method_name, arg=None, *, return_type=None, effective_canister_id=None, verify_certificate=True, ...)`

- Low-level:
  - `Agent.query_raw(...)`
  - `Agent.update_raw(..., verify_certificate=False)`  
    *(set `verify_certificate=True` to enable BLS verification)*

Both styles are compatible with the new request-id hashing and envelope signing.

---

## 5) Certificate Verification (Recommended)

Enable full verification on updates:

```python
agent.update(..., verify_certificate=True)
# or
agent.update_raw(..., verify_certificate=True)
```

This uses `icp_certificate.Certificate` and requires the official `blst` binding.  
If unavailable, keep `verify_certificate=False` for prototyping.

---

## 6) Principals & Identities

- `Principal.self_authenticating(...)` accepts **DER-encoded** public keys (strict).
- `Identity` (Ed25519) and `DelegateIdentity` are available under `icp_identity`.
- `Principal` helpers live in `icp_principal`.

---

## 7) Minimal Migration Example

```python
# Old
from ic.agent import Agent
from ic.client import Client
from ic.identity import Identity
from ic.candid import encode

iden = Identity()
client = Client(url="https://ic0.app")
agent = Agent(iden, client)
result = agent.update_raw("ryjl3-tyaaa-aaaaa-aaaba-cai", "set_value", encode([42]))

# New (facade)
from icp_core import Agent, Client, Identity, encode

iden = Identity()
client = Client(url="https://ic0.app")
agent = Agent(iden, client)
result = agent.update("ryjl3-tyaaa-aaaaa-aaaba-cai", "set_value", [42], verify_certificate=True)
```

---

## 8) Breaking Changes

- Facade package is **`icp_core`** (not `icp`).
- Update endpoint moved to **v3**.
- `Principal.self_authenticating()` is **DER-only**.
- `update()` now defaults to `verify_certificate=True`; use `False` if you do not have `blst` installed.
- Request-id hashing follows the canonical rules (ints → ULEB128, lists hashed element-wise, etc.).

---

That’s it! You can now import the most-used APIs from **`icp_core`** and rely on the modular internals for clarity and maintainability.
