# Migration Guide: `ic-py` → `icp-py-core`

This guide helps you migrate existing projects from **ic-py** to **icp-py-core**.

---

## 1) Package Renaming & Layout

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
  - `icp_core`: **unified facade** that re-exports common APIs

You can import per subpackage **or** use the **`icp_core` facade** for convenience.

---

## 2) Import Mapping

Prefer the facade for most apps:

```python
# New (facade):
from icp_core import (
    Agent, Client,
    Identity, DelegateIdentity,
    Principal, Certificate,
    encode, decode, Types,
)
```

If you want fine-grained imports:

| Old import                               | New import (subpackage)                        | New import (facade)              |
|------------------------------------------|------------------------------------------------|----------------------------------|
| `from ic.agent import Agent`             | `from icp_agent import Agent`                  | `from icp_core import Agent`     |
| `from ic.client import Client`           | `from icp_agent import Client`                 | `from icp_core import Client`    |
| `from ic.identity import Identity`       | `from icp_identity import Identity`            | `from icp_core import Identity`  |
| `from ic.principal import Principal`     | `from icp_principal import Principal`          | `from icp_core import Principal` |
| `from ic.candid import encode, decode`   | `from icp_candid import encode, decode, Types` | `from icp_core import encode, decode, Types` |
| `from ic.certificate import Certificate` | `from icp_certificate import Certificate`      | `from icp_core import Certificate` |

---

## 3) Endpoint Changes

- **Update calls** moved from legacy `/api/v2/.../call` to **Boundary Node v4** `/api/v4/canister/.../call`.
- **Query calls** moved to **Boundary Node v3** `/api/v3/canister/.../query`.
- **Read state calls** moved to **Boundary Node v3** endpoints (`/api/v3/canister/.../read_state` and `/api/v3/subnet/.../read_state`).
- Ensure your environment allows access to v3/v4 endpoints. The included `Client` already targets the latest endpoints.

---

## 4) High-level API Changes (`Agent.query` / `Agent.update`)

`icp-py-core` adds ergonomic methods mirroring Rust/TS agents:

- `Agent.query(canister_id, method_name, arg=None, *, return_type=None, effective_canister_id=None)`
- `Agent.update(canister_id, method_name, arg=None, *, return_type=None, effective_canister_id=None, verify_certificate=True, ...)`

### Auto-encoding behavior
Both `query` and `update` **auto-encode** arguments:

- `arg is None` → encodes to empty DIDL (`encode([])`)
- `arg` is `bytes/bytearray/memoryview` → used **as-is** (no re-encode)
- Otherwise → passed to `icp_candid.candid.encode()` automatically

> You **should not** pre-encode with `encode(...)` unless you intentionally want to send raw bytes.

### Examples

**Update (auto-encode):**
```python
from icp_core import Agent, Client, Identity

client = Client(url="https://ic0.app")
iden = Identity(privkey="...hex...")
agent = Agent(iden, client)

# Auto-encodes [42] to DIDL
result = agent.update("ryjl3-tyaaa-aaaaa-aaaba-cai", "set_value", [42], verify_certificate=True)
```

**Query (auto-encode empty args):**
```python
from icp_core import Types

# None → encode([]) under the hood
reply = agent.query("ryjl3-tyaaa-aaaaa-aaaba-cai", "get_value", None, return_type=[Types.Nat])
```

**Passing raw bytes intentionally:**
```python
from icp_core import encode
raw = encode([42])          # pre-encode manually if needed
result = agent.update("ryjl3-tyaaa-aaaaa-aaaba-cai", "set_value", raw)
```

---

## 5) Certificate Verification (Enabled by Default)

Certificate verification is **enabled by default** for security. All update methods verify the BLS signature chain (root/subnet) using the official **blst** Python binding:

```python
# Default behavior: verification enabled
agent.update(...)
agent.update_raw(...)

# To disable verification (for compatibility/testing):
agent.update(..., verify_certificate=False)
agent.update_raw(..., verify_certificate=False)
```

- Install blst from source (not on PyPI). See the project README for steps.
- If blst is not installed and verification is enabled, calls will fail. Disable verification if blst is unavailable.

---

## 6) Behavior of `update_raw` and Polling

- `update_raw` submits the call and handles:
  - Immediate `"replied"` (with certificate verification and reply extraction)
  - `"accepted"` → polling via `poll_and_wait`/`poll`
  - `"non_replicated_rejection"` → raises with details
- `poll` uses exponential backoff (configurable) and validates certificates/time skew when `verify_certificate=True`.

You can continue to use the low-level `*_raw` methods if you need full control, but most apps should prefer the ergonomic `query` / `update`.

---

## 7) Identity & Principal Changes

- **SLIP-0010 only** for seed → key derivation (no legacy paths).
- `Principal.self_authenticating(...)` is now **strict DER (SPKI)** only.
  - Pass an Ed25519 **SPKI DER** public key (RFC 8410) hex/bytes.
- `Principal` textual encoding/decoding adheres to IC spec (CRC + base32 with hyphens).

---

## 8) Quick Migration Checklist

1. Replace imports to use `icp_core` (or subpackages).
2. Stop manually encoding args for `query`/`update` unless you want to pass **raw bytes**.
3. Ensure your network allows **/api/v3/.../call**.
4. Install **blst** for certificate verification (enabled by default). If blst is unavailable, you can disable verification with `verify_certificate=False`.
5. For self-authenticating principals, pass **SPKI DER** (not raw 32-byte pubkeys).

---

## 9) Minimal End-to-End Example

```python
from icp_core import Agent, Client, Identity, Types

client = Client("https://ic0.app")
iden = Identity(privkey="...hex...")
agent = Agent(iden, client)

# Update (auto-encode, certificate verification enabled by default)
agent.update("ryjl3-tyaaa-aaaaa-aaaba-cai", "set_value", [42])

# Query (auto-encode empty args), decode as Nat
out = agent.query("ryjl3-tyaaa-aaaaa-aaaba-cai", "get_value", None, return_type=[Types.Nat])
print(out)
```

---

If you encounter issues during migration, check:
- Call endpoint version (v3 for updates)
- blst installation (if verification enabled)
- Input arg types (ensure you rely on auto-encoding unless passing raw bytes)
