# 🐍 ICP-PY-CORE

<p style="center" style="margin:0; padding:0;">
  <img src="pics/icp-py-core-logo.png" alt="ICP-PY-CORE Logo" style="width:100%; max-width:1200px; height:auto; border-radius:8px;" />
</p>

<p style="center">
  <a href="https://pypi.org/project/icp-py-core/"><img src="https://badge.fury.io/py/icp-py-core.svg" alt="PyPI version"></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="https://internetcomputer.org"><img src="https://img.shields.io/badge/Powered%20by-Internet%20Computer-blue.svg" alt="Internet Computer"></a>
</p>

---

## 📖 About This Project

**ICP-PY-CORE** is a maintained and extended fork of [ic-py](https://github.com/rocklabs-io/ic-py).  
This version introduces a modular architecture, protocol upgrades, and new APIs while preserving compatibility with the IC ecosystem.

**Highlights:**
- ✅ Modular structure under `src/` (`icp_agent`, `icp_identity`, `icp_candid`, etc.)
- ✅ Updated boundary node v3 endpoints (`/api/v3/canister/.../call`)
- ✅ Optional **certificate verification** via `blst`
- ✅ Type-safe Candid encoding/decoding
- ✅ Pythonic high-level `Agent.update()` and `Agent.query()` methods

🙏 Special thanks to the original `ic-py` author for their foundational work.

---

## 🔧 Installation

```bash
pip install icp-py-core
```

> If you use the Candid parser, we pin `antlr4-python3-runtime==4.9.3`.  
> For optional certificate verification, see the **blst** section below.

---

## 🚀 Key Improvements

### ✳️ Modular Codebase
Each component is isolated for clarity and extensibility:

```
src/
├── icp_agent/         # Agent & HTTP Client
├── icp_identity/      # ed25519 / secp256k1 identities
├── icp_candid/        # Candid encoder/decoder
├── icp_principal/     # Principal utilities
├── icp_certificate/   # Certificate validation
├── icp_core/          # Unified facade (one-line import)
```

### 🔗 Unified Facade (`icp_core`)
Import everything from a single entrypoint:

```python
from icp_core import (
    Agent, Client,
    Identity, DelegateIdentity,
    Principal, Certificate,
    encode, decode, Types,
)
```

### ⚡ Endpoint Upgrade
All update calls now target **Boundary Node v3** endpoints:  
`/api/v3/canister/<canister_id>/call`

### 🔒 Certificate Verification
Enable verifiable responses via **BLS12-381** signatures with `blst`:

```python
agent.update("canister-id", "method_name", [{'type': Types.Nat, 'value': 2}], verify_certificate=True)
```

---

## 🧩 Example Usage

### Identity
```python
from icp_core import Identity
iden = Identity(privkey="833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
print(iden.sender().to_str())
```

### Client & Agent
```python
from icp_core import Agent, Client, Identity

iden = Identity()
client = Client("https://ic0.app")
agent = Agent(iden, client)
```

### Update (auto-encode)
```python
from icp_core import Types
result = agent.update(
    "wcrzb-2qaaa-aaaap-qhpgq-cai",
    "set",
    [{'type': Types.Nat, 'value': 2}],
    verify_certificate=True,
    return_type=[Types.Nat],
)
```

### Query (auto-encode empty args)
```python
reply = agent.query("wcrzb-2qaaa-aaaap-qhpgq-cai", "get", [])
print(reply)
```

---

## 🔑 Installing `blst` (optional)

### macOS / Linux

```bash
git clone https://github.com/supranational/blst
cd blst/bindings/python

# For Apple Silicon (if needed)
# export BLST_PORTABLE=1

python3 run.me
export PYTHONPATH="$PWD:$PYTHONPATH"
```

**Or copy to site-packages manually:**
```bash
BLST_SRC="/path/to/blst/bindings/python"
PYBIN="python3"

SITE_PURE="$($PYBIN -c 'import sysconfig; print(sysconfig.get_paths()[\\"purelib\\"])')"
SITE_PLAT="$($PYBIN -c 'import sysconfig; print(sysconfig.get_paths()[\\"platlib\\"])')"

cp "$BLST_SRC/blst.py" "$SITE_PURE"/
cp "$BLST_SRC"/_blst*.so "$SITE_PLAT"/
```

### Windows
Use **WSL2 (Ubuntu)** for best compatibility.

---

## 🧠 Features

1. 🧩 Candid encode & decode  
2. 🔐 ed25519 & secp256k1 identities  
3. 🧾 Principal utilities (strict DER mode)  
4. ⚙️ High-level canister calls via Agent  
5. 🪙 Support for Ledger / Governance / Management / Cycles Wallet  
6. 🔁 Sync & async APIs  

---

## 🧰 Example — End-to-End

```python
from icp_core import Agent, Client, Identity, Types

client = Client("https://ic0.app")
iden = Identity()
agent = Agent(iden, client)

# Update (auto-encode [42])
agent.update("wcrzb-2qaaa-aaaap-qhpgq-cai", "set_value", [42], verify_certificate=True)

# Query (auto-encode empty args)
res = agent.query("wcrzb-2qaaa-aaaap-qhpgq-cai", "get_value", None, return_type=[Types.Nat])
print(res)
```

---

## 🔄 Migration

Migrating from **ic-py**? See **[MIGRATION.md](./MIGRATION.md)** for:
- New package layout (`icp_*` subpackages and the `icp_core` facade)
- Endpoint changes (v3 call)
- Argument auto-encoding in `Agent.update()` / `Agent.query()`
- Certificate verification flag

---

## 📝 Changelog

We maintain release notes on GitHub Releases:  
**https://github.com/eliezhao/icp-py-core/releases**

---

## 🗺 Roadmap

See [ROADMAP.md](./ROADMAP.md)

✅ Milestone 1: v3 endpoint migration & polling stability  
✅ Milestone 2: Certificate verification with `blst`  
🔜 Milestone 3: ICRC utilities, Candid enhancements, type reflection  

---

## 🔖 Version

- Current release: **v1.0.0**

---

## 🙌 Acknowledgments

Special thanks to the IC community and contributors to the original **ic-py**.  
**icp-py-core** continues this legacy with modern Python standards and long-term maintenance.