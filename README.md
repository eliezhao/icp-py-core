# icp-py-core

[![PyPI version](https://badge.fury.io/py/icp-py-core.svg)](https://pypi.org/project/icp-py-core/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

**icp-py-core** is a Python Agent Library for the [DFINITY Internet Computer](https://internetcomputer.org).  
It provides the fundamental building blocks to interact with canisters, including **Candid parsing**, **identity management**, and **agent communication**.

---

## 📖 About This Project

This project is a **fork of [ic-py](https://github.com/rocklabs-io/ic-py)**.  
Since the original maintainer has stopped maintaining `ic-py`, this repository (**icp-py-core**) continues its development with:

- **Active maintenance** and timely releases to PyPI  
- **Security fixes** (certificate verification with `blst`)  
- **New features** aligned with the Internet Computer roadmap  

🙏 Thanks to the original author of `ic-py` for the important contributions to the IC ecosystem.

---

## 🔧 Installation

```bash
pip install icp-py-core
```

---

## 🚀 What’s New

### Endpoint Upgrade (Milestone 1 ✅)
- Migrated update calls from legacy `/api/v2/.../call` to the new BN v3 endpoint `/api/v3/canister/.../call`  
- Adapted response parsing for v3 responses  
- Added retry logic and fixed poll implementation  

### Timeouts & Error Classification (Milestone 1 ✅)
- Added configurable timeout handling  
- Introduced structured error types for common canister-level failures  

### Certificate Verification (Milestone 2 ✅)
- Added optional certificate verification with `blst`  
- New flag: `agent.update_raw(..., verify_certificate=True)`  
- Verifies IC responses with **BLS12-381 (G1 signature, G2 public key)**  

⚠️ **Security note:** Verification is disabled by default. For production, enable it.  

---

## 🔑 Installing blst (optional)

### macOS / Linux

```bash
git clone https://github.com/supranational/blst
cd blst/bindings/python

# For Apple Silicon:
# export BLST_PORTABLE=1

python3 run.me
export PYTHONPATH="$PWD:$PYTHONPATH"
```

**Or copy to site-packages**

```bash
BLST_SRC="/path/to/blst/bindings/python"
PYBIN="python3"

SITE_PURE="$($PYBIN -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"
SITE_PLAT="$($PYBIN -c 'import sysconfig; print(sysconfig.get_paths()["platlib"])')"

cp "$BLST_SRC/blst.py" "$SITE_PURE"/
cp "$BLST_SRC"/_blst*.so "$SITE_PLAT"/
```

### Windows
- Recommended: WSL2 (Ubuntu)  

---

## ✨ Features
1. Candid encode & decode  
2. secp256k1 & ed25519 identities  
3. Canister DID parsing  
4. Canister class  
5. Ledger / management / NNS / cycles wallet  
6. Async support  

---

## 📦 Modules & Usage

### Principal
```python
from icp_principal import Principal
p = Principal()
p1 = Principal(bytes=b'')
p2 = Principal.anonymous()
p3 = Principal.self_authenticating(pubkey)
p4 = Principal.from_str('aaaaa-aa')
```

### Identity
```python
from icp_identity import Identity
i = Identity()
i1 = Identity(privkey="833fe62409...dca3d42")
```

### Client
```python
from icp_agent import Client
client = Client(url="https://ic0.app")
```

### Candid
```python
from icp_candid import encode, decode, Types
params = [{'type': Types.Nat, 'value': 10}]
data = encode(params)
decoded = decode(data)
```

### Agent
```python
from icp_agent import Agent, Client
from icp_identity import Identity
from icp_candid import encode

iden = Identity()
client = Client()
agent = Agent(iden, client)

name = agent.query_raw("gvbup-jyaaa-aaaah-qcdwa-cai", "name", encode([]))
```

### Canister
```python
from icp_canister import Canister
from icp_agent import Agent, Client
from icp_identity import Identity

iden = Identity()
client = Client()
agent = Agent(iden, client)
gov_did = open("governance.did").read()

gov = Canister(agent, "rrkah-fqaaa-aaaaa-aaaaq-cai", gov_did)
res = gov.list_proposals({"include_status": [1]})
```

### Async
```python
import asyncio
from icp_canister import Canister
from icp_agent import Agent, Client
from icp_identity import Identity

iden = Identity()
client = Client()
agent = Agent(iden, client)

gov_did = open("governance.did").read()
gov = Canister(agent, "rrkah-fqaaa-aaaaa-aaaaq-cai", gov_did)

async def async_test():
    res = await gov.list_proposals_async({'include_status': [1]})
    print(res)

asyncio.run(async_test())
```

---

## 🗺 Roadmap

See [ROADMAP.md](./ROADMAP.md)  
Milestone 1 & 2 completed. Future: Candid enhancements, routing, ICRC helpers.  

---

## 🔖 Version
- Current release: v2.0.0  

---

## 🙌 Acknowledgments
Thanks to the IC community and the original ic-py author.  

