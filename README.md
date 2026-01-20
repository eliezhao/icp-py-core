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
- ✅ Updated boundary node endpoints (v3/v4: `/api/v3/canister/.../query`, `/api/v4/canister/.../call`)
- ✅ Optional **certificate verification** via `blst`
- ✅ Type-safe Candid encoding/decoding
- ✅ Pythonic high-level `Agent.update()` and `Agent.query()` methods

🙏 Special thanks to the original `ic-py` author for their foundational work.

### 🤝 Community & Contribution

- **[Contributing Guidelines](./CONTRIBUTING.md)** - How to contribute to the project
- **[Code of Conduct](./CODE_OF_CONDUCT.md)** - Community standards and expectations
- **[Security Policy](./SECURITY.md)** - How to report security vulnerabilities

---

## 🔧 Installation

```bash
pip install icp-py-core
```

> The Candid parser uses a Rust extension with pre-built binary wheels for all platforms.  
> No Rust compiler is required for installation.  
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
    Canister, Ledger, Governance, Management, CyclesWallet,
    encode, decode, Types,
)
```

### ⚡ Endpoint Upgrade
All endpoints now target the latest **Boundary Node** versions:  
- Query: `/api/v3/canister/<canister_id>/query`
- Call: `/api/v4/canister/<canister_id>/call`
- Read State: `/api/v3/canister/<canister_id>/read_state`
- Read Subnet State: `/api/v3/subnet/<subnet_id>/read_state`

### 🔒 Certificate Verification
Certificate verification is **enabled by default** for security. Verifies responses via **BLS12-381** signatures with `blst`:

**With Agent directly:**
```python
# Default: verification enabled
agent.update("canister-id", "method_name", [{'type': Types.Nat, 'value': 2}])

# To disable (for compatibility/testing):
agent.update("canister-id", "method_name", [{'type': Types.Nat, 'value': 2}], verify_certificate=False)
```

**With Canister wrapper:**
```python
# Default: verification enabled (matches Agent.update() behavior)
canister.set_value(42)

# Explicitly enable (same as default)
canister.set_value(42, verify_certificate=True)

# Disable verification (when blst is not installed)
canister.set_value(42, verify_certificate=False)
```

> **Note:** Both `Agent.update()` and `Canister` methods default to `verify_certificate=True` for security. If `blst` is not installed, you must explicitly pass `verify_certificate=False` to avoid errors.

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
    return_type=[Types.Nat],
)
```

### Query (auto-encode empty args)
```python
reply = agent.query("wcrzb-2qaaa-aaaap-qhpgq-cai", "get", [])
print(reply)
```

### Canister Wrapper (Type-Safe Method Calls)
The `Canister` class provides a high-level, type-safe interface for interacting with canisters. It automatically parses Candid DID files and creates Python methods that match your canister's interface.

**Creating a Canister instance:**
```python
from icp_core import Agent, Client, Identity, Canister

# Setup agent
client = Client("https://ic0.app")
identity = Identity()
agent = Agent(identity, client)

# Define Candid interface
COUNTER_DID = """
service : {
  get : () -> (nat) query;
  set : (nat) -> (nat)
}
"""

# Create Canister wrapper
counter = Canister(agent, "wcrzb-2qaaa-aaaap-qhpgq-cai", COUNTER_DID)
```

**Calling canister methods:**
```python
# Query call (no arguments)
value = counter.get()
print(f"Current value: {value[0]['value']}")

# Update call (with positional argument)
result = counter.set(42)
print(f"Set to: {result[0]['value']}")

# Update call with keyword arguments (for record types)
# If your method takes a single record parameter, you can use kwargs:
# result = counter.update_profile(name="Alice", age=30)
```

**Certificate Verification with Canister:**
By default, `Canister` methods enable certificate verification (`verify_certificate=True`) to match `Agent.update()` behavior for security. You can control this per method call:

```python
# Default: certificate verification enabled (requires blst)
result = counter.set(42)  # Uses verify_certificate=True by default

# Explicitly enable verification (same as default)
result = counter.set(42, verify_certificate=True)

# Disable verification (useful when blst is not installed)
result = counter.set(42, verify_certificate=False)
```

**Important Notes:**
- `verify_certificate` is a **control parameter**, not a method argument. It's extracted from kwargs before processing method arguments.
- Default value is `True` to match `Agent.update()` default behavior for security.
- If `blst` is not installed and you don't pass `verify_certificate=False`, update calls will fail.
- For query calls, certificate verification is not applicable (queries don't return certificates).

**Example: Complete Canister Usage**
```python
from icp_core import Agent, Client, Identity, Canister

# Setup
client = Client("https://ic0.app")
identity = Identity(anonymous=True)
agent = Agent(identity, client)

# Define interface
DID = """
service : {
  get : () -> (nat) query;
  set : (nat) -> (nat);
  increment : () -> (nat)
}
"""

# Create canister wrapper
counter = Canister(agent, "wcrzb-2qaaa-aaaap-qhpgq-cai", DID)

# Query (no verification needed)
current = counter.get()
print(f"Current: {current[0]['value']}")

# Update with verification enabled (default, requires blst)
try:
    result = counter.set(100)
    print(f"Set to: {result[0]['value']}")
except Exception as e:
    if "blst" in str(e).lower():
        # Fallback: disable verification if blst not available
        result = counter.set(100, verify_certificate=False)
        print(f"Set to: {result[0]['value']} (verification disabled)")
    else:
        raise

# Update with verification explicitly disabled
result = counter.increment(verify_certificate=False)
print(f"Incremented: {result[0]['value']}")
```

---

## ⚠️ Error Handling

ICP-PY-CORE provides a structured error hierarchy for better error handling and debugging. All errors inherit from `ICError` and are categorized by type.

### Error Classes

```python
from icp_core import (
    ICError,                    # Base class for all errors
    TransportError,             # HTTP/network errors
    SecurityError,              # Base class for security errors
    SignatureVerificationFailed,
    CertificateVerificationError,
    ReplicaReject,              # Canister rejection
    PayloadEncodingError,
    IngressExpiryError,
)
```

### Common Error Scenarios

**Transport Errors (Network Issues):**
```python
from icp_core import Client, TransportError

client = Client()
try:
    data = client.query("canister-id", b"data")
except TransportError as e:
    print(f"Failed to connect to {e.url}")
    print(f"Error: {e.original_error}")
```

**Replica Rejections (Canister Errors):**
```python
from icp_core import Agent, Client, Identity, ReplicaReject

agent = Agent(identity, client)
try:
    result = agent.update("canister-id", "method", args)
except ReplicaReject as e:
    print(f"Rejected with code {e.reject_code}")
    print(f"Message: {e.reject_message}")
    if e.error_code:
        print(f"Error code: {e.error_code}")
```

**Security Errors (Certificate Verification):**
```python
from icp_core import (
    CertificateVerificationError,
    SignatureVerificationFailed,
)

try:
    certificate.assert_certificate_valid(canister_id)
except CertificateVerificationError as e:
    print(f"Certificate verification failed: {e.reason}")
except SignatureVerificationFailed:
    print("BLS signature verification failed")
```

### Error Hierarchy

```
ICError (base class)
├── TransportError (HTTP/network errors)
├── SecurityError (security errors)
│   ├── SignatureVerificationFailed
│   ├── CertificateVerificationError
│   ├── LookupPathMissing
│   ├── NodeKeyNotFoundError
│   └── ReplicaSignatureVerificationFailed
├── ReplicaReject (canister rejections)
├── PayloadEncodingError (CBOR encoding errors)
└── IngressExpiryError (expiry validation errors)
```

### Best Practices

1. **Catch specific errors** for better error handling:
   ```python
   try:
       result = agent.update("canister-id", "method", args)
   except ReplicaReject as e:
       # Handle canister rejection
       handle_rejection(e)
   except TransportError as e:
       # Handle network issues
       handle_network_error(e)
   except SecurityError as e:
       # Handle security issues
       handle_security_error(e)
   ```

2. **Check error attributes** for detailed information:
   ```python
   except ReplicaReject as e:
       if e.reject_code == 3:
           # Canister trapped
           retry_with_different_args()
       elif e.reject_code == 4:
           # Canister did not reply
           check_canister_status()
   ```

3. **Preserve error context** when re-raising:
   ```python
   try:
       result = agent.update("canister-id", "method", args)
   except TransportError as e:
       logger.error(f"Network error: {e.url}", exc_info=True)
       raise  # Re-raise to preserve stack trace
   ```

---

## 🔑 Installing `blst` (optional)

`blst` is required for certificate verification (enabled by default). If `blst` is not installed, you can disable verification with `verify_certificate=False`.

### Prerequisites

**macOS:**
```bash
# Install Xcode Command Line Tools
xcode-select --install

# Install SWIG (required for Python bindings)
brew install swig
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get update
sudo apt-get install build-essential swig python3-dev
```

**Linux (Fedora/RHEL):**
```bash
sudo dnf install gcc gcc-c++ make swig python3-devel
```

### macOS / Linux Installation

**Method 1: Build and add to PYTHONPATH (recommended for development)**

```bash
git clone https://github.com/supranational/blst
cd blst/bindings/python

# For Apple Silicon (M1/M2/M3) if you encounter ABI issues:
# export BLST_PORTABLE=1

python3 run.me

# Temporary (current session only):
export PYTHONPATH="$PWD:$PYTHONPATH"

# Permanent (add to ~/.bashrc or ~/.zshrc):
echo 'export PYTHONPATH="/path/to/blst/bindings/python:$PYTHONPATH"' >> ~/.bashrc
source ~/.bashrc
```

**Method 2: Install to site-packages (recommended for production)**

```bash
git clone https://github.com/supranational/blst
cd blst/bindings/python

# For Apple Silicon (M1/M2/M3) if needed:
# export BLST_PORTABLE=1

python3 run.me

# Copy to site-packages
BLST_SRC="$PWD"
PYBIN="python3"

SITE_PURE="$($PYBIN -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"
SITE_PLAT="$($PYBIN -c 'import sysconfig; print(sysconfig.get_paths()["platlib"])')"

cp "$BLST_SRC/blst.py" "$SITE_PURE"/
cp "$BLST_SRC"/_blst*.so "$SITE_PLAT"/
```

**Method 3: Install in virtual environment**

```bash
# Activate your virtual environment first
source venv/bin/activate  # or: source .venv/bin/activate

git clone https://github.com/supranational/blst
cd blst/bindings/python

# For Apple Silicon if needed:
# export BLST_PORTABLE=1

python3 run.me

# Copy to virtual environment's site-packages
BLST_SRC="$PWD"
SITE_PURE="$(python3 -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"
SITE_PLAT="$(python3 -c 'import sysconfig; print(sysconfig.get_paths()["platlib"])')"

cp "$BLST_SRC/blst.py" "$SITE_PURE"/
cp "$BLST_SRC"/_blst*.so "$SITE_PLAT"/
```

### Windows Installation

**Option 1: WSL2 (Ubuntu) - Recommended**

1. Install WSL2 and Ubuntu from Microsoft Store
2. Follow the Linux installation instructions above in WSL2

**Option 2: Native Windows (Advanced)**

1. Install Visual Studio Build Tools with C++ support
2. Install SWIG for Windows from [swig.org](http://www.swig.org/download.html)
3. Install Python 3.8+ with development headers
4. Follow the Linux build steps in PowerShell or Command Prompt
5. Note: Windows support is experimental; WSL2 is recommended

### Verify Installation

Test if `blst` is correctly installed:

```python
try:
    import blst
    assert all(hasattr(blst, n) for n in ("P1_Affine", "P2_Affine", "Pairing", "BLST_SUCCESS"))
    print("✓ blst is installed and working correctly")
except (ModuleNotFoundError, AssertionError):
    print("✗ blst is not available or incomplete")
```

Or test with `icp-py-core`:

```python
from icp_certificate.certificate import ensure_blst_available
try:
    ensure_blst_available()
    print("✓ blst is available for certificate verification")
except RuntimeError as e:
    print(f"✗ {e}")
```

### Troubleshooting

**Issue: "No module named 'blst'"**
- Ensure `blst.py` and `_blst*.so` are in your Python path
- Check `python3 -c "import sys; print(sys.path)"` to see search paths
- If using virtual environment, ensure it's activated

**Issue: "ABI mismatch" on Apple Silicon**
- Set `export BLST_PORTABLE=1` before running `python3 run.me`
- This builds a portable version compatible with all architectures

**Issue: "SWIG not found"**
- Install SWIG: `brew install swig` (macOS) or `sudo apt-get install swig` (Linux)
- Ensure SWIG is in your PATH: `which swig`

**Issue: Import succeeds but API is incomplete**
- Ensure you're using the official `supranational/blst` repository
- Rebuild: `cd blst/bindings/python && python3 run.me`
- Check that all required symbols exist: `P1_Affine`, `P2_Affine`, `Pairing`, `BLST_SUCCESS`

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

# Update (auto-encode [42], certificate verification enabled by default)
agent.update("wcrzb-2qaaa-aaaap-qhpgq-cai", "set_value", [42])

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

- Current release: **v2.1.1**

---

## 🙌 Acknowledgments

Special thanks to the IC community and contributors to the original **ic-py**.  
**icp-py-core** continues this legacy with modern Python standards and long-term maintenance.

---

## 📚 Additional Resources

- **[CONTRIBUTING.md](./CONTRIBUTING.md)** - Guidelines for contributing to the project
- **[CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)** - Community code of conduct
- **[SECURITY.md](./SECURITY.md)** - Security policy and vulnerability reporting
- **[MIGRATION.md](./MIGRATION.md)** - Migration guide from ic-py
- **[CHANGELOG.md](./CHANGELOG.md)** - Release notes and changelog
- **[ROADMAP.md](./ROADMAP.md)** - Project roadmap and future plans