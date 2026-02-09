# Changelog

## [Unreleased]

## [2.3.0] - 2026-02-06

### Added

- **Configurable query and update timeouts** ⏱️
  - Default query timeout: **30 seconds** (`DEFAULT_QUERY_TIMEOUT_SEC`); override per call via `timeout` on `Agent.query()`, `Agent.query_async()`, and query endpoint helpers
  - Default poll timeout for updates: **60 seconds** (`DEFAULT_POLL_TIMEOUT_SECS`); same `timeout` parameter for `Agent.update()` and `Agent.update_async()`
  - On timeout, the library raises **`TimeoutWaitingForResponse`** (with `timeout_seconds` and optional `request_id`) for consistent handling

- **Verify query response signatures (opt-in)** 🔐
  - New **`verify_query_signatures=True`** on `Agent` or per call to `Agent.query()` / `Agent.query_async()` to verify replica-signed query responses (default: `False`)
  - Signable payload built per IC spec (`\x0Bic-response` + request ID and response); Ed25519 verified with subnet node public keys (fetched on demand, cached)
  - New error types: **`QuerySignatureVerificationFailed`**, **`QueryResponseMissingSignature`**, **`QueryResponseSignatureCountMismatch`** (and existing certificate/node-key errors for debugging)

- **Automatically fetch .did from canister** 📄
  - **`Canister(agent, canister_id, candid_str=None, auto_fetch_candid=True)`**: when `candid_str` is not provided, the client fetches Candid from the IC (tries public `candid:service`, then private `candid` metadata)
  - Clear `ValueError` if both fail; passing `candid_str` or `auto_fetch_candid=False` keeps previous behavior (no fetch, manual DID only)

- **Canister async method support** 🔄
  - For each canister method, an async variant **`<method_name>_async`** is exposed (e.g. `get_async`, `set_async`); same type safety and encoding as sync methods
  - See **`examples/simple_counter_example_async.py`** for async query/update usage with the Canister wrapper

- **Candid composite query support** 📦
  - Added Candid support for composite query

### Changed

- **Canister wrapper timeout passthrough** ⏱️
  - Canister high-level methods pass through `timeout` kwarg to `Agent.query` / `Agent.query_async` and related calls

### Fixed

- **Read state and v4 polling** 🐛
  - Merged [PR #13](https://github.com/eliezhao/icp-py-core/pull/13): Fix/read state and v4 polling

## [2.2.1] - 2026-01-22

### Fixed

- **VarT service reference fix included** 🐛
  - Updated dependency to `ic_candid_parser>=0.1.1` to include VarT (type reference) fix
  - This release includes the fix for `service : () -> TypeName` pattern that was committed (commit 83d6dca) but not published in the original v2.2.0 release
  - The Rust extension `ic-candid-parser` is now published as v0.1.1 with the VarT fix
  - Resolves [GitHub issue #10](https://github.com/eliezhao/icp-py-core/issues/10)

## [2.2.0] - 2026-01-21

### Added

- **Structured Error Handling Hierarchy** 🎯
  - New comprehensive error hierarchy with 11 error classes
  - `ICError` - Base class for all agent errors
  - `TransportError` - HTTP/network errors with URL and original error context
  - `SecurityError` and subclasses:
    - `SignatureVerificationFailed` - BLS signature verification failures
    - `CertificateVerificationError` - Certificate validation errors
    - `LookupPathMissing` - Certificate path lookup failures
    - `NodeKeyNotFoundError` - Node public key lookup failures
    - `ReplicaSignatureVerificationFailed` - Replica signature verification failures
  - `ReplicaReject` - Canister rejection errors with detailed codes and messages
  - `PayloadEncodingError` - CBOR encoding/decoding errors
  - `IngressExpiryError` - Ingress message expiry validation errors
  - All errors exported from `icp_core` for easy importing
  - Comprehensive error handling documentation in README.md

- **HTTP/2 Support** ⚡
  - Enabled HTTP/2 in all async methods (`AsyncClient`)
  - Improved performance through HTTP/2 multiplexing and header compression
  - Automatic fallback to HTTP/1.1 if HTTP/2 is not supported
  - Better connection reuse and reduced latency for concurrent requests

- **V4 API Sharded Canister Ranges Support** 🔐
  - Added support for v4 API sharded `canister_ranges` structure
  - Updated certificate verification to handle sharded structure: `[canister_ranges, subnet_id, shard_label]`
  - Improved `lookup_tree` and `list_paths` methods for shard navigation
  - Updated test certificates to use v4 API format

- **Enhanced Certificate Verification** 🔒
  - Improved certificate delegation path handling
  - Better error messages for certificate verification failures
  - Enhanced subnet-level read_state operations
  - Node key caching for performance optimization

### Changed

- **Error Handling Improvements** 🛠️
  - All `Client` methods now raise `TransportError` for network issues
  - All `Agent` methods raise structured errors (`ReplicaReject`, `SecurityError`, etc.)
  - Certificate verification raises `SecurityError` subclasses
  - Better error chaining with `__cause__` attribute preservation
  - Improved error messages with sanitized stack traces

- **API Endpoint Updates** 🌐
  - Restored `check_delegation` logic for proper delegation verification
  - Updated to use v3 endpoint for call operations (`/api/v3/canister/.../call`)
  - Maintained backward compatibility with existing code

- **Code Quality Improvements** ✨
  - Fixed circular import issues in `icp_core.__init__.py` using `__getattr__` lazy loading
  - Improved error chain setup for `TransportError` and `PayloadEncodingError`
  - Enhanced type annotations throughout codebase
  - Better code organization and maintainability

### Fixed

- **Circular Import Issues** 🐛
  - Fixed circular imports in `icp_core.__init__.py` using lazy loading pattern
  - Improved import structure to prevent import-time circular dependencies
  - Fixed mock import paths in tests

- **Error Chain Setup** 🔗
  - Fixed `__cause__` attribute setting for `TransportError` and `PayloadEncodingError`
  - Proper exception chaining for better debugging and error context

- **Subnet ID Extraction** 🔍
  - Improved subnet_id extraction from delegation with proper None checking
  - Better error handling when delegation is missing or invalid

### Migration Notes

- **Error Handling**: If you catch generic `Exception`, consider catching specific error types (`TransportError`, `ReplicaReject`, `SecurityError`) for better error handling
- **HTTP/2**: No code changes required - HTTP/2 is automatically enabled for async methods
- **Certificate Verification**: Query signature verification is temporarily disabled in v2.2.0
- **Imports**: Error classes are now available from `icp_core`: `from icp_core import TransportError, ReplicaReject, SecurityError`

## [2.1.1] - 2025-12-20

### Fixed

- **Fixed VarT (type reference) handling in Candid DID parser** 🐛
  - Fixed issue where DID files using type references for service definitions failed to parse
  - Added support for `service : () -> TypeName` pattern (common in Motoko-generated DID files)
  - Added support for nested type references (e.g., `type A = B; type B = service {...}`)
  - Added support for type references with initialization arguments
  - Resolves [GitHub issue #7](https://github.com/eliezhao/icp-py-core/issues/7)

### Technical Details

- Enhanced `lookup_service_type` function in Rust parser to handle VarT type references
- Added recursive lookup for nested type references
- Added comprehensive test coverage for VarT service reference patterns
- All 66 tests passing (64 passed, 2 skipped)

## [2.1.0] - 2025-12-16

### Performance

- **Candid DID Parser Performance Optimization** ⚡
  - Migrated from Python ANTLR4 implementation to Rust-based `candid-parser` crate
  - Significant performance improvements with multiple times faster parsing speed
  - Reduced memory footprint and faster startup time
  - New Rust extension module (`ic_candid_parser`) with PyO3 bindings
  - Maintains full backward compatibility with existing API

### Added

- **Comprehensive Example Code Library** 📚
  - `ledger_example.py` - ICP token transfers, balance queries, transaction history
  - `governance_example.py` - Neuron management, proposal queries and voting
  - `cycles_wallet_example.py` - Cycles transfers, wallet operations, canister creation
  - `management_example.py` - Canister creation, code installation, status queries
  - `simple_counter_example.py` - Basic query/update calls with error handling
  - `helpers.py` - Common utility functions and formatted output helpers

- **Enhanced Governance Module**
  - Complete NNS Governance interface implementation
  - Proposal creation and management functionality
  - Voting functionality with full type system support
  - Neuron management and configuration
  - Expanded from ~218 lines to 1510 lines with comprehensive coverage

- **New DID Loader Interface**
  - New `DIDLoader` class providing clean API for DID file parsing
  - Improved error handling with clearer error messages
  - Support for recursive type definitions and service interface parsing

- **Testing & Configuration**
  - New comprehensive test files: `test_did_loader_comprehensive.py`, `test_parser.py`
  - Enhanced `test_candid_comprehensive.py` with 186 new lines
  - Pytest warning filters for cleaner test output (filters known `blst` library warnings)

### Changed

- **Canister Module Optimization**
  - Simplified `canister.py` from 1322 lines to ~112 lines (90%+ reduction)
  - Improved code structure and maintainability
  - Better error handling and dynamic method binding support
  - Maintains full backward compatibility

- **Documentation Improvements**
  - Expanded `blst` installation guide with detailed instructions (150+ lines)
  - Added prerequisites for macOS, Linux (Ubuntu/Debian, Fedora/RHEL), and Windows
  - Three installation methods: development, production, and virtual environment
  - Complete troubleshooting section for common issues
  - Installation verification examples

### Removed

- **Legacy ANTLR Parser Files**
  - Removed `src/icp_candid/parser/DIDParser.py` (1586 lines)
  - Removed `src/icp_candid/parser/DIDLexer.py` (195 lines)
  - Removed `src/icp_candid/parser/DIDParserListener.py` (246 lines)
  - Removed ANTLR-related resource files (`*.g4`, `*.jar`)
  - Dependency on `antlr4-python3-runtime==4.9.3` no longer required

### Technical Details

- Rust extension implementation with `serde` for JSON serialization
- Custom `JsonType` enum matching Python expected format
- Complete error handling and type conversion
- All 56 tests passing with ~7.3 seconds test duration
- Net change: +1212 lines (41 files changed, +5951 added, -4739 deleted)

## [2.0.0] - 2025-12-01

### Breaking Changes

- **Certificate verification is now enabled by default for all query calls.**  
  - This improves security by ensuring responses are properly certified.  
  - If you need the previous behavior (verification disabled), you can do:
  
    ```python
    client = IcpClient(..., verify_certification=False)
    ```

### Bug Fixes

- Fixed: Missing flag byte in Principal decoding.
- Fixed: Authenticated query calls failing under certain conditions.

## [1.0.1] - 2025-12-01

### Fixed
- **secp256k1 identity documentation and tests**  
  - Corrected documentation to clarify that secp256k1 uses 64-byte raw signatures (r||s format) with canonical low-S, not DER format.  
  - Fixed test expectation for secp256k1 public key length (128 hex characters for x||y coordinates, no 0x04 prefix).

## [1.0.0] - 2025-10-20

### Security
- **Certificate verification now enabled by default**  
  - `Agent.update_raw()` and `Agent.update_raw_async()` now default to `verify_certificate=True` for maximum security.  
  - Users can still disable verification with `verify_certificate=False` for compatibility or testing purposes.  
  - This change ensures the most secure option is used by default, protecting against unverified responses from boundary nodes.

### Added
- **Certificate verification**  
  - Introduced BLS12-381 certificate verification using the official [`blst`](https://github.com/supranational/blst) Python binding.  
  - New parameter `verify_certificate` in `Agent.update_raw` and `Agent.update_raw_async`.  
  - When `verify_certificate=True`, update calls are verified against the IC's certified responses.  
  - Includes full unit test coverage for verification scenarios.  
  - **Note:** In later versions, certificate verification is enabled by default for security.  

### Changed
- **Endpoint upgrade**  
  - Migrated `update_raw` calls from legacy `/api/v2/.../call` endpoint to new **BN v4 call endpoint** (`/api/v4/canister/.../call`).  
  - Migrated query calls to **BN v3 endpoint** (`/api/v3/canister/.../query`).  
  - Migrated read_state calls to **BN v3 endpoints** (`/api/v3/canister/.../read_state` and `/api/v3/subnet/.../read_state`).  
  - Implemented response adaptation and improved retry logic for more stable request handling.  
  - Enhanced the `poll` and `poll_and_wait` methods for correctness and resilience.  

- **Timeouts & error classification**  
  - Added configurable timeout handling in client calls.  
  - Improved error classification for common canister rejection codes, with more structured runtime exceptions.

### Security
- Addresses longstanding gaps in certificate validation:  
  - `update_raw` and `poll` now support certificate verification when enabled.  
  - Protects against unverified responses from boundary nodes.

### References
- [DFINITY forum: Reducing end-to-end latencies](https://forum.dfinity.org/t/reducing-end-to-end-latencies-on-the-internet-computer/34383)  
- [DFINITY forum: Boundary node roadmap](https://forum.dfinity.org/t/boundary-node-roadmap/15562/104)  
- [GitHub issue #117](https://github.com/rocklabs-io/ic-py/issues/117)  
- [GitHub issue #115](https://github.com/rocklabs-io/ic-py/issues/115)  
- [Forum discussion: Unmaintained agents & vulnerabilities](https://forum.dfinity.org/t/unmaintained-ic-agents-containing-vulnerabilities/41589)  
- [GitHub issue #109](https://github.com/rocklabs-io/ic-py/issues/109)  
- [GitHub issue #76](https://github.com/rocklabs-io/ic-py/issues/76)  
