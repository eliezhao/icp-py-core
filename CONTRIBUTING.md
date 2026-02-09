# Contributing to ICP-PY-CORE

Thank you for your interest in contributing to ICP-PY-CORE! This document provides guidelines and instructions for contributing to the project.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Submitting Changes](#submitting-changes)
- [Code Style](#code-style)
- [Testing](#testing)
- [Documentation](#documentation)

## Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. Please read [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) before participating.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/your-username/icp-py-core.git
   cd icp-py-core
   ```
3. **Add the upstream remote**:
   ```bash
   git remote add upstream https://github.com/eliezhao/icp-py-core.git
   ```

## Development Setup

### Prerequisites

- Python 3.8 or higher
- pip
- (Optional) Rust toolchain (for building Rust extensions locally)

### Setting Up the Environment

1. **Create a virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install the package in development mode**:
   ```bash
   pip install -e .
   ```

3. **Install development dependencies**:
   ```bash
   pip install pytest pytest-cov
   ```

4. **Verify the installation**:
   ```bash
   python -c "from icp_core import Agent, Identity, Principal; print('Installation successful!')"
   ```

### Building Rust Extensions (Optional)

If you need to modify the Rust-based Candid parser:

1. **Install Rust**:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **Build the extension**:
   ```bash
   cd src/icp_candid/ic_candid_parser
   cargo build --release
   ```

### Releasing a new version (main package + ic-candid-parser)

When bumping icp-py-core's version you **must also bump** the Rust extension ic-candid-parser's version; otherwise the release workflow will still publish the old extension version.

**Recommended steps:**

1. **Bump both versions** (main package + extension in one go):
   ```bash
   ./scripts/bump_versions.sh <new_main_version> [extension_version]
   ```
   - Example: `./scripts/bump_versions.sh 2.3.0` → sets main to 2.3.0, extension patch+1 (e.g. 0.1.2 → 0.1.3), and updates main's dependency to `ic_candid_parser>=0.1.3`.
   - To set extension explicitly: `./scripts/bump_versions.sh 2.3.0 0.1.5`.
2. Update **CHANGELOG.md** (replace `[Unreleased]` with `[x.y.z] - date`).
3. Commit, tag, and push to trigger the release:
   ```bash
   git add -A && git commit -m "chore: release v2.3.0" && git tag v2.3.0 && git push && git push --tags
   ```
   `.github/workflows/release.yml` will publish ic-candid-parser first, then icp-py-core.

### Publishing ic-candid-parser to PyPI (maintainers)

The Rust extension is published as a separate PyPI package **ic-candid-parser**; its version is read from `src/icp_candid/ic_candid_parser/Cargo.toml`.

- **Publish extension only** (single-platform build + sdist): from the repo root run  
  `./scripts/publish_ic_candid_parser.sh`  
  Requires `maturin` and PyPI credentials (e.g. `TWINE_USERNAME` / `TWINE_PASSWORD`).
- **Full multi-platform wheels (recommended)**: Use a GitHub Release. Pushing a tag (e.g. `v2.3.0`) triggers `.github/workflows/release.yml`, which builds multi-platform wheels and publishes ic-candid-parser first, then icp-py-core.

## Making Changes

### Branch Naming

Create a new branch for your changes:

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
# or
git checkout -b docs/your-documentation-update
```

### Commit Messages

Write clear, descriptive commit messages:

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests after the first line

Example:
```
Add support for ICRC-1 token standard

- Implement ICRC-1 ledger interface
- Add transfer and balance query methods
- Include comprehensive tests

Fixes #123
```

## Submitting Changes

### Pull Request Process

1. **Update your fork**:
   ```bash
   git fetch upstream
   git checkout main
   git merge upstream/main
   ```

2. **Push your changes**:
   ```bash
   git push origin feature/your-feature-name
   ```

3. **Create a Pull Request** on GitHub:
   - Provide a clear title and description
   - Reference any related issues
   - Include screenshots or examples if applicable
   - Ensure all tests pass

### Pull Request Checklist

Before submitting, please ensure:

- [ ] Code follows the project's style guidelines
- [ ] All tests pass (`pytest tests/`)
- [ ] New features include tests
- [ ] Documentation is updated (if needed)
- [ ] Commit messages follow the guidelines
- [ ] Code is self-documenting with clear variable names
- [ ] No hardcoded credentials or sensitive data

## Code Style

### Python Style Guide

- Follow [PEP 8](https://pep8.org/) style guide
- Use type hints where appropriate
- Maximum line length: 100 characters (soft limit)
- Use meaningful variable and function names
- Add docstrings for public functions and classes

### Example

```python
def transfer_tokens(
    self,
    to: Principal,
    amount: int,
    verify_certificate: bool = True
) -> Dict[str, Any]:
    """
    Transfer tokens to another principal.
    
    Args:
        to: Recipient principal
        amount: Amount in e8s (smallest unit)
        verify_certificate: Whether to verify response certificate
        
    Returns:
        Transaction result dictionary
        
    Raises:
        ValueError: If amount is invalid
        RuntimeError: If transfer fails
    """
    # Implementation here
    pass
```

### Import Organization

Organize imports in this order:

1. Standard library imports
2. Third-party imports
3. Local application imports

Example:
```python
# Standard library
import hashlib
from typing import Optional, Dict

# Third-party
import httpx
from ecdsa import SigningKey

# Local
from icp_principal import Principal
from icp_identity import Identity
```

## Testing

### Running Tests

Run all tests:
```bash
pytest tests/
```

Run specific test file:
```bash
pytest tests/test_agent.py
```

Run with coverage:
```bash
pytest --cov=src tests/
```

### Writing Tests

- Write tests for all new features
- Aim for high code coverage
- Use descriptive test names
- Test both success and failure cases
- Mock external dependencies when appropriate

Example:
```python
def test_principal_from_str():
    """Test creating Principal from string representation."""
    principal_str = "giyn2-fnnjo-xgyb5-526bm-xz3ve-bpekl-nrtae-muc55-tjukq-jyscs-zqe"
    principal = Principal.from_str(principal_str)
    assert principal.to_str() == principal_str
```

## Documentation

### Code Documentation

- Add docstrings to all public functions, classes, and methods
- Use Google-style docstrings
- Include parameter descriptions and return values
- Add examples for complex functions

### README Updates

If your changes affect:
- Installation process
- API usage
- Configuration
- Dependencies

Please update the README.md accordingly.

### Changelog

For significant changes, add an entry to `CHANGELOG.md`:
- New features
- Bug fixes
- Breaking changes
- Deprecations

## Questions?

If you have questions or need help:

1. Check existing [Issues](https://github.com/eliezhao/icp-py-core/issues)
2. Open a new issue with the "question" label
3. Review the [README.md](./README.md) and [MIGRATION.md](./MIGRATION.md)

## Recognition

Contributors will be recognized in:
- The project's README (for significant contributions)
- Release notes (for code contributions)
- GitHub contributors page

Thank you for contributing to ICP-PY-CORE! 🎉
