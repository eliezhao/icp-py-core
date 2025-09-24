from pathlib import Path
from setuptools import setup, find_packages

README = (Path(__file__).parent / "README.md").read_text(encoding="utf-8")

setup(
    name="icp-py-core",
    version="2.0.0",
    description="Python Agent Library for the DFINITY Internet Computer (fork of ic-py)",
    long_description=README,
    long_description_content_type="text/markdown",
    author="icp-py-core maintainers",
    license="MIT",
    url="https://github.com/eliezhao/icp-py-core",
    project_urls={
        "Source": "https://github.com/eliezhao/icp-py-core",
        "Changelog": "https://github.com/eliezhao/icp-py-core/blob/main/CHANGELOG.md",
        "Roadmap": "https://github.com/eliezhao/icp-py-core/blob/main/ROADMAP.md",
    },
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    include_package_data=True,  # work with MANIFEST.in for assets
    package_data={
        # If you prefer explicit mapping (optional, MANIFEST.in already covers it)
        "icp_candid": [],
        "icp_candid.parser": [],
        "icp_candid.parser.assets": ["*.g4", "*.jar", "*.sh"],
    },
    python_requires=">=3.9",
    install_requires=[
        "httpx>=0.24,<0.28",
        "cbor2>=5.5.1",
        "leb128>=1.0.5",
        "antlr4-python3-runtime==4.9.3",
    ],
    extras_require={
        # `blst` is not on PyPI; leave empty but document install in README
        "blst": [],
        "dev": [
            "pytest>=7",
            "tox>=4",
            "ruff>=0.5",
            "mypy>=1.8",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Internet",
        "Topic :: Software Development :: Libraries",
    ],
    keywords=[
        "dfinity",
        "internet-computer",
        "icp",
        "agent",
        "candid",
        "canister",
    ],
)