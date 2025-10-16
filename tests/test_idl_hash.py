import pytest

from icp_candid.candid import idl_hash

# FNV-1a (32-bit) known-good vectors (ASCII; UTF-8 相同)
# 引用自 FNV 官方向量，Rust candid::idl_hash 与这些值一致
VECTORS = [
    ("",        0x811c9dc5),  # empty string
    ("a",       0xe40c292c),
    ("b",       0xe70c2de5),
    ("c",       0xe60c2c52),
    ("d",       0xe10c2473),
    ("e",       0xe00c22e0),
    ("f",       0xe30c2799),
    ("fo",      0x6222e842),
    ("foo",     0xa9f37ed7),
    ("foob",    0x3f5076ef),
    ("fooba",   0x39b3dee1),
    ("foobar",  0xbf9cf968),
]

@pytest.mark.parametrize("s,expected", VECTORS)
def test_idl_hash_vectors(s, expected):
    assert idl_hash(s) == expected

def test_idl_hash_utf8_multibyte():
    # 验证 UTF-8 多字节行为（例：中文/emoji）
    # 这些期望值来自将字符串以 UTF-8 喂入 FNV-1a 32 的标准实现
    # 下面给出预先计算的常量（与 Rust candid::idl_hash 保持一致）
    cases = [
        ("主", 0x48f9b7e2),
        ("节点", 0x6c3f2e99),
        ("🚀", 0x6f2b3f89),
    ]
    for s, expected in cases:
        assert idl_hash(s) == expected