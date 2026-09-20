"""防篡改原语：逐行哈希链、Merkle 树与稳定编码。

核验包的证据强度来自两层结构：

* **哈希链**：流水每条记录 ``chain_hash = H(prev_hash || 行字节)``。改任意一条
  的任意字节，该条及其后所有链哈希全部变化，篡改位置即第一处分叉处。
* **Merkle 根**：把一段记录（或一份状态快照的全部文档）压成单个 32B 根，签名
  只需要覆盖这个根；状态快照可在不暴露全部文档的情况下做包含性证明（后续
  扩展用），这里先整体导出、整体核对。

哈希一律 SHA-256，域前缀 ``FS1`` 防止叶子节点与内部节点、事件与状态之间被
人为构造出碰撞。
"""

from __future__ import annotations

import hashlib
from typing import Any, Iterable, Mapping, Sequence

from ..store.codec import canonical_json

GENESIS_HASH = "0" * 64
LEAF_EVENT = b"FS1\x01event\x00"
LEAF_STATE = b"FS1\x01state\x00"
NODE_INTERNAL = b"FS1\x02node\x00\x00"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def chain_hash(prev_hash: str, row_bytes: bytes) -> str:
    """计算一条流水记录的链哈希。

    ``row_bytes`` 必须是该记录落盘时的**原始字节**（JSONL 去掉行尾换行），
    这样核验端无需重新序列化即可逐字节复算，避免「规范化不一致导致误报」。
    """

    digest = hashlib.sha256()
    digest.update(bytes.fromhex(prev_hash))
    digest.update(b"\x00")
    digest.update(row_bytes)
    return digest.hexdigest()


def event_leaf(row_hash: str) -> bytes:
    digest = hashlib.sha256()
    digest.update(LEAF_EVENT)
    digest.update(bytes.fromhex(row_hash))
    return digest.digest()


def state_leaf(key: str, record_bytes: bytes) -> bytes:
    """状态叶子（旧版，按信封规范字节）。"""

    digest = hashlib.sha256()
    digest.update(LEAF_STATE)
    digest.update(key.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(record_bytes)
    return digest.digest()


def state_line_leaf(key: str, line_bytes: bytes) -> bytes:
    """状态叶子：对 state.jsonl 中**整行原始字节**取哈希。

    导出端用规范 JSON 写行，所有核验端（Python/浏览器/独立脚本）都按字节透传，
    不需要重新序列化，彻底绕开不同语言对数字（``5200.0`` 与 ``5200``）规范化
    不一致的问题。
    """

    digest = hashlib.sha256()
    digest.update(LEAF_STATE)
    digest.update(key.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(line_bytes)
    return digest.digest()


def merkle_root(leaves: Sequence[bytes]) -> str:
    """标准 Merkle 根；奇数节点复制最后一个；空树定义为 64 个 0。"""

    if not leaves:
        return GENESIS_HASH
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        nxt: list[bytes] = []
        for index in range(0, len(level), 2):
            digest = hashlib.sha256()
            digest.update(NODE_INTERNAL)
            digest.update(level[index])
            digest.update(level[index + 1])
            nxt.append(digest.digest())
        level = nxt
    return level[0].hex()


def verify_chain(rows: Iterable[tuple[str, str]], *, start_prev: str = GENESIS_HASH) -> tuple[bool, int, str]:
    """就地重算哈希链。

    ``rows`` 为 ``(prev_hash, 行原始字节)`` 序列。返回 ``(是否通过, 首个失败
    位置(从 0 计，全部通过时为 -1), 末端链哈希)``。
    """

    previous = start_prev
    tip = start_prev
    for index, (prev_hash, row_bytes) in enumerate(rows):
        if prev_hash != previous:
            return False, index, tip
        tip = chain_hash(previous, row_bytes.encode("utf-8"))
        previous = tip
    return True, -1, tip


def manifest_bytes(manifest: Mapping[str, Any]) -> bytes:
    """清单的规范字节：签名与验签都必须针对这同一串字节。"""

    return canonical_json(manifest).encode("utf-8")


__all__ = [
    "GENESIS_HASH",
    "sha256_hex",
    "chain_hash",
    "event_leaf",
    "state_leaf",
    "state_line_leaf",
    "merkle_root",
    "verify_chain",
    "manifest_bytes",
]
