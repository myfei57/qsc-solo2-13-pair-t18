"""离线核验包：断网可查、事后可证。

三件事：

* :func:`export_bundle` —— 线上导出「当前状态 + 一段流水 + 哈希链 + 签名」；
* :func:`verify_bundle` —— 断网车间里只读核验，回答「记录有没有被动过」；
* :func:`reconcile_bundle` —— 回联后逐条对账，指出哪条被改、哪段缺失。

信任根是一对 Ed25519 密钥：私钥只留在线上（建议进 HSM），公钥钉在车间核验端。
"""

from __future__ import annotations

from .bundle import (
    ReconcileReport,
    VerifyReport,
    export_bundle,
    journal_relpath,
    open_bundle,
    reconcile_bundle,
    verify_bundle,
)
from .chain import (
    EMPTY_ROOT,
    PREV_ZERO,
    ChainLink,
    build_chain,
    link_hash,
    merkle_root,
    state_root,
)
from .crypto import (
    KeyPair,
    generate_keypair,
    load_private_key,
    load_public_key,
    save_keypair,
    sign,
    verify_signature,
)

__all__ = [
    "KeyPair",
    "ReconcileReport",
    "VerifyReport",
    "build_chain",
    "export_bundle",
    "generate_keypair",
    "journal_relpath",
    "link_hash",
    "load_private_key",
    "load_public_key",
    "merkle_root",
    "open_bundle",
    "reconcile_bundle",
    "save_keypair",
    "sign",
    "state_root",
    "verify_bundle",
    "verify_signature",
    "EMPTY_ROOT",
    "PREV_ZERO",
]
