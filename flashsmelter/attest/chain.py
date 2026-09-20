"""哈希链与默克尔根：离线核验的防篡改原语。

平台原有流水只对每一行单独做校验和：能发现「某一行被改」，但证明不了「中间少了
一段」或「记录顺序被动过」。核验包在不改写原有落盘格式的前提下，额外在导出时对
整条流重算一条前向哈希链：

    link[0] = H(domain | stream | seq | written_at | checksum | body | PREV_ZERO)
    link[i] = H(domain | stream | seq | written_at | checksum | body | link[i-1])

其中 ``body`` 是该行 payload 的规范化摘要：链既绑定原有逐行校验和，也直接绑定
内容本身——只改内容不重算校验和、或连校验和一起重算，链头都会变。只要把链头
``head`` 和序号边界放进被签名的清单里，任何一行被改、任何一段被抽掉、任何顺序
被调换，验包时都会在第一处出错的序号上暴露出来。当前状态则按
``key -> 版本/时间戳/校验和/内容`` 组织成默克尔根，状态缺一个键、改一个值都会
改变根。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from ..errors import IntegrityError, ValidationError
from ..store.codec import canonical_json

LINK_DOMAIN = b"flashsmelter/attest-link/v1\n"
BODY_DOMAIN = b"flashsmelter/attest-body/v1\n"
LEAF_DOMAIN = b"flashsmelter/attest-leaf/v1\n"
NODE_DOMAIN = b"flashsmelter/attest-node/v1\n"
EMPTY_DOMAIN = b"flashsmelter/attest-empty/v1\n"
PREV_ZERO = "0" * 64
EMPTY_ROOT = hashlib.sha256(EMPTY_DOMAIN + b"empty").hexdigest()


@dataclass(frozen=True, slots=True)
class ChainLink:
    """流水某一行在核验链中的一环。"""

    seq: int
    written_at: str
    checksum: str
    link: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "written_at": self.written_at,
            "checksum": self.checksum,
            "link": self.link,
        }


def entry_body_digest(payload: Any) -> str:
    """流水条目 payload 的规范化摘要（域分隔，避免跨用途碰撞）。"""

    digest = hashlib.sha256()
    digest.update(BODY_DOMAIN)
    digest.update(canonical_json(payload).encode("utf-8"))
    return digest.hexdigest()


def link_hash(
    *,
    stream: str,
    seq: int,
    written_at: str,
    checksum: str,
    body_digest: str,
    prev: str,
) -> str:
    digest = hashlib.sha256()
    digest.update(LINK_DOMAIN)
    digest.update(stream.encode("utf-8"))
    digest.update(b"\x1f")
    digest.update(str(seq).encode("utf-8"))
    digest.update(b"\x1f")
    digest.update(written_at.encode("utf-8"))
    digest.update(b"\x1f")
    digest.update(checksum.encode("utf-8"))
    digest.update(b"\x1f")
    digest.update(body_digest.encode("ascii"))
    digest.update(b"\x1f")
    digest.update(prev.encode("utf-8"))
    return digest.hexdigest()


def build_chain(
    entries: Sequence[Mapping[str, Any]],
    *,
    stream: str,
    prev: str = PREV_ZERO,
) -> list[ChainLink]:
    """对按序号排好序的流水条目重算哈希链。

    条目必须是 ``{"seq", "written_at", "checksum", "payload"}`` 形式（原始 JSONL
    行解析结果即可）。序号必须从 ``prev`` 之后连续，否则拒算：导出时整链不完整的
    库不允许打包，核验时断链直接判失败。
    """

    links: list[ChainLink] = []
    expected_seq = 0 if prev == PREV_ZERO else None
    cursor = prev
    for entry in entries:
        try:
            seq = int(entry["seq"])
            written_at = str(entry["written_at"])
            checksum = str(entry["checksum"])
            body_digest = entry_body_digest(entry["payload"])
        except (KeyError, TypeError, ValueError) as exc:
            raise IntegrityError("流水条目缺少哈希链所需字段", details={"stream": stream}) from exc
        if expected_seq is not None and seq != expected_seq + 1:
            raise IntegrityError(
                "流水序号不连续，哈希链无法建立",
                details={"stream": stream, "expected": (expected_seq + 1), "actual": seq},
            )
        cursor = link_hash(
            stream=stream,
            seq=seq,
            written_at=written_at,
            checksum=checksum,
            body_digest=body_digest,
            prev=cursor,
        )
        links.append(ChainLink(seq=seq, written_at=written_at, checksum=checksum, link=cursor))
        expected_seq = seq
    return links


def state_leaf_hash(key: str, version: Any, written_at: Any, checksum: Any, payload: Any) -> str:
    digest = hashlib.sha256()
    digest.update(LEAF_DOMAIN)
    digest.update(key.encode("utf-8"))
    digest.update(b"\x1f")
    digest.update(str(version).encode("utf-8"))
    digest.update(b"\x1f")
    digest.update(str(written_at).encode("utf-8"))
    digest.update(b"\x1f")
    digest.update(str(checksum).encode("utf-8"))
    digest.update(b"\x1f")
    digest.update(canonical_json(payload).encode("utf-8"))
    return digest.hexdigest()


def merkle_root(leaves: Sequence[str]) -> str:
    """重复最后一个节点补齐偶数层的标准默克尔根；空集合返回固定空根。"""

    if not leaves:
        return EMPTY_ROOT
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        nxt: list[str] = []
        for index in range(0, len(level), 2):
            digest = hashlib.sha256()
            digest.update(NODE_DOMAIN)
            digest.update(level[index].encode("ascii"))
            digest.update(level[index + 1].encode("ascii"))
            nxt.append(digest.hexdigest())
        level = nxt
    return level[0]


def state_root(records: Sequence[Mapping[str, Any]]) -> str:
    """对文档库当前状态（envelope 列表）计算默克尔根。"""

    leaves = [
        state_leaf_hash(
            str(record["key"]),
            record["version"],
            record["written_at"],
            record["checksum"],
            record["payload"],
        )
        for record in sorted(records, key=lambda item: str(item["key"]))
    ]
    return merkle_root(leaves)


def digest_bytes(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def digest_text(text: str) -> str:
    return digest_bytes(text.encode("utf-8"))


def digest_json(payload: Any) -> str:
    return digest_text(canonical_json(payload))


def require_positive_range(seq_from: int, seq_to: int) -> None:
    if seq_from < 1:
        raise ValidationError("起始序号必须 >= 1", details={"seq_from": seq_from})
    if seq_to < seq_from:
        raise ValidationError(
            "结束序号不能小于起始序号",
            details={"seq_from": seq_from, "seq_to": seq_to},
        )


__all__ = [
    "ChainLink",
    "PREV_ZERO",
    "EMPTY_ROOT",
    "link_hash",
    "build_chain",
    "state_leaf_hash",
    "merkle_root",
    "state_root",
    "digest_bytes",
    "digest_text",
    "digest_json",
    "require_positive_range",
]
