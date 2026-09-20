#!/usr/bin/env python3
"""FlashSmelter 离线核验包自证脚本（零依赖，可在断网机直接运行）。

用法：
    python3 verifier.py <核验包目录或 .zip> [--pubkey trusted.pub] [--json]

它会：
  1. 用产线公钥（预置的最可信；否则退而用包内公钥并告警）校验清单签名；
  2. 逐字节核对 events.jsonl / chain.jsonl / state.jsonl 的文件哈希；
  3. 从前置锚点逐行复算 SHA-256 哈希链，精确定位首个被改动的事件序号；
  4. 复算事件段与状态快照两棵 Merkle 根并与清单比对。

退出码：0 = 全部通过；2 = 核验未通过（证据被破坏或来源不可信）；1 = 用法/读取错误。
本脚本只用 Python 标准库，不访问网络。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import zipfile
from typing import Any, Mapping, Sequence

PACK_FORMAT = "flashsmelter-verify-pack/1"
MANIFEST_NAME = "manifest.json"
SIGNATURE_NAME = "manifest.sig"
PUBLIC_NAME = "public.pub"
EVENTS_NAME = "events.jsonl"
CHAIN_NAME = "chain.jsonl"
STATE_NAME = "state.jsonl"
GENESIS_HASH = "0" * 64
LEAF_EVENT = b"FS1\x01event\x00"
LEAF_STATE = b"FS1\x01state\x00"
NODE_INTERNAL = b"FS1\x02node\x00\x00"


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def chain_hash(prev_hash: str, row_bytes: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(bytes.fromhex(prev_hash))
    digest.update(b"\x00")
    digest.update(row_bytes)
    return digest.hexdigest()


def merkle_root(leaves: Sequence[bytes]) -> str:
    if not leaves:
        return GENESIS_HASH
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        nxt = []
        for i in range(0, len(level), 2):
            d = hashlib.sha256()
            d.update(NODE_INTERNAL)
            d.update(level[i])
            d.update(level[i + 1])
            nxt.append(d.digest())
        level = nxt
    return level[0].hex()


def event_leaf(row_hash: str) -> bytes:
    d = hashlib.sha256()
    d.update(LEAF_EVENT)
    d.update(bytes.fromhex(row_hash))
    return d.digest()


def state_line_leaf(key: str, line: str) -> bytes:
    # 对 state.jsonl 整行原始字节取叶，跨语言字节透传，不重新规范化数字。
    d = hashlib.sha256()
    d.update(LEAF_STATE)
    d.update(key.encode("utf-8"))
    d.update(b"\x00")
    d.update(line.encode("utf-8"))
    return d.digest()


# --------------------------------------------------------------------- Ed25519
q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _inv(x: int) -> int:
    return pow(x, q - 2, q)


d = -121665 * _inv(121666)
I = pow(2, (q - 1) // 4, q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(d * y * y + 1)
    x = pow(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * I) % q
    if x % 2 != 0:
        x = q - x
    return x


By = 4 * _inv(5)
Bx = _xrecover(By)
B = (Bx, By, 1, (Bx * By) % q)


def _edwards(P, Q):
    # RFC 8032 参考实现的扩展坐标统一加法（不消 z），与浏览器/OpenSSL 互通。
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    A = (y1 - x1) * (y2 - x2) % q
    Bb = (y1 + x1) * (y2 + x2) % q
    C = (t1 * 2 * d * t2) % q
    Dd = (z1 * 2 * z2) % q
    E = (Bb - A) % q
    F = (Dd - C) % q
    G = (Dd + C) % q
    H = (Bb + A) % q
    return (E * F % q, G * H % q, F * G % q, E * H % q)


def _scalarmult(P, e):
    if e == 0:
        return (0, 1, 1, 0)
    Q = _scalarmult(P, e // 2)
    Q = _edwards(Q, Q)
    if e & 1:
        Q = _edwards(Q, P)
    return Q


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _encodepoint(P) -> bytes:
    x, y, z, _ = P
    zi = _inv(z)
    x = (x * zi) % q
    y = (y * zi) % q
    bits = [(y >> i) & 1 for i in range(255)] + [x & 1]
    out = bytearray(32)
    for i, bit in enumerate(bits):
        out[i // 8] |= bit << (i % 8)
    return bytes(out)


def _isoncurve(P) -> bool:
    x, y, z, t = P
    if (x * y - z * t) % q:
        return False
    return (y * y - x * x - z * z - d * t * t) % q == 0


def _decodepoint(s: bytes):
    y = sum(_bit(s, i) << i for i in range(255))
    x = _xrecover(y)
    if (x & 1) != _bit(s, 255):
        x = q - x
    P = (x, y, 1, (x * y) % q)
    if not _isoncurve(P):
        raise ValueError("点不在曲线上")
    return P


def _hint(m: bytes) -> int:
    return int.from_bytes(_H(m), "little")


def ed25519_verify(pub: bytes, message: bytes, signature: bytes) -> bool:
    try:
        if len(pub) != 32 or len(signature) != 64:
            return False
        R = _decodepoint(signature[:32])
        A = _decodepoint(pub)
        S = int.from_bytes(signature[32:], "little")
        if S >= l:
            return False
        h = _hint(_encodepoint(R) + pub + message)
        # 射影坐标同一等价点有多种表示，必须比较编码点。
        return _encodepoint(_scalarmult(B, S)) == _encodepoint(_edwards(R, _scalarmult(A, h)))
    except (ValueError, ZeroDivisionError):
        return False


# --------------------------------------------------------------------- 读取
class Pack:
    def __init__(self, location: str) -> None:
        path = os.path.abspath(location)
        if not os.path.exists(path):
            raise FileNotFoundError(path)
        if os.path.isdir(path):
            self.kind = "dir"
            self.dir = path
            self.zip = None
        else:
            self.kind = "zip"
            self.zip = zipfile.ZipFile(path)

    def read(self, name: str) -> bytes:
        if self.kind == "dir":
            with open(os.path.join(self.dir, name), "rb") as handle:
                return handle.read()
        return self.zip.read(name)

    def lines(self, name: str):
        for raw in self.read(name).decode("utf-8").splitlines():
            line = raw.strip()
            if line:
                yield line

    def close(self) -> None:
        if self.zip is not None:
            self.zip.close()


def decode_pubkey(blob: bytes) -> bytes:
    text = blob.decode("ascii").strip()
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            text = str(parsed.get("public_key", ""))
    except json.JSONDecodeError:
        pass
    raw = bytes.fromhex("".join(text.split()))
    if len(raw) != 32:
        raise ValueError("公钥必须是 32 字节")
    return raw


def fingerprint(pub: bytes) -> str:
    return sha256_hex(pub)[:16]


def compress_runs(seqs: Sequence[int]) -> str:
    if not seqs:
        return ""
    runs, start, prev = [], seqs[0], seqs[0]
    for value in seqs[1:]:
        if value == prev + 1:
            prev = value
            continue
        runs.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = value
    runs.append(str(start) if start == prev else f"{start}-{prev}")
    return ", ".join(runs)


def verify(pack: Pack, trusted_pub: bytes | None) -> dict[str, Any]:
    failures: list[str] = []
    warnings: list[str] = []
    manifest_bytes_raw = pack.read(MANIFEST_NAME)
    manifest = json.loads(manifest_bytes_raw.decode("utf-8"))
    if manifest.get("format") != PACK_FORMAT:
        failures.append(f"不支持的核验包格式：{manifest.get('format')!r}")

    embedded = None
    try:
        embedded = decode_pubkey(pack.read(PUBLIC_NAME))
    except (KeyError, ValueError) as exc:
        failures.append(f"包内公钥不可读：{exc}")
    pub = trusted_pub if trusted_pub is not None else embedded
    if trusted_pub is not None and embedded is not None and trusted_pub != embedded:
        failures.append("包内公钥与预置信任公钥不一致——来源不可信")
    if trusted_pub is None and embedded is not None:
        warnings.append("未提供 --pubkey，仅用包内公钥验签；首次使用务必线下核对指纹")
    try:
        signature = bytes.fromhex(pack.read(SIGNATURE_NAME).decode("ascii").strip())
    except KeyError:
        signature = b""
        failures.append("签名文件缺失")
    signature_ok = bool(pub) and ed25519_verify(pub, manifest_bytes_raw, signature)
    if pub is not None and signature and not signature_ok:
        failures.append("清单签名校验失败——清单可能被伪造或篡改")

    events_meta = manifest.get("events", {})
    state_meta = manifest.get("state", {})
    rng = manifest.get("range", {})
    pred = manifest.get("predecessor", {})

    for label, name, meta_hash in (
        ("events", EVENTS_NAME, events_meta.get("sha256_file")),
        ("chain", CHAIN_NAME, events_meta.get("sha256_chain_file")),
        ("state", STATE_NAME, state_meta.get("sha256_file")),
    ):
        try:
            blob = pack.read(name)
        except KeyError:
            if label == "state" and not state_meta.get("count"):
                continue
            failures.append(f"缺少文件 {name}")
            continue
        if meta_hash and sha256_hex(blob) != meta_hash:
            failures.append(f"{name} 文件哈希与清单不一致")

    rows = [(int(json.loads(line)["seq"]), line) for line in pack.lines(EVENTS_NAME)]
    anchors = [json.loads(line) for line in pack.lines(CHAIN_NAME)]
    if len(rows) != events_meta.get("count"):
        failures.append(f"事件条数不一致：文件 {len(rows)}，清单 {events_meta.get('count')}")
    if len(anchors) != len(rows):
        failures.append(f"chain.jsonl 条数（{len(anchors)}）与 events.jsonl（{len(rows)}）不一致")

    missing, duplicates, seen = [], [], set()
    prev_seq = (pred.get("seq") or (rng.get("first_seq") or 1) - 1) if rows else 0
    for seq, _ in rows:
        if seq in seen:
            duplicates.append(seq)
        seen.add(seq)
        if seq != prev_seq + 1:
            missing.extend(range(prev_seq + 1, seq))
        prev_seq = seq
    if duplicates:
        failures.append(f"出现重复序号：{duplicates[:20]}")
    if missing:
        failures.append(f"缺失 {len(missing)} 个序号：{compress_runs(missing)}")

    expected_prev = pred.get("chain_hash") or GENESIS_HASH
    leaves, previous, tampered = [], expected_prev, []
    anchor_map = {int(a["seq"]): a for a in anchors}
    for seq, line in rows:
        current = chain_hash(previous, line.encode("utf-8"))
        leaves.append(event_leaf(current))
        anchor = anchor_map.get(seq, {})
        if anchor.get("prev_hash") != previous or anchor.get("chain_hash") != current:
            tampered.append(seq)
        previous = current
    if events_meta.get("chain_tip") and previous != events_meta["chain_tip"]:
        failures.append(
            "事件哈希链与清单链尖不一致；首个异常序号：" + (str(tampered[0]) if tampered else str(rng.get("first_seq")))
        )
    if events_meta.get("merkle_root") and merkle_root(leaves) != events_meta["merkle_root"]:
        failures.append("事件 Merkle 根与清单不一致——事件段被改动或替换")

    state_leaves, state_count = [], 0
    for line in pack.lines(STATE_NAME):
        state_count += 1
        try:
            parsed = json.loads(line)
            key = str(parsed["key"])
        except (json.JSONDecodeError, KeyError) as exc:
            failures.append(f"state.jsonl 第 {state_count} 行不合法：{exc}")
            continue
        state_leaves.append(state_line_leaf(key, line))
    if state_count != state_meta.get("count"):
        failures.append(f"状态条数不一致：文件 {state_count}，清单 {state_meta.get('count')}")
    if state_meta.get("merkle_root") and merkle_root(state_leaves) != state_meta["merkle_root"]:
        failures.append("状态 Merkle 根与清单不一致——状态快照被改动或替换")

    self_check = manifest.get("self_check", {})
    if not self_check.get("ok", True):
        warnings.append("导出方申报：导出时现网自校验已有问题 " + json.dumps(self_check.get("problems", []), ensure_ascii=False))

    return {
        "ok": not failures,
        "signature_ok": signature_ok,
        "trusted_key": trusted_pub is not None,
        "signer_fingerprint": manifest.get("signer_fingerprint"),
        "created_at": manifest.get("created_at"),
        "namespace": manifest.get("namespace"),
        "range": rng,
        "predecessor": pred,
        "events": {
            "count": len(rows),
            "missing_seqs": missing,
            "tampered_seqs": tampered,
            "first_tampered_seq": tampered[0] if tampered else None,
            "chain_tip": previous if rows else events_meta.get("chain_tip"),
        },
        "state": {"count": state_count},
        "failures": failures,
        "warnings": warnings,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="FlashSmelter 离线核验包自证（零依赖、不联网）")
    parser.add_argument("pack", help="核验包目录或 .zip 路径")
    parser.add_argument("--pubkey", help="预置信任公钥文件（.pub）；不给则用包内公钥并告警")
    parser.add_argument("--json", action="store_true", help="只输出 JSON 结论")
    args = parser.parse_args(argv)

    trusted = None
    if args.pubkey:
        try:
            with open(args.pubkey, "rb") as handle:
                trusted = decode_pubkey(handle.read())
        except (OSError, ValueError) as exc:
            print(f"信任公钥读取失败：{exc}", file=sys.stderr)
            return 1

    pack = None
    try:
        pack = Pack(args.pack)
        report = verify(pack, trusted)
    except FileNotFoundError as exc:
        print(f"核验包不存在：{exc}", file=sys.stderr)
        return 1
    except (zipfile.BadZipFile, json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        print(f"核验包无法读取：{exc}", file=sys.stderr)
        return 1
    finally:
        if pack is not None:
            pack.close()

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        status = "通过 ✅" if report["ok"] else "未通过 ❌"
        print(f"核验结论：{status}")
        print(f"签名有效：{'是' if report['signature_ok'] else '否'}"
              f"（信任公钥：{'预置' if report['trusted_key'] else '包内，需线下核对'}）")
        print(f"签名指纹：{report['signer_fingerprint']}")
        print(f"命名空间：{report['namespace']}    导出时间：{report['created_at']}")
        ev = report["events"]
        rng = report["range"] or {}
        print(f"事件范围：{rng.get('first_seq')}–{rng.get('last_seq')}，共 {ev['count']} 条")
        if ev["missing_seqs"]:
            print(f"  缺失序号：{compress_runs(ev['missing_seqs'])}")
        if ev["first_tampered_seq"]:
            print(f"  首个被改动序号：{ev['first_tampered_seq']}（其后链哈希全部连锁失效）")
        print(f"状态快照：{report['state']['count']} 条")
        for warning in report["warnings"]:
            print(f"[警告] {warning}")
        for failure in report["failures"]:
            print(f"[失败] {failure}")
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    sys.exit(main())
