"""离线核验包：导出、离线自验、回线上对账。

一个核验包（目录或 zip）包含：

==================  =====================================================
``manifest.json``   清单（规范 JSON），所有完整性结论的签名对象
``manifest.sig``    产线私钥对清单字节的 Ed25519 签名（hex）
``public.pub``      对应公钥，便于离线机现场取得（首次仍须线下核对指纹）
``events.jsonl``    审计流水导出段，**逐行原始字节**
``chain.jsonl``    导出段每条事件的 prev/chain_hash（旁路锚点，覆盖在
                   Merkle 根内），用于在离线时把断链精确定位到序号
``state.jsonl``     导出时刻的状态快照（每条落盘信封）
``verifier.py``     零依赖离线核验脚本，拷到断网机直接 ``python3`` 运行
``verifier.html``   浏览器核验页（Web Crypto 验签，无服务器）
``README.txt``      车间使用说明
==================  =====================================================

证据模型：

1. 事件段每一行 ``chain_hash = SHA256(prev_hash || 行字节)``，段首锚住流水里
   它前一行的链哈希（*predecessor*）。改一个字节→该行及之后全断；删一段→
   序号不连续且锚点对不上；截断导出段→回线上对锚点立刻暴露。
2. 事件段与状态快照各压一棵 Merkle 树，根连同文件哈希、范围、时间戳写进清单；
   清单由产线 Ed25519 私钥签名。离线机凭预置公钥确认「导出当时确实如此」。
3. 回线上 :func:`reconcile_pack` 把包里的原始行/信封与当前落盘数据逐条比对，
   直接指出改动位置、字段差异、缺号与插入号。
"""

from __future__ import annotations

import json
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

from ..errors import FlashSmelterError, IntegrityError, NotFoundError, ValidationError
from ..ns import Namespace
from ..runtime import Clock
from ..store import DurableStore
from ..store.codec import canonical_json
from . import ed25519
from .chain import (
    GENESIS_HASH,
    chain_hash,
    event_leaf,
    manifest_bytes,
    merkle_root,
    sha256_hex,
    state_line_leaf,
)
from .keychain import SigningIdentity, fingerprint, public_key_text
from .streams import AUDIT_STREAM

PACK_FORMAT = "flashsmelter-verify-pack/1"
MANIFEST_NAME = "manifest.json"
SIGNATURE_NAME = "manifest.sig"
PUBLIC_NAME = "public.pub"
EVENTS_NAME = "events.jsonl"
CHAIN_NAME = "chain.jsonl"
STATE_NAME = "state.jsonl"
STANDALONE_VERIFIER = "verifier.py"
HTML_VERIFIER = "verifier.html"
README_NAME = "README.txt"
ASSETS = (STANDALONE_VERIFIER, HTML_VERIFIER)

PACK_FILES = (
    MANIFEST_NAME,
    SIGNATURE_NAME,
    PUBLIC_NAME,
    EVENTS_NAME,
    CHAIN_NAME,
    STATE_NAME,
    STANDALONE_VERIFIER,
    HTML_VERIFIER,
    README_NAME,
)


class PackError(FlashSmelterError):
    """核验包结构或证据不合法。"""

    code = "verify-pack-error"
    status = 400


# --------------------------------------------------------------------- 读取
class PackReader:
    """统一读取目录形态与 zip 形态的核验包。"""

    def __init__(self, location: Path | str) -> None:
        self.location = Path(location)
        if not self.location.exists():
            raise NotFoundError("核验包不存在", details={"path": str(self.location)})
        self.is_zip = self.location.is_file()
        if self.is_zip and self.location.suffix != ".zip":
            raise PackError("文件形态的核验包必须是 .zip", details={"path": str(self.location)})
        if self.is_zip:
            try:
                self._zip = zipfile.ZipFile(self.location)
            except zipfile.BadZipFile as exc:
                raise PackError("核验包 zip 无法打开", details={"path": str(self.location)}) from exc
            self._names = set(self._zip.namelist())
        else:
            self._zip = None
            self._names = {path.name for path in self.location.iterdir() if path.is_file()}

    def close(self) -> None:
        if self._zip is not None:
            self._zip.close()

    def __enter__(self) -> "PackReader":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def has(self, name: str) -> bool:
        return name in self._names

    def read_bytes(self, name: str) -> bytes:
        if name not in self._names:
            raise PackError("核验包缺少文件", details={"missing": name})
        if self._zip is not None:
            return self._zip.read(name)
        return (self.location / name).read_bytes()

    def read_text(self, name: str) -> str:
        return self.read_bytes(name).decode("utf-8")

    def read_manifest(self) -> dict[str, Any]:
        try:
            parsed = json.loads(self.read_text(MANIFEST_NAME))
        except (PackError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PackError("清单无法解析") from exc
        if not isinstance(parsed, dict):
            raise PackError("清单必须是 JSON 对象")
        return parsed

    def jsonl(self, name: str) -> Iterator[tuple[int, str]]:
        text = self.read_text(name)
        for line_number, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if line:
                yield line_number, line


# --------------------------------------------------------------------- 导出
@dataclass(frozen=True, slots=True)
class ExportResult:
    path: Path
    manifest: Mapping[str, Any]
    event_count: int
    state_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "event_count": self.event_count,
            "state_count": self.state_count,
            "manifest": dict(self.manifest),
        }


def export_pack(
    store: DurableStore,
    namespace: Namespace,
    clock: Clock,
    identity: SigningIdentity,
    out_dir: Path | str,
    *,
    since_seq: int = 0,
    state_prefix: str = "",
    allow_inconsistent: bool = False,
    zip_pack: bool = False,
    assets_dir: Path | str | None = None,
) -> ExportResult:
    """导出当前状态与一段流水，签名后写成自证核验包。

    导出前会先跑整库自校验：现网数据自身校验和都对不上时，默认拒绝导出，
    避免把已经损坏的数据签成「正常快照」；确有需要可用
    ``allow_inconsistent`` 强制导出，问题会如实写进清单。
    """

    if since_seq < 0:
        raise ValidationError("since 不能为负", details={"since": since_seq})

    report = store.verify()
    self_problems = list(report.problems)
    if self_problems and not allow_inconsistent:
        raise IntegrityError(
            "现网落盘数据自校验未通过，拒绝签名导出；如确需导出请显式允许",
            details={"problems": self_problems},
        )

    rows = store.read_stream_raw(AUDIT_STREAM, since_seq=since_seq)
    if not rows:
        raise ValidationError("指定区间内没有审计流水可导出", details={"since_seq": since_seq})

    # 前置锚点：把整段流水从创世复算到导出段之前一行，拿到它的链哈希。
    first_seq = rows[0].seq
    predecessor = store.predecessor_raw(AUDIT_STREAM, first_seq)
    if predecessor is not None:
        anchor_rows = store.read_stream_raw(AUDIT_STREAM, max_seq=predecessor.seq)
        previous = GENESIS_HASH
        for anchor in anchor_rows:
            previous = chain_hash(previous, anchor.raw_line.encode("utf-8"))
        pred_seq: int | None = predecessor.seq
        pred_hash: str | None = previous
        start_prev = previous
    else:
        pred_seq = None
        pred_hash = GENESIS_HASH
        start_prev = GENESIS_HASH

    # 导出段自身的链与 Merkle 叶（叶哈希即逐行链哈希）。
    leaves: list[bytes] = []
    chain_lines: list[str] = []
    previous = start_prev
    for row in rows:
        prev_hash = previous
        previous = chain_hash(previous, row.raw_line.encode("utf-8"))
        leaves.append(event_leaf(previous))
        chain_lines.append(canonical_json({"seq": row.seq, "prev_hash": prev_hash, "chain_hash": previous}))
    chain_tip = previous
    event_merkle = merkle_root(leaves)
    events_blob = ("\n".join(row.raw_line for row in rows) + "\n").encode("utf-8")
    chain_blob = ("\n".join(chain_lines) + "\n").encode("utf-8")

    # 状态快照：取命名空间下全部（或指定前缀）落盘文档的信封。
    # state.jsonl 每行都是规范 JSON；Merkle 叶直接对**整行原始字节**取哈希，
    # 各核验端字节透传即可，不依赖任何语言的数字规范化。
    prefix = namespace.prefix + "/" + state_prefix.lstrip("/") if state_prefix else namespace.prefix + "/"
    keys = [key for key in store.list_keys() if key.startswith(prefix)]
    state_leaves: list[bytes] = []
    state_lines: list[str] = []
    for key in keys:
        raw = store.read_record_raw(key)
        if raw is None:  # pragma: no cover - 列表来自同一目录
            continue
        _, envelope_bytes = raw
        envelope = json.loads(envelope_bytes.decode("utf-8"))
        line = canonical_json({"key": key, "envelope": envelope})
        state_lines.append(line)
        state_leaves.append(state_line_leaf(key, line.encode("utf-8")))
    state_merkle = merkle_root(state_leaves)
    state_blob = ("\n".join(state_lines) + "\n").encode("utf-8") if state_lines else b""

    public = identity.public()
    seed = identity.secret()
    manifest: dict[str, Any] = {
        "format": PACK_FORMAT,
        "key_id": identity.key_id,
        "signer_fingerprint": fingerprint(public),
        "created_at": clock.timestamp_iso(),
        "namespace": namespace.prefix,
        "stream": AUDIT_STREAM,
        "range": {"first_seq": first_seq, "last_seq": rows[-1].seq, "count": len(rows)},
        "predecessor": {"seq": pred_seq, "chain_hash": pred_hash},
        "events": {
            "count": len(rows),
            "chain_tip": chain_tip,
            "merkle_root": event_merkle,
            "sha256_file": sha256_hex(events_blob),
            "sha256_chain_file": sha256_hex(chain_blob),
        },
        "state": {
            "count": len(keys),
            "merkle_root": state_merkle,
            "sha256_file": sha256_hex(state_blob),
            "as_of_seq": rows[-1].seq,
        },
        "self_check": {"ok": not self_problems, "problems": self_problems},
    }
    signature = ed25519.sign(seed, manifest_bytes(manifest))

    target = Path(out_dir)
    if zip_pack:
        target.parent.mkdir(parents=True, exist_ok=True)
        _write_zip(
            target,
            manifest,
            signature,
            public,
            events_blob,
            chain_blob,
            state_blob,
            assets_dir=assets_dir,
        )
    else:
        target.mkdir(parents=True, exist_ok=True)
        _write_dir(
            target,
            manifest,
            signature,
            public,
            events_blob,
            chain_blob,
            state_blob,
            assets_dir=assets_dir,
        )
    return ExportResult(
        path=target,
        manifest=manifest,
        event_count=len(rows),
        state_count=len(keys),
    )


def _write_dir(
    target: Path,
    manifest: Mapping[str, Any],
    signature: bytes,
    public: bytes,
    events_blob: bytes,
    chain_blob: bytes,
    state_blob: bytes,
    *,
    assets_dir: Path | str | None,
) -> None:
    (target / MANIFEST_NAME).write_bytes(manifest_bytes(manifest))
    (target / SIGNATURE_NAME).write_text(signature.hex() + "\n", encoding="ascii")
    (target / PUBLIC_NAME).write_text(public_key_text(public, key_id=str(manifest["key_id"])), encoding="ascii")
    (target / EVENTS_NAME).write_bytes(events_blob)
    (target / CHAIN_NAME).write_bytes(chain_blob)
    (target / STATE_NAME).write_bytes(state_blob)
    _copy_assets(target, assets_dir)
    (target / README_NAME).write_text(readme_text(manifest), encoding="utf-8")


def _write_zip(
    target: Path,
    manifest: Mapping[str, Any],
    signature: bytes,
    public: bytes,
    events_blob: bytes,
    chain_blob: bytes,
    state_blob: bytes,
    *,
    assets_dir: Path | str | None,
) -> None:
    assets = _load_assets(assets_dir)
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(MANIFEST_NAME, manifest_bytes(manifest))
        archive.writestr(SIGNATURE_NAME, signature.hex() + "\n")
        archive.writestr(PUBLIC_NAME, public_key_text(public, key_id=str(manifest["key_id"])))
        archive.writestr(EVENTS_NAME, events_blob)
        archive.writestr(CHAIN_NAME, chain_blob)
        archive.writestr(STATE_NAME, state_blob)
        for name, blob in assets.items():
            archive.writestr(name, blob)
        archive.writestr(README_NAME, readme_text(manifest))


def _load_assets(assets_dir: Path | str | None) -> dict[str, bytes]:
    base = Path(assets_dir) if assets_dir else Path(__file__).parent / "assets"
    assets: dict[str, bytes] = {}
    for name in ASSETS:
        path = base / name
        if not path.exists():
            raise NotFoundError("离线核验资源缺失", details={"path": str(path)})
        assets[name] = path.read_bytes()
    return assets


def _copy_assets(target: Path, assets_dir: Path | str | None) -> None:
    for name, blob in _load_assets(assets_dir).items():
        (target / name).write_bytes(blob)


def readme_text(manifest: Mapping[str, Any]) -> str:
    rng = manifest["range"]
    return f"""FlashSmelter 离线核验包
=======================

导出时间（UTC）：{manifest['created_at']}
命名空间       ：{manifest['namespace']}
流水范围       ：审计流水第 {rng['first_seq']} – {rng['last_seq']} 条（共 {rng['count']} 条）
签名公钥指纹   ：{manifest['signer_fingerprint']}
密钥标识       ：{manifest['key_id']}

车间断网时怎么看
----------------
1. 图形界面：双击打开 verifier.html，把本目录（或本 zip）整个选进去；
   首次使用请在页面里录入/核对信任公钥指纹：{manifest['signer_fingerprint']}。
2. 命令行：  python3 verifier.py <本目录或zip路径>
   （verifier.py 只用 Python 标准库，不需要安装任何东西；也不联网。）

只有“签名有效”且“链与 Merkle 根全部通过”，才能证明导出当时的数据没被动过。
回线上后由控制系统执行 reconcile 子命令逐条对账，会直接列出被改条目、
缺失序号、插入序号与状态字段差异。
"""


# --------------------------------------------------------------------- 验包
def _event_payloads(reader: PackReader) -> list[tuple[int, str]]:
    rows: list[tuple[int, str]] = []
    for _, line in reader.jsonl(EVENTS_NAME):
        seq = int(json.loads(line).get("seq", 0))
        rows.append((seq, line))
    return rows


def verify_pack(reader: PackReader, *, trusted_pubkey: bytes | None = None) -> dict[str, Any]:
    """离线自验：签名、文件哈希、事件哈希链、序号连续性、两棵 Merkle 根。"""

    failures: list[str] = []
    warnings: list[str] = []
    manifest = reader.read_manifest()

    if manifest.get("format") != PACK_FORMAT:
        failures.append(f"不支持的核验包格式：{manifest.get('format')!r}")

    # 1) 公钥与签名
    try:
        embedded = _embedded_pubkey(reader)
    except PackError as exc:
        embedded = None
        failures.append(exc.message)
    pubkey = trusted_pubkey if trusted_pubkey is not None else embedded
    if pubkey is not None and embedded is not None and trusted_pubkey is not None and pubkey != embedded:
        failures.append("包内公钥与预置信任公钥不一致——包的来源不可信")
    if trusted_pubkey is None and embedded is not None:
        warnings.append("未预置信任公钥，本次仅用包内公钥验签；首次使用必须线下核对指纹")
    signature: bytes | None = None
    try:
        signature = bytes.fromhex(reader.read_text(SIGNATURE_NAME).strip())
    except (PackError, ValueError):
        failures.append("签名文件缺失或不是十六进制")
    signature_ok = False
    if pubkey is not None and signature is not None:
        signature_ok = ed25519.verify(pubkey, manifest_bytes(manifest), signature)
        if not signature_ok:
            failures.append("清单签名校验失败——清单可能被伪造或篡改")

    # 2) 文件哈希
    events_meta = manifest.get("events", {})
    state_meta = manifest.get("state", {})
    file_hashes = {"events": (EVENTS_NAME, events_meta.get("sha256_file")),
                   "chain": (CHAIN_NAME, events_meta.get("sha256_chain_file")),
                   "state": (STATE_NAME, state_meta.get("sha256_file"))}
    actual_file_hashes: dict[str, str] = {}
    for label, (name, expected_hash) in file_hashes.items():
        try:
            actual_file_hashes[label] = sha256_hex(reader.read_bytes(name))
        except PackError as exc:
            actual_file_hashes[label] = ""
            if not (label == "state" and state_meta.get("count", 0) == 0):
                failures.append(exc.message)
        if label != "state" or state_meta.get("count", 0):
            if expected_hash and actual_file_hashes[label] and actual_file_hashes[label] != expected_hash:
                failures.append(f"{name} 与清单记录的文件哈希不一致")

    # 3) 事件链：序号连续 + 从前置锚点逐行复算 + 链尖与 Merkle 根
    event_results = _verify_events(reader, manifest)
    failures.extend(event_results.pop("failures"))

    # 4) 状态 Merkle 根
    state_results = _verify_state(reader, manifest)
    failures.extend(state_results.pop("failures"))

    # 5) 导出时的现网自检结论（仅提示：是导出方主动申报的）
    self_check = manifest.get("self_check", {})
    if not self_check.get("ok", True):
        warnings.append("导出方申报：导出时现网数据自校验已存在问题：" + json.dumps(self_check.get("problems", []), ensure_ascii=False))

    return {
        "ok": not failures,
        "signature_ok": signature_ok,
        "trusted_key": trusted_pubkey is not None,
        "signer_fingerprint": manifest.get("signer_fingerprint"),
        "created_at": manifest.get("created_at"),
        "namespace": manifest.get("namespace"),
        "range": manifest.get("range"),
        "predecessor": manifest.get("predecessor"),
        "events": event_results,
        "state": state_results,
        "failures": failures,
        "warnings": warnings,
    }


def _embedded_pubkey(reader: PackReader) -> bytes:
    from .keychain import load_public_key
    import tempfile

    blob = reader.read_bytes(PUBLIC_NAME)
    temporary = tempfile.NamedTemporaryFile(suffix=".pub", delete=False)
    try:
        temporary.write(blob)
        temporary.close()
        return load_public_key(temporary.name)
    finally:
        Path(temporary.name).unlink(missing_ok=True)


def _verify_events(reader: PackReader, manifest: Mapping[str, Any]) -> dict[str, Any]:
    failures: list[str] = []
    meta = manifest.get("events", {})
    rng = manifest.get("range", {})
    pred = manifest.get("predecessor", {})
    try:
        rows = _event_payloads(reader)
        anchors = _read_chain(reader)
    except PackError as exc:
        return {"failures": [exc.message], "count": 0}
    except (ValueError, json.JSONDecodeError) as exc:
        return {"failures": [f"events.jsonl/chain.jsonl 存在无法解析的行：{exc}"], "count": 0}

    if len(rows) != meta.get("count") or len(rows) != rng.get("count"):
        failures.append(f"事件条数不一致：文件 {len(rows)} 行，清单记录 {meta.get('count')} 行")
    if len(anchors) != len(rows):
        failures.append(f"chain.jsonl 条数（{len(anchors)}）与 events.jsonl（{len(rows)}）不一致")

    first_seq = rng.get("first_seq")
    last_seq = rng.get("last_seq")
    if rows and (rows[0][0] != first_seq or rows[-1][0] != last_seq):
        failures.append(
            f"事件范围不一致：文件为 {rows[0][0] if rows else '-'}–{rows[-1][0] if rows else '-'}，"
            f"清单为 {first_seq}–{last_seq}"
        )

    missing_seqs: list[int] = []
    duplicates: list[int] = []
    seen: set[int] = set()
    previous_seq = (pred.get("seq") or (first_seq or 1) - 1) if rows else 0
    for seq, _ in rows:
        if seq in seen:
            duplicates.append(seq)
        seen.add(seq)
        if seq != previous_seq + 1:
            missing_seqs.extend(range(previous_seq + 1, seq))
        previous_seq = seq
    if duplicates:
        failures.append(f"事件段内出现重复序号：{duplicates[:20]}")
    if missing_seqs:
        failures.append(f"事件段缺失 {len(missing_seqs)} 个序号：{_compress_runs(missing_seqs)}")

    # 逐行复算并与 chain.jsonl 里的旁路锚点对照，精确定位首个被改动的行。
    expected_prev = pred.get("chain_hash") if pred.get("chain_hash") else GENESIS_HASH
    leaves: list[bytes] = []
    previous = expected_prev
    tampered_seqs: list[int] = []
    anchor_map = {anchor["seq"]: anchor for anchor in anchors}
    for index, (seq, line) in enumerate(rows):
        current = chain_hash(previous, line.encode("utf-8"))
        leaves.append(event_leaf(current))
        anchor = anchor_map.get(seq, {})
        if anchor.get("prev_hash") != previous or anchor.get("chain_hash") != current:
            tampered_seqs.append(seq)
        previous = current
    tip = previous
    if meta.get("chain_tip") and tip != meta["chain_tip"]:
        failures.append(
            "事件哈希链与清单链尖不一致；首个异常序号："
            + (str(tampered_seqs[0]) if tampered_seqs else str(first_seq))
        )
    elif tampered_seqs:
        failures.append(f"旁路链锚点与重算结果不一致，异常序号：{tampered_seqs[:20]}")

    root = merkle_root(leaves)
    if meta.get("merkle_root") and root != meta["merkle_root"]:
        failures.append("事件 Merkle 根与清单不一致——事件段已被改动或替换")

    return {
        "failures": failures,
        "count": len(rows),
        "first_seq": rows[0][0] if rows else None,
        "last_seq": rows[-1][0] if rows else None,
        "chain_tip": tip,
        "merkle_root": root,
        "missing_seqs": missing_seqs,
        "tampered_seqs": tampered_seqs,
        "first_tampered_seq": tampered_seqs[0] if tampered_seqs else None,
    }


def _read_chain(reader: PackReader) -> list[dict[str, Any]]:
    anchors: list[dict[str, Any]] = []
    for _, line in reader.jsonl(CHAIN_NAME):
        parsed = json.loads(line)
        anchors.append({"seq": int(parsed["seq"]), "prev_hash": parsed["prev_hash"], "chain_hash": parsed["chain_hash"]})
    return anchors


def _verify_state(reader: PackReader, manifest: Mapping[str, Any]) -> dict[str, Any]:
    failures: list[str] = []
    meta = manifest.get("state", {})
    leaves: list[bytes] = []
    keys: list[str] = []
    count = 0
    if meta.get("count", 0) == 0:
        return {"failures": [], "count": 0, "merkle_root": GENESIS_HASH, "keys": []}
    try:
        iterator = list(reader.jsonl(STATE_NAME))
    except PackError as exc:
        return {"failures": [exc.message], "count": 0, "merkle_root": "", "keys": []}
    for _, line in iterator:
        count += 1
        try:
            parsed = json.loads(line)
            key = str(parsed["key"])
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            failures.append(f"state.jsonl 第 {count} 行结构不合法：{exc}")
            continue
        keys.append(key)
        leaves.append(state_line_leaf(key, line.encode("utf-8")))
    if count != meta.get("count"):
        failures.append(f"状态条数不一致：文件 {count} 条，清单记录 {meta.get('count')} 条")
    root = merkle_root(leaves)
    if root != meta.get("merkle_root"):
        failures.append("状态 Merkle 根与清单不一致——状态快照已被改动或替换")
    return {"failures": failures, "count": count, "merkle_root": root, "keys": sorted(keys)}


def _compress_runs(seqs: Sequence[int]) -> str:
    if not seqs:
        return ""
    runs: list[str] = []
    start = prev = seqs[0]
    for value in seqs[1:]:
        if value == prev + 1:
            prev = value
            continue
        runs.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = value
    runs.append(str(start) if start == prev else f"{start}-{prev}")
    return ", ".join(runs)


# --------------------------------------------------------------------- 对账
def reconcile_pack(
    reader: PackReader,
    store: DurableStore,
    namespace: Namespace,
    *,
    trusted_pubkey: bytes | None = None,
) -> dict[str, Any]:
    """回线上把核验包逐条对回当前落盘数据。

    结论分类：

    * ``missing``  包里有、线上没有（被删除/缺段）；
    * ``inserted`` 区间内线上多出来、包里没有（事后插入）；
    * ``altered``  同序号原始行不一致；其中线上自校验和失效记 ``live-corrupt``，
      自校验和仍有效记 ``live-rewritten``（改完重算了校验和，哈希链仍能抓到）；
    * 状态：``state-changed`` / ``state-deleted`` / ``state-added``。
    """

    verification = verify_pack(reader, trusted_pubkey=trusted_pubkey)
    failures: list[str] = []
    if not verification["ok"]:
        failures.append("核验包自身未通过校验，拒绝以它为基准对账")
        return {"verdict": "pack-invalid", "ok": False, "verify": verification, "failures": failures}

    manifest = reader.read_manifest()
    if manifest.get("namespace") != namespace.prefix:
        failures.append(
            f"命名空间不匹配：包来自 {manifest.get('namespace')}，当前是 {namespace.prefix}"
        )
        return {"verdict": "pack-invalid", "ok": False, "verify": verification, "failures": failures}

    rng = manifest["range"]
    first_seq, last_seq = int(rng["first_seq"]), int(rng["last_seq"])
    pack_rows = {seq: line for seq, line in _event_payloads(reader)}

    live_entries = store.read_stream_raw(AUDIT_STREAM, since_seq=0, max_seq=last_seq)
    # 区间内插入会造成同一 seq 出现多次（重号），必须显式抓出，不能被 dict 静默覆盖。
    seen_live: set[int] = set()
    duplicate_seqs: list[int] = []
    live_rows: dict[int, Any] = {}
    for entry in live_entries:
        if entry.seq in seen_live and entry.seq not in duplicate_seqs:
            duplicate_seqs.append(entry.seq)
        seen_live.add(entry.seq)
        live_rows[entry.seq] = entry

    missing: list[int] = []
    altered: list[dict[str, Any]] = []
    for seq in range(first_seq, last_seq + 1):
        packed = pack_rows.get(seq)
        live = live_rows.get(seq)
        if packed is None:
            continue  # 包内缺号已在 verify_pack 阶段报告
        if live is None:
            missing.append(seq)
            continue
        if live.raw_line != packed:
            altered.append(_classify_event_diff(seq, packed, live.raw_line))
    inserted = sorted(seq for seq in live_rows if first_seq <= seq <= last_seq and seq not in pack_rows)

    # 前置锚点：线上锚点行必须还在，且从创世复算出的链哈希与清单一致。
    anchor = _check_anchor(store, manifest)

    # 线上全链复算：给出第一个链断裂位置（无论是否落在导出区间）。
    chain_status = _live_chain_status(store)

    events_ok = (
        not missing and not altered and not inserted and not duplicate_seqs
        and anchor["ok"] and chain_status["ok"]
    )

    state_diff = _reconcile_state(reader, store, namespace)
    state_ok = not state_diff["changed"] and not state_diff["deleted"] and not state_diff["added"]

    if events_ok and state_ok and chain_status["ok"]:
        verdict = "ok"
    elif not chain_status["ok"]:
        verdict = "journal-tampered"
    else:
        verdict = "mismatch"

    return {
        "verdict": verdict,
        "ok": verdict == "ok",
        "verify": {"ok": True, "signer_fingerprint": verification["signer_fingerprint"]},
        "range": {"first_seq": first_seq, "last_seq": last_seq},
        "events": {
            "ok": events_ok,
            "missing_seqs": missing,
            "missing_runs": _compress_runs(missing),
            "inserted_seqs": inserted,
            "duplicate_seqs": duplicate_seqs,
            "altered": altered,
        },
        "anchor": anchor,
        "live_chain": chain_status,
        "state": state_diff,
        "failures": failures,
    }


def _check_anchor(store: DurableStore, manifest: Mapping[str, Any]) -> dict[str, Any]:
    pred = manifest.get("predecessor") or {}
    pred_seq = pred.get("seq")
    if pred_seq is None:
        return {"ok": True, "seq": None, "note": "导出段从流水第 1 条开始，无前置锚点"}
    rows = store.read_stream_raw(AUDIT_STREAM, max_seq=int(pred_seq))
    if not rows or rows[-1].seq != pred_seq:
        return {"ok": False, "seq": pred_seq, "reason": "线上已找不到导出段的前置锚点行——早期流水被删改过"}
    previous = GENESIS_HASH
    for row in rows:
        previous = chain_hash(previous, row.raw_line.encode("utf-8"))
    if previous != pred.get("chain_hash"):
        return {"ok": False, "seq": pred_seq, "reason": "前置锚点链哈希不一致——锚点之前的流水已被改写"}
    return {"ok": True, "seq": pred_seq, "chain_hash": previous}


def _live_chain_status(store: DurableStore) -> dict[str, Any]:
    """从创世逐行复算线上审计流水，并顺带核对每行自校验和。"""

    from ..store.codec import checksum_of

    previous = GENESIS_HASH
    last_seq = 0
    checksum_bad: list[int] = []
    chain_broken_at: int | None = None
    expected_seq = 0
    gap_after: int | None = None
    for row in store.read_stream_raw(AUDIT_STREAM):
        try:
            parsed = json.loads(row.raw_line)
            written_at = str(parsed.get("written_at", ""))
            if checksum_of(row.seq, written_at, parsed.get("payload", {})) != parsed.get("checksum"):
                checksum_bad.append(row.seq)
        except (json.JSONDecodeError, KeyError, TypeError):
            checksum_bad.append(row.seq)
        if chain_broken_at is None:
            current = chain_hash(previous, row.raw_line.encode("utf-8"))
            previous = current
        expected_seq += 1
        if gap_after is None and row.seq != expected_seq:
            gap_after = expected_seq
        last_seq = row.seq
    return {
        "ok": chain_broken_at is None and not checksum_bad and gap_after is None,
        "tip": previous,
        "last_seq": last_seq,
        "self_checksum_bad_seqs": checksum_bad[:50],
        "first_gap_after": gap_after,
        "note": "自校验和失效=直接破坏；自校验和正常但包对账失败=改后重算，哈希链仍可定位",
    }


def _classify_event_diff(seq: int, packed_line: str, live_line: str) -> dict[str, Any]:
    from ..store.codec import checksum_of

    packed = json.loads(packed_line)
    live = json.loads(live_line)
    live_self_ok = True
    try:
        live_self_ok = checksum_of(seq, str(live.get("written_at", "")), live.get("payload", {})) == live.get("checksum")
    except (KeyError, TypeError):
        live_self_ok = False
    return {
        "seq": seq,
        "kind": "live-corrupt" if not live_self_ok else "live-rewritten",
        "packed_written_at": packed.get("written_at"),
        "live_written_at": live.get("written_at"),
        "payload_changes": _leaf_diff(packed.get("payload"), live.get("payload")),
    }


def _reconcile_state(reader: PackReader, store: DurableStore, namespace: Namespace) -> dict[str, Any]:
    manifest = reader.read_manifest()
    meta = manifest.get("state", {})
    packed: dict[str, dict[str, Any]] = {}
    for _, line in reader.jsonl(STATE_NAME):
        parsed = json.loads(line)
        packed[str(parsed["key"])] = parsed["envelope"]

    prefix = namespace.prefix + "/"
    live_keys = [key for key in store.list_keys() if key.startswith(prefix)]
    changed: list[dict[str, Any]] = []
    deleted: list[str] = []
    leaves: list[bytes] = []
    for key, envelope in packed.items():
        raw = store.read_record_raw(key)
        if raw is None:
            deleted.append(key)
            continue
        live_envelope = json.loads(raw[1].decode("utf-8"))
        leaves.append(state_line_leaf(key, canonical_json({"key": key, "envelope": live_envelope}).encode("utf-8")))
        if canonical_json(live_envelope) != canonical_json(envelope):
            changed.append(
                {
                    "key": key,
                    "packed_version": envelope.get("version"),
                    "live_version": live_envelope.get("version"),
                    "payload_changes": _leaf_diff(envelope.get("payload"), live_envelope.get("payload")),
                }
            )
    added = sorted(key for key in live_keys if key not in packed)
    current_root = merkle_root(
        leaves + [state_line_leaf(k, _canonical_state_line(store, k)) for k in added]
    )
    return {
        "ok": not changed and not deleted and not added,
        "packed_count": meta.get("count"),
        "live_count": len(live_keys),
        "packed_merkle_root": meta.get("merkle_root"),
        "live_merkle_root": current_root,
        "changed": changed,
        "deleted": sorted(deleted),
        "added": added,
    }


def _canonical_state_line(store: DurableStore, key: str) -> bytes:
    raw = store.read_record_raw(key)
    if raw is None:  # pragma: no cover
        return b""
    envelope = json.loads(raw[1].decode("utf-8"))
    return canonical_json({"key": key, "envelope": envelope}).encode("utf-8")


def _leaf_diff(left: Any, right: Any, *, path: str = "") -> dict[str, Any]:
    """递归输出叶子级差异：``{字段路径: {"packed": 旧值, "live": 新值}}``。"""

    changes: dict[str, Any] = {}
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        for key in sorted(set(left) | set(right)):
            sub = f"{path}.{key}" if path else str(key)
            if key not in left:
                changes[sub] = {"packed": None, "live": right[key]}
            elif key not in right:
                changes[sub] = {"packed": left[key], "live": None}
            else:
                changes.update(_leaf_diff(left[key], right[key], path=sub))
    elif left != right:
        changes[path or "$"] = {"packed": left, "live": right}
    return changes


__all__ = [
    "PACK_FORMAT",
    "PACK_FILES",
    "PackReader",
    "PackError",
    "ExportResult",
    "export_pack",
    "verify_pack",
    "reconcile_pack",
]
