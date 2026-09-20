"""离线核验包：导出、验包与回联对账。

一个核验包是一个目录（或同名 zip）::

    manifest.json        清单：序号边界、链头、状态根、各文件 SHA-256（被签名）
    manifest.sig         对 manifest.json 原始字节的 Ed25519 签名
    public.pem           签名公钥（车间端可用预置公钥覆盖，不信任包内公钥）
    chain.json           导出区间的哈希链（链头/前驱/逐环，供人工抽查）
    journal/<流>.jsonl   导出区间的流水原文（逐行 JSON）
    data/records.jsonl   导出时刻文档库当前状态（逐行 envelope）

信任边界只有一处：验签所用的公钥必须是车间端预置/钉住的。包内附带的 public.pem
只是方便分发，若拿包内公钥验包内签名，等于让包裹自证清白，没有意义。
"""

from __future__ import annotations

import contextlib
import json
import shutil
import tempfile
import uuid
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

from ..errors import IntegrityError, PersistenceError, ValidationError
from ..runtime import Clock
from ..store import DurableStore
from ..store.codec import canonical_json, checksum_of, validate_key
from .chain import (
    PREV_ZERO,
    ChainLink,
    build_chain,
    digest_bytes,
    require_positive_range,
    state_root,
)
from .crypto import KeyPair, sign, verify_signature

BUNDLE_FORMAT = "flashsmelter-attest/1"
MANIFEST_NAME = "manifest.json"
SIGNATURE_NAME = "manifest.sig"
PUBLIC_KEY_NAME = "public.pem"
CHAIN_NAME = "chain.json"
STATE_NAME = "data/records.jsonl"
STATE_PREFIX = "state/"
ZIP_SUFFIX = ".zip"


# --------------------------------------------------------------------------- 数据类型
@dataclass(frozen=True, slots=True)
class VerifyReport:
    """离线验包结果。``problems`` 为空即整包可信。"""

    ok: bool
    package_id: str
    stream: str
    seq_from: int
    seq_to: int
    journal_entries: int
    state_records: int
    key_id: str
    problems: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "package_id": self.package_id,
            "stream": self.stream,
            "seq_from": self.seq_from,
            "seq_to": self.seq_to,
            "journal_entries": self.journal_entries,
            "state_records": self.state_records,
            "signed_by": self.key_id,
            "problems": list(self.problems),
        }


@dataclass(frozen=True, slots=True)
class ReconcileReport:
    """回联对账结果：逐条、逐键指出差异。"""

    ok: bool
    package_id: str
    stream: str
    seq_from: int
    seq_to: int
    findings: tuple[Mapping[str, Any], ...] = ()
    live_head: int = 0
    appended_entries: int = 0
    state_added: tuple[str, ...] = ()
    summary: Mapping[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "package_id": self.package_id,
            "stream": self.stream,
            "seq_from": self.seq_from,
            "seq_to": self.seq_to,
            "live_head": self.live_head,
            "appended_entries": self.appended_entries,
            "state_added": list(self.state_added),
            "findings": [dict(item) for item in self.findings],
            "summary": dict(self.summary),
        }


# --------------------------------------------------------------------------- 打包读写
def journal_relpath(stream: str) -> str:
    segments = validate_key(stream)
    return "journal/" + "/".join(segments) + ".jsonl"


def _dump_jsonl(rows: Sequence[Mapping[str, Any]]) -> bytes:
    return b"".join(canonical_json(row).encode("utf-8") + b"\n" for row in rows)


def read_raw_entries(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """读取 JSONL 原文，不做校验和判断（对账时被改的行也要看得到）。

    返回 ``(条目, 解析错误描述)``；条目的键为 ``seq/written_at/checksum/payload``。
    """

    entries: list[dict[str, Any]] = []
    errors: list[str] = []
    if not path.exists():
        return entries, errors
    with path.open("rb") as handle:
        for line_number, raw in enumerate(handle, start=1):
            text = raw.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                errors.append(f"第 {line_number} 行无法解析")
                continue
            entries.append(parsed)
    return entries, errors


def _verify_entry_checksum(entry: Mapping[str, Any]) -> bool:
    try:
        expected = checksum_of(int(entry["seq"]), str(entry["written_at"]), entry["payload"])
    except (KeyError, TypeError, ValueError):
        return False
    return expected == str(entry.get("checksum", ""))


@contextlib.contextmanager
def open_bundle(source: Path | str) -> Iterator[Path]:
    """目录直接返回；zip 解到临时目录后返回，退出时清理。"""

    source = Path(source)
    if source.is_dir():
        yield source
        return
    if not source.exists():
        raise ValidationError("核验包不存在", details={"path": str(source)})
    temp_dir = Path(tempfile.mkdtemp(prefix="flashsmelter-bundle-"))
    try:
        with zipfile.ZipFile(source) as archive:
            archive.extractall(temp_dir)
        yield temp_dir
    except (zipfile.BadZipFile, OSError) as exc:
        raise ValidationError("核验包不是合法的 zip", details={"path": str(source)}) from exc
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _load_manifest(bundle_dir: Path) -> tuple[dict[str, Any], bytes]:
    manifest_path = bundle_dir / MANIFEST_NAME
    if not manifest_path.exists():
        raise ValidationError("核验包缺少 manifest.json", details={"path": str(bundle_dir)})
    raw = manifest_path.read_bytes()
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("manifest.json 无法解析") from exc
    if not isinstance(manifest, dict):
        raise ValidationError("manifest.json 结构不正确")
    return manifest, raw


# --------------------------------------------------------------------------- 导出
def export_bundle(
    store: DurableStore,
    out_path: Path | str,
    *,
    stream: str,
    seq_from: int = 1,
    seq_to: int | None = None,
    namespace: str,
    key_pair: KeyPair,
    clock: Clock,
) -> dict[str, Any]:
    """把当前状态与一段流水导出为带签名的离线核验包。

    导出是只读操作：整库完整性不通过、流水有断号，一律拒签，绝不把已经损坏的库
    封进「可信」包里。
    """

    require_positive_range(seq_from, seq_to if seq_to is not None else seq_from)
    report = store.verify()
    if not report.ok:
        raise IntegrityError(
            "整库校验未通过，禁止导出核验包",
            details={"problems": list(report.problems)},
        )

    head_seq = store.stream_length(stream)
    if head_seq < 1:
        raise ValidationError("指定流水为空，无法导出", details={"stream": stream})
    end = head_seq if seq_to is None else min(seq_to, head_seq)
    if seq_from > end:
        raise ValidationError(
            "导出区间超出流水范围",
            details={"stream": stream, "seq_from": seq_from, "head": head_seq},
        )

    all_entries = [
        entry.to_dict() for entry in store.read_stream(stream, limit=10_000_000, verify=True)
    ]
    full_chain = build_chain(all_entries, stream=stream)
    sliced = [entry for entry in all_entries if seq_from <= int(entry["seq"]) <= end]
    if len(sliced) != end - seq_from + 1:  # build_chain 已保证连续，双保险
        raise IntegrityError("导出区间存在断号", details={"stream": stream})

    prev = full_chain[seq_from - 2].link if seq_from > 1 else PREV_ZERO
    slice_links = [link.to_dict() for link in full_chain[seq_from - 1 : end]]
    head_link = full_chain[end - 1].link

    state_envelopes = _collect_state(store)
    state_tree_root = state_root(state_envelopes)

    journal_name = journal_relpath(stream)
    payloads: dict[str, bytes] = {
        journal_name: _dump_jsonl(sliced),
        STATE_NAME: _dump_jsonl(state_envelopes),
        CHAIN_NAME: canonical_json(
            {
                "stream": stream,
                "seq_from": seq_from,
                "seq_to": end,
                "prev": prev,
                "head": head_link,
                "links": slice_links,
            }
        ).encode("utf-8"),
        PUBLIC_KEY_NAME: key_pair.public_pem,
    }

    package_id = uuid.uuid4().hex
    manifest = {
        "format": BUNDLE_FORMAT,
        "package_id": package_id,
        "created_at": clock.timestamp_iso(),
        "namespace": namespace,
        "stream": stream,
        "seq_from": seq_from,
        "seq_to": end,
        "chain": {
            "prev": prev,
            "head": head_link,
            "record_count": len(sliced),
        },
        "state": {
            "record_count": len(state_envelopes),
            "root": state_tree_root,
        },
        "source": {"store": store.root.name},
        "files": {name: digest_bytes(blob) for name, blob in sorted(payloads.items())},
    }
    manifest_bytes = canonical_json(manifest).encode("utf-8")
    signature = sign(manifest_bytes, key_pair.private_pem)

    out_path = Path(out_path)
    staging = Path(tempfile.mkdtemp(prefix="flashsmelter-export-"))
    try:
        bundle_dir = staging / f"{package_id}"
        bundle_dir.mkdir()
        (bundle_dir / MANIFEST_NAME).write_bytes(manifest_bytes)
        (bundle_dir / SIGNATURE_NAME).write_bytes(signature)
        for name, blob in payloads.items():
            target = bundle_dir / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(blob)
        _materialize(bundle_dir, out_path)
    finally:
        shutil.rmtree(staging, ignore_errors=True)

    return {
        "package_id": package_id,
        "path": str(out_path),
        "stream": stream,
        "seq_from": seq_from,
        "seq_to": end,
        "journal_entries": len(sliced),
        "state_records": len(state_envelopes),
        "state_root": state_tree_root,
        "chain_head": head_link,
        "signed_by": key_pair.key_id,
    }


def _collect_state(store: DurableStore) -> list[dict[str, Any]]:
    envelopes: list[dict[str, Any]] = []
    for key in store.list_keys():
        record = store.get(key)
        if record is None:
            continue
        envelopes.append(
            {
                "key": record.key,
                "version": record.version,
                "written_at": record.written_at,
                "checksum": record.checksum,
                "payload": dict(record.payload),
            }
        )
    return envelopes


def _materialize(bundle_dir: Path, out_path: Path) -> None:
    out_path = Path(out_path)
    if out_path.suffix.lower() == ZIP_SUFFIX:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(bundle_dir.rglob("*")):
                if path.is_file():
                    archive.write(path, path.relative_to(bundle_dir))
        return
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        if not out_path.is_dir():
            raise PersistenceError("导出目标已存在且不是目录", details={"path": str(out_path)})
        shutil.rmtree(out_path)
    shutil.move(str(bundle_dir), str(out_path))


# --------------------------------------------------------------------------- 验包
def verify_bundle(bundle_dir: Path | str, *, pinned_public_pem: bytes | None = None) -> VerifyReport:
    """离线核验：验签 → 文件哈希 → 状态根 → 哈希链。

    这是车间断网时唯一需要跑的步骤，不读线上库、不访问网络。
    """

    with open_bundle(bundle_dir) as located:
        manifest, manifest_bytes = _load_manifest(located)
        problems: list[str] = []

        stream = str(manifest.get("stream", ""))
        seq_from = int(manifest.get("seq_from", 0))
        seq_to = int(manifest.get("seq_to", 0))
        package_id = str(manifest.get("package_id", ""))
        key_id = ""

        bundled_key_path = located / PUBLIC_KEY_NAME
        public_pem = pinned_public_pem
        if public_pem is None and bundled_key_path.exists():
            public_pem = bundled_key_path.read_bytes()
        signature_path = located / SIGNATURE_NAME
        if public_pem is None:
            problems.append("缺少可信公钥：包内无 public.pem，也未提供预置公钥")
        elif not signature_path.exists():
            problems.append("缺少签名文件 manifest.sig")
        else:
            key_id = digest_bytes(public_pem)[:16]
            if not verify_signature(manifest_bytes, signature_path.read_bytes(), public_pem):
                problems.append("清单签名验证失败：包不是对应私钥签发的，或已被改动")

        expected_files = dict(manifest.get("files", {}))
        for name, expected_hash in sorted(expected_files.items()):
            target = located / name
            if not target.exists():
                problems.append(f"缺少清单所列文件：{name}")
                continue
            actual_hash = digest_bytes(target.read_bytes())
            if actual_hash != expected_hash:
                problems.append(f"文件内容与清单不一致：{name}（期望 {expected_hash[:12]}…，实际 {actual_hash[:12]}…）")

        journal_entries = 0
        state_records = int(manifest.get("state", {}).get("record_count", 0))

        state_path = located / STATE_NAME
        if state_path.exists():
            state_rows, state_errors = read_raw_entries(state_path)
            for error in state_errors:
                problems.append(f"状态文件 {STATE_NAME} {error}")
            try:
                actual_root = state_root(state_rows)
            except (KeyError, TypeError, ValueError):
                actual_root = None
                problems.append(f"状态文件 {STATE_NAME} 存在结构非法的行")
            expected_root = manifest.get("state", {}).get("root")
            expected_state_count = int(manifest.get("state", {}).get("record_count", -1))
            if expected_state_count >= 0 and len(state_rows) != expected_state_count:
                problems.append(
                    f"状态条目数不符：清单声明 {expected_state_count}，实际 {len(state_rows)}"
                )
            if actual_root is not None and actual_root != expected_root:
                problems.append("当前状态默克尔根不符：至少有一个状态键缺失或被改动")
            state_records = len(state_rows)

        chain_meta = manifest.get("chain", {})
        chain_path = located / CHAIN_NAME
        chain_doc: dict[str, Any] = {}
        if chain_path.exists():
            try:
                chain_doc = json.loads(chain_path.read_bytes())
            except (UnicodeDecodeError, json.JSONDecodeError):
                problems.append("chain.json 无法解析")

        journal_name = journal_relpath(stream) if stream else ""
        journal_path = located / journal_name if journal_name else None
        if journal_path is not None and journal_path.exists():
            rows, row_errors = read_raw_entries(journal_path)
            for error in row_errors:
                problems.append(f"流水文件 {journal_name} {error}")
            for row in rows:
                if not _verify_entry_checksum(row):
                    problems.append(
                        f"流水第 {row.get('seq', '?')} 行校验和不匹配：该行内容已被改动"
                    )
            seqs = [int(row.get("seq", -1)) for row in rows]
            if seqs and sorted(seqs) != list(range(seq_from, seq_to + 1)):
                missing = sorted(set(range(seq_from, seq_to + 1)) - set(seqs))
                if missing:
                    problems.append(
                        "流水缺段：序号 " + _format_ranges(missing) + " 不在包内"
                    )
                extra = sorted(set(seqs) - set(range(seq_from, seq_to + 1)))
                if extra:
                    problems.append(f"流水含有区间外序号：{_format_ranges(extra)}")
            prev = str(chain_meta.get("prev", chain_doc.get("prev", PREV_ZERO)))
            try:
                links = build_chain(rows, stream=stream, prev=prev)
                journal_entries = len(links)
                expected_head = chain_meta.get("head", chain_doc.get("head"))
                if links and links[-1].link != expected_head:
                    problems.append(
                        f"哈希链链头不符：在序号 {links[-1].seq} 处与清单分叉，"
                        "说明该序号或之前的内容被改动/抽段"
                    )
                expected_count = int(chain_meta.get("record_count", -1))
                if expected_count >= 0 and len(links) != expected_count:
                    problems.append(
                        f"哈希链条目数不符：清单声明 {expected_count}，实际 {len(links)}"
                    )
            except IntegrityError as exc:
                problems.append(f"哈希链无法建立：{exc.message}")
                journal_entries = len(rows)
        elif stream:
            problems.append(f"缺少流水文件：{journal_name}")

        if str(manifest.get("format")) != BUNDLE_FORMAT:
            problems.append(
                f"核验包格式不受支持：{manifest.get('format')!r}（期望 {BUNDLE_FORMAT}）"
            )

        return VerifyReport(
            ok=not problems,
            package_id=package_id,
            stream=stream,
            seq_from=seq_from,
            seq_to=seq_to,
            journal_entries=journal_entries,
            state_records=state_records,
            key_id=key_id,
            problems=tuple(problems),
        )


# --------------------------------------------------------------------------- 对账
def reconcile_bundle(
    bundle_dir: Path | str,
    store: DurableStore,
    *,
    pinned_public_pem: bytes | None = None,
) -> ReconcileReport:
    """回联后把可信核验包与线上库一条条对回来。"""

    with open_bundle(bundle_dir) as located:
        report = verify_bundle(located, pinned_public_pem=pinned_public_pem)
        if not report.ok:
            return ReconcileReport(
                ok=False,
                package_id=report.package_id,
                stream=report.stream,
                seq_from=report.seq_from,
                seq_to=report.seq_to,
                findings=tuple(
                    {"kind": "bundle-invalid", "detail": problem} for problem in report.problems
                ),
                summary={"conclusion": "核验包自身不可信，拒绝对账"},
            )

        manifest, _ = _load_manifest(located)
        stream = report.stream
        seq_from, seq_to = report.seq_from, report.seq_to
        findings: list[dict[str, Any]] = []

        packaged_rows, _ = read_raw_entries(located / journal_relpath(stream))
        packaged = {int(row["seq"]): row for row in packaged_rows}

        live_rows, live_errors = read_raw_entries(
            store.journal_root.joinpath(*validate_key(stream)).with_suffix(".jsonl")
        )
        for error in live_errors:
            findings.append({"kind": "unparseable-line", "stream": stream, "detail": error})
        live = {}
        for row in live_rows:
            try:
                live[int(row["seq"])] = row
            except (KeyError, TypeError, ValueError):
                findings.append({"kind": "unparseable-line", "stream": stream, "detail": "存在无序号行"})

        # 区间内逐条比对
        for seq in range(seq_from, seq_to + 1):
            packaged_row = packaged.get(seq)
            live_row = live.get(seq)
            if packaged_row is None:
                continue  # 验包阶段已保证包内完整，理论上不会发生
            if live_row is None:
                findings.append(
                    {
                        "kind": "missing",
                        "stream": stream,
                        "seq": seq,
                        "detail": "线上库缺少该序号（整段被删除/截断时会连续出现）",
                    }
                )
                continue
            diff = _diff_entry(packaged_row, live_row)
            if diff and "checksum" not in diff and not _verify_entry_checksum(live_row):
                # 内容被改但校验和字段没跟着重算：原校验和对该行已失效。
                diff.append("checksum")
            if diff:
                findings.append(
                    {
                        "kind": "altered",
                        "stream": stream,
                        "seq": seq,
                        "fields": diff,
                        "packaged_at": packaged_row.get("written_at"),
                        "detail": _describe_row(packaged_row),
                    }
                )

        # 导出区间之前的历史也要对：用清单里的 prev 锚住历史链头，防止
        # 「保留区间内原样、重写更早历史」这种绕过手段。
        before_seqs = [seq for seq in sorted(live) if seq < seq_from]
        if seq_from == 1:
            if manifest["chain"]["prev"] != PREV_ZERO:
                findings.append(
                    {
                        "kind": "prefix-rewritten",
                        "stream": stream,
                        "detail": "核验包声明了区间前驱，但流水应从序号 1 开始",
                    }
                )
        elif before_seqs != list(range(1, seq_from)):
            findings.append(
                {
                    "kind": "prefix-rewritten",
                    "stream": stream,
                    "missing_before": sorted(set(range(1, seq_from)) - set(live)),
                    "detail": "导出区间之前的历史缺段",
                }
            )
        else:
            prefix_chain = build_chain([live[seq] for seq in before_seqs], stream=stream)
            if prefix_chain[-1].link != manifest["chain"]["prev"]:
                findings.append(
                    {
                        "kind": "prefix-rewritten",
                        "stream": stream,
                        "seq": seq_from - 1,
                        "detail": "导出区间之前的历史与核验包对不上（历史被重写）",
                    }
                )

        live_head = max(live, default=0)
        appended = [seq for seq in sorted(live) if seq > seq_to]
        for seq in appended:
            if not _verify_entry_checksum(live[seq]):
                findings.append(
                    {
                        "kind": "altered",
                        "stream": stream,
                        "seq": seq,
                        "fields": ["checksum"],
                        "detail": "导出之后新增的条目校验和不合法",
                    }
                )
        suffix_rows = [live[seq] for seq in range(1, seq_to + 1) if seq in live]
        if len(suffix_rows) == seq_to:
            whole_chain = build_chain(suffix_rows, stream=stream)
            if whole_chain[-1].link != manifest["chain"]["head"]:
                if not any(item["kind"] == "altered" and item.get("seq", 0) <= seq_to for item in findings):
                    findings.append(
                        {
                            "kind": "chain-fork",
                            "stream": stream,
                            "seq": seq_to,
                            "detail": "链头分叉但逐条字段未见差异（可能重新计算过校验和）",
                        }
                    )

        # 当前状态逐键比对
        state_rows, _ = read_raw_entries(located / STATE_NAME)
        packaged_state = {str(row["key"]): row for row in state_rows}
        live_state = _collect_state(store)
        live_state_by_key = {row["key"]: row for row in live_state}
        for key, packaged_row in sorted(packaged_state.items()):
            live_row = live_state_by_key.get(key)
            if live_row is None:
                findings.append({"kind": "state-missing", "key": key, "detail": "状态键已被删除"})
            elif live_row["checksum"] != packaged_row["checksum"]:
                findings.append(
                    {
                        "kind": "state-changed",
                        "key": key,
                        "packaged_version": packaged_row["version"],
                        "live_version": live_row["version"],
                        "detail": "该状态文档在导出后被改写",
                    }
                )
        added = sorted(set(live_state_by_key) - set(packaged_state))

        missing_count = sum(1 for item in findings if item["kind"] == "missing")
        altered_count = sum(1 for item in findings if item["kind"] in ("altered", "chain-fork"))
        if findings:
            conclusion = (
                f"发现 {len(findings)} 处差异：{missing_count} 条缺失/缺段，{altered_count} 条被改"
            )
        elif added:
            conclusion = f"区间内记录完全一致；导出后新增 {len(appended)} 条流水、{len(added)} 个状态键（正常增长）"
        else:
            conclusion = "区间内记录与当前状态完全一致，无改动无缺段"

        return ReconcileReport(
            ok=not findings,
            package_id=report.package_id,
            stream=stream,
            seq_from=seq_from,
            seq_to=seq_to,
            findings=tuple(findings),
            live_head=live_head,
            appended_entries=len(appended),
            state_added=tuple(added),
            summary={"conclusion": conclusion},
        )


def _diff_entry(packaged: Mapping[str, Any], live: Mapping[str, Any]) -> list[str]:
    changed: list[str] = []
    if str(packaged.get("written_at")) != str(live.get("written_at")):
        changed.append("written_at")
    if str(packaged.get("checksum")) != str(live.get("checksum")):
        changed.append("checksum")
    if canonical_json(packaged.get("payload")) != canonical_json(live.get("payload")):
        changed.append("payload")
    return changed


def _describe_row(row: Mapping[str, Any]) -> str:
    payload = row.get("payload", {})
    if isinstance(payload, Mapping):
        bits = [
            str(payload.get(key))
            for key in ("at", "actor", "action", "target", "outcome")
            if payload.get(key)
        ]
        return " / ".join(bits) or "流水条目"
    return "流水条目"


def _format_ranges(seqs: list[int]) -> str:
    """[1,2,3,7,9,10] -> '1-3、7、9-10'。"""

    if not seqs:
        return ""
    ranges: list[str] = []
    start = prev = seqs[0]
    for seq in seqs[1:]:
        if seq == prev + 1:
            prev = seq
            continue
        ranges.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = seq
    ranges.append(str(start) if start == prev else f"{start}-{prev}")
    return "、".join(ranges)


__all__ = [
    "VerifyReport",
    "ReconcileReport",
    "export_bundle",
    "verify_bundle",
    "reconcile_bundle",
    "open_bundle",
    "journal_relpath",
]
