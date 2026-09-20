"""文件型持久化。

控制平台的硬约束是「先落盘、后动作」：任何会改变工艺状态的指令都必须先把意图
写入磁盘并回读校验，确认字节级一致之后才允许驱动执行机构。本模块提供：

* 原子写（临时文件 + ``fsync`` + ``os.replace`` + 目录 ``fsync``）；
* 写后回读校验（校验和不一致立即抛错，绝不静默降级）；
* JSONL 追加流水（审计与批次记录），单调序号 + 逐行校验和；
* 启动期孤儿文件清理与整库校验，供 ``verify`` 命令与回归复跑使用。
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ..errors import IntegrityError, NotFoundError, PersistenceError, ValidationError
from .codec import canonical_json, checksum_of, stringify_mapping, validate_key

DATA_DIR = "data"
JOURNAL_DIR = "journal"
TEMP_SUFFIX = ".tmp"


@dataclass(frozen=True, slots=True)
class Record:
    """一次已落盘的文档写入。"""

    key: str
    version: int
    written_at: str
    checksum: str
    payload: Mapping[str, Any]
    bytes_written: int
    durable: bool

    def to_dict(self, *, include_payload: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "key": self.key,
            "version": self.version,
            "written_at": self.written_at,
            "checksum": self.checksum,
            "bytes_written": self.bytes_written,
            "durable": self.durable,
        }
        if include_payload:
            data["payload"] = dict(self.payload)
        return data


@dataclass(frozen=True, slots=True)
class JournalEntry:
    stream: str
    seq: int
    written_at: str
    checksum: str
    payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "stream": self.stream,
            "seq": self.seq,
            "written_at": self.written_at,
            "checksum": self.checksum,
            "payload": dict(self.payload),
        }


@dataclass(frozen=True, slots=True)
class RawJournalEntry:
    """带落盘原始字节的流水行，供离线核验包复算哈希链。"""

    seq: int
    raw_line: str
    payload: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class IntegrityReport:
    records_checked: int
    journals_checked: int
    journal_entries: int
    orphans_removed: int
    problems: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.problems

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "records_checked": self.records_checked,
            "journals_checked": self.journals_checked,
            "journal_entries": self.journal_entries,
            "orphans_removed": self.orphans_removed,
            "problems": list(self.problems),
        }


class DurableStore:
    """原子、可回读校验的本地文档库。"""

    def __init__(self, root: Path | str, *, clock: Any) -> None:
        self.root = Path(root)
        self.data_root = self.root / DATA_DIR
        self.journal_root = self.root / JOURNAL_DIR
        self._clock = clock
        self._lock = threading.RLock()
        self.data_root.mkdir(parents=True, exist_ok=True)
        self.journal_root.mkdir(parents=True, exist_ok=True)
        self.orphans_removed = self._remove_orphans()

    # ------------------------------------------------------------------ 文档
    def put(self, key: str, payload: Mapping[str, Any]) -> Record:
        """写入并回读校验；返回落盘记录。"""

        segments = validate_key(key)
        body = stringify_mapping(payload)
        with self._lock:
            current = self._read_record(key, tolerate_missing=True)
            version = 1 if current is None else current.version + 1
            written_at = self._clock.timestamp_iso()
            checksum = checksum_of(version, written_at, body)
            envelope = {
                "key": key,
                "version": version,
                "written_at": written_at,
                "checksum": checksum,
                "payload": body,
            }
            target = self.data_root.joinpath(*segments).with_suffix(".json")
            target.parent.mkdir(parents=True, exist_ok=True)
            blob = canonical_json(envelope).encode("utf-8")
            temporary = target.with_name(target.name + TEMP_SUFFIX)
            self._write_atomic(temporary, target, blob)
            record = self._read_record(key, tolerate_missing=False)
            if record is None:  # pragma: no cover - 原子写之后必然可读
                raise PersistenceError("落盘后回读失败", details={"key": key})
            if record.checksum != checksum or record.version != version:
                raise PersistenceError(
                    "落盘回读内容与写入不一致",
                    details={"key": key, "expected": checksum, "actual": record.checksum},
                )
            return record

    def commit_intent(self, key: str, payload: Mapping[str, Any]) -> Record:
        """工艺意图专用写入：必须 durable，且回读内容与意图逐字段一致。"""

        body = stringify_mapping(payload)
        record = self.put(key, body)
        if not record.durable:
            raise PersistenceError("意图未落盘，禁止执行机构动作", details={"key": key})
        if dict(record.payload) != body:
            raise PersistenceError(
                "意图回读内容与写入不一致",
                details={"key": key},
            )
        return record

    def get(self, key: str) -> Record | None:
        validate_key(key)
        with self._lock:
            return self._read_record(key, tolerate_missing=True)

    def require(self, key: str) -> Record:
        record = self.get(key)
        if record is None:
            raise NotFoundError("记录不存在", details={"key": key})
        return record

    def exists(self, key: str) -> bool:
        return self.get(key) is not None

    def list_keys(self, prefix: str = "") -> list[str]:
        keys: list[str] = []
        for path in sorted(self.data_root.rglob("*.json")):
            relative = path.relative_to(self.data_root).with_suffix("")
            key = "/".join(relative.parts)
            if prefix and not key.startswith(prefix):
                continue
            keys.append(key)
        return keys

    def snapshot(self, prefix: str = "") -> dict[str, Mapping[str, Any]]:
        snapshot: dict[str, Mapping[str, Any]] = {}
        for key in self.list_keys(prefix):
            record = self.get(key)
            if record is not None:
                snapshot[key] = record.payload
        return snapshot

    def versions(self, prefix: str = "") -> dict[str, int]:
        versions: dict[str, int] = {}
        for key in self.list_keys(prefix):
            record = self.get(key)
            if record is not None:
                versions[key] = record.version
        return versions

    # ------------------------------------------------------------------ 流水
    def append(self, stream: str, payload: Mapping[str, Any]) -> JournalEntry:
        segments = validate_key(stream)
        body = stringify_mapping(payload)
        with self._lock:
            path = self.journal_root.joinpath(*segments).with_suffix(".jsonl")
            path.parent.mkdir(parents=True, exist_ok=True)
            seq = self._last_sequence(path) + 1
            written_at = self._clock.timestamp_iso()
            entry = {
                "seq": seq,
                "written_at": written_at,
                "checksum": checksum_of(seq, written_at, body),
                "payload": body,
            }
            line = canonical_json(entry).encode("utf-8") + b"\n"
            with path.open("ab") as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())
            self._fsync_directory(path.parent)
            return JournalEntry(
                stream=stream,
                seq=seq,
                written_at=written_at,
                checksum=entry["checksum"],
                payload=body,
            )

    def read_stream(
        self,
        stream: str,
        *,
        limit: int = 100,
        since_seq: int = 0,
        verify: bool = True,
    ) -> list[JournalEntry]:
        if limit < 1:
            raise ValidationError("limit 必须为正", details={"limit": limit})
        segments = validate_key(stream)
        path = self.journal_root.joinpath(*segments).with_suffix(".jsonl")
        if not path.exists():
            return []
        entries: list[JournalEntry] = []
        with self._lock, path.open("rb") as handle:
            for line_number, raw in enumerate(handle, start=1):
                text = raw.decode("utf-8").strip()
                if not text:
                    continue
                try:
                    parsed = json.loads(text)
                except json.JSONDecodeError as exc:
                    raise IntegrityError(
                        "流水行无法解析，文件已被破坏",
                        details={"stream": stream, "line": line_number},
                    ) from exc
                seq = int(parsed.get("seq", 0))
                if seq <= since_seq:
                    continue
                written_at = str(parsed.get("written_at", ""))
                payload = parsed.get("payload", {})
                if verify:
                    expected = checksum_of(seq, written_at, payload)
                    if expected != parsed.get("checksum"):
                        raise IntegrityError(
                            "流水行校验和不匹配",
                            details={"stream": stream, "line": line_number, "seq": seq},
                        )
                entries.append(
                    JournalEntry(
                        stream=stream,
                        seq=seq,
                        written_at=written_at,
                        checksum=str(parsed.get("checksum", "")),
                        payload=payload,
                    )
                )
        if len(entries) > limit:
            entries = entries[-limit:]
        return entries

    def read_stream_raw(
        self,
        stream: str,
        *,
        since_seq: int = 0,
        max_seq: int | None = None,
        verify: bool = False,
    ) -> list[RawJournalEntry]:
        """按原始字节读取流水行（含序号过滤），核验包导出专用。

        与 :meth:`read_stream` 不同，这里返回**逐字节的原始行文本**并默认不做
        自校验和校验：核验链需要原始字节，而且数据是否被动过本就该由哈希链与
        签名判定。序号不连续的文件会被如实读出（每条都返回），缺段由链锚点
        与序号连续性检查发现。
        """

        segments = validate_key(stream)
        path = self.journal_root.joinpath(*segments).with_suffix(".jsonl")
        if not path.exists():
            return []
        rows: list[RawJournalEntry] = []
        with self._lock, path.open("rb") as handle:
            for line_number, raw in enumerate(handle, start=1):
                text = raw.decode("utf-8").strip()
                if not text:
                    continue
                try:
                    parsed = json.loads(text)
                except json.JSONDecodeError as exc:
                    raise IntegrityError(
                        "流水行无法解析，文件已被破坏",
                        details={"stream": stream, "line": line_number},
                    ) from exc
                seq = int(parsed.get("seq", 0))
                if seq <= since_seq:
                    continue
                if max_seq is not None and seq > max_seq:
                    continue
                payload = parsed.get("payload", {})
                if verify:
                    written_at = str(parsed.get("written_at", ""))
                    if checksum_of(seq, written_at, payload) != parsed.get("checksum"):
                        raise IntegrityError(
                            "流水行校验和不匹配",
                            details={"stream": stream, "line": line_number, "seq": seq},
                        )
                rows.append(RawJournalEntry(seq=seq, raw_line=text, payload=payload))
        return rows

    def predecessor_raw(self, stream: str, seq: int) -> RawJournalEntry | None:
        """返回序号严格小于 ``seq`` 的最后一条原始行，用作导出段的前置锚点。"""

        if seq <= 1:
            return None
        rows = self.read_stream_raw(stream, since_seq=0, max_seq=seq - 1)
        return rows[-1] if rows else None

    def read_record_raw(self, key: str) -> tuple[str, bytes] | None:
        """返回 ``(键, 落盘信封原始字节)``；不存在返回 None。"""

        segments = validate_key(key)
        path = self.data_root.joinpath(*segments).with_suffix(".json")
        if not path.exists():
            return None
        return key, path.read_bytes()

    def stream_path(self, stream: str) -> Path:
        segments = validate_key(stream)
        return self.journal_root.joinpath(*segments).with_suffix(".jsonl")

    def stream_length(self, stream: str) -> int:
        segments = validate_key(stream)
        path = self.journal_root.joinpath(*segments).with_suffix(".jsonl")
        return self._last_sequence(path)

    def list_streams(self) -> list[str]:
        streams: list[str] = []
        for path in sorted(self.journal_root.rglob("*.jsonl")):
            relative = path.relative_to(self.journal_root).with_suffix("")
            streams.append("/".join(relative.parts))
        return streams

    # ------------------------------------------------------------------ 校验
    def verify(self) -> IntegrityReport:
        problems: list[str] = []
        records_checked = 0
        for path in sorted(self.data_root.rglob("*.json")):
            key = "/".join(path.relative_to(self.data_root).with_suffix("").parts)
            try:
                record = self.get(key)
            except (IntegrityError, PersistenceError) as exc:
                problems.append(f"{key}: {exc.message}")
                continue
            if record is None:
                problems.append(f"{key}: 记录不可读")
                continue
            records_checked += 1
        journals_checked = 0
        journal_entries = 0
        for stream in self.list_streams():
            try:
                entries = self.read_stream(stream, limit=1_000_000)
            except IntegrityError as exc:
                problems.append(f"{stream}: {exc.message}")
                continue
            journals_checked += 1
            journal_entries += len(entries)
        return IntegrityReport(
            records_checked=records_checked,
            journals_checked=journals_checked,
            journal_entries=journal_entries,
            orphans_removed=self.orphans_removed,
            problems=tuple(problems),
        )

    # ------------------------------------------------------------------ 内部
    def _write_atomic(self, temporary: Path, target: Path, blob: bytes) -> None:
        try:
            with temporary.open("wb") as handle:
                handle.write(blob)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
            self._fsync_directory(target.parent)
        except OSError as exc:
            if temporary.exists():
                try:
                    temporary.unlink()
                except OSError:  # pragma: no cover - 清理失败不掩盖原始错误
                    pass
            raise PersistenceError(
                "落盘失败",
                details={"target": str(target), "reason": exc.strerror or str(exc)},
            ) from exc

    def _read_record(self, key: str, *, tolerate_missing: bool) -> Record | None:
        segments = validate_key(key)
        path = self.data_root.joinpath(*segments).with_suffix(".json")
        if not path.exists():
            if tolerate_missing:
                return None
            raise NotFoundError("记录不存在", details={"key": key})
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise PersistenceError("记录读取失败", details={"key": key}) from exc
        try:
            envelope = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IntegrityError("记录无法解析", details={"key": key}) from exc
        try:
            version = int(envelope["version"])
            written_at = str(envelope["written_at"])
            payload = envelope["payload"]
            stored_checksum = str(envelope["checksum"])
        except (KeyError, TypeError, ValueError) as exc:
            raise IntegrityError("记录缺少必要字段", details={"key": key}) from exc
        expected = checksum_of(version, written_at, payload)
        if expected != stored_checksum:
            raise IntegrityError(
                "记录校验和不匹配",
                details={"key": key, "expected": expected, "actual": stored_checksum},
            )
        return Record(
            key=key,
            version=version,
            written_at=written_at,
            checksum=stored_checksum,
            payload=payload,
            bytes_written=len(raw),
            durable=True,
        )

    def _last_sequence(self, path: Path) -> int:
        if not path.exists():
            return 0
        last = 0
        with path.open("rb") as handle:
            for raw in handle:
                text = raw.strip()
                if not text:
                    continue
                try:
                    last = int(json.loads(text.decode("utf-8")).get("seq", last))
                except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
                    continue
        return last

    def _remove_orphans(self) -> int:
        removed = 0
        for path in self.root.rglob("*" + TEMP_SUFFIX):
            try:
                path.unlink()
                removed += 1
            except OSError:  # pragma: no cover - 并发清理竞态
                continue
        return removed

    def _fsync_directory(self, path: Path) -> None:
        if os.name == "nt":  # Windows 不支持对目录 fsync
            return
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

__all__ = ["DurableStore", "Record", "JournalEntry", "RawJournalEntry", "IntegrityReport"]
