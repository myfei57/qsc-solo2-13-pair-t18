"""离线核验包：哈希链、导出验包与回联对账。"""

from __future__ import annotations

import json
import shutil
import unittest
from pathlib import Path

from flashsmelter.attest import (
    PREV_ZERO,
    build_chain,
    export_bundle,
    generate_keypair,
    journal_relpath,
    link_hash,
    merkle_root,
    reconcile_bundle,
    state_root,
    verify_bundle,
)
from flashsmelter.attest.bundle import read_raw_entries
from flashsmelter.errors import IntegrityError
from flashsmelter.runtime import ManualClock
from flashsmelter.store import DurableStore

from .helpers import make_root

KEY_PAIR = generate_keypair()


def seed_store(store: DurableStore, count: int = 6) -> None:
    for index in range(1, count + 1):
        store.append(
            "audit/events",
            {
                "at": f"2026-09-19T08:{index:02d}:00+00:00",
                "namespace": "smelter/line1",
                "actor": "control-room",
                "action": f"action-{index}",
                "target": "furnace",
                "outcome": "ok" if index % 2 else "rejected",
                "correlation_id": f"cid-{index}",
                "details": {"n": index},
            },
        )
    store.put("furnace/state", {"phase": "smelting", "heat": "H-1"})
    store.put("oxygen/baseline", {"value": 0.62})


def journal_path(root: Path, stream: str = "audit/events") -> Path:
    return root / "journal" / Path(journal_relpath(stream)).relative_to("journal")


class ChainPrimitivesTest(unittest.TestCase):
    def test_chain_head_changes_when_any_entry_is_tampered(self) -> None:
        store = DurableStore(make_root(), clock=ManualClock())
        seed_store(store)
        entries = [entry.to_dict() for entry in store.read_stream("audit/events", limit=100)]
        head = build_chain(entries, stream="audit/events")[-1].link

        entries[2]["payload"]["details"]["n"] = 999
        tampered_head = build_chain(entries, stream="audit/events")[-1].link
        self.assertNotEqual(head, tampered_head)

    def test_chain_is_bound_to_stream_name(self) -> None:
        link = link_hash(
            stream="a", seq=1, written_at="t", checksum="c", body_digest="b", prev=PREV_ZERO
        )
        other = link_hash(
            stream="b", seq=1, written_at="t", checksum="c", body_digest="b", prev=PREV_ZERO
        )
        self.assertNotEqual(link, other)

    def test_build_chain_rejects_gap(self) -> None:
        with self.assertRaises(IntegrityError):
            build_chain(
                [
                    {"seq": 1, "written_at": "t", "checksum": "a", "payload": {"x": 1}},
                    {"seq": 3, "written_at": "t", "checksum": "b", "payload": {"x": 3}},
                ],
                stream="audit/events",
            )

    def test_merkle_root_is_order_and_content_sensitive(self) -> None:
        self.assertNotEqual(merkle_root(["a", "b"]), merkle_root(["b", "a"]))
        self.assertNotEqual(merkle_root(["a", "b"]), merkle_root(["a", "c"]))
        self.assertEqual(merkle_root(["a", "b"]), merkle_root(["a", "b"]))

    def test_state_root_detects_single_key_change(self) -> None:
        records = [
            {"key": "a", "version": 1, "written_at": "t", "checksum": "h1", "payload": {"v": 1}},
            {"key": "b", "version": 1, "written_at": "t", "checksum": "h2", "payload": {"v": 2}},
        ]
        before = state_root(records)
        records[1]["payload"]["v"] = 99
        self.assertNotEqual(before, state_root(records))


class ExportVerifyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = ManualClock()
        self.root = make_root()
        self.store = DurableStore(self.root, clock=self.clock)
        seed_store(self.store)
        self.bundle_dir = make_root(prefix="bundle-") / "pkg"

    def _export(self, **kwargs) -> dict:
        options = dict(
            stream="audit/events",
            namespace="smelter/line1",
            key_pair=KEY_PAIR,
            clock=self.clock,
        )
        options.update(kwargs)
        return export_bundle(self.store, self.bundle_dir, **options)

    def test_roundtrip_verifies_with_pinned_key(self) -> None:
        result = self._export()
        report = verify_bundle(self.bundle_dir, pinned_public_pem=KEY_PAIR.public_pem)
        self.assertTrue(report.ok, report.problems)
        self.assertEqual(6, report.journal_entries)
        self.assertEqual(2, report.state_records)
        self.assertEqual(result["package_id"], report.package_id)

    def test_slice_chain_is_anchored_to_full_history(self) -> None:
        self._export(seq_from=3, seq_to=5)
        report = verify_bundle(self.bundle_dir, pinned_public_pem=KEY_PAIR.public_pem)
        self.assertTrue(report.ok, report.problems)
        self.assertEqual((3, 5), (report.seq_from, report.seq_to))

    def test_altered_journal_line_is_reported(self) -> None:
        self._export()
        path = self.bundle_dir / journal_relpath("audit/events")
        rows, errors = read_raw_entries(path)
        self.assertEqual([], errors)
        rows[3]["payload"]["outcome"] = "ok"  # 原来是 rejected
        path.write_text(
            "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
            encoding="utf-8",
        )
        report = verify_bundle(self.bundle_dir, pinned_public_pem=KEY_PAIR.public_pem)
        self.assertFalse(report.ok)
        joined = "\n".join(report.problems)
        self.assertIn("校验和不匹配", joined)
        self.assertIn("哈希链链头不符", joined)

    def test_missing_segment_is_reported(self) -> None:
        self._export()
        path = self.bundle_dir / journal_relpath("audit/events")
        rows, _ = read_raw_entries(path)
        rows = [row for row in rows if row["seq"] not in (3, 4)]
        path.write_text(
            "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
            encoding="utf-8",
        )
        report = verify_bundle(self.bundle_dir, pinned_public_pem=KEY_PAIR.public_pem)
        self.assertFalse(report.ok)
        self.assertTrue(any("缺段：序号 3-4" in problem for problem in report.problems), report.problems)

    def test_state_tamper_is_reported_via_merkle_root(self) -> None:
        self._export()
        path = self.bundle_dir / "data" / "records.jsonl"
        rows, _ = read_raw_entries(path)
        rows[0]["payload"]["phase"] = "stopped"
        path.write_text(
            "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
            encoding="utf-8",
        )
        report = verify_bundle(self.bundle_dir, pinned_public_pem=KEY_PAIR.public_pem)
        self.assertFalse(report.ok)
        self.assertTrue(any("默克尔根不符" in problem for problem in report.problems))

    def test_signature_from_other_key_fails(self) -> None:
        self._export()
        other = generate_keypair()
        report = verify_bundle(self.bundle_dir, pinned_public_pem=other.public_pem)
        self.assertFalse(report.ok)
        self.assertTrue(any("签名验证失败" in problem for problem in report.problems))

    def test_manifest_tamper_breaks_signature(self) -> None:
        self._export()
        manifest_path = self.bundle_dir / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["seq_to"] = 5
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
        report = verify_bundle(self.bundle_dir, pinned_public_pem=KEY_PAIR.public_pem)
        self.assertFalse(report.ok)
        self.assertTrue(any("签名验证失败" in problem for problem in report.problems))

    def test_export_refuses_when_store_is_corrupt(self) -> None:
        path = journal_path(self.root)
        line = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
        line["payload"]["actor"] = "intruder"
        path.write_text(json.dumps(line, ensure_ascii=False) + "\n", encoding="utf-8")
        with self.assertRaises(IntegrityError):
            self._export()


class ReconcileTest(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = ManualClock()
        self.root = make_root()
        self.store = DurableStore(self.root, clock=self.clock)
        seed_store(self.store)
        self.bundle_dir = make_root(prefix="bundle-") / "pkg"
        export_bundle(
            self.store,
            self.bundle_dir,
            stream="audit/events",
            namespace="smelter/line1",
            key_pair=KEY_PAIR,
            clock=self.clock,
        )

    def _rewrite_journal(self, rows: list[dict]) -> None:
        journal_path(self.root).write_text(
            "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
            encoding="utf-8",
        )

    def test_clean_reconcile(self) -> None:
        report = reconcile_bundle(
            self.bundle_dir, self.store, pinned_public_pem=KEY_PAIR.public_pem
        )
        self.assertTrue(report.ok, report.findings)

    def test_clean_reconcile_allows_normal_growth(self) -> None:
        self.store.append("audit/events", {"action": "later", "at": "t", "namespace": "n"})
        self.store.put("furnace/state", {"phase": "tapping", "heat": "H-2"})  # 合法新版本
        self.store.put("new/key", {"v": 1})
        report = reconcile_bundle(
            self.bundle_dir, self.store, pinned_public_pem=KEY_PAIR.public_pem
        )
        self.assertFalse(report.ok)  # 状态被改写仍要报
        kinds = {item["kind"] for item in report.findings}
        self.assertIn("state-changed", kinds)
        self.assertEqual(("new/key",), report.state_added)
        self.assertEqual(1, report.appended_entries)

    def test_altered_entry_is_pinpointed(self) -> None:
        rows, _ = read_raw_entries(journal_path(self.root))
        rows[2]["payload"]["actor"] = "someone-else"
        self._rewrite_journal(rows)
        report = reconcile_bundle(
            self.bundle_dir, self.store, pinned_public_pem=KEY_PAIR.public_pem
        )
        altered = [item for item in report.findings if item["kind"] == "altered"]
        self.assertEqual([3], [item["seq"] for item in altered])
        self.assertIn("payload", altered[0]["fields"])
        self.assertIn("checksum", altered[0]["fields"])

    def test_deleted_middle_segment_is_reported_per_seq(self) -> None:
        rows, _ = read_raw_entries(journal_path(self.root))
        remaining = [row for row in rows if row["seq"] not in (3, 4)]
        self._rewrite_journal(remaining)
        report = reconcile_bundle(
            self.bundle_dir, self.store, pinned_public_pem=KEY_PAIR.public_pem
        )
        missing = [item["seq"] for item in report.findings if item["kind"] == "missing"]
        self.assertEqual([3, 4], missing)

    def test_prefix_rewrite_is_detected_even_if_slice_intact(self) -> None:
        # 只导出 3-6（prev 锚住 1-2 的历史链头），再删掉线上历史 1-2。
        slice_dir = make_root(prefix="bundle-slice-") / "pkg"
        export_bundle(
            self.store,
            slice_dir,
            stream="audit/events",
            seq_from=3,
            seq_to=6,
            namespace="smelter/line1",
            key_pair=KEY_PAIR,
            clock=self.clock,
        )
        rows, _ = read_raw_entries(journal_path(self.root))
        self._rewrite_journal(rows[2:])  # 删掉 1-2，保留 3-6 原样
        report = reconcile_bundle(
            slice_dir, self.store, pinned_public_pem=KEY_PAIR.public_pem
        )
        kinds = {item["kind"] for item in report.findings}
        self.assertIn("prefix-rewritten", kinds)

    def test_tail_truncation_is_reported(self) -> None:
        rows, _ = read_raw_entries(journal_path(self.root))
        self._rewrite_journal(rows[:4])  # 删掉 5-6
        report = reconcile_bundle(
            self.bundle_dir, self.store, pinned_public_pem=KEY_PAIR.public_pem
        )
        missing = [item["seq"] for item in report.findings if item["kind"] == "missing"]
        self.assertEqual([5, 6], missing)
        self.assertEqual(4, report.live_head)

    def test_deleted_state_key_is_reported(self) -> None:
        target = self.root / "data" / "oxygen" / "baseline.json"
        target.unlink()
        report = reconcile_bundle(
            self.bundle_dir, self.store, pinned_public_pem=KEY_PAIR.public_pem
        )
        self.assertIn(
            "state-missing", {item["kind"] for item in report.findings}
        )
        self.assertTrue(
            any(item.get("key") == "oxygen/baseline" for item in report.findings)
        )

    def test_tampered_bundle_is_refused_for_reconcile(self) -> None:
        shutil.copy(
            self.bundle_dir / "manifest.json",
            self.bundle_dir / "manifest.json.bak",
        )
        manifest_path = self.bundle_dir / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["package_id"] = "forged"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        report = reconcile_bundle(
            self.bundle_dir, self.store, pinned_public_pem=KEY_PAIR.public_pem
        )
        self.assertFalse(report.ok)
        self.assertTrue(all(item["kind"] == "bundle-invalid" for item in report.findings))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
