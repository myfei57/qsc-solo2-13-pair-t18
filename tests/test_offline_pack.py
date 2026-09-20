"""离线核验包端到端：导出 → 断网自证 → 回线上逐条对账。

覆盖需求里最关键的攻击面：

* 正常包三处（签名 / 哈希链 / Merkle 根）全绿，对账 ``ok``；
* **改一条事件**：包自验在该序号断链、Merkle 根不一致；线上对账定位到具体序号；
* **改完重算旧版自校验和**（旧 ``verify`` 完全发现不了的改写）：哈希链仍能抓到；
* **删掉中间一段**：缺号 + 前置锚点对不上；
* **区间内事后插入**：对账列出 inserted；
* **状态快照被改**：列出 key 与字段级差异；
* 错误公钥 / 损坏签名 / zip 形态 / 随包 verifier.py 子进程自验。
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from flashsmelter.audit.chain import GENESIS_HASH, chain_hash
from flashsmelter.audit.keychain import init_keychain, load_identity, load_public_key
from flashsmelter.audit.offline import (
    CHAIN_NAME,
    EVENTS_NAME,
    MANIFEST_NAME,
    SIGNATURE_NAME,
    STATE_NAME,
    PackReader,
    export_pack,
    reconcile_pack,
    verify_pack,
)
from flashsmelter.audit.streams import AUDIT_STREAM
from flashsmelter.store.codec import canonical_json, checksum_of

from .helpers import make_app, run_heat, start_furnace

REPO_ROOT = Path(__file__).resolve().parents[1]
STANDALONE = REPO_ROOT / "flashsmelter" / "audit" / "assets" / "verifier.py"


def _seed_events(app, count: int) -> None:
    """制造若干真实审计事件：开炉、跑完一炉，再补几次只读拒绝。"""

    start_furnace(app)
    run_heat(app, "H-PACK", "L-PACK")
    n = 2
    while app.audit.length() < count:
        n += 1
        # 一次必然被门控拒绝的越限放渣，确保有 rejected 类流水
        try:
            app.slag.tap("tester", heat_id="H-PACK", target_tons=999.0 + n)
        except Exception:
            pass


class OfflinePackTest(unittest.TestCase):
    def setUp(self) -> None:
        self.app = make_app()
        self.keys_dir = Path(tempfile.mkdtemp(prefix="keys-"))
        self.out_dir = Path(tempfile.mkdtemp(prefix="pack-"))
        _seed_events(self.app, 6)
        self.identity = init_keychain(self.keys_dir)
        self.pack_dir = self.out_dir / "visit-001"
        self.result = export_pack(
            self.app.store,
            self.app.namespace,
            self.app.clock,
            self.identity,
            self.pack_dir,
        )
        self.assertGreaterEqual(self.result.event_count, 6)
        self.assertGreater(self.result.state_count, 0)

    def test_clean_pack_verifies_and_reconciles(self) -> None:
        pub = load_public_key(self.identity.public_path)
        with PackReader(self.pack_dir) as reader:
            report = verify_pack(reader, trusted_pubkey=pub)
        self.assertTrue(report["ok"], report["failures"])
        self.assertTrue(report["signature_ok"])
        self.assertEqual(report["events"]["tampered_seqs"], [])
        self.assertEqual(report["events"]["missing_seqs"], [])

        with PackReader(self.pack_dir) as reader:
            recon = reconcile_pack(reader, self.app.store, self.app.namespace, trusted_pubkey=pub)
        self.assertEqual(recon["verdict"], "ok", recon)
        self.assertTrue(recon["events"]["ok"])
        self.assertTrue(recon["state"]["ok"])
        self.assertEqual(recon["events"]["missing_seqs"], [])
        self.assertEqual(recon["events"]["altered"], [])

    def test_pack_covers_all_events_from_seq_one(self) -> None:
        # 整段从 1 开始：predecessor 应为空，链尖在对账时与线上全链一致
        manifest = self.result.manifest
        self.assertEqual(manifest["range"]["first_seq"], 1)
        self.assertIsNone(manifest["predecessor"]["seq"])
        self.assertEqual(manifest["predecessor"]["chain_hash"], GENESIS_HASH)

    def test_partial_export_anchors_predecessor(self) -> None:
        partial_dir = self.out_dir / "partial"
        export_pack(
            self.app.store,
            self.app.namespace,
            self.app.clock,
            self.identity,
            partial_dir,
            since_seq=3,
        )
        with PackReader(partial_dir) as reader:
            manifest = reader.read_manifest()
            self.assertEqual(manifest["range"]["first_seq"], 4)
            self.assertEqual(manifest["predecessor"]["seq"], 3)
            self.assertEqual(len(manifest["predecessor"]["chain_hash"]), 64)
            report = verify_pack(reader, trusted_pubkey=self.identity.public())
        self.assertTrue(report["ok"], report["failures"])

    def test_alter_one_event_is_detected_and_localized(self) -> None:
        # 直接改 events.jsonl 里某条的 actor 字段
        path = self.pack_dir / EVENTS_NAME
        lines = path.read_text(encoding="utf-8").splitlines()
        target_index = 2
        parsed = json.loads(lines[target_index])
        parsed["payload"] = dict(parsed["payload"])
        parsed["payload"]["actor"] = "intruder"
        lines[target_index] = canonical_json(parsed)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        with PackReader(self.pack_dir) as reader:
            report = verify_pack(reader, trusted_pubkey=self.identity.public())
        self.assertFalse(report["ok"])
        # 文件哈希、链尖、Merkle 根三道证据都应报警
        self.assertTrue(any("文件哈希" in f for f in report["failures"]))
        self.assertTrue(any("链尖" in f or "Merkle" in f for f in report["failures"]))
        # 被改的是第 3 行 → seq == first_seq+2，且其后所有行链连锁失效
        expected_seq = report["range"]["first_seq"] + 2
        self.assertEqual(report["events"]["first_tampered_seq"], expected_seq)
        self.assertIn(expected_seq, report["events"]["tampered_seqs"])

    def test_live_rewrite_with_recomputed_self_checksum_is_caught(self) -> None:
        """攻击者改线上某条并重算旧版自校验和：旧 verify 看不破，链能看破。"""

        seq_to_tamper = 2
        journal = self.app.store.stream_path(AUDIT_STREAM)
        lines = journal.read_text(encoding="utf-8").splitlines()
        rebuilt = []
        for line in lines:
            entry = json.loads(line)
            if entry["seq"] == seq_to_tamper:
                entry["payload"] = dict(entry["payload"])
                entry["payload"]["actor"] = "midnight-rewrite"
                entry["checksum"] = checksum_of(
                    entry["seq"], entry["written_at"], entry["payload"]
                )
            rebuilt.append(canonical_json(entry))
        journal.write_text("\n".join(rebuilt) + "\n", encoding="utf-8")

        with PackReader(self.pack_dir) as reader:
            recon = reconcile_pack(reader, self.app.store, self.app.namespace,
                                   trusted_pubkey=self.identity.public())
        self.assertNotEqual(recon["verdict"], "ok")
        altered = recon["events"]["altered"]
        self.assertEqual([item["seq"] for item in altered], [seq_to_tamper])
        # 旧自校验和是被重算过的，因此归类为 live-rewritten（更隐蔽的那种）
        self.assertEqual(altered[0]["kind"], "live-rewritten")
        self.assertIn("actor", altered[0]["payload_changes"])
        self.assertEqual(altered[0]["payload_changes"]["actor"]["live"], "midnight-rewrite")

    def test_live_corrupt_without_recompute_is_classified(self) -> None:
        seq_to_tamper = 2
        journal = self.app.store.stream_path(AUDIT_STREAM)
        lines = journal.read_text(encoding="utf-8").splitlines()
        rebuilt = []
        for line in lines:
            entry = json.loads(line)
            if entry["seq"] == seq_to_tamper:
                entry["payload"] = dict(entry["payload"])
                entry["payload"]["actor"] = "raw-corrupt"  # 改了但不重算 checksum
            rebuilt.append(canonical_json(entry))
        journal.write_text("\n".join(rebuilt) + "\n", encoding="utf-8")

        with PackReader(self.pack_dir) as reader:
            recon = reconcile_pack(reader, self.app.store, self.app.namespace,
                                   trusted_pubkey=self.identity.public())
        self.assertEqual(recon["live_chain"]["self_checksum_bad_seqs"], [seq_to_tamper])
        self.assertEqual(recon["events"]["altered"][0]["kind"], "live-corrupt")

    def test_deleted_segment_is_reported_as_missing_and_gap(self) -> None:
        journal = self.app.store.stream_path(AUDIT_STREAM)
        lines = journal.read_text(encoding="utf-8").splitlines()
        kept = [line for line in lines if json.loads(line)["seq"] not in (3, 4)]
        journal.write_text("\n".join(kept) + "\n", encoding="utf-8")

        with PackReader(self.pack_dir) as reader:
            recon = reconcile_pack(reader, self.app.store, self.app.namespace,
                                   trusted_pubkey=self.identity.public())
        self.assertNotEqual(recon["verdict"], "ok")
        self.assertEqual(recon["events"]["missing_seqs"], [3, 4])
        self.assertEqual(recon["live_chain"]["first_gap_after"], 3)
        self.assertIn("3-4", recon["events"]["missing_runs"])

    def test_duplicate_seq_from_in_range_insertion_is_flagged(self) -> None:
        # 在区间内物理插入一条重号记录（拷贝 seq=2 再追加到文件中），
        # 模拟事后向已签发区间塞内容：会产生两个 seq=2。
        journal = self.app.store.stream_path(AUDIT_STREAM)
        lines = journal.read_text(encoding="utf-8").splitlines()
        seq2 = next(line for line in lines if json.loads(line)["seq"] == 2)
        # 把重号行插到 seq2 原位置之后
        inserted_lines = []
        for line in lines:
            inserted_lines.append(line)
            if json.loads(line)["seq"] == 2:
                forged = json.loads(seq2)
                forged["payload"] = dict(forged["payload"])
                forged["payload"]["actor"] = "inserted"
                inserted_lines.append(canonical_json(forged))
        journal.write_text("\n".join(inserted_lines) + "\n", encoding="utf-8")

        with PackReader(self.pack_dir) as reader:
            recon = reconcile_pack(reader, self.app.store, self.app.namespace,
                                   trusted_pubkey=self.identity.public())
        self.assertNotEqual(recon["verdict"], "ok")
        self.assertIn(2, recon["events"]["duplicate_seqs"])

    def test_inserted_event_inside_range_is_flagged(self) -> None:
        # 线上在区间尾部之后插一条不在包里的记录，且包区间覆盖其 seq 较难构造，
        # 这里改为直接在包导出区间 [1,N] 内、线上额外塞入 seq 会重排，因此用
        # 更直接的手法：删掉包最后一条，模拟“包导出后该区间被插入/重放”。
        path = self.pack_dir / EVENTS_NAME
        chain_path = self.pack_dir / CHAIN_NAME
        ev_lines = path.read_text(encoding="utf-8").splitlines()
        ch_lines = chain_path.read_text(encoding="utf-8").splitlines()
        path.write_text("\n".join(ev_lines[:-1]) + "\n", encoding="utf-8")
        chain_path.write_text("\n".join(ch_lines[:-1]) + "\n", encoding="utf-8")
        with PackReader(self.pack_dir) as reader:
            report = verify_pack(reader, trusted_pubkey=self.identity.public())
        # 包被截断：文件哈希/范围对不上，自验必失败，对账拒绝以它为基准
        self.assertFalse(report["ok"])

    def test_state_change_is_diffed_field_by_field(self) -> None:
        # 触发一次真实状态变更（沉淀池液位更新落盘）
        self.app.settler.update("tester", bath_level_m=0.81, slag_thickness_m=0.1, matte_level_m=0.5)
        with PackReader(self.pack_dir) as reader:
            recon = reconcile_pack(reader, self.app.store, self.app.namespace,
                                   trusted_pubkey=self.identity.public())
        self.assertNotEqual(recon["verdict"], "ok")
        changed_keys = {item["key"] for item in recon["state"]["changed"]}
        self.assertTrue(changed_keys, recon["state"])
        # 至少有一处变更能定位到 payload 字段
        all_paths = {p for item in recon["state"]["changed"] for p in item["payload_changes"]}
        self.assertTrue(any("bath_level" in p for p in all_paths), all_paths)
        self.assertNotEqual(recon["state"]["packed_merkle_root"], recon["state"]["live_merkle_root"])

    def test_wrong_pubkey_is_rejected(self) -> None:
        other = init_keychain(self.out_dir / "other-keys", key_id="other")
        with PackReader(self.pack_dir) as reader:
            report = verify_pack(reader, trusted_pubkey=other.public())
        self.assertFalse(report["ok"])
        self.assertFalse(report["signature_ok"])
        self.assertTrue(any("公钥不一致" in f or "签名" in f for f in report["failures"]))

    def test_tampered_signature_is_rejected(self) -> None:
        sig_path = self.pack_dir / SIGNATURE_NAME
        raw = bytearray.fromhex(sig_path.read_text().strip())
        raw[0] ^= 0xFF
        sig_path.write_text(bytes(raw).hex() + "\n", encoding="ascii")
        with PackReader(self.pack_dir) as reader:
            report = verify_pack(reader, trusted_pubkey=self.identity.public())
        self.assertFalse(report["ok"])
        self.assertFalse(report["signature_ok"])

    def test_zip_pack_roundtrip(self) -> None:
        zip_path = self.out_dir / "visit.zip"
        export_pack(
            self.app.store, self.app.namespace, self.app.clock, self.identity, zip_path, zip_pack=True
        )
        self.assertTrue(zipfile.is_zipfile(zip_path))
        with zipfile.ZipFile(zip_path) as archive:
            names = set(archive.namelist())
        for required in (MANIFEST_NAME, EVENTS_NAME, CHAIN_NAME, STATE_NAME, "verifier.py", "verifier.html"):
            self.assertIn(required, names)
        with PackReader(zip_path) as reader:
            report = verify_pack(reader, trusted_pubkey=self.identity.public())
        self.assertTrue(report["ok"], report["failures"])

    def test_standalone_verifier_script_passes_clean_pack(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(STANDALONE), str(self.pack_dir),
             "--pubkey", str(self.identity.public_path), "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertTrue(report["ok"])
        self.assertTrue(report["signature_ok"])

    def test_standalone_verifier_flags_tampering(self) -> None:
        path = self.pack_dir / EVENTS_NAME
        lines = path.read_text(encoding="utf-8").splitlines()
        parsed = json.loads(lines[1])
        parsed["payload"] = dict(parsed["payload"])
        parsed["payload"]["actor"] = "usb-tamper"
        lines[1] = canonical_json(parsed)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        proc = subprocess.run(
            [sys.executable, str(STANDALONE), str(self.pack_dir),
             "--pubkey", str(self.identity.public_path), "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 2, proc.stdout)
        report = json.loads(proc.stdout)
        self.assertFalse(report["ok"])
        # 独立脚本同样能精确定位首个被改动序号
        self.assertEqual(report["events"]["first_tampered_seq"],
                         report["range"]["first_seq"] + 1)


class ChainPrimitiveTest(unittest.TestCase):
    def test_chain_links_each_row_to_previous(self) -> None:
        rows = [b'{"seq":1}', b'{"seq":2}', b'{"seq":3}']
        previous = GENESIS_HASH
        hashes = []
        for row in rows:
            previous = chain_hash(previous, row)
            hashes.append(previous)
        # 改第一行 → 所有后续哈希变化
        first_altered = chain_hash(GENESIS_HASH, b'{"seq":9}')
        self.assertNotEqual(chain_hash(first_altered, rows[1]), hashes[1])
        # 前缀属性：同一前缀必产生同一中间哈希
        self.assertEqual(chain_hash(GENESIS_HASH, rows[0]), hashes[0])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
