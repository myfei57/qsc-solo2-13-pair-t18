"""CLI：状态、动作、审计、校验与退出码。"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest

from .helpers import make_root


def run_cli(*args: str, root):
    completed = subprocess.run(
        [sys.executable, "-m", "flashsmelter", "--root", str(root), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )
    return completed


class CliTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = make_root("flashsmelter-cli-")

    def _json(self, completed: subprocess.CompletedProcess) -> dict:
        self.assertTrue(completed.stdout.strip(), msg=completed.stderr)
        return json.loads(completed.stdout)

    def test_version_and_help(self) -> None:
        completed = run_cli("--version", root=self.root)
        self.assertEqual(0, completed.returncode)
        self.assertIn("1.0.0", completed.stdout)
        completed = run_cli(root=self.root)
        self.assertEqual(1, completed.returncode)
        self.assertIn("flashsmelter", completed.stdout)

    def test_status_actions_and_verify(self) -> None:
        status = run_cli("status", root=self.root)
        self.assertEqual(0, status.returncode)
        payload = self._json(status)
        self.assertEqual("smelter/line1", payload["service"]["namespace"]["prefix"])
        self.assertEqual("smelter", payload["service"]["namespace"]["site"])
        self.assertEqual("cold", payload["components"]["furnace"]["state"]["state"])
        actions = run_cli("actions", root=self.root)
        names = {item["action"] for item in self._json(actions)["actions"]}
        self.assertIn("furnace.start", names)
        verify = run_cli("verify", root=self.root)
        self.assertEqual(0, verify.returncode)
        self.assertTrue(self._json(verify)["ok"])
        component = run_cli("status", "--component", "oxygen", root=self.root)
        self.assertEqual(0, component.returncode)
        self.assertEqual("oxygen", self._json(component)["name"])

    def test_call_sequence_and_audit(self) -> None:
        baseline = run_cli(
            "call", "oxygen.set_baseline", "--param", "value=0.62", "--param", "source=analyzer-a", root=self.root
        )
        self.assertEqual(0, baseline.returncode)
        started = run_cli(
            "call",
            "furnace.start",
            "--params-json",
            json.dumps(
                {
                    "drum_level": 0.6,
                    "fuel_pressure_kpa": 200.0,
                    "air_flow_nm3h": 5200.0,
                    "oxygen_baseline": 0.62,
                    "oxygen_baseline_source": "analyzer-a",
                    "oxygen_target": 0.62,
                    "oxygen_flow_nm3h": 9000.0,
                }
            ),
            root=self.root,
        )
        self.assertEqual(0, started.returncode)
        self.assertEqual("oxygen_ready", self._json(started)["result"]["state"])
        audit = run_cli("audit", "--limit", "5", "--action", "start", root=self.root)
        self.assertEqual(0, audit.returncode)
        events = self._json(audit)["events"]
        self.assertTrue(events)
        self.assertTrue(all(event["action"] == "start" for event in events))
        heat = run_cli("heat", "--limit", "2", root=self.root)
        self.assertEqual(0, heat.returncode)
        self.assertIn("current", self._json(heat))

    def test_failed_call_returns_error_payload(self) -> None:
        completed = run_cli("call", "furnace.feed", "--param", "heat_id=H1", root=self.root)
        self.assertEqual(1, completed.returncode)
        payload = self._json(completed)
        self.assertIn("error", payload)
        unknown = run_cli("call", "nope.nope", root=self.root)
        self.assertEqual(1, unknown.returncode)
        self.assertEqual("validation-error", self._json(unknown)["error"])

    def test_offline_pack_cli_lifecycle(self) -> None:
        from pathlib import Path

        keys_dir = self.root / "keys"
        pack_dir = self.root / "visit"

        created = run_cli("keychain-init", "--keys-dir", str(keys_dir), root=self.root)
        self.assertEqual(0, created.returncode)
        self.assertEqual(16, len(self._json(created)["fingerprint"]))

        # 没有流水时导出应失败（避免空包当证据）
        empty = run_cli("pack-export", str(pack_dir), "--keys-dir", str(keys_dir), root=self.root)
        self.assertNotEqual(0, empty.returncode)

        run_cli(
            "call", "furnace.start",
            "--params-json", json.dumps({
                "drum_level": 0.6, "fuel_pressure_kpa": 200.0, "air_flow_nm3h": 5200.0,
                "oxygen_baseline": 0.62, "oxygen_baseline_source": "analyzer-a",
                "oxygen_target": 0.62, "oxygen_flow_nm3h": 9000.0,
            }),
            root=self.root,
        )

        exported = run_cli("pack-export", str(pack_dir), "--keys-dir", str(keys_dir), root=self.root)
        self.assertEqual(0, exported.returncode, exported.stderr)
        self.assertGreaterEqual(self._json(exported)["event_count"], 1)
        self.assertTrue((pack_dir / "verifier.py").exists())

        pubkey = keys_dir / "line1.pub"
        verified = run_cli("pack-verify", str(pack_dir), "--pubkey", str(pubkey), root=self.root)
        self.assertEqual(0, verified.returncode, verified.stdout)
        self.assertTrue(self._json(verified)["ok"])

        reconciled = run_cli("pack-reconcile", str(pack_dir), "--pubkey", str(pubkey), root=self.root)
        self.assertEqual(0, reconciled.returncode, reconciled.stdout)
        self.assertEqual("ok", self._json(reconciled)["verdict"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
