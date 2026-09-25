#!/usr/bin/env python3
"""record/replay 子命令回归：热加载事件流的录制日志与重放。

仅用标准库；通过 `python switch.py record CONFIG EVENTS LOG`
与 `python switch.py replay LOG` 端到端驱动。
"""

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SWITCH = os.path.join(HERE, "switch.py")

from test_reload import base_config, frame  # noqa: E402


def run_cli(*args):
    proc = subprocess.run(
        [sys.executable, SWITCH, *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return proc.returncode, proc.stdout, proc.stderr


def write_json(tmp, name, value):
    path = os.path.join(tmp, name)
    with open(path, "wb") as handle:
        handle.write(json.dumps(value).encode("utf-8"))
    return path


def linked_config():
    """base_config 加一条 b1-p6 <-> b2-x 的初始 up 链路。"""
    config = base_config()
    config["bridges"] = ["b1", "b2"]
    config["links"] = [
        {"id": "L", "x": ["b1", "p6"], "y": ["b2", "x"],
         "cost": 1, "up": True}
    ]
    config["ports"].append(
        {"name": "p6", "mode": "access", "pvid": 1,
         "allowed": [1], "untagged": [1], "up": True}
    )
    config["security"].append(
        {"port": "p6", "limit": 2, "action": "drop", "static": []}
    )
    return config


def log_digest(log):
    header = {key: log[key] for key in ("schema", "config", "records")}
    text = json.dumps(header, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256((text + "\n").encode("utf-8")).hexdigest()


def resign(log):
    """篡改后重算 sha256，使日志越过摘要校验进入逐项核对。"""
    log["sha256"] = log_digest(log)
    return log


class RecordReplayTest(unittest.TestCase):
    def _run(self, config, events, *, extras=("log.json",)):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        cfg = write_json(tmp.name, "config.json", config)
        evt = write_json(tmp.name, "events.json", events)
        log_path = os.path.join(tmp.name, *extras)
        code, out, err = run_cli("reload", cfg, evt)
        self.assertEqual(code, 0, err)
        code, rec_out, err = run_cli("record", cfg, evt, log_path)
        self.assertEqual(code, 0, err)
        self.assertEqual(rec_out, out)  # 成功输出与 reload 逐字节相同
        with open(log_path, "rb") as handle:
            log_raw = handle.read()
        self.assertTrue(log_raw.endswith(b"\n"))
        code, rep_out, err = run_cli("replay", log_path)
        self.assertEqual(code, 0, err)
        self.assertEqual(rep_out, out)  # replay 输出与 record 逐字节相同
        return json.loads(log_raw.decode("utf-8")), out

    def test_log_shape_and_key_order(self):
        new = copy.deepcopy(base_config())
        new["age"] = 5
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "config": new},
            {"t": 2, "config": copy.deepcopy(new)},  # 无变化也算一次
        ]
        log, _ = self._run(base_config(), events)
        self.assertEqual(list(log), ["schema", "config", "records", "sha256"])
        self.assertEqual(log["schema"], 1)
        self.assertRegex(log["sha256"], r"[0-9a-f]{64}\Z")
        self.assertEqual(log["sha256"], log_digest(log))
        self.assertEqual(log["config"]["age"], 100)  # 初始配置
        self.assertEqual(list(log["config"]), sorted(log["config"]))
        self.assertEqual(len(log["records"]), 3)
        for record in log["records"]:
            self.assertEqual(
                list(record), ["t", "version", "event", "applied", "output"]
            )

    def test_version_increments_every_reload(self):
        new = copy.deepcopy(base_config())
        new["age"] = 5
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "config": new},
            frame(2, "p1", "00:00:00:00:00:02"),
            {"t": 3, "config": copy.deepcopy(new)},  # 无变化仍加 1
            {"t": 4, "port": "p3", "count": 1},
        ]
        log, out = self._run(base_config(), events)
        self.assertEqual(
            [r["version"] for r in log["records"]], [0, 1, 1, 2, 2]
        )
        results = json.loads(out.decode("utf-8"))["results"]
        for record, event, result in zip(log["records"], events, results):
            self.assertEqual(record["t"], event["t"])
            self.assertEqual(record["event"], event)  # 原事件
            self.assertIs(record["applied"], True)
            self.assertEqual(record["output"], result)  # 新增 results 项

    def test_applied_only_false_for_idempotent_link_member(self):
        config = linked_config()
        events = [
            {"t": 0, "id": "L", "up": False},  # 状态翻转
            {"t": 1, "id": "L", "up": False},  # 幂等
            {"t": 2, "id": "L", "up": True},   # 翻转
            {"t": 3, "member": "p4", "up": False},
            {"t": 4, "member": "p4", "up": False},  # 幂等
            frame(5, "p1", "00:00:00:00:00:01"),
        ]
        log, _ = self._run(config, events)
        self.assertEqual(
            [r["applied"] for r in log["records"]],
            [True, False, True, True, False, True],
        )
        # 链路/成员事件不产生 results 项：output 为 null
        for index in (0, 1, 2, 3, 4):
            self.assertIsNone(log["records"][index]["output"])
        self.assertIsNotNone(log["records"][5]["output"])

    def test_empty_events(self):
        log, out = self._run(base_config(), [])
        self.assertEqual(log["records"], [])
        self.assertEqual(log["sha256"], log_digest(log))

    def test_record_invalid_does_not_touch_log(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["security"][0]["limit"] = 1
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            frame(1, "p1", "00:00:00:00:00:02"),
            {"t": 2, "config": new},  # 动态绑定超新 limit
        ]
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write_json(tmp, "config.json", config)
            evt = write_json(tmp, "events.json", events)
            log_path = os.path.join(tmp, "log.json")
            with open(log_path, "wb") as handle:
                handle.write(b"PREEXISTING")
            code, out, err = run_cli("record", cfg, evt, log_path)
            self.assertEqual(code, 4)
            self.assertEqual(out, b"")
            self.assertEqual(err, b'{"error":"invalid_input"}\n')
            with open(log_path, "rb") as handle:
                self.assertEqual(handle.read(), b"PREEXISTING")

    def test_record_missing_input_is_file_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, err = run_cli(
                "record", os.path.join(tmp, "no"), os.path.join(tmp, "x"),
                os.path.join(tmp, "log"),
            )
            self.assertEqual((code, out, err),
                             (3, b"", b'{"error":"file_not_found"}\n'))

    def test_record_unwritable_log_is_file_error(self):
        config = base_config()
        events = [frame(0, "p1", "00:00:00:00:00:01")]
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write_json(tmp, "config.json", config)
            evt = write_json(tmp, "events.json", events)
            target = os.path.join(tmp, "dir")
            os.mkdir(target)  # 目标为目录：原子替换失败
            code, out, err = run_cli("record", cfg, evt, target)
            self.assertEqual((code, out, err),
                             (3, b"", b'{"error":"file_not_found"}\n'))

    def test_record_missing_log_directory_is_file_error(self):
        config = base_config()
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write_json(tmp, "config.json", config)
            evt = write_json(tmp, "events.json", [])
            target = os.path.join(tmp, "nodir", "log.json")
            code, _, _ = run_cli("record", cfg, evt, target)
            self.assertEqual(code, 3)
            self.assertFalse(os.path.exists(os.path.join(tmp, "nodir")))


class ReplayInvalidTest(unittest.TestCase):
    def _record(self, config, events):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        cfg = write_json(self.tmp.name, "config.json", config)
        evt = write_json(self.tmp.name, "events.json", events)
        self.log_path = os.path.join(self.tmp.name, "log.json")
        code, _, err = run_cli("record", cfg, evt, self.log_path)
        self.assertEqual(code, 0, err)
        with open(self.log_path, "rb") as handle:
            return json.loads(handle.read().decode("utf-8"))

    def _write_log(self, log):
        path = os.path.join(self.tmp.name, "other.json")
        with open(path, "wb") as handle:
            handle.write(
                (json.dumps(log, ensure_ascii=False,
                            separators=(",", ":")) + "\n").encode("utf-8")
            )
        return path

    def _assert_invalid(self, log):
        path = self._write_log(log)
        code, out, err = run_cli("replay", path)
        self.assertEqual((code, out, err),
                         (4, b"", b'{"error":"invalid_input"}\n'))

    def test_bad_sha(self):
        log = self._record(base_config(),
                           [frame(0, "p1", "00:00:00:00:00:01")])
        log["sha256"] = "0" * 64
        self._assert_invalid(log)

    def test_tampered_record_field(self):
        events = [frame(0, "p1", "00:00:00:00:00:01")]
        log = self._record(base_config(), events)
        log["records"][0]["version"] = 99
        self._assert_invalid(resign(log))
        log = self._record(base_config(), events)
        log["records"][0]["t"] = 7
        self._assert_invalid(resign(log))
        log = self._record(base_config(), events)
        log["records"][0]["applied"] = False
        self._assert_invalid(resign(log))
        log = self._record(base_config(), events)
        log["records"][0]["output"]["action"] = "bogus"
        self._assert_invalid(resign(log))
        log = self._record(base_config(), events)
        log["records"][0]["event"]["t"] = 5
        self._assert_invalid(resign(log))

    def test_tampered_config_rejected_by_validation(self):
        log = self._record(base_config(),
                           [frame(0, "p1", "00:00:00:00:00:01")])
        log["config"]["age"] = -1
        self._assert_invalid(resign(log))

    def test_extra_record_mismatch(self):
        log = self._record(
            base_config(),
            [frame(0, "p1", "00:00:00:00:00:01"),
             frame(1, "p1", "00:00:00:00:00:02")],
        )
        # 追加一条事件合法、但 output 伪造为 null 的记录：长度等长仍须被核对出
        log["records"].append(
            {
                "t": 2,
                "version": 0,
                "event": frame(2, "p1", "00:00:00:00:00:03"),
                "applied": True,
                "output": None,
            }
        )
        self._assert_invalid(resign(log))

    def test_shape_errors(self):
        good = self._record(base_config(), [])
        for mutate in (
            lambda l: l.pop("sha256"),
            lambda l: l.update(schema=2),
            lambda l: l.update(records={}),
            lambda l: l.update(config=[]),
            lambda l: l["records"].append(
                {"t": 0, "version": 0, "event": {}, "applied": True,
                 "output": None, "x": 1}),
        ):
            log = copy.deepcopy(good)
            mutate(log)
            self._assert_invalid(log)

    def test_malformed_bytes(self):
        self._record(base_config(), [])
        for raw in (
            b"not json\n",
            b"[1,2]\n",
            b"{}\n",
            b'{"schema":1,"config":{},"records":[],"sha256":"x"}\n',
            b'{"schema":1,"schema":2,"config":{},"records":[],'
            b'"sha256":"00"}\n',
        ):
            path = os.path.join(self.tmp.name, "raw.json")
            with open(path, "wb") as handle:
                handle.write(raw)
            code, out, _ = run_cli("replay", path)
            self.assertEqual((code, out), (4, b""), raw)

    def test_missing_log_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, err = run_cli("replay", os.path.join(tmp, "nope"))
            self.assertEqual((code, out, err),
                             (3, b"", b'{"error":"file_not_found"}\n'))


class UsageTest(unittest.TestCase):
    def test_usage(self):
        for args in (
            (),
            ("record",),
            ("record", "a", "b"),
            ("replay",),
            ("replay", "a", "b"),
            ("bogus", "a", "b"),
        ):
            with self.subTest(args=args):
                code, out, err = run_cli(*args)
                self.assertEqual((code, out, err),
                                 (2, b"", b'{"error":"usage"}\n'))


if __name__ == "__main__":
    unittest.main()
