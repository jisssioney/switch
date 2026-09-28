#!/usr/bin/env python3
"""record / replay 对 fdb 模式的回归。

fdb 形态：config 恰含 ports,age 且 ports 为非空字符串端口名数组；事件为
{t,port,mac,vlan}。record 的 stdout 须与直接 `fdb` 子命令逐字节相同，
replay 的 stdout 须与 record 逐字节相同；LOG 键序
schema,config,records,sha256，记录项键序 t,version,event,applied,output，
event 为规范化原事件、output 恒 null；事件处理后含 port、seen 的 FDB
不同于事件前则 applied=true，version 初值 0 且仅 applied 时递增；工作量
逐事件按老化前表项数 K 累计 K+1，等于上限合法，首次超限退出 5。
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SWITCH = os.path.join(HERE, "switch.py")

LOG_KEYS = ["schema", "config", "records", "sha256"]
RECORD_KEYS = ["t", "version", "event", "applied", "output"]


def fdb_config(ports=("p1", "p2", "p3"), age=10):
    return {"ports": list(ports), "age": age}


def ev(t, port, mac="00:00:00:00:00:01", vlan=1):
    return {"t": t, "port": port, "mac": mac, "vlan": vlan}


def run_cli(args, files=None):
    with tempfile.TemporaryDirectory() as tmp:
        paths = {}
        for name, content in (files or {}).items():
            path = os.path.join(tmp, name)
            with open(path, "wb") as handle:
                handle.write(content)
            paths[name] = path
        argv = [sys.executable, SWITCH, args[0]] + [
            paths.get(a, os.path.join(tmp, a)) for a in args[1:]
        ]
        proc = subprocess.run(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        logs = {}
        for name in os.listdir(tmp):
            if name.endswith(".log"):
                with open(os.path.join(tmp, name), "rb") as handle:
                    logs[name] = handle.read()
    return proc.returncode, proc.stdout, proc.stderr, logs


def write_inputs(config, events):
    return {
        "config.json": json.dumps(config).encode("utf-8"),
        "events.json": json.dumps(events).encode("utf-8"),
    }


def record_raw(config, events, *limits):
    files = write_inputs(config, events)
    args = ["record", "config.json", "events.json", "out.log", *limits]
    return run_cli(args, files)


def record(config, events):
    code, out, err, logs = record_raw(config, events)
    assert code == 0, (code, err.decode())
    return out, logs["out.log"]


def fdb_stdout(config, events):
    code, out, err, _ = run_cli(
        ["fdb", "config.json", "events.json"], write_inputs(config, events)
    )
    assert code == 0, (code, err.decode())
    return out


def replay(log_bytes, *limits):
    files = {"in.log": log_bytes}
    args = ["replay", "in.log", *limits]
    code, out, err, _ = run_cli(args, files)
    return code, out, err


def prefix_digest(doc):
    prefix = {
        "schema": doc["schema"],
        "config": doc["config"],
        "records": doc["records"],
    }
    raw = (
        json.dumps(prefix, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class FdbRecordBasicTest(unittest.TestCase):
    def test_record_stdout_byte_identical_to_direct_fdb(self):
        config = fdb_config()
        events = [
            ev(0, "p1", "00:00:00:00:00:01"),
            ev(5, "p2", "00:00:00:00:00:02"),
            ev(20, "p3", "00:00:00:00:00:03"),
        ]
        out, log_bytes = record(config, events)
        self.assertEqual(out, fdb_stdout(config, events))
        self.assertTrue(out.endswith(b"\n"))
        # 末态：前两项于 t=20 老化（20-seen>=10）
        self.assertEqual(
            json.loads(out.decode()),
            {"fdb": [{"vlan": 1, "mac": "00:00:00:00:00:03",
                      "port": "p3", "seen": 20}]},
        )
        code, replay_out, err = replay(log_bytes)
        self.assertEqual(code, 0, err)
        self.assertEqual(replay_out, out)

    def test_empty_events(self):
        config = fdb_config()
        out, log_bytes = record(config, [])
        self.assertEqual(out, b'{"fdb":[]}\n')
        self.assertEqual(out, fdb_stdout(config, []))
        doc = json.loads(log_bytes.decode())
        self.assertEqual(list(doc), LOG_KEYS)
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["records"], [])
        code, replay_out, err = replay(log_bytes)
        self.assertEqual(code, 0, err)
        self.assertEqual(replay_out, out)

    def test_log_shape_and_canonical_event(self):
        config = fdb_config()
        events = [ev(0, "p1")]
        _, log_bytes = record(config, events)
        doc = json.loads(log_bytes.decode())
        self.assertEqual(list(doc), LOG_KEYS)
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["config"], {"age": 10, "ports": ["p1", "p2", "p3"]})
        self.assertEqual(len(doc["records"]), 1)
        rec = doc["records"][0]
        self.assertEqual(list(rec), RECORD_KEYS)
        self.assertEqual(rec["t"], 0)
        self.assertEqual(rec["version"], 1)
        # 规范化原事件：键按码点升序 mac,port,t,vlan
        self.assertEqual(
            rec["event"],
            {"mac": "00:00:00:00:00:01", "port": "p1", "t": 0, "vlan": 1},
        )
        self.assertEqual(list(rec["event"]), ["mac", "port", "t", "vlan"])
        self.assertIs(rec["applied"], True)
        self.assertIsNone(rec["output"])
        self.assertEqual(doc["sha256"], prefix_digest(doc))
        self.assertTrue(log_bytes.endswith(b"\n"))

    def test_records_align_one_per_event(self):
        config = fdb_config()
        events = [ev(i, "p1", "00:00:00:00:00:%02x" % (i + 1))
                  for i in range(4)]
        _, log_bytes = record(config, events)
        doc = json.loads(log_bytes.decode())
        self.assertEqual([r["t"] for r in doc["records"]], [0, 1, 2, 3])

    def test_unsorted_input_keys_round_trip_byte_identical(self):
        # 输入键序任意：record 规范化后写 LOG；replay 重建逐字节一致
        config = {"age": 10, "ports": ["p1", "p2"]}
        events = [{"vlan": 1, "mac": "00:00:00:00:00:01",
                   "t": 0, "port": "p1"}]
        out, log_bytes = record(config, events)
        self.assertEqual(out, fdb_stdout(config, events))
        code, replay_out, err = replay(log_bytes)
        self.assertEqual(code, 0, err)
        self.assertEqual(replay_out, out)


class FdbAppliedVersionTest(unittest.TestCase):
    def setUp(self):
        # age=10；下列事件刻意覆盖：新学习、同时刻重复（不变）、seen 刷新、
        # 迁移、老化后学习
        self.config = fdb_config(age=10)
        self.events = [
            ev(0, "p1", "00:00:00:00:00:01"),   # 新学习 applied
            ev(0, "p1", "00:00:00:00:00:01"),   # 完全重复：FDB 不变
            ev(1, "p1", "00:00:00:00:00:01"),   # seen 0->1 applied
            ev(1, "p2", "00:00:00:00:00:01"),   # 迁移 p1->p2 applied
            ev(20, "p3", "00:00:00:00:00:02"),  # 旧项老化+新学习 applied
        ]

    def _records(self):
        _, log_bytes = record(self.config, self.events)
        return json.loads(log_bytes.decode())["records"]

    def test_applied_flags(self):
        records = self._records()
        self.assertEqual(
            [r["applied"] for r in records],
            [True, False, True, True, True],
        )

    def test_version_bumps_only_when_applied(self):
        records = self._records()
        self.assertEqual(
            [r["version"] for r in records],
            [1, 1, 2, 3, 4],
        )

    def test_output_always_null(self):
        for rec in self._records():
            self.assertIsNone(rec["output"])

    def test_aging_keeps_working_table_consistent(self):
        out, _ = record(self.config, self.events)
        # t=20：(1,m1) 已老化，仅剩 (1,m2)->p3
        self.assertEqual(
            json.loads(out.decode()),
            {"fdb": [{"vlan": 1, "mac": "00:00:00:00:00:02",
                      "port": "p3", "seen": 20}]},
        )


class FdbModeDetectionTest(unittest.TestCase):
    def test_string_ports_is_fdb_mode(self):
        # 能通过 fdb 校验并产出 fdb 形态输出即进入 fdb 模式
        out, log_bytes = record(fdb_config(age=10), [ev(0, "p1")])
        self.assertEqual(json.loads(out.decode())["fdb"][0]["port"], "p1")
        doc = json.loads(log_bytes.decode())
        self.assertEqual(doc["records"][0]["version"], 1)

    def test_object_ports_config_not_fdb_and_invalid(self):
        # ports 为端口对象数组时不是 fdb 模式（无任何模式接受该形状）
        config = {"ports": [{"name": "p1", "vlan": 1, "up": True}], "age": 10}
        code, out, err, logs = record_raw(config, [{"t": 0}])
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertNotIn("out.log", logs)

    def test_bad_config_and_events_are_invalid(self):
        cases = [
            (fdb_config(age=0), [ev(0, "p1")]),          # age 非正
            (fdb_config(age="10"), [ev(0, "p1")]),       # age 类型错
            (fdb_config(ports=("p1", "p1")), [ev(0, "p1")]),  # 端口重名
            (fdb_config(), [ev(0, "p9")]),               # 未知端口
            (fdb_config(), [ev(0, "p1", "ff:ff:ff:ff:ff:ff")]),  # 广播 MAC
            (fdb_config(), [ev(0, "p1", vlan=4095)]),    # vlan 越界
            (fdb_config(), [ev(-1, "p1")]),              # t 负
            (fdb_config(), [ev(1, "p1"), ev(0, "p2")]),  # t 倒序
        ]
        for config, events in cases:
            with self.subTest(config=config, events=events):
                code, out, err, logs = record_raw(config, events)
                self.assertEqual(code, 4)
                self.assertEqual(out, b"")
                self.assertEqual(err, b'{"error":"invalid_input"}\n')
                self.assertNotIn("out.log", logs)

    def test_records_event_kind_rejects_other_shapes(self):
        # fdb LOG 中混入其他形态事件即便重算摘要也按非法输入拒绝
        _, log_bytes = record(fdb_config(), [ev(0, "p1")])
        doc = json.loads(log_bytes.decode())
        doc["records"][0]["event"] = {"t": 0, "id": "L1", "up": True}
        doc["sha256"] = prefix_digest(doc)
        code, out, err = replay(json.dumps(doc).encode())
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')


class FdbWorkLimitTest(unittest.TestCase):
    # 逐事件 K+1（K 为老化前表项数）：
    # t=0  学 m1：K=0 -> 1
    # t=1  学 m2：K=1 -> 2（累计 3）
    # t=100 学 m3：老化前 K=2 -> 3（累计 6，随后两项老化）
    TOTAL = 6

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.cfg = os.path.join(d, "config.json")
        self.evt = os.path.join(d, "events.json")
        self.log = os.path.join(d, "out.log")
        self.config = fdb_config(age=10)
        self.events = [
            ev(0, "p1", "00:00:00:00:00:01"),
            ev(1, "p2", "00:00:00:00:00:02"),
            ev(100, "p3", "00:00:00:00:00:03"),
        ]
        with open(self.cfg, "wb") as handle:
            handle.write(json.dumps(self.config).encode())
        with open(self.evt, "wb") as handle:
            handle.write(json.dumps(self.events).encode())
        rec = subprocess.run(
            [sys.executable, SWITCH, "record", self.cfg, self.evt, self.log],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(rec.returncode, 0, rec.stderr)
        self.record_out = rec.stdout
        with open(self.log, "rb") as handle:
            self.log_bytes = handle.read()

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, *args):
        proc = subprocess.run(
            [sys.executable, SWITCH, *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        return proc.returncode, proc.stdout, proc.stderr

    def test_equal_limit_is_legal_and_byte_identical(self):
        code, out, err = self._run(
            "record", self.cfg, self.evt, self.log,
            "100000", "16777216", "1048576", "16777216", "16777216",
            str(self.TOTAL),
        )
        self.assertEqual((code, err), (0, b""))
        self.assertEqual(out, self.record_out)
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)

    def test_record_first_exceed_exit5_no_stdout_no_log(self):
        os.unlink(self.log)
        code, out, err = self._run(
            "record", self.cfg, self.evt, self.log,
            "100000", "16777216", "1048576", "16777216", "16777216",
            str(self.TOTAL - 1),
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"record_work_limit"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_record_exceed_does_not_replace_existing_log(self):
        code, out, err = self._run(
            "record", self.cfg, self.evt, self.log,
            "100000", "16777216", "1048576", "16777216", "16777216",
            str(self.TOTAL - 1),
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"record_work_limit"}\n')
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)

    def test_replay_equal_legal(self):
        code, out, err = self._run(
            "replay", self.log, "100000", "16777216", "16777216",
            str(self.TOTAL),
        )
        self.assertEqual((code, err), (0, b""))
        self.assertEqual(out, self.record_out)

    def test_replay_first_exceed_exit5_and_keeps_log(self):
        code, out, err = self._run(
            "replay", self.log, "100000", "16777216", "16777216",
            str(self.TOTAL - 1),
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"replay_work_limit"}\n')
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)

    def test_bad_work_token_is_usage(self):
        for token in ("0", "-1", "1x"):
            with self.subTest(token=token):
                code, out, err = self._run(
                    "record", self.cfg, self.evt, self.log,
                    "100000", "16777216", "1048576", "16777216", "16777216",
                    token,
                )
                self.assertEqual((code, out), (2, b""))
                self.assertEqual(err, b'{"error":"usage"}\n')


class FdbReplayVerifyTest(unittest.TestCase):
    def setUp(self):
        self.config = fdb_config(age=10)
        self.events = [
            ev(0, "p1", "00:00:00:00:00:01"),
            ev(0, "p1", "00:00:00:00:00:01"),  # 重复 -> not applied
            ev(5, "p2", "00:00:00:00:00:01"),  # 迁移
        ]
        _, self.log_bytes = record(self.config, self.events)

    def _expect_invalid(self, doc, rehash=False):
        if rehash:
            doc["sha256"] = prefix_digest(doc)
        code, out, err = replay(json.dumps(doc).encode())
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')

    def test_valid_log_replays_byte_identical(self):
        code, out, err = replay(self.log_bytes)
        self.assertEqual(code, 0, err)
        self.assertEqual(out, fdb_stdout(self.config, self.events))

    def test_tampered_applied(self):
        doc = json.loads(self.log_bytes.decode())
        doc["records"][1]["applied"] = True  # 原记录为 False
        self._expect_invalid(doc)

    def test_tampered_version(self):
        doc = json.loads(self.log_bytes.decode())
        doc["records"][1]["version"] = 2  # 非 applied 项 version 应停留在 1
        self._expect_invalid(doc)

    def test_tampered_event_even_with_rehash(self):
        doc = json.loads(self.log_bytes.decode())
        doc["records"][0]["event"]["port"] = "p2"
        self._expect_invalid(doc, rehash=True)

    def test_tampered_config_even_with_rehash(self):
        doc = json.loads(self.log_bytes.decode())
        doc["config"]["age"] = 5
        self._expect_invalid(doc, rehash=True)

    def test_output_non_null_rejected(self):
        doc = json.loads(self.log_bytes.decode())
        doc["records"][0]["output"] = {"t": 0}
        self._expect_invalid(doc, rehash=True)

    def test_bad_sha256(self):
        doc = json.loads(self.log_bytes.decode())
        doc["sha256"] = "0" * 64
        self._expect_invalid(doc)

    def test_wrong_schema(self):
        doc = json.loads(self.log_bytes.decode())
        doc["schema"] = 2
        self._expect_invalid(doc, rehash=True)

    def test_extra_top_key(self):
        doc = json.loads(self.log_bytes.decode())
        doc["extra"] = 1
        self._expect_invalid(doc, rehash=True)

    def test_trailing_bytes_rejected(self):
        code, out, err = replay(self.log_bytes + b" ")
        self.assertEqual((code, out), (4, b""))
        self.assertEqual(err, b'{"error":"invalid_input"}\n')


if __name__ == "__main__":
    unittest.main()
