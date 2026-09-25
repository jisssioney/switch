#!/usr/bin/env python3
"""record / replay 子命令回归：日志格式、版本与 applied 语义、逐字节重放。

仅用标准库；通过 `python switch.py record CONFIG EVENTS LOG` 与
`python switch.py replay LOG` 端到端驱动。
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

LOG_KEYS = ["schema", "config", "records", "sha256"]
RECORD_KEYS = ["t", "version", "event", "applied", "output"]


def make_port(name, pvid=1):
    return {
        "name": name,
        "mode": "access",
        "pvid": pvid,
        "allowed": [pvid],
        "untagged": [pvid],
        "up": True,
    }


def base_config():
    ports = [make_port(name) for name in ("p1", "p2", "p3", "p4", "p5")]
    return {
        "bridges": ["b1"],
        "links": [],
        "delay": 1,
        "bridge": "b1",
        "ports": ports,
        "age": 100,
        "storm": {
            "window": 10,
            "limits": {"broadcast": 100, "multicast": 100, "unknown": 100},
            "move_limit": 100,
            "hold": 10,
        },
        "lags": [{"name": "L1", "members": ["p4", "p5"], "hash": ["src"]}],
        "mirror": {"sources": ["p1"], "target": "p2", "direction": "both"},
        "acl": [
            {
                "src": None,
                "dst": None,
                "vlan": None,
                "ethertype": None,
                "priority": None,
                "action": "allow",
                "to_vlan": None,
            }
        ],
        "qos": {
            "map": [0, 1, 2, 3, 0, 1, 2, 3],
            "cap": 1000,
            "mode": "wrr",
            "weights": [1, 1, 1, 1],
            "drop": "tail",
        },
        "security": [
            {"port": p, "limit": 2, "action": "drop", "static": []}
            for p in ("p1", "p2", "p3", "p4", "p5")
        ],
    }


def linked_config():
    # p3 为跨桥链路口（不得再入 LAG）；p4/p5 为 LAG 成员
    config = base_config()
    config["bridges"] = ["b1", "b2"]
    config["links"] = [
        {"id": "L2", "x": ["b1", "p3"], "y": ["b2", "x"],
         "cost": 1, "up": True}
    ]
    return config


def frame(t, port, src, dst="ff:ff:ff:ff:ff:ff"):
    return {
        "t": t,
        "port": port,
        "src": src,
        "dst": dst,
        "vlan": None,
        "ethertype": 0x0800,
        "priority": 0,
    }


def service(t, port, count):
    return {"t": t, "port": port, "count": count}


def run_cli(args, files=None):
    """files: {相对名: bytes}，写入临时目录；args 中的文件名相对该目录。"""
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


def write_inputs(config, events, log_name="out.log"):
    return {
        "config.json": json.dumps(config).encode("utf-8"),
        "events.json": json.dumps(events).encode("utf-8"),
    }, log_name


def record(config, events):
    files, log_name = write_inputs(config, events)
    code, out, err, logs = run_cli(
        ["record", "config.json", "events.json", log_name], files
    )
    assert code == 0, (code, err.decode())
    return out, logs[log_name]


def reload_stdout(config, events):
    files, _ = write_inputs(config, events)
    code, out, err, _ = run_cli(
        ["reload", "config.json", "events.json"], files
    )
    assert code == 0, (code, err.decode())
    return out


def replay(log_bytes):
    files = {"in.log": log_bytes}
    code, out, err, _ = run_cli(["replay", "in.log"], files)
    return code, out, err


def canonical_key_order(value):
    if isinstance(value, dict):
        keys = list(value)
        return keys == sorted(keys) and all(
            canonical_key_order(value[k]) for k in keys
        )
    if isinstance(value, list):
        return all(canonical_key_order(item) for item in value)
    return True


def prefix_digest(doc):
    prefix = {
        "schema": doc["schema"],
        "config": doc["config"],
        "records": doc["records"],
    }
    raw = (
        json.dumps(prefix, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest(), raw


class RecordBasicTest(unittest.TestCase):
    def test_record_matches_reload_and_replay_matches_record(self):
        config = base_config()
        events = [frame(0, "p1", "00:00:00:00:00:01")]
        out, log_bytes = record(config, events)
        # record stdout 沿用 reload（含末态 config 键）
        self.assertEqual(out, reload_stdout(config, events))
        self.assertTrue(out.endswith(b"\n"))
        # replay stdout 与 record 逐字节相同
        code, replay_out, err = replay(log_bytes)
        self.assertEqual(code, 0, err)
        self.assertEqual(replay_out, out)

    def test_log_shape_and_canonical_order(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["age"] = 50
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "config": new},
        ]
        _, log_bytes = record(config, events)
        doc = json.loads(log_bytes.decode())
        # 顶层键序 schema,config,records,sha256
        self.assertEqual(list(doc), LOG_KEYS)
        self.assertEqual(doc["schema"], 1)
        # 日志以单个 LF 结尾
        self.assertTrue(log_bytes.endswith(b"}" + b"\n"))
        self.assertFalse(log_bytes.endswith(b"\n\n"))
        # config 为初始配置（age 仍为 100），递归键序按码点升序
        self.assertEqual(doc["config"]["age"], 100)
        self.assertTrue(canonical_key_order(doc["config"]))
        self.assertEqual(len(doc["records"]), len(events))
        for item in doc["records"]:
            self.assertEqual(list(item), RECORD_KEYS)
            self.assertTrue(canonical_key_order(item["event"]))

    def test_records_align_with_events_in_order(self):
        config = base_config()
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            service(1, "p2", 1),
        ]
        _, log_bytes = record(config, events)
        doc = json.loads(log_bytes.decode())
        self.assertEqual([r["t"] for r in doc["records"]], [0, 1])
        self.assertEqual(
            [set(r["event"]) for r in doc["records"]],
            [set(events[0]), set(events[1])],
        )

    def test_sha256_covers_prefix_with_lf(self):
        config = base_config()
        events = [frame(0, "p1", "00:00:00:00:00:01")]
        _, log_bytes = record(config, events)
        doc = json.loads(log_bytes.decode())
        digest, raw_prefix = prefix_digest(doc)
        self.assertEqual(doc["sha256"], digest)
        # 64 位小写十六进制
        self.assertRegex(doc["sha256"], r"[0-9a-f]{64}")
        # 摘要文本为去掉末尾 sha256 段的前缀、且以 LF 结尾
        self.assertTrue(raw_prefix.endswith(b"}\n"))
        # 完整 LOG 即前缀（去 LF 与闭合括号）插入 sha256 后再闭合、含 LF
        expected = (
            raw_prefix.decode()[:-2]
            + ',"sha256":"' + digest + '"}\n'
        )
        self.assertEqual(log_bytes.decode(), expected)

    def test_empty_events(self):
        config = base_config()
        out, log_bytes = record(config, [])
        doc = json.loads(log_bytes.decode())
        self.assertEqual(doc["records"], [])
        code, replay_out, err = replay(log_bytes)
        self.assertEqual(code, 0, err)
        self.assertEqual(replay_out, out)

    def test_unsorted_input_keys_still_round_trip_byte_identical(self):
        # 输入 config/event 键序任意：输出规范化，record 与 replay 仍逐字节一致
        config = base_config()
        new = copy.deepcopy(config)
        new["age"] = 50
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"config": new, "t": 1},  # 键序反转
        ]
        reversed_cfg = {k: config[k] for k in reversed(list(config))}
        with tempfile.TemporaryDirectory() as tmp:
            cfg = os.path.join(tmp, "config.json")
            evt = os.path.join(tmp, "events.json")
            log_path = os.path.join(tmp, "out.log")
            with open(cfg, "wb") as handle:
                handle.write(json.dumps(reversed_cfg).encode())
            with open(evt, "wb") as handle:
                handle.write(json.dumps(events).encode())
            rec = subprocess.run(
                [sys.executable, SWITCH, "record", cfg, evt, log_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(rec.returncode, 0, rec.stderr)
            rel = subprocess.run(
                [sys.executable, SWITCH, "reload", cfg, evt],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(rec.stdout, rel.stdout)
            with open(log_path, "rb") as handle:
                log_bytes = handle.read()
            rep = subprocess.run(
                [sys.executable, SWITCH, "replay", log_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(rep.returncode, 0, rep.stderr)
            self.assertEqual(rep.stdout, rec.stdout)


class VersionTest(unittest.TestCase):
    def test_version_starts_zero_and_bumps_on_every_reload(self):
        config = base_config()
        first = copy.deepcopy(config)
        first["age"] = 10
        second = copy.deepcopy(first)
        second["age"] = 20
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "config": first},  # 有变化
            frame(2, "p1", "00:00:00:00:00:02"),
            {"t": 3, "config": copy.deepcopy(first)},  # 无变化亦加 1
            {"t": 4, "config": second},  # 再加 1
        ]
        _, log_bytes = record(config, events)
        doc = json.loads(log_bytes.decode())
        self.assertEqual(
            [r["version"] for r in doc["records"]], [0, 1, 1, 2, 3]
        )


class AppliedTest(unittest.TestCase):
    def test_link_and_member_applied_reflect_state_change(self):
        config = linked_config()
        events = [
            {"t": 1, "id": "L2", "up": True},  # 初始即 up：幂等
            {"t": 2, "id": "L2", "up": False},  # 状态改变
            {"t": 3, "id": "L2", "up": False},  # 幂等
            {"t": 4, "id": "L2", "up": True},  # 状态改变
            {"t": 5, "member": "p4", "up": True},  # 初始可用：幂等
            {"t": 6, "member": "p4", "up": False},  # 状态改变
            {"t": 7, "member": "p4", "up": False},  # 幂等
        ]
        _, log_bytes = record(config, events)
        doc = json.loads(log_bytes.decode())
        self.assertEqual(
            [r["applied"] for r in doc["records"]],
            [False, True, False, True, False, True, False],
        )
        # 链路/成员事件不产生 results 项：output 恒 null
        for item in doc["records"]:
            self.assertIsNone(item["output"])

    def test_frame_service_reload_always_applied_with_output(self):
        config = linked_config()
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            service(1, "p2", 1),  # 镜像 target，无帧可服务也仍有 results 项
            {"t": 2, "config": copy.deepcopy(config)},
        ]
        _, log_bytes = record(config, events)
        doc = json.loads(log_bytes.decode())
        for item in doc["records"]:
            self.assertTrue(item["applied"])
            self.assertIsInstance(item["output"], dict)

    def test_output_is_the_new_result_item(self):
        config = base_config()
        out, log_bytes = record(
            config, [frame(0, "p1", "00:00:00:00:00:01")]
        )
        result = json.loads(out.decode())
        doc = json.loads(log_bytes.decode())
        self.assertEqual(doc["records"][0]["output"], result["results"][0])
        # reload 的 output 含 action=reload 与 changes
        new = copy.deepcopy(config)
        new["age"] = 50
        _, log_bytes = record(config, [{"t": 1, "config": new}])
        doc = json.loads(log_bytes.decode())
        self.assertEqual(
            doc["records"][0]["output"],
            {"t": 1, "action": "reload",
             "changes": [{"key": "age", "before": 100, "after": 50}]},
        )


class ReplayVerifyTest(unittest.TestCase):
    def setUp(self):
        self.config = base_config()
        new = copy.deepcopy(self.config)
        new["age"] = 50
        self.events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "config": new},
        ]
        _, self.log_bytes = record(self.config, self.events)

    def _expect_invalid(self, doc, rehash=False):
        if rehash:
            doc["sha256"] = prefix_digest(doc)[0]
        code, _, err = replay(json.dumps(doc).encode())
        self.assertEqual(code, 4)
        self.assertEqual(err, b'{"error":"invalid_input"}\n')

    def test_valid_log_replays(self):
        code, out, err = replay(self.log_bytes)
        self.assertEqual(code, 0, err)

    def test_tampered_applied(self):
        doc = json.loads(self.log_bytes.decode())
        doc["records"][0]["applied"] = False
        self._expect_invalid(doc)

    def test_tampered_version(self):
        doc = json.loads(self.log_bytes.decode())
        doc["records"][1]["version"] = 9
        self._expect_invalid(doc)

    def test_tampered_output_even_with_rehash(self):
        doc = json.loads(self.log_bytes.decode())
        doc["records"][0]["output"] = None
        self._expect_invalid(doc, rehash=True)

    def test_tampered_event_even_with_rehash(self):
        doc = json.loads(self.log_bytes.decode())
        doc["records"][0]["event"]["src"] = "00:00:00:00:00:09"
        self._expect_invalid(doc, rehash=True)

    def test_tampered_config_even_with_rehash(self):
        doc = json.loads(self.log_bytes.decode())
        doc["config"]["age"] = 7
        self._expect_invalid(doc, rehash=True)

    def test_bad_sha256(self):
        doc = json.loads(self.log_bytes.decode())
        doc["sha256"] = "0" * 64
        self._expect_invalid(doc)

    def test_bad_sha256_type(self):
        doc = json.loads(self.log_bytes.decode())
        doc["sha256"] = 123
        self._expect_invalid(doc)

    def test_wrong_schema(self):
        doc = json.loads(self.log_bytes.decode())
        doc["schema"] = 2
        self._expect_invalid(doc, rehash=True)

    def test_schema_wrong_type(self):
        text = self.log_bytes.decode().replace('"schema":1', '"schema":"1"', 1)
        code, _, err = replay(text.encode())
        self.assertEqual(code, 4)
        self.assertEqual(err, b'{"error":"invalid_input"}\n')

    def test_extra_top_key(self):
        doc = json.loads(self.log_bytes.decode())
        doc["extra"] = 1
        self._expect_invalid(doc, rehash=True)

    def test_missing_record_key(self):
        doc = json.loads(self.log_bytes.decode())
        del doc["records"][0]["event"]
        self._expect_invalid(doc, rehash=True)

    def test_records_wrong_type(self):
        doc = json.loads(self.log_bytes.decode())
        doc["records"] = {}
        self._expect_invalid(doc, rehash=True)

    def test_applied_wrong_type(self):
        doc = json.loads(self.log_bytes.decode())
        doc["records"][0]["applied"] = 1
        self._expect_invalid(doc, rehash=True)

    def test_log_not_object(self):
        code, _, err = replay(b"[]")
        self.assertEqual(code, 4)
        self.assertEqual(err, b'{"error":"invalid_input"}\n')

    def test_invalid_json(self):
        code, _, err = replay(b"{not json")
        self.assertEqual(code, 4)
        self.assertEqual(err, b'{"error":"invalid_input"}\n')

    def test_unsorted_keys_rejected(self):
        # config 键非码点升序：结构校验即拒（即便重算 sha）
        doc = json.loads(self.log_bytes.decode())
        doc["config"] = {k: doc["config"][k] for k in reversed(sorted(doc["config"]))}
        self._expect_invalid(doc, rehash=True)

    def test_trailing_bytes_rejected(self):
        code, _, err = replay(self.log_bytes + b" ")
        self.assertEqual(code, 4)
        self.assertEqual(err, b'{"error":"invalid_input"}\n')


class RecordFailureTest(unittest.TestCase):
    def test_illegal_reload_exceeding_limit_writes_nothing(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["security"][0]["limit"] = 0
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "config": new},
        ]
        files, log_name = write_inputs(config, events)
        code, out, err, logs = run_cli(
            ["record", "config.json", "events.json", log_name], files
        )
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertNotIn(log_name, logs)

    def test_illegal_reload_new_static_writes_nothing(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["security"][1]["static"] = [
            {"mac": "00:00:00:00:00:01", "vlan": 1}
        ]
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "config": new},
        ]
        files, log_name = write_inputs(config, events)
        code, out, err, logs = run_cli(
            ["record", "config.json", "events.json", log_name], files
        )
        self.assertEqual(code, 4)
        self.assertNotIn(log_name, logs)

    def test_bad_event_is_invalid(self):
        config = base_config()
        files, log_name = write_inputs(config, [{"t": 0}])
        code, out, err, logs = run_cli(
            ["record", "config.json", "events.json", log_name], files
        )
        self.assertEqual(code, 4)
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertNotIn(log_name, logs)

    def test_failed_atomic_write_leaves_existing_log_unchanged(self):
        config = base_config()
        events = [frame(0, "p1", "00:00:00:00:00:01")]
        with tempfile.TemporaryDirectory() as tmp:
            cfg = os.path.join(tmp, "config.json")
            evt = os.path.join(tmp, "events.json")
            log_path = os.path.join(tmp, "out.log")
            with open(cfg, "wb") as handle:
                handle.write(json.dumps(config).encode())
            with open(evt, "wb") as handle:
                handle.write(json.dumps(events).encode())
            first = subprocess.run(
                [sys.executable, SWITCH, "record", cfg, evt, log_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(first.returncode, 0)
            with open(log_path, "rb") as handle:
                original = handle.read()
            # 目标父目录不存在：临时文件无法创建 -> 3，既有 LOG 不变
            bad = subprocess.run(
                [sys.executable, SWITCH, "record", cfg, evt,
                 os.path.join(tmp, "nodir", "out.log")],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(bad.returncode, 3)
            self.assertEqual(bad.stderr, b'{"error":"file_not_found"}\n')
            with open(log_path, "rb") as handle:
                self.assertEqual(handle.read(), original)


class LogLimitTest(unittest.TestCase):
    """MAX_EVENTS / MAX_LOG_BYTES 上界：默认值、边界、优先级与 LOG 不动。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.cfg = os.path.join(d, "config.json")
        self.evt = os.path.join(d, "events.json")
        self.log = os.path.join(d, "out.log")
        self.inlog = os.path.join(d, "in.log")
        self.config = base_config()
        self.events = [
            frame(i, "p1", "00:00:00:00:00:01") for i in range(5)
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

    def test_record_event_limit_exceeded(self):
        os.unlink(self.log)  # 仅校验超限不创建 LOG
        code, out, err = self._run(
            "record", self.cfg, self.evt, self.log, "4", "16777216"
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"event_limit"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_record_event_limit_equal_is_legal(self):
        code, _, err = self._run(
            "record", self.cfg, self.evt, self.log, "5", "16777216"
        )
        self.assertEqual(code, 0, err)

    def test_replay_records_limit_exceeded(self):
        with open(self.inlog, "wb") as handle:
            handle.write(self.log_bytes)
        code, out, err = self._run(
            "replay", self.inlog, "4", "16777216"
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"event_limit"}\n')

    def test_replay_records_limit_equal_is_legal_and_byte_identical(self):
        with open(self.inlog, "wb") as handle:
            handle.write(self.log_bytes)
        code, out, err = self._run(
            "replay", self.inlog, "5", "16777216"
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(out, self.record_out)

    def test_record_log_byte_boundary(self):
        size = len(self.log_bytes)
        # 等于上限合法，且与无上限输出逐字节一致
        code, _, err = self._run(
            "record", self.cfg, self.evt, self.log, "100000", str(size)
        )
        self.assertEqual(code, 0, err)
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)
        os.unlink(self.log)
        # 超一字节即拒，且不创建 LOG
        code, out, err = self._run(
            "record", self.cfg, self.evt, self.log, "100000", str(size - 1)
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"log_limit"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_replay_log_byte_boundary(self):
        size = len(self.log_bytes)
        code, _, err = self._run(
            "replay", self.log, "100000", str(size)
        )
        self.assertEqual(code, 0, err)
        code, out, err = self._run(
            "replay", self.log, "100000", str(size - 1)
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"log_limit"}\n')

    def test_record_leaves_existing_log_untouched_on_log_limit(self):
        code, _, err = self._run(
            "record", self.cfg, self.evt, self.log, "100000", "5"
        )
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"log_limit"}\n')
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)

    def test_record_double_overflow_prefers_event_limit(self):
        code, _, err = self._run(
            "record", self.cfg, self.evt, self.log, "1", "1"
        )
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"event_limit"}\n')

    def test_replay_double_overflow_prefers_log_limit(self):
        code, _, err = self._run("replay", self.log, "1", "1")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"log_limit"}\n')

    def test_replay_byte_limit_checked_before_parse(self):
        bulky = os.path.join(self.tmp.name, "bulky.log")
        with open(bulky, "wb") as handle:
            handle.write(b"{not json" + b" " * 200)
        code, _, err = self._run("replay", bulky, "100000", "10")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"log_limit"}\n')

    def test_replay_event_limit_after_shape_validation(self):
        # records 类型非法：结构校验失败（invalid_input）优先于条数上界
        doc = json.loads(self.log_bytes.decode())
        doc["records"] = {}
        digest, _ = prefix_digest(doc)
        doc["sha256"] = digest
        bad = os.path.join(self.tmp.name, "bad.log")
        with open(bad, "wb") as handle:
            handle.write(
                (json.dumps(doc, separators=(",", ":")) + "\n").encode()
            )
        code, _, err = self._run("replay", bad, "1", "99999999")
        self.assertEqual(code, 4)
        self.assertEqual(err, b'{"error":"invalid_input"}\n')

    def test_nonlist_events_remains_invalid_input_under_limit(self):
        with open(self.evt, "wb") as handle:
            handle.write(b"{}")
        code, _, err = self._run(
            "record", self.cfg, self.evt, self.log, "1", "1"
        )
        self.assertEqual(code, 4)
        self.assertEqual(err, b'{"error":"invalid_input"}\n')

    def test_bad_event_remains_invalid_input(self):
        with open(self.evt, "wb") as handle:
            handle.write(json.dumps([{"t": 0}]).encode())
        code, _, err = self._run(
            "record", self.cfg, self.evt, self.log, "100", "100000"
        )
        self.assertEqual(code, 4)
        self.assertEqual(err, b'{"error":"invalid_input"}\n')

    def test_defaults_and_explicit_limits_byte_identical(self):
        code, out, err = self._run("record", self.cfg, self.evt, self.log)
        self.assertEqual(code, 0, err)
        self.assertEqual(out, self.record_out)
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)
        code, out, err = self._run("replay", self.log)
        self.assertEqual(code, 0, err)
        self.assertEqual(out, self.record_out)
        code, out, err = self._run(
            "replay", self.log, "100000", "16777216"
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(out, self.record_out)

    def test_bad_limit_arguments_are_usage_errors(self):
        bad = [
            ("0", "10"), ("1", "0"), ("-1", "10"), ("a", "10"),
            ("1", "1.5"), ("01", "10"), ("1", "0x10"), ("+1", "10"),
            ("", "10"), ("10",),
        ]
        for extra in bad:
            code, _, err = self._run(
                "record", self.cfg, self.evt, self.log, *extra
            )
            self.assertEqual((code, err), (2, b'{"error":"usage"}\n'), extra)
            code, _, err = self._run("replay", self.log, *extra)
            self.assertEqual((code, err), (2, b'{"error":"usage"}\n'), extra)

    def test_limit_arity_per_subcommand(self):
        # record 可选上限仅 0、2、4、5 个；replay 仅 0、2、3 个
        for extra in [("1", "2", "3"), ("1", "2", "3", "4", "5", "6")]:
            code, _, err = self._run(
                "record", self.cfg, self.evt, self.log, *extra
            )
            self.assertEqual((code, err), (2, b'{"error":"usage"}\n'), extra)
        for extra in [("1", "2", "3", "4"), ("1", "2", "3", "4", "5")]:
            code, _, err = self._run("replay", self.log, *extra)
            self.assertEqual((code, err), (2, b'{"error":"usage"}\n'), extra)
        # 合法个数：record 5 个、replay 3 个
        code, out, err = self._run(
            "record", self.cfg, self.evt, self.log,
            "100000", "16777216", "1048576", "16777216", "16777216",
        )
        self.assertEqual((code, out, err), (0, self.record_out, b""))
        code, out, err = self._run(
            "replay", self.log, "100000", "16777216", "16777216"
        )
        self.assertEqual((code, out, err), (0, self.record_out, b""))

    def test_record_output_limit_exceeded(self):
        os.unlink(self.log)  # 仅校验超限不创建 LOG
        limit = str(len(self.record_out) - 1)
        code, out, err = self._run(
            "record", self.cfg, self.evt, self.log,
            "100000", "16777216", "1048576", "16777216", limit,
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"output_limit"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_record_output_limit_does_not_replace_log(self):
        limit = str(len(self.record_out) - 1)
        code, out, err = self._run(
            "record", self.cfg, self.evt, self.log,
            "100000", "16777216", "1048576", "16777216", limit,
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"output_limit"}\n')
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)

    def test_record_output_limit_equal_is_legal(self):
        limit = str(len(self.record_out))
        code, out, err = self._run(
            "record", self.cfg, self.evt, self.log,
            "100000", "16777216", "1048576", "16777216", limit,
        )
        self.assertEqual((code, out, err), (0, self.record_out, b""))
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)

    def test_record_output_limit_after_log_limit(self):
        # log_limit 先于 output_limit 判定
        limit = str(len(self.record_out) - 1)
        code, out, err = self._run(
            "record", self.cfg, self.evt, self.log,
            "100000", "1", "1048576", "16777216", limit,
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"log_limit"}\n')

    def test_replay_output_limit_exceeded(self):
        with open(self.inlog, "wb") as handle:
            handle.write(self.log_bytes)
        limit = str(len(self.record_out) - 1)
        code, out, err = self._run(
            "replay", self.inlog, "100000", "16777216", limit
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"output_limit"}\n')
        with open(self.inlog, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)

    def test_replay_output_limit_equal_is_legal(self):
        with open(self.inlog, "wb") as handle:
            handle.write(self.log_bytes)
        limit = str(len(self.record_out))
        code, out, err = self._run(
            "replay", self.inlog, "100000", "16777216", limit
        )
        self.assertEqual((code, out, err), (0, self.record_out, b""))

    def test_replay_output_limit_after_log_checks(self):
        # 日志语义错误仍按 invalid_input，先于 output_limit
        doc = json.loads(self.log_bytes.decode())
        doc["records"][0]["applied"] = not doc["records"][0]["applied"]
        digest, _ = prefix_digest(doc)
        doc["sha256"] = digest
        bad = (json.dumps(doc, separators=(",", ":")) + "\n").encode()
        with open(self.inlog, "wb") as handle:
            handle.write(bad)
        code, out, err = self._run("replay", self.inlog, "100000", "99999999", "1")
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')


class CliErrorTest(unittest.TestCase):
    def test_record_usage(self):
        code, out, err, _ = run_cli(["record", "a", "b"])
        self.assertEqual(code, 2)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"usage"}\n')

    def test_replay_usage(self):
        code, out, err, _ = run_cli(["replay"])
        self.assertEqual(code, 2)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"usage"}\n')

    def test_record_missing_input(self):
        code, out, err, _ = run_cli(
            ["record", "nope1", "nope2", "o.log"]
        )
        self.assertEqual(code, 3)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"file_not_found"}\n')

    def test_replay_missing_log(self):
        code, out, err, _ = run_cli(["replay", "nope.log"])
        self.assertEqual(code, 3)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"file_not_found"}\n')

    def test_unknown_command_still_usage(self):
        code, out, err, _ = run_cli(["frobnicate", "a", "b", "c"])
        self.assertEqual(code, 2)
        self.assertEqual(err, b'{"error":"usage"}\n')


if __name__ == "__main__":
    unittest.main()
