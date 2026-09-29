#!/usr/bin/env python3
"""log-config 子命令回归：按游标重演 port-security 模式 LOG 的前 offset
条事件并给出当前配置与回滚栈快照。

仅用标准库；端到端驱动 `python switch.py log-config LOG CURSOR [MAX_WORK]`。
参数、资源、CURSOR 及错误顺序完全沿用 log-qos；成功产物键序固定为
schema,source_sha256,offset,snapshot,sha256，末项为前四键紧凑 UTF-8 加 LF
的 sha256；CURSOR 的 * 表示 records 长度（重演全部），否则
<sha256>:<offset>，offset=0 为初始快照。snapshot 键序 t,config,stack：
t 为 0（无消费项）或末条已消费记录的 t；config 为当前配置；stack 按入栈
序保存可回滚配置（reload 替换前压入当前配置，rollback 按 LIFO 恢复，
其余事件不改配置）。仅 config 与 stack 内配置对象递归按 Unicode 码点
排序，数组保序，标量保类型与值。LOG 须通过摘要核对、port-security 语义、
全部记录核对与重建日志逐字节一致，其他模式 invalid_input/4；重演前
offset 项按 reload 工作量公式计费，等于上限合法，首次超过 stderr 仅
{"error":"reload_work_limit"} 加 LF 并退出 5。
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
sys.path.insert(0, HERE)

# 5000 位游标 offset/MAX_WORK 须按不限长十进制处理；测试自身解析产物时
# 同样需关闭 3.11+ 的 int↔str 位数上限
if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(0)

from test_log_fdb import fdb_config, record as record_log  # noqa: E402
from test_log_security import good_frame as sec_good, mac  # noqa: E402
from test_log_qos import qos_log, good_frame as qos_good  # noqa: E402
from test_reload import base_config, frame  # noqa: E402
from test_security_check import config as security_check_config  # noqa: E402

CONFIG_KEYS = ["schema", "source_sha256", "offset", "snapshot", "sha256"]
SNAPSHOT_KEYS = ["t", "config", "stack"]


def reload_config():
    return copy.deepcopy(base_config())


def changed_config(**fields):
    cfg = copy.deepcopy(base_config())
    for key, value in fields.items():
        cfg[key] = value
    return cfg


def reload_log(events, cfg=None):
    return record_log(cfg or base_config(), events)


def digest_of(doc):
    prefix = {
        "schema": doc["schema"],
        "source_sha256": doc["source_sha256"],
        "offset": doc["offset"],
        "snapshot": doc["snapshot"],
    }
    raw = (
        json.dumps(prefix, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def run_config(log_bytes, cursor, *extra):
    with tempfile.TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "in.log")
        with open(log_path, "wb") as handle:
            handle.write(log_bytes)
        proc = subprocess.run(
            [sys.executable, SWITCH, "log-config", log_path, cursor, *extra],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        with open(log_path, "rb") as handle:
            after = handle.read()
    return proc.returncode, proc.stdout, proc.stderr, after


def assert_canonical(value):
    """配置对象内各层键须递归按 Unicode 码点升序，数组保序。"""
    if isinstance(value, dict):
        assert list(value) == sorted(value), list(value)
        for item in value.values():
            assert_canonical(item)
    elif isinstance(value, list):
        for item in value:
            assert_canonical(item)


class HappyPathTests(unittest.TestCase):
    def reload_events(self):
        new = changed_config(age=50)
        new["security"][0]["limit"] = 5
        return [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "config": new},
            {"t": 2, "rollback": True},
            frame(3, "p2", "00:00:00:00:00:02"),
        ]

    def test_star_is_records_length_with_fixed_key_order_and_digest(self):
        log_bytes = reload_log(self.reload_events())
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_config(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertTrue(out.endswith(b"\n"))
        self.assertNotIn(b", ", out)
        self.assertNotIn(b": ", out)
        self.assertEqual(after, log_bytes)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(list(doc), CONFIG_KEYS)
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["source_sha256"], source)
        self.assertEqual(doc["offset"], 4)
        snapshot = doc["snapshot"]
        self.assertEqual(list(snapshot), SNAPSHOT_KEYS)
        # 末条 rollback 后恢复初始配置，栈空；t 取末条记录的 t=3
        self.assertEqual(snapshot["t"], 3)
        self.assertEqual(snapshot["config"]["age"], 100)
        self.assertEqual(snapshot["config"]["security"][0]["limit"], 2)
        self.assertEqual(snapshot["stack"], [])
        self.assertEqual(doc["sha256"], digest_of(doc))
        assert_canonical(snapshot["config"])

    def test_star_equals_sha_cursor_at_record_count(self):
        log_bytes = reload_log(self.reload_events())
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        _, star_out, _, _ = run_config(log_bytes, "*")
        code, cur_out, err, _ = run_config(log_bytes, source + ":4")
        self.assertEqual(code, 0, err)
        self.assertEqual(cur_out, star_out)
        self.assertEqual(json.loads(cur_out.decode())["offset"], 4)

    def test_offset_zero_is_initial_snapshot(self):
        log_bytes = reload_log(self.reload_events())
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        original = json.loads(log_bytes.decode("utf-8"))["config"]
        code, out, err, _ = run_config(log_bytes, source + ":0")
        self.assertEqual(code, 0, err)
        snapshot = json.loads(out.decode("utf-8"))["snapshot"]
        self.assertEqual(snapshot["t"], 0)
        self.assertEqual(snapshot["config"], original)
        self.assertEqual(snapshot["stack"], [])
        assert_canonical(snapshot["config"])

    def test_reload_pushes_current_config_before_replace(self):
        new = changed_config(age=50)
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "config": new},
        ]
        log_bytes = reload_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        original = json.loads(log_bytes.decode("utf-8"))["config"]
        code, out, err, _ = run_config(log_bytes, source + ":2")
        self.assertEqual(code, 0, err)
        snapshot = json.loads(out.decode("utf-8"))["snapshot"]
        self.assertEqual(snapshot["t"], 1)
        self.assertEqual(snapshot["config"]["age"], 50)
        # 入栈序：仅压入替换前的当前配置（初始配置）
        self.assertEqual(len(snapshot["stack"]), 1)
        self.assertEqual(snapshot["stack"][0], original)
        assert_canonical(snapshot["stack"])

    def test_stack_preserves_push_order_across_reloads(self):
        cfg = base_config()
        first = copy.deepcopy(cfg)
        first["age"] = 50
        second = copy.deepcopy(cfg)
        second["age"] = 30
        events = [
            {"t": 0, "config": first},
            {"t": 1, "config": second},
        ]
        log_bytes = reload_log(events, cfg)
        code, out, err, _ = run_config(log_bytes, "*")
        self.assertEqual(code, 0, err)
        snapshot = json.loads(out.decode("utf-8"))["snapshot"]
        self.assertEqual(snapshot["config"]["age"], 30)
        self.assertEqual([item["age"] for item in snapshot["stack"]], [100, 50])

    def test_partial_offsets_follow_lifo(self):
        cfg = base_config()
        first = copy.deepcopy(cfg)
        first["age"] = 50
        second = copy.deepcopy(cfg)
        second["age"] = 30
        events = [
            {"t": 0, "config": first},
            {"t": 1, "config": second},
            {"t": 2, "rollback": True},
            {"t": 3, "rollback": True},
        ]
        log_bytes = reload_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        expected = [
            (0, 100, []),
            (0, 50, [100]),
            (1, 30, [100, 50]),
            (2, 50, [100]),
            (3, 100, []),
        ]
        for offset, (last_t, age, stack_ages) in enumerate(expected):
            code, out, err, _ = run_config(
                log_bytes, source + ":%d" % offset
            )
            self.assertEqual(code, 0, (offset, err))
            snapshot = json.loads(out.decode("utf-8"))["snapshot"]
            self.assertEqual(snapshot["t"], last_t)
            self.assertEqual(snapshot["config"]["age"], age)
            self.assertEqual(
                [item["age"] for item in snapshot["stack"]], stack_ages
            )

    def test_plain_events_do_not_change_config(self):
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            frame(5, "p2", "00:00:00:00:00:02"),
        ]
        log_bytes = reload_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        original = json.loads(log_bytes.decode("utf-8"))["config"]
        for offset in range(3):
            code, out, err, _ = run_config(
                log_bytes, source + ":%d" % offset
            )
            self.assertEqual(code, 0, err)
            snapshot = json.loads(out.decode("utf-8"))["snapshot"]
            self.assertEqual(snapshot["config"], original)
            self.assertEqual(snapshot["stack"], [])
            self.assertEqual(snapshot["t"], 0 if offset == 0 else (0, 5)[offset - 1])

    def test_t_zero_when_no_consumed_records_even_with_later_t(self):
        events = [{"t": 7, "config": changed_config(age=50)}]
        log_bytes = reload_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_config(log_bytes, source + ":0")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out.decode())["snapshot"]["t"], 0)

    def test_scalars_keep_type_and_value(self):
        new = changed_config(age=50)
        log_bytes = reload_log(
            [frame(0, "p1", "00:00:00:00:00:01"), {"t": 1, "config": new}]
        )
        code, out, err, _ = run_config(log_bytes, "*")
        self.assertEqual(code, 0, err)
        snapshot = json.loads(out.decode("utf-8"))["snapshot"]
        cfg = snapshot["config"]
        self.assertIsInstance(cfg["age"], int)
        self.assertIsInstance(cfg["delay"], int)
        self.assertIsInstance(cfg["ports"][0]["up"], bool)
        self.assertTrue(cfg["ports"][0]["up"])
        self.assertIsNone(cfg["acl"][0]["src"])
        self.assertEqual(cfg["qos"]["weights"], [1, 1, 1, 1])

    def test_empty_log_star_and_zero_identical(self):
        log_bytes = reload_log([])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        outputs = []
        for cursor in ("*", source + ":0"):
            code, out, err, _ = run_config(log_bytes, cursor)
            self.assertEqual(code, 0, err)
            doc = json.loads(out.decode("utf-8"))
            self.assertEqual(doc["offset"], 0)
            self.assertEqual(doc["snapshot"]["t"], 0)
            self.assertEqual(doc["snapshot"]["stack"], [])
            outputs.append(out)
        self.assertEqual(outputs[0], outputs[1])


class UsageTests(unittest.TestCase):
    def test_arg_counts(self):
        log_bytes = reload_log([frame(0, "p1", "00:00:00:00:00:01")])
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "in.log")
            with open(path, "wb") as handle:
                handle.write(log_bytes)
            for tokens in ([], [path], [path, "*", "1", "2"]):
                proc = subprocess.run(
                    [sys.executable, SWITCH, "log-config", *tokens],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                self.assertEqual(proc.returncode, 2, tokens)

    def test_bad_cursor_tokens(self):
        log_bytes = reload_log([frame(0, "p1", "00:00:00:00:00:01")])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for cursor in (
            "",
            "x",
            "* ",
            source[:63],
            source + "x:0",
            "G" * 64 + ":0",
            source.upper() + ":0",
            source + ":",
            source + ":01",
            source + ":-0",
            source + ":+1",
            source + ":1.0",
            source + ":0:0",
        ):
            code, _, _, _ = run_config(log_bytes, cursor)
            self.assertEqual(code, 2, cursor)

    def test_bad_max_work_tokens(self):
        log_bytes = reload_log([frame(0, "p1", "00:00:00:00:00:01")])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for token in ("", "0", "-1", "01", "1.0", "1 ", "x", "1e3"):
            code, _, _, _ = run_config(log_bytes, source + ":0", token)
            self.assertEqual(code, 2, token)
            code, _, _, _ = run_config(log_bytes, "*", token)
            self.assertEqual(code, 2, token)

    def test_arbitrary_length_decimal_max_work_accepted(self):
        log_bytes = reload_log([frame(0, "p1", "00:00:00:00:00:01")])
        code, _, err, _ = run_config(log_bytes, "*", "9" * 60)
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_config(log_bytes, "*", "9" * 5000)
        self.assertEqual(code, 0, err)

    def test_five_thousand_digit_cursor_offset_unbounded(self):
        log_bytes = reload_log([frame(0, "p1", "00:00:00:00:00:01")])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_config(
            log_bytes, source + ":" + "1" * 5000
        )
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)


class ErrorPrecedenceTests(unittest.TestCase):
    def test_file_not_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "nope.log")
            proc = subprocess.run(
                [sys.executable, SWITCH, "log-config", missing, "*"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(proc.returncode, 3)
        self.assertIn(b"file_not_found", proc.stderr)
        self.assertEqual(proc.stdout, b"")

    def test_log_limit_before_invalid_input(self):
        oversized = b"{" + b" " * (16 * 1024 * 1024)
        code, out, err, after = run_config(oversized, "*")
        self.assertEqual(code, 5)
        self.assertIn(b"log_limit", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, oversized)

    def test_bad_internal_sha_invalid_input(self):
        log_bytes = reload_log([frame(0, "p1", "00:00:00:00:00:01")])
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_config(bad, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_sha_mismatch_invalid_input(self):
        log_bytes = reload_log([frame(0, "p1", "00:00:00:00:00:01")])
        code, out, err, _ = run_config(log_bytes, "0" * 64 + ":0")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_offset_beyond_record_count_invalid_input(self):
        log_bytes = reload_log([frame(0, "p1", "00:00:00:00:00:01")])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_config(log_bytes, source + ":2")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_fdb_mode_rejected(self):
        events = [
            {"t": 0, "port": "p1", "mac": mac(1), "vlan": 1},
        ]
        log_bytes = record_log(fdb_config(), events)
        code, out, err, after = run_config(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_security_check_mode_rejected(self):
        log_bytes = record_log(
            security_check_config(), [sec_good(0, "p1", mac(1))]
        )
        code, out, err, after = run_config(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_qos_check_mode_rejected(self):
        log_bytes = qos_log([qos_good(0, "p1", "00:00:00:00:00:01")])
        code, out, err, after = run_config(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_tampered_records_fail_verification(self):
        events = [frame(0, "p1", "00:00:00:00:00:01")]
        log_bytes = reload_log(events)
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["records"][0]["applied"] = False
        prefix = {
            "schema": doc["schema"],
            "config": doc["config"],
            "records": doc["records"],
        }
        doc["sha256"] = hashlib.sha256(
            (json.dumps(prefix, separators=(",", ":")) + "\n").encode("utf-8")
        ).hexdigest()
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, after = run_config(bad, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, bad)

    def test_invalid_input_before_work_limit(self):
        log_bytes = reload_log([frame(0, "p1", "00:00:00:00:00:01")])
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_config(bad, "*", "1")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_semantically_invalid_rollback_rejected(self):
        # 空栈 rollback 无法形成合法 LOG：record 即 invalid_input/4
        events = [{"t": 0, "rollback": True}]
        with tempfile.TemporaryDirectory() as tmp:
            cp = os.path.join(tmp, "c.json")
            ep = os.path.join(tmp, "e.json")
            lp = os.path.join(tmp, "o.log")
            with open(cp, "w", encoding="utf-8") as handle:
                json.dump(base_config(), handle)
            with open(ep, "w", encoding="utf-8") as handle:
                json.dump(events, handle)
            proc = subprocess.run(
                [sys.executable, SWITCH, "record", cp, ep, lp],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(proc.returncode, 4)
        self.assertIn(b"invalid_input", proc.stderr)


class WorkLimitTests(unittest.TestCase):
    def events(self):
        # 初始 B+L+2U=1；首帧空状态 19；reload 10；rollback 10；末帧 22；
        # 累计 62（与 reload-rollback 同一公式）
        new = changed_config(age=50)
        return [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "config": new},
            {"t": 2, "rollback": True},
            frame(3, "p1", "00:00:00:00:00:02"),
        ]

    def test_equal_limit_legal_first_exceed_rejected(self):
        log_bytes = reload_log(self.events())
        code, out, err, _ = run_config(log_bytes, "*", "62")
        self.assertEqual(code, 0, err)
        code, out, err, after = run_config(log_bytes, "*", "61")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"reload_work_limit"}\n')
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_work_counts_only_prefix_events(self):
        log_bytes = reload_log(self.events())
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        # offset=1：初始 1 + 首帧 19 = 20；等于上限合法，19 首次超过
        code, _, err, _ = run_config(log_bytes, source + ":1", "20")
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_config(log_bytes, source + ":1", "19")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"reload_work_limit"}\n')
        # offset=2：再加重载 10 = 30
        code, _, err, _ = run_config(log_bytes, source + ":2", "30")
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_config(log_bytes, source + ":2", "29")
        self.assertEqual(code, 5)
        # offset=0：仅初始收敛 1
        code, out, err, _ = run_config(log_bytes, source + ":0", "1")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out.decode())["offset"], 0)

    def test_default_max_work_is_ten_million(self):
        code, _, err, _ = run_config(reload_log([]), "*")
        self.assertEqual(code, 0, err)


if __name__ == "__main__":
    unittest.main()
