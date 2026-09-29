#!/usr/bin/env python3
"""log-config 子命令回归：按游标重演 port-security 模式 LOG 的前 offset 条
事件并给出当前配置与回滚栈快照。

仅用标准库；端到端驱动 `python switch.py log-config LOG CURSOR [MAX_WORK]`。
参数、资源、CURSOR 及错误顺序完全沿用 log-qos；成功产物键序固定为
schema,source_sha256,offset,snapshot,sha256，末项为前四键紧凑 UTF-8 加 LF
的 sha256；CURSOR 的 * 表示 records 长度（重演全部），否则
<sha256>:<offset>，offset=0 为初始配置与空栈、t=0。snapshot 键序
t,config,stack：t 为 0 或末条已消费记录的 t，config 为当前配置，stack
按入栈序保存可回滚配置（reload 压入当前配置再替换，rollback 按 LIFO
恢复，余事件不改配置）。LOG 须通过摘要核对、port-security 语义、全部
记录核对与重建日志逐字节一致，其他模式 invalid_input/4；重演前
offset 项按 reload 工作量公式计费（rollback 按 reload 分支），等于上限
合法，首次超过 stderr 仅 {"error":"reload_work_limit"} 加 LF 并退出 5。
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

from test_log_fdb import fdb_config, record  # noqa: E402
from test_reload import base_config, frame  # noqa: E402

OUTER_KEYS = ["schema", "source_sha256", "offset", "snapshot", "sha256"]
SNAPSHOT_KEYS = ["t", "config", "stack"]


def reload_at(t, config):
    return {"t": t, "config": config}


def rollback_at(t):
    return {"t": t, "rollback": True}


def ps_log(events, cfg=None):
    return record(cfg or base_config(), events)


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


def sorted_keys_recursively(value):
    if isinstance(value, dict):
        keys = list(value)
        return keys == sorted(keys) and all(
            sorted_keys_recursively(v) for v in value.values()
        )
    if isinstance(value, list):
        return all(sorted_keys_recursively(v) for v in value)
    return True


class HappyPathTests(unittest.TestCase):
    def test_star_is_records_length_with_fixed_key_order_and_digest(self):
        cfg = base_config()
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            reload_at(1, cfg),
        ]
        log_bytes = ps_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_config(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertTrue(out.endswith(b"\n"))
        self.assertNotIn(b", ", out)
        self.assertNotIn(b": ", out)
        self.assertEqual(after, log_bytes)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(list(doc), OUTER_KEYS)
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["source_sha256"], source)
        self.assertEqual(doc["offset"], 2)
        snap = doc["snapshot"]
        self.assertEqual(list(snap), SNAPSHOT_KEYS)
        self.assertEqual(snap["t"], 1)
        self.assertEqual(snap["config"], json.loads(json.dumps(cfg)))
        self.assertEqual(snap["stack"], [json.loads(json.dumps(cfg))])
        self.assertRegex(doc["sha256"], r"[0-9a-f]{64}")
        self.assertEqual(doc["sha256"], digest_of(doc))
        # 顶层键固定序（含 snapshot/sha256），原始字节核对
        self.assertIn(
            b'"schema":1,"source_sha256":"%s","offset":2,"snapshot":'
            % source.encode(),
            out,
        )
        self.assertTrue(
            out.rstrip(b"\n").endswith(
                b',"sha256":"' + doc["sha256"].encode() + b'"}'
            )
        )

    def test_star_equals_sha_cursor_at_record_count(self):
        events = [frame(0, "p1", "00:00:00:00:00:01")]
        log_bytes = ps_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        _, star_out, _, _ = run_config(log_bytes, "*")
        code, cur_out, err, _ = run_config(log_bytes, source + ":1")
        self.assertEqual(code, 0, err)
        self.assertEqual(cur_out, star_out)
        self.assertEqual(json.loads(cur_out.decode())["offset"], 1)

    def test_offset_zero_is_initial_config_empty_stack_t_zero(self):
        new = copy.deepcopy(base_config())
        new["age"] = 50
        events = [reload_at(7, new)]
        log_bytes = ps_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_config(log_bytes, source + ":0")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["offset"], 0)
        snap = doc["snapshot"]
        self.assertEqual(snap["t"], 0)
        self.assertEqual(snap["config"]["age"], 100)
        self.assertEqual(snap["stack"], [])
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_reload_pushes_then_replaces_and_tracks_t(self):
        cfg = base_config()
        new = copy.deepcopy(cfg)
        new["age"] = 50
        new["security"][0]["limit"] = 5
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),   # 0 余事件不改配置
            reload_at(1, new),                      # 1 压入旧配置、替换
            frame(3, "p1", "00:00:00:00:00:03"),   # 2 余事件不改配置
        ]
        log_bytes = ps_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        expected = {
            0: (0, 100, 0),
            1: (0, 100, 0),
            2: (1, 50, 1),
            3: (3, 50, 1),
        }
        for off in range(4):
            code, out, err, _ = run_config(log_bytes, source + ":%d" % off)
            self.assertEqual(code, 0, (off, err))
            doc = json.loads(out.decode("utf-8"))
            self.assertEqual(doc["offset"], off)
            snap = doc["snapshot"]
            t, age, stack_len = expected[off]
            self.assertEqual(snap["t"], t, off)
            self.assertEqual(snap["config"]["age"], age, off)
            self.assertEqual(len(snap["stack"]), stack_len, off)
            self.assertEqual(doc["sha256"], digest_of(doc))
        # reload 后栈顶恰为重载前的当前配置
        _, out, _, _ = run_config(log_bytes, source + ":3")
        snap = json.loads(out.decode("utf-8"))["snapshot"]
        self.assertEqual(snap["stack"][0], json.loads(json.dumps(cfg)))
        self.assertEqual(snap["config"], json.loads(json.dumps(new)))

    def test_rollback_restores_lifo_and_empties_stack(self):
        cfg = base_config()
        first = copy.deepcopy(cfg)
        first["age"] = 50
        second = copy.deepcopy(cfg)
        second["age"] = 30
        events = [
            reload_at(0, first),                       # 0 栈 [100]，当前 50
            reload_at(1, second),                      # 1 栈 [100,50]，当前 30
            rollback_at(2),                            # 2 栈 [100]，当前 50
            rollback_at(3),                            # 3 栈 []，当前 100
        ]
        log_bytes = ps_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        # offset=0 初始；其后各 offset 对应当前缀末事件
        cases = {0: (0, 100, [])}
        expected = [
            (0, 50, [100]),
            (1, 30, [100, 50]),
            (2, 50, [100]),
            (3, 100, []),
        ]
        for i, (t, age, stack_ages) in enumerate(expected, start=1):
            cases[i] = (t, age, stack_ages)
        for off in range(5):
            code, out, err, _ = run_config(log_bytes, source + ":%d" % off)
            self.assertEqual(code, 0, (off, err))
            snap = json.loads(out.decode("utf-8"))["snapshot"]
            t, age, stack_ages = cases[off]
            self.assertEqual(snap["t"], t, off)
            self.assertEqual(snap["config"]["age"], age, off)
            self.assertEqual(
                [c["age"] for c in snap["stack"]], stack_ages, off
            )

    def test_member_and_service_events_do_not_change_config(self):
        cfg = base_config()
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "member": "p4", "up": False},
            {"t": 2, "port": "p2", "count": 1},
        ]
        log_bytes = ps_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        canonical_cfg = json.loads(json.dumps(cfg))
        for off in (1, 2, 3):
            code, out, err, _ = run_config(log_bytes, source + ":%d" % off)
            self.assertEqual(code, 0, (off, err))
            snap = json.loads(out.decode("utf-8"))["snapshot"]
            self.assertEqual(snap["config"], canonical_cfg)
            self.assertEqual(snap["stack"], [])
            self.assertEqual(snap["t"], events[off - 1]["t"])

    def test_config_and_stack_objects_sorted_arrays_and_scalars_kept(self):
        cfg = base_config()
        new = copy.deepcopy(cfg)
        new["security"][0]["limit"] = 3
        events = [reload_at(0, new)]
        log_bytes = ps_log(events, cfg)
        code, out, err, _ = run_config(log_bytes, "*")
        self.assertEqual(code, 0, err)
        snap = json.loads(out.decode("utf-8"))["snapshot"]
        self.assertTrue(sorted_keys_recursively(snap["config"]))
        self.assertTrue(all(sorted_keys_recursively(c) for c in snap["stack"]))
        # 数组保序、标量保类型
        self.assertEqual(
            [p["name"] for p in snap["config"]["ports"]],
            ["p1", "p2", "p3", "p4", "p5"],
        )
        self.assertIsInstance(snap["config"]["age"], int)
        self.assertIsInstance(snap["t"], int)

    def test_empty_log_star_and_zero_identical(self):
        log_bytes = ps_log([])
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
        log_bytes = ps_log([frame(0, "p1", "00:00:00:00:00:01")])
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
                self.assertEqual(proc.stdout, b"")
                self.assertEqual(proc.stderr, b'{"error":"usage"}\n')

    def test_bad_cursor_tokens(self):
        log_bytes = ps_log([frame(0, "p1", "00:00:00:00:00:01")])
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
        log_bytes = ps_log([frame(0, "p1", "00:00:00:00:00:01")])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for token in ("", "0", "-1", "01", "1.0", "1 ", "x", "1e3"):
            code, _, _, _ = run_config(log_bytes, source + ":0", token)
            self.assertEqual(code, 2, token)
            code, _, _, _ = run_config(log_bytes, "*", token)
            self.assertEqual(code, 2, token)

    def test_arbitrary_length_decimal_max_work_accepted(self):
        log_bytes = ps_log([frame(0, "p1", "00:00:00:00:00:01")])
        code, _, err, _ = run_config(log_bytes, "*", "9" * 60)
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_config(log_bytes, "*", "9" * 5000)
        self.assertEqual(code, 0, err)

    def test_five_thousand_digit_cursor_offset_unbounded(self):
        log_bytes = ps_log([frame(0, "p1", "00:00:00:00:00:01")])
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
        log_bytes = ps_log([frame(0, "p1", "00:00:00:00:00:01")])
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
        log_bytes = ps_log([frame(0, "p1", "00:00:00:00:00:01")])
        code, out, err, _ = run_config(log_bytes, "0" * 64 + ":0")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_offset_beyond_record_count_invalid_input(self):
        log_bytes = ps_log([frame(0, "p1", "00:00:00:00:00:01")])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_config(log_bytes, source + ":2")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_fdb_mode_rejected(self):
        events = [
            {"t": 0, "port": "p1", "mac": "00:00:00:00:00:01", "vlan": 1},
        ]
        log_bytes = record(fdb_config(), events)
        code, out, err, after = run_config(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_security_check_mode_rejected(self):
        # security-check 配置较 port-security 多 max_frame
        from test_security_check import check_frame, config as sc_config
        log_bytes = record(
            sc_config(), [check_frame(0, "p1", "00:00:00:00:00:01")]
        )
        code, out, err, after = run_config(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_qos_check_mode_rejected(self):
        from test_qos_check import check_frame, config as qc_config
        log_bytes = record(
            qc_config(),
            [check_frame(0, "p1", "ff:ff:ff:ff:ff:ff",
                         src="00:00:00:00:00:01")],
        )
        code, out, err, _ = run_config(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_rollback_without_prior_reload_invalid_input(self):
        # 空栈回滚使 record 整批 invalid_input、无法产出 LOG；直接构造结构
        # 与内部自洽摘要均合法但语义不成立的文档，log-config 须按
        # invalid_input/4 拒绝
        cfg = base_config()
        canonical_config = json.loads(json.dumps(cfg, sort_keys=True))
        event = json.loads(json.dumps(rollback_at(0), sort_keys=True))
        doc = {
            "schema": 1,
            "config": canonical_config,
            "records": [
                {
                    "t": 0, "version": 1,
                    "event": event, "applied": True,
                    "output": None,
                }
            ],
        }
        prefix = {
            "schema": doc["schema"], "config": doc["config"],
            "records": doc["records"],
        }
        doc["sha256"] = hashlib.sha256(
            (json.dumps(prefix, separators=(",", ":")) + "\n").encode()
        ).hexdigest()
        # 结构/自洽摘要通过但语义（空栈回滚）不成立
        log_bytes = (json.dumps(doc, separators=(",", ":")) + "\n").encode()
        code, out, err, _ = run_config(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_invalid_input_before_work_limit(self):
        log_bytes = ps_log([frame(0, "p1", "00:00:00:00:00:01")])
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_config(bad, "*", "1")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")


class WorkLimitTests(unittest.TestCase):
    def CONFIG_NEW(self):
        cfg = base_config()
        new = copy.deepcopy(cfg)
        new["age"] = 50
        new["security"][0]["limit"] = 5
        return cfg, new

    def test_reload_chain_charges_equal_legal_first_exceed(self):
        # 同 test_reload：初始 B+L+2U=1；帧 19、22；重载
        # X+D+P+A+T+1=4+2+5+1+0+1=13；末帧 25；累计 1+19+22+13+25=80。
        # 各 offset 累计：1（0）、20（1）、42（2）、55（3）、80（*）
        cfg, new = self.CONFIG_NEW()
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            frame(1, "p1", "00:00:00:00:00:02"),
            reload_at(2, new),
            frame(3, "p1", "00:00:00:00:00:03"),
        ]
        log_bytes = ps_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_config(log_bytes, "*", "80")
        self.assertEqual(code, 0, err)
        code, out, err, after = run_config(log_bytes, "*", "79")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"reload_work_limit"}\n')
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)
        # 逐 offset 边界：offset=2 累计 42，等于合法、41 首次超过
        code, _, err, _ = run_config(log_bytes, source + ":2", "42")
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_config(log_bytes, source + ":2", "41")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"reload_work_limit"}\n')

    def test_work_counts_only_prefix_events(self):
        # offset=1 累计 1+19=20：上限 20 合法；offset=2 需 42，同上限超限
        cfg, new = self.CONFIG_NEW()
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            frame(1, "p1", "00:00:00:00:00:02"),
            reload_at(2, new),
        ]
        log_bytes = ps_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, _, err, _ = run_config(log_bytes, source + ":1", "20")
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_config(log_bytes, source + ":2", "20")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"reload_work_limit"}\n')
        # offset=0：仅初始收敛 1
        code, out, err, _ = run_config(log_bytes, source + ":0", "1")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out.decode())["offset"], 0)

    def test_rollback_charged_as_reload_branch(self):
        # 同 test_reload_rollback：初始 1；帧 19；重载
        # X+D+P+A+T+1=2+1+5+1+0+1=10；回滚同式 10；末帧 22；累计 62。
        # 各 offset：1、20、30、40、62
        cfg = base_config()
        new = copy.deepcopy(cfg)
        new["age"] = 50
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            reload_at(1, new),
            rollback_at(2),
            frame(3, "p1", "00:00:00:00:00:02"),
        ]
        log_bytes = ps_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, _, err, _ = run_config(log_bytes, "*", "62")
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_config(log_bytes, "*", "61")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"reload_work_limit"}\n')
        # offset=3（帧+reload+rollback）累计 40
        code, _, err, _ = run_config(log_bytes, source + ":3", "40")
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_config(log_bytes, source + ":3", "39")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"reload_work_limit"}\n')

    def test_default_max_work_is_ten_million(self):
        code, _, err, _ = run_config(ps_log([]), "*")
        self.assertEqual(code, 0, err)


if __name__ == "__main__":
    unittest.main()
