#!/usr/bin/env python3
"""log-fdb 子命令回归：按游标重演 fdb 模式 LOG 的前 offset 条学习记录。

仅用标准库；端到端驱动 `python switch.py log-fdb LOG CURSOR [MAX_WORK]`。
成功产物键序固定为 schema,source_sha256,offset,fdb,sha256，末项为前四键
紧凑 UTF-8 加 LF 的 sha256；CURSOR 沿用 log-page（* 或
<sha256>:<offset>），但 * 表示 records 长度（重演全部）；offset 项后
FDB，offset=0 为空；表项按 vlan 数值、mac 字典序，项键序
vlan,mac,port,seen。LOG 须通过 record 结构与摘要核对并仅接受 fdb 模式，
否则 invalid_input/4；逐事件按老化前表项 K 计 K+1，等于上限合法，首次
超过 stderr 仅 {"error":"fdb_work_limit"} 加 LF 并退出 5。
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
sys.path.insert(0, HERE)

FDB_KEYS = ["schema", "source_sha256", "offset", "fdb", "sha256"]
ENTRY_KEYS = ["vlan", "mac", "port", "seen"]


def fdb_config(names=("p1", "p2", "p3"), age=100):
    return {"ports": list(names), "age": age}


def learn(t, port, mac, vlan=1):
    return {"t": t, "port": port, "mac": mac, "vlan": vlan}


def mac(n):
    return "00:00:00:00:00:%02x" % n


def record(cfg, events, *limits):
    """record CONFIG EVENTS → LOG 字节（断言成功）。"""
    with tempfile.TemporaryDirectory() as tmp:
        cp = os.path.join(tmp, "config.json")
        ep = os.path.join(tmp, "events.json")
        lp = os.path.join(tmp, "out.log")
        with open(cp, "w", encoding="utf-8") as handle:
            json.dump(cfg, handle)
        with open(ep, "w", encoding="utf-8") as handle:
            json.dump(events, handle)
        proc = subprocess.run(
            [sys.executable, SWITCH, "record", cp, ep, lp, *limits],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        assert proc.returncode == 0, proc.stderr.decode()
        with open(lp, "rb") as handle:
            return handle.read()


def fdb_log(events, config=None):
    return record(config or fdb_config(), events)


def digest_of(doc):
    prefix = {
        "schema": doc["schema"],
        "source_sha256": doc["source_sha256"],
        "offset": doc["offset"],
        "fdb": doc["fdb"],
    }
    raw = (
        json.dumps(prefix, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def run_fdb(log_bytes, cursor, *extra):
    with tempfile.TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "in.log")
        with open(log_path, "wb") as handle:
            handle.write(log_bytes)
        proc = subprocess.run(
            [sys.executable, SWITCH, "log-fdb", log_path, cursor, *extra],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        with open(log_path, "rb") as handle:
            after = handle.read()
    return proc.returncode, proc.stdout, proc.stderr, after


class HappyPathTests(unittest.TestCase):
    def test_star_is_records_length_with_fixed_key_order_and_digest(self):
        events = [
            learn(0, "p1", mac(1), 1),
            learn(1, "p2", mac(2), 1),
            learn(2, "p3", mac(3), 2),
        ]
        log_bytes = fdb_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_fdb(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertTrue(out.endswith(b"\n"))
        self.assertEqual(after, log_bytes)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(list(doc), FDB_KEYS)
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["source_sha256"], source)
        self.assertEqual(doc["offset"], 3)
        self.assertEqual(
            doc["fdb"],
            [
                {"vlan": 1, "mac": mac(1), "port": "p1", "seen": 0},
                {"vlan": 1, "mac": mac(2), "port": "p2", "seen": 1},
                {"vlan": 2, "mac": mac(3), "port": "p3", "seen": 2},
            ],
        )
        for entry in doc["fdb"]:
            self.assertEqual(list(entry), ENTRY_KEYS)
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_star_equals_sha_cursor_at_record_count(self):
        events = [learn(0, "p1", mac(1)), learn(1, "p2", mac(2))]
        log_bytes = fdb_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        _, star_out, _, _ = run_fdb(log_bytes, "*")
        code, cur_out, err, _ = run_fdb(log_bytes, source + ":2")
        self.assertEqual(code, 0, err)
        self.assertEqual(cur_out, star_out)
        self.assertEqual(json.loads(cur_out.decode())["offset"], 2)

    def test_offset_zero_is_empty_fdb(self):
        events = [learn(0, "p1", mac(1)), learn(1, "p2", mac(2))]
        log_bytes = fdb_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_fdb(log_bytes, source + ":0")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["offset"], 0)
        self.assertEqual(doc["fdb"], [])
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_partial_offset_replays_only_prefix(self):
        events = [
            learn(0, "p1", mac(1)),
            learn(1, "p2", mac(2)),
            learn(2, "p3", mac(3)),
            learn(3, "p1", mac(4)),
        ]
        log_bytes = fdb_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_fdb(log_bytes, source + ":2")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["offset"], 2)
        self.assertEqual(
            doc["fdb"],
            [
                {"vlan": 1, "mac": mac(1), "port": "p1", "seen": 0},
                {"vlan": 1, "mac": mac(2), "port": "p2", "seen": 1},
            ],
        )
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_entries_sorted_by_vlan_numeric_then_mac_lexicographic(self):
        events = [
            learn(0, "p1", mac(10), 10),
            learn(1, "p2", mac(2), 10),
            learn(2, "p3", mac(1), 2),
            learn(3, "p1", mac(9), 2),
        ]
        log_bytes = fdb_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_fdb(log_bytes, source + ":4")
        self.assertEqual(code, 0, err)
        self.assertEqual(
            [(e["vlan"], e["mac"]) for e in json.loads(out.decode())["fdb"]],
            [
                (2, mac(1)),
                (2, mac(9)),
                (10, mac(2)),
                (10, mac(10)),
            ],
        )

    def test_aging_applied_within_prefix_replay(self):
        # age=100：t=100 时 A（seen=0）满足 t-seen>=age 被老化
        events = [
            learn(0, "p1", mac(1)),
            learn(100, "p2", mac(2)),
            learn(101, "p3", mac(3)),
        ]
        log_bytes = record(fdb_config(age=100), events)
        for offset, kept in ((1, [mac(1)]), (2, [mac(2)]), (3, [mac(2), mac(3)])):
            source = json.loads(log_bytes.decode("utf-8"))["sha256"]
            code, out, err, _ = run_fdb(log_bytes, source + ":%d" % offset)
            self.assertEqual(code, 0, (offset, err))
            doc = json.loads(out.decode("utf-8"))
            self.assertEqual([e["mac"] for e in doc["fdb"]], kept)
            self.assertEqual(doc["sha256"], digest_of(doc))

    def test_move_updates_port_and_seen(self):
        events = [
            learn(0, "p1", mac(1)),
            learn(5, "p2", mac(1)),
        ]
        log_bytes = fdb_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_fdb(log_bytes, "*")
        self.assertEqual(code, 0, err)
        entries = json.loads(out.decode("utf-8"))["fdb"]
        self.assertEqual(
            entries,
            [{"vlan": 1, "mac": mac(1), "port": "p2", "seen": 5}],
        )

    def test_empty_log_star_and_zero_identical_empty(self):
        log_bytes = fdb_log([])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for cursor in ("*", source + ":0"):
            code, out, err, _ = run_fdb(log_bytes, cursor)
            self.assertEqual(code, 0, err)
            doc = json.loads(out.decode("utf-8"))
            self.assertEqual(doc["offset"], 0)
            self.assertEqual(doc["fdb"], [])


class UsageTests(unittest.TestCase):
    def test_arg_counts(self):
        log_bytes = fdb_log([learn(0, "p1", mac(1))])
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "in.log")
            with open(path, "wb") as handle:
                handle.write(log_bytes)
            # 缺 CURSOR；多余位置参数均 usage/2
            for tokens in ([], [path], [path, "*", "1", "2"]):
                proc = subprocess.run(
                    [sys.executable, SWITCH, "log-fdb", *tokens],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                self.assertEqual(proc.returncode, 2, tokens)

    def test_bad_cursor_tokens(self):
        log_bytes = fdb_log([learn(0, "p1", mac(1))])
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
            code, _, _, _ = run_fdb(log_bytes, cursor)
            self.assertEqual(code, 2, cursor)

    def test_bad_max_work_tokens(self):
        log_bytes = fdb_log([learn(0, "p1", mac(1))])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for token in ("", "0", "-1", "01", "1.0", "1 ", "x", "1e3"):
            code, _, _, _ = run_fdb(log_bytes, source + ":0", token)
            self.assertEqual(code, 2, token)
            code, _, _, _ = run_fdb(log_bytes, "*", token)
            self.assertEqual(code, 2, token)

    def test_arbitrary_length_decimal_max_work_accepted(self):
        log_bytes = fdb_log([learn(0, "p1", mac(1))])
        code, _, err, _ = run_fdb(log_bytes, "*", "9" * 60)
        self.assertEqual(code, 0, err)


class ErrorPrecedenceTests(unittest.TestCase):
    def test_file_not_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "nope.log")
            proc = subprocess.run(
                [sys.executable, SWITCH, "log-fdb", missing, "*"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(proc.returncode, 3)
        self.assertIn(b"file_not_found", proc.stderr)
        self.assertEqual(proc.stdout, b"")

    def test_log_limit_before_invalid_input(self):
        # 固定输入上限 16777216；超限先于 JSON 解析（log_limit/5）
        oversized = b"{" + b" " * (16 * 1024 * 1024)
        code, out, err, after = run_fdb(oversized, "*")
        self.assertEqual(code, 5)
        self.assertIn(b"log_limit", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, oversized)

    def test_bad_internal_sha_invalid_input(self):
        log_bytes = fdb_log([learn(0, "p1", mac(1))])
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_fdb(bad, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_sha_mismatch_invalid_input(self):
        log_bytes = fdb_log([learn(0, "p1", mac(1))])
        code, out, err, _ = run_fdb(log_bytes, "0" * 64 + ":0")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_offset_beyond_record_count_invalid_input(self):
        log_bytes = fdb_log([learn(0, "p1", mac(1))])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_fdb(log_bytes, source + ":2")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_non_fdb_mode_rejected(self):
        # 旧式 forward 配置（ports 为对象数组）：静态合法 LOG 但非 fdb 模式
        cfg = {
            "ports": [
                {"name": "p1", "vlan": 1, "up": True},
                {"name": "p2", "vlan": 1, "up": True},
            ],
            "age": 100,
        }
        events = [{"t": 0, "port": "p1", "src": mac(1),
                   "dst": "ff:ff:ff:ff:ff:ff"}]
        log_bytes = record(cfg, events)
        code, out, err, after = run_fdb(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_tampered_records_fail_replay_verification(self):
        # 同时刻同口重复学习幂等 applied=false；篡改为 true 并重算内部摘要
        events = [learn(0, "p1", mac(1)), learn(0, "p1", mac(1))]
        log_bytes = fdb_log(events)
        doc = json.loads(log_bytes.decode("utf-8"))
        # 同时刻同口重复学习 applied=false；篡改为 true 并重算内部摘要
        doc["records"][1]["applied"] = True
        doc["records"][1]["version"] = 1
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
        code, out, err, _ = run_fdb(bad, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_invalid_input_before_work_limit(self):
        # 摘要错与极小工作量上限同时成立：invalid_input/4 优先
        log_bytes = fdb_log([learn(0, "p1", mac(1))])
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_fdb(bad, "*", "1")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")


class WorkLimitTests(unittest.TestCase):
    def test_distinct_sources_cost_k_plus_one(self):
        # 四个不同源：老化前 K=0,1,2,3 → 累计 1,3,6,10
        config = fdb_config(("p1", "p2", "p3", "p4"))
        events = [learn(i, "p%d" % (i + 1), mac(i + 1)) for i in range(4)]
        log_bytes = fdb_log(events, config)
        # 等于上限合法
        code, out, err, _ = run_fdb(log_bytes, "*", "10")
        self.assertEqual(code, 0, err)
        self.assertEqual(len(json.loads(out.decode())["fdb"]), 4)
        # 首次超过：stderr 仅错误 JSON + LF，stdout 空，退出 5
        code, out, err, after = run_fdb(log_bytes, "*", "9")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"fdb_work_limit"}\n')
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_work_counts_only_prefix_events(self):
        config = fdb_config(("p1", "p2", "p3", "p4"))
        events = [learn(i, "p%d" % (i + 1), mac(i + 1)) for i in range(4)]
        log_bytes = fdb_log(events, config)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        # offset=3：仅前三项，累计 1+2+3=6
        code, _, err, _ = run_fdb(log_bytes, source + ":3", "6")
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_fdb(log_bytes, source + ":3", "5")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"fdb_work_limit"}\n')
        # offset=0：不重演任何事件，上限再小也合法
        code, out, err, _ = run_fdb(log_bytes, source + ":0", "1")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out.decode())["fdb"], [])

    def test_repeat_source_still_charged_but_keeps_single_entry(self):
        # 同源迁移：每次仍计老化前 K+1（第 2、3 项 K=1），累计 1+2+2=5，
        # 但 FDB 始终只有一项
        events = [learn(0, "p1", mac(1)), learn(1, "p2", mac(1)),
                  learn(2, "p3", mac(1))]
        log_bytes = fdb_log(events)
        code, _, err, _ = run_fdb(log_bytes, "*", "5")
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_fdb(log_bytes, "*", "4")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"fdb_work_limit"}\n')
        code, out, err, _ = run_fdb(log_bytes, "*", "5")
        self.assertEqual(code, 0, err)
        self.assertEqual(
            json.loads(out.decode())["fdb"],
            [{"vlan": 1, "mac": mac(1), "port": "p3", "seen": 2}],
        )

    def test_default_max_work_is_ten_million(self):
        code, _, err, _ = run_fdb(fdb_log([]), "*")
        self.assertEqual(code, 0, err)


if __name__ == "__main__":
    unittest.main()
