#!/usr/bin/env python3
"""log-fdb 子命令回归：按游标重演 LOG 前 offset 项并输出当时 FDB。

仅用标准库；端到端驱动 `python switch.py log-fdb LOG CURSOR [MAX_WORK]`。
成功产物键序固定为 schema,source_sha256,offset,fdb,sha256，末项为前四键
紧凑 UTF-8 加 LF 的 sha256；CURSOR 沿用 log-page，`*` 表示 records 长度，
offset 为 0 或无前导零十进制；FDB 表项按 vlan 数值、mac 字典序，键序
vlan,mac,port,seen。逐事件按老化前表项数 K 计 K+1，等于 MAX_WORK 合法，
首次超过 stderr 仅 {"error":"fdb_work_limit"} 加 LF 并退出 5。
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


FDB_KEYS = ("schema", "source_sha256", "offset", "fdb")


def fdb_config(age=100, ports=("p1", "p2", "p3")):
    return {"age": age, "ports": list(ports)}


def learn(t, port, mac, vlan):
    return {"t": t, "port": port, "mac": mac, "vlan": vlan}


def digest_of(doc):
    prefix = {key: doc[key] for key in FDB_KEYS}
    raw = (
        json.dumps(prefix, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def rehash(doc):
    prefix = {key: doc[key] for key in ("schema", "config", "records")}
    raw = (
        json.dumps(prefix, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    doc["sha256"] = hashlib.sha256(raw).hexdigest()
    return doc


def fdb_log(events, age=100, ports=("p1", "p2", "p3")):
    """用 record 端到端产出 fdb 模式 LOG，返回 LOG 字节。"""
    config = fdb_config(age, ports)
    with tempfile.TemporaryDirectory() as tmp:
        config_path = os.path.join(tmp, "config.json")
        events_path = os.path.join(tmp, "events.json")
        log_path = os.path.join(tmp, "out.log")
        with open(config_path, "wb") as handle:
            handle.write(json.dumps(config).encode("utf-8"))
        with open(events_path, "wb") as handle:
            handle.write(json.dumps(events).encode("utf-8"))
        proc = subprocess.run(
            [sys.executable, SWITCH, "record", config_path, events_path,
             log_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        assert proc.returncode == 0, proc.stderr
        with open(log_path, "rb") as handle:
            return handle.read()


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


def doc_of(log_bytes):
    return json.loads(log_bytes.decode("utf-8"))


def sample_events():
    return [
        learn(0, "p1", "00:00:00:00:00:02", 2),
        learn(1, "p1", "00:00:00:00:00:01", 1),
        learn(2, "p2", "00:00:00:00:00:01", 1),
        learn(3, "p3", "00:00:00:00:00:0a", 1),
        learn(200, "p1", "00:00:00:00:00:03", 1),
    ]


class HappyPathTests(unittest.TestCase):
    def test_star_key_order_digest_and_full_fdb(self):
        log_bytes = fdb_log(sample_events())
        source = doc_of(log_bytes)["sha256"]
        code, out, err, _ = run_fdb(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertTrue(out.endswith(b"\n"))
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(
            list(doc),
            ["schema", "source_sha256", "offset", "fdb", "sha256"],
        )
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["source_sha256"], source)
        # * 表示 records 长度
        self.assertEqual(doc["offset"], 5)
        # t=200 老化 t<100 的 vlan1 旧项；vlan2 项 seen=0 亦被老化
        self.assertEqual(
            doc["fdb"],
            [
                {"vlan": 1, "mac": "00:00:00:00:00:03",
                 "port": "p1", "seen": 200},
            ],
        )
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_entries_sorted_vlan_then_mac(self):
        events = [
            learn(0, "p1", "00:00:00:00:00:09", 3),
            learn(1, "p1", "00:00:00:00:00:01", 1),
            learn(2, "p2", "00:00:00:00:00:02", 1),
            learn(3, "p3", "00:00:00:00:00:01", 2),
            learn(4, "p1", "00:00:00:00:00:0a", 1),
        ]
        code, out, err, _ = run_fdb(fdb_log(events), "*")
        self.assertEqual(code, 0, err)
        fdb = json.loads(out.decode("utf-8"))["fdb"]
        self.assertEqual(
            [(item["vlan"], item["mac"]) for item in fdb],
            [
                (1, "00:00:00:00:00:01"),
                (1, "00:00:00:00:00:02"),
                (1, "00:00:00:00:00:0a"),
                (2, "00:00:00:00:00:01"),
                (3, "00:00:00:00:00:09"),
            ],
        )
        self.assertEqual(
            [list(item) for item in fdb],
            [["vlan", "mac", "port", "seen"]] * len(fdb),
        )

    def test_offset_prefix_replay(self):
        log_bytes = fdb_log(sample_events())
        source = doc_of(log_bytes)["sha256"]
        code, out, err, _ = run_fdb(log_bytes, source + ":3")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["offset"], 3)
        self.assertEqual(
            doc["fdb"],
            [
                {"vlan": 1, "mac": "00:00:00:00:00:01",
                 "port": "p2", "seen": 2},
                {"vlan": 2, "mac": "00:00:00:00:00:02",
                 "port": "p1", "seen": 0},
            ],
        )
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_offset_zero_empty_fdb(self):
        log_bytes = fdb_log(sample_events())
        source = doc_of(log_bytes)["sha256"]
        code, out, err, _ = run_fdb(log_bytes, source + ":0")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["offset"], 0)
        self.assertEqual(doc["fdb"], [])
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_star_equals_cursor_at_record_count(self):
        log_bytes = fdb_log(sample_events())
        source = doc_of(log_bytes)["sha256"]
        _, star_out, _, _ = run_fdb(log_bytes, "*")
        _, cursor_out, _, _ = run_fdb(log_bytes, source + ":5")
        self.assertEqual(star_out, cursor_out)

    def test_offset_equal_record_count_legal(self):
        log_bytes = fdb_log(sample_events())
        source = doc_of(log_bytes)["sha256"]
        code, _, _, _ = run_fdb(log_bytes, source + ":5")
        self.assertEqual(code, 0)

    def test_empty_records_log(self):
        doc = rehash({"schema": 1, "config": fdb_config(), "records": []})
        log_bytes = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_fdb(log_bytes, "*")
        self.assertEqual(code, 0, err)
        result = json.loads(out.decode("utf-8"))
        self.assertEqual(result["offset"], 0)
        self.assertEqual(result["fdb"], [])

    def test_aging_applied_at_prefix_offset(self):
        # offset=4（t=3 时）：m02(vlan2)、m01(vlan1,已迁移到 p2)、
        # m0a(vlan1) 共 3 项；offset=5（t=200）触发老化后仅剩 1 项
        log_bytes = fdb_log(sample_events())
        source = doc_of(log_bytes)["sha256"]
        code, out, _, _ = run_fdb(log_bytes, source + ":4")
        self.assertEqual(code, 0)
        self.assertEqual(
            len(json.loads(out.decode("utf-8"))["fdb"]), 3
        )

    def test_log_file_not_modified_on_success(self):
        log_bytes = fdb_log(sample_events())
        _, _, _, after = run_fdb(log_bytes, "*")
        self.assertEqual(after, log_bytes)


class UsageTests(unittest.TestCase):
    def test_arg_counts(self):
        log_bytes = fdb_log(sample_events())
        for tokens in (
            [],
            ["*", "1", "2"],
        ):
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "in.log")
                with open(path, "wb") as handle:
                    handle.write(log_bytes)
                proc = subprocess.run(
                    [sys.executable, SWITCH, "log-fdb", path, *tokens],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
            self.assertEqual(proc.returncode, 2, tokens)

    def test_bad_cursor_tokens(self):
        log_bytes = fdb_log(sample_events())
        source = doc_of(log_bytes)["sha256"]
        for cursor in (
            "",
            "x",
            "* ",
            source[:63],
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
        log_bytes = fdb_log(sample_events())
        for work in ("0", "-1", "01", "1.0", "1 ", "x", "1e3"):
            code, _, _, _ = run_fdb(log_bytes, "*", work)
            self.assertEqual(code, 2, work)


class ErrorPrecedenceTests(unittest.TestCase):
    def test_file_not_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "nope.log")
            proc = subprocess.run(
                [sys.executable, SWITCH, "log-fdb", missing, "*"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(proc.stderr, b'{"error":"file_not_found"}\n')
        self.assertEqual(proc.stdout, b"")

    def test_log_limit_before_invalid_input(self):
        # 输入固定上界 16 MiB：超出即 log_limit/5，先于 JSON 解析与
        # invalid_input；失败 stdout 为空且不触碰不存在的改写
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "big.log")
            with open(log_path, "wb") as handle:
                handle.write(b"[")
                handle.truncate(16 * 1024 * 1024 + 1)
            proc = subprocess.run(
                [sys.executable, SWITCH, "log-fdb", log_path, "*"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(proc.returncode, 5)
            self.assertEqual(proc.stderr, b'{"error":"log_limit"}\n')
            self.assertEqual(proc.stdout, b"")

    def test_bad_internal_sha_invalid_input(self):
        log_bytes = fdb_log(sample_events())
        doc = doc_of(log_bytes)
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_fdb(bad, "*")
        self.assertEqual(code, 4)
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertEqual(out, b"")

    def test_cursor_sha_mismatch_invalid_input(self):
        log_bytes = fdb_log(sample_events())
        code, out, err, _ = run_fdb(log_bytes, "0" * 64 + ":0")
        self.assertEqual(code, 4)
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertEqual(out, b"")

    def test_cursor_offset_beyond_record_count_invalid_input(self):
        log_bytes = fdb_log(sample_events())
        source = doc_of(log_bytes)["sha256"]
        code, out, err, _ = run_fdb(log_bytes, source + ":6")
        self.assertEqual(code, 4)
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertEqual(out, b"")

    def test_other_mode_rejected(self):
        # forward 模式（ports 为对象数组）一律 invalid_input/4
        from test_record import base_config
        from test_record import frame
        from test_record import record
        _, forward_log = record(
            base_config(), [frame(0, "p1", "00:00:00:00:00:01")]
        )
        code, out, err, _ = run_fdb(forward_log, "*")
        self.assertEqual(code, 4)
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertEqual(out, b"")

    def test_tampered_record_invalid_input(self):
        log_bytes = fdb_log(sample_events())
        doc = doc_of(log_bytes)
        doc["records"][1]["applied"] = not doc["records"][1]["applied"]
        bad = (
            json.dumps(rehash(doc), separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_fdb(bad, "*")
        self.assertEqual(code, 4)
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertEqual(out, b"")

    def test_failure_leaves_log_unchanged(self):
        log_bytes = fdb_log(sample_events())
        _, _, _, after = run_fdb(log_bytes, "0" * 64 + ":0")
        self.assertEqual(after, log_bytes)


class WorkLimitTests(unittest.TestCase):
    def test_work_counts_k_plus_one_before_aging(self):
        # 5 个不同学习：成本 1+2+3+4+5=15
        events = [
            learn(0, "p1", "00:00:00:00:00:01", 1),
            learn(1, "p2", "00:00:00:00:00:02", 1),
            learn(2, "p3", "00:00:00:00:00:03", 1),
            learn(3, "p1", "00:00:00:00:00:04", 1),
            learn(4, "p2", "00:00:00:00:00:05", 1),
        ]
        log_bytes = fdb_log(events)
        code, _, _, _ = run_fdb(log_bytes, "*", "15")
        self.assertEqual(code, 0)
        code, out, err, _ = run_fdb(log_bytes, "*", "14")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"fdb_work_limit"}\n')
        self.assertEqual(out, b"")

    def test_aging_reduces_k_before_event(self):
        # t=0 学习一项（成本 1）；t=200 老化前表中仍有该旧项，K=1，
        # 第二项老化前成本 2，合计 3（K 按老化前表项计，老化不降低该项成本）
        events = [
            learn(0, "p1", "00:00:00:00:00:01", 1),
            learn(200, "p2", "00:00:00:00:00:02", 1),
        ]
        log_bytes = fdb_log(events, age=100)
        code, _, _, _ = run_fdb(log_bytes, "*", "3")
        self.assertEqual(code, 0)
        code, _, err, _ = run_fdb(log_bytes, "*", "2")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"fdb_work_limit"}\n')

    def test_same_source_refresh_still_charges_k_plus_one(self):
        # 同时刻同口幂等学习不改变 FDB（applied=False），但老化前表项已存在，
        # K=1，第二项成本 2：合计 1+2=3
        events = [
            learn(0, "p1", "00:00:00:00:00:01", 1),
            learn(0, "p1", "00:00:00:00:00:01", 1),
        ]
        log_bytes = fdb_log(events)
        code, _, _, _ = run_fdb(log_bytes, "*", "3")
        self.assertEqual(code, 0)
        code, _, err, _ = run_fdb(log_bytes, "*", "2")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"fdb_work_limit"}\n')

    def test_prefix_offset_work_only_covers_prefix(self):
        events = [
            learn(0, "p1", "00:00:00:00:00:01", 1),
            learn(1, "p2", "00:00:00:00:00:02", 1),
            learn(2, "p3", "00:00:00:00:00:03", 1),
        ]
        log_bytes = fdb_log(events)
        source = doc_of(log_bytes)["sha256"]
        # 前两项成本 1+2=3
        code, _, _, _ = run_fdb(log_bytes, source + ":2", "3")
        self.assertEqual(code, 0)
        code, _, err, _ = run_fdb(log_bytes, source + ":2", "2")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"fdb_work_limit"}\n')
        # offset=0 无工作量，任意正上限合法
        code, _, _, _ = run_fdb(log_bytes, source + ":0", "1")
        self.assertEqual(code, 0)

    def test_work_limit_after_invalid_input_contract(self):
        # 坏游标摘要（invalid_input/4）先于工作量判定，即使上限极小
        log_bytes = fdb_log(sample_events())
        code, _, _, _ = run_fdb(log_bytes, "0" * 64 + ":0", "1")
        self.assertEqual(code, 4)

    def test_output_limit_not_directly_settable(self):
        # 输出上界固定 16 MiB；成功产物远小于该值
        log_bytes = fdb_log(sample_events())
        code, out, _, _ = run_fdb(log_bytes, "*")
        self.assertEqual(code, 0)
        self.assertLess(len(out), 16 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
