#!/usr/bin/env python3
"""log-stp 子命令回归：按游标重演 stp 模式 LOG 的前 offset 条链路事件并
给出该时刻的生成树快照。

仅用标准库；端到端驱动 `python switch.py log-stp LOG CURSOR [MAX_WORK]`。
参数、资源、CURSOR 及错误顺序完全沿用 log-qos；成功产物键序固定为
schema,source_sha256,offset,snapshot,sha256，末项为前四键紧凑非 ASCII
转义 UTF-8 JSON 加 LF 的小写 sha256；CURSOR 的 * 表示 records 长度
（重演全部），否则 <sha256>:<offset>，offset 为已消费记录数（含
applied=false 记录）；offset=0 为 t=0 初态，否则 snapshot.t 取第
offset 项记录的 t。snapshot 键序 t,bridges；bridges 按配置序，项键序
name,root,cost,ports；ports 按名字典序，项键序 name,role,state。
LOG 须通过内部摘要核对、stp 语义、全部记录核对与重建日志逐字节一致，
仅接受 stp 模式，否则 invalid_input/4；重演前 offset 项按 stp 工作量
公式计费（初值 B+L+2U；前缀内 up 实际改变时按新 U 再加同式，幂等
不加），等于上限合法，首次超过 stderr 仅 {"error":"stp_work_limit"}
加 LF 并退出 5；失败 stdout 为空且 LOG 只读。
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

import switch as switch_mod  # noqa: E402
from test_log_fdb import record, fdb_config  # noqa: E402

STP_KEYS = ["schema", "source_sha256", "offset", "snapshot", "sha256"]
BRIDGE_KEYS = ["name", "root", "cost", "ports"]
PORT_KEYS = ["name", "role", "state"]


def link(lid, xb, xp, yb, yp, cost=1, up=True):
    return {
        "id": lid, "x": [xb, xp], "y": [yb, yp], "cost": cost, "up": up,
    }


def stp_config():
    # B=3、L=3、初始 U=3、delay=2
    return {
        "bridges": ["b1", "b2", "b3"],
        "links": [
            link("L1", "b1", "p1", "b2", "p1"),
            link("L2", "b2", "p2", "b3", "p1"),
            link("L3", "b3", "p2", "b1", "p2"),
        ],
        "delay": 2,
    }


def evt(t, lid, up):
    return {"t": t, "id": lid, "up": up}


def stp_log(events, cfg=None):
    return record(cfg or stp_config(), events)


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


def run_stp(log_bytes, cursor, *extra):
    with tempfile.TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "in.log")
        with open(log_path, "wb") as handle:
            handle.write(log_bytes)
        proc = subprocess.run(
            [sys.executable, SWITCH, "log-stp", log_path, cursor, *extra],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        with open(log_path, "rb") as handle:
            after = handle.read()
    return proc.returncode, proc.stdout, proc.stderr, after


def direct_snapshot(cfg, events, offset):
    """直接调用 stp 求前 offset 项事件后的快照（offset=0 为 t=0 初态）。"""
    config = copy.deepcopy(cfg)
    bridges, links, delay = switch_mod.validate_stp_config(config)
    link_ids = {item["id"] for item in links}
    checked = switch_mod.validate_stp_events(copy.deepcopy(events), link_ids)
    results = switch_mod.stp(
        bridges, links, delay, checked[:offset]
    )["results"]
    return results[-1]


class HappyPathTests(unittest.TestCase):
    def setUp(self):
        # 幂等 up、实际 down、幂等 down、实际 up
        self.events = [
            evt(1, "L1", True),
            evt(2, "L1", False),
            evt(3, "L1", False),
            evt(4, "L1", True),
        ]
        self.log_bytes = stp_log(self.events)
        self.source = json.loads(
            self.log_bytes.decode("utf-8")
        )["sha256"]

    def test_star_is_records_length_with_fixed_key_order_and_digest(self):
        code, out, err, after = run_stp(self.log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertTrue(out.endswith(b"\n"))
        self.assertNotIn(b", ", out)
        self.assertNotIn(b": ", out)
        self.assertEqual(after, self.log_bytes)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(list(doc), STP_KEYS)
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["source_sha256"], self.source)
        self.assertEqual(doc["offset"], 4)
        snapshot = doc["snapshot"]
        self.assertEqual(list(snapshot), ["t", "bridges"])
        self.assertEqual(snapshot["t"], 4)
        self.assertEqual(
            [b["name"] for b in snapshot["bridges"]], ["b1", "b2", "b3"]
        )
        for bridge in snapshot["bridges"]:
            self.assertEqual(list(bridge), BRIDGE_KEYS)
            names = [port["name"] for port in bridge["ports"]]
            self.assertEqual(names, sorted(names))
            for port in bridge["ports"]:
                self.assertEqual(list(port), PORT_KEYS)
                self.assertIn(
                    port["role"],
                    ("root", "designated", "alternate", "disabled"),
                )
                self.assertIn(
                    port["state"],
                    ("discarding", "learning", "forwarding"),
                )
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_star_equals_sha_cursor_at_record_count(self):
        _, star_out, _, _ = run_stp(self.log_bytes, "*")
        code, cur_out, err, _ = run_stp(self.log_bytes, self.source + ":4")
        self.assertEqual(code, 0, err)
        self.assertEqual(cur_out, star_out)
        self.assertEqual(json.loads(cur_out.decode())["offset"], 4)

    def test_offset_zero_is_initial_t0_state(self):
        code, out, err, _ = run_stp(self.log_bytes, self.source + ":0")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["offset"], 0)
        self.assertEqual(doc["snapshot"]["t"], 0)
        self.assertEqual(
            doc["snapshot"], direct_snapshot(stp_config(), self.events, 0)
        )
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_every_offset_matches_record_output_and_direct_run(self):
        log_doc = json.loads(self.log_bytes.decode("utf-8"))
        cfg = stp_config()
        for offset in range(5):
            code, out, err, _ = run_stp(
                self.log_bytes, self.source + ":%d" % offset
            )
            self.assertEqual(code, 0, (offset, err))
            doc = json.loads(out.decode("utf-8"))
            self.assertEqual(doc["offset"], offset)
            snapshot = doc["snapshot"]
            if offset == 0:
                self.assertEqual(snapshot["t"], 0)
            else:
                self.assertEqual(
                    snapshot["t"], log_doc["records"][offset - 1]["t"]
                )
                self.assertEqual(
                    snapshot, log_doc["records"][offset - 1]["output"]
                )
            self.assertEqual(
                snapshot, direct_snapshot(cfg, self.events, offset)
            )
            self.assertEqual(doc["sha256"], digest_of(doc))

    def test_idempotent_records_are_consumed_but_change_nothing(self):
        # offset=2 与 3 间仅隔一条幂等 down：快照完全相同、t 不同
        code, out2, err, _ = run_stp(self.log_bytes, self.source + ":2")
        self.assertEqual(code, 0, err)
        code, out3, err, _ = run_stp(self.log_bytes, self.source + ":3")
        self.assertEqual(code, 0, err)
        snap2 = json.loads(out2.decode())["snapshot"]
        snap3 = json.loads(out3.decode())["snapshot"]
        self.assertEqual(snap2["t"], 2)
        self.assertEqual(snap3["t"], 3)
        self.assertEqual(snap2["bridges"], snap3["bridges"])

    def test_bridges_follow_config_order(self):
        cfg = stp_config()
        cfg["bridges"] = ["b3", "b1", "b2"]
        log_bytes = stp_log([evt(0, "L1", False)], cfg)
        code, out, err, _ = run_stp(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(
            [b["name"] for b in json.loads(out.decode())["snapshot"]["bridges"]],
            ["b3", "b1", "b2"],
        )

    def test_empty_log_star_and_zero_identical(self):
        log_bytes = stp_log([])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        outputs = []
        for cursor in ("*", source + ":0"):
            code, out, err, _ = run_stp(log_bytes, cursor)
            self.assertEqual(code, 0, err)
            doc = json.loads(out.decode("utf-8"))
            self.assertEqual(doc["offset"], 0)
            self.assertEqual(doc["snapshot"]["t"], 0)
            outputs.append(out)
        self.assertEqual(outputs[0], outputs[1])

    def test_non_ascii_digest_uses_unescaped_utf8(self):
        cfg = {
            "bridges": ["桥1", "桥2"],
            "links": [link("L1", "桥1", "p1", "桥2", "p1")],
            "delay": 2,
        }
        log_bytes = stp_log([evt(3, "L1", False)], cfg)
        code, out, err, _ = run_stp(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertNotIn(b"\\u", out)
        self.assertIn("桥".encode("utf-8"), out)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["sha256"], digest_of(doc))


class UsageTests(unittest.TestCase):
    def test_arg_counts(self):
        log_bytes = stp_log([evt(0, "L1", False)])
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "in.log")
            with open(path, "wb") as handle:
                handle.write(log_bytes)
            for tokens in ([], [path], [path, "*", "1", "2"]):
                proc = subprocess.run(
                    [sys.executable, SWITCH, "log-stp", *tokens],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                self.assertEqual(proc.returncode, 2, tokens)

    def test_bad_cursor_tokens(self):
        log_bytes = stp_log([evt(0, "L1", False)])
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
            code, _, _, _ = run_stp(log_bytes, cursor)
            self.assertEqual(code, 2, cursor)

    def test_bad_max_work_tokens(self):
        log_bytes = stp_log([evt(0, "L1", False)])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for token in ("", "0", "-1", "01", "1.0", "1 ", "x", "1e3"):
            code, _, _, _ = run_stp(log_bytes, source + ":0", token)
            self.assertEqual(code, 2, token)
            code, _, _, _ = run_stp(log_bytes, "*", token)
            self.assertEqual(code, 2, token)

    def test_arbitrary_length_decimal_max_work_accepted(self):
        log_bytes = stp_log([evt(0, "L1", False)])
        code, _, err, _ = run_stp(log_bytes, "*", "9" * 60)
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_stp(log_bytes, "*", "9" * 5000)
        self.assertEqual(code, 0, err)

    def test_five_thousand_digit_cursor_offset_unbounded(self):
        log_bytes = stp_log([evt(0, "L1", False)])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_stp(
            log_bytes, source + ":" + "1" * 5000
        )
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)


class ErrorPrecedenceTests(unittest.TestCase):
    def setUp(self):
        self.events = [
            evt(1, "L1", True),
            evt(2, "L1", False),
            evt(3, "L1", False),
            evt(4, "L1", True),
        ]
        self.log_bytes = stp_log(self.events)
        self.source = json.loads(
            self.log_bytes.decode("utf-8")
        )["sha256"]

    def test_file_not_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "nope.log")
            proc = subprocess.run(
                [sys.executable, SWITCH, "log-stp", missing, "*"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(proc.returncode, 3)
        self.assertIn(b"file_not_found", proc.stderr)
        self.assertEqual(proc.stdout, b"")

    def test_log_limit_before_invalid_input(self):
        oversized = b"{" + b" " * (16 * 1024 * 1024)
        code, out, err, after = run_stp(oversized, "*")
        self.assertEqual(code, 5)
        self.assertIn(b"log_limit", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, oversized)

    def test_bad_internal_sha_invalid_input(self):
        doc = json.loads(self.log_bytes.decode("utf-8"))
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_stp(bad, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_sha_mismatch_invalid_input(self):
        code, out, err, _ = run_stp(self.log_bytes, "0" * 64 + ":0")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_offset_beyond_record_count_invalid_input(self):
        code, out, err, after = run_stp(self.log_bytes, self.source + ":5")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, self.log_bytes)

    def test_fdb_mode_rejected(self):
        events = [
            {"t": 0, "port": "p1", "mac": "00:00:00:00:00:01", "vlan": 1},
        ]
        log_bytes = record(fdb_config(), events)
        code, out, err, after = run_stp(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_forward_stp_mode_rejected(self):
        # forward-stp 配置形状（七键）静态合法但非 stp 模式
        cfg = {
            "bridges": ["b1", "b2"],
            "links": [link("L1", "b1", "p1", "b2", "p1")],
            "delay": 2,
            "bridge": "b1",
            "ports": [
                {"name": "p1", "mode": "access", "pvid": 1,
                 "allowed": [1], "untagged": [1], "up": True},
                {"name": "p2", "mode": "access", "pvid": 1,
                 "allowed": [1], "untagged": [1], "up": True},
                {"name": "p3", "mode": "access", "pvid": 1,
                 "allowed": [1], "untagged": [1], "up": True},
            ],
            "age": 100,
        }
        events = [evt(0, "L1", False)]
        log_bytes = record(cfg, events)
        code, out, err, after = run_stp(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_tampered_records_fail_verification(self):
        # 幂等记录 applied=false 篡改为 true 并重算内部摘要 → 记录核对失败
        doc = json.loads(self.log_bytes.decode("utf-8"))
        doc["records"][0]["applied"] = True
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
        code, out, err, after = run_stp(bad, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, bad)

    def test_tampered_output_bytes_fail_rebuild(self):
        # 仅改动 output 并重算内部摘要：全量重演重建字节不一致 → 4
        doc = json.loads(self.log_bytes.decode("utf-8"))
        doc["records"][1]["output"]["t"] = 99
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
        code, out, err, _ = run_stp(bad, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_invalid_input_before_work_limit(self):
        code, out, err, _ = run_stp(
            self.log_bytes, "0" * 64 + ":0", "1"
        )
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")


class WorkLimitTests(unittest.TestCase):
    def setUp(self):
        # B=3,L=3,初始 U=3：初值 12；事件 幂等(+0)、down→U2(+10)、
        # 幂等(+0)、up→U3(+12)。前缀累计：
        # offset 0/1=12，2/3=22，4=34
        self.events = [
            evt(1, "L1", True),
            evt(2, "L1", False),
            evt(3, "L1", False),
            evt(4, "L1", True),
        ]
        self.log_bytes = stp_log(self.events)
        self.source = json.loads(
            self.log_bytes.decode("utf-8")
        )["sha256"]

    def test_formula_boundaries_for_every_prefix(self):
        totals = {0: 12, 1: 12, 2: 22, 3: 22, 4: 34}
        for offset, total in totals.items():
            code, _, err, _ = run_stp(
                self.log_bytes, self.source + ":%d" % offset, str(total)
            )
            self.assertEqual(code, 0, (offset, total, err))
            code, out, err, after = run_stp(
                self.log_bytes, self.source + ":%d" % offset, str(total - 1)
            )
            self.assertEqual(code, 5, (offset, total))
            self.assertEqual(err, b'{"error":"stp_work_limit"}\n')
            self.assertEqual(out, b"")
            self.assertEqual(after, self.log_bytes)

    def test_idempotent_events_not_charged(self):
        # offset=1 仅含幂等事件：工作量与 offset=0 同为 12
        for offset in (0, 1):
            code, _, err, _ = run_stp(
                self.log_bytes, self.source + ":%d" % offset, "12"
            )
            self.assertEqual(code, 0, err)
            code, _, _, _ = run_stp(
                self.log_bytes, self.source + ":%d" % offset, "11"
            )
            self.assertEqual(code, 5)

    def test_work_counts_only_prefix_records(self):
        # offset=2 累计 22；offset=4 累计 34：上限 22 对前者合法、对后者超限
        code, _, err, _ = run_stp(self.log_bytes, self.source + ":2", "22")
        self.assertEqual(code, 0, err)
        code, _, _, _ = run_stp(self.log_bytes, self.source + ":4", "22")
        self.assertEqual(code, 5)

    def test_default_max_work_is_ten_million(self):
        code, _, err, _ = run_stp(self.log_bytes, "*")
        self.assertEqual(code, 0, err)


if __name__ == "__main__":
    unittest.main()
