#!/usr/bin/env python3
"""log-stp 子命令回归：按游标重演 stp 模式 LOG 的前 offset 条链路记录并
给出该时刻生成树快照。

仅用标准库；端到端驱动 `python switch.py log-stp LOG CURSOR [MAX_WORK]`。
参数、资源、CURSOR 及错误顺序完全沿用 log-qos；成功产物键序固定为
schema,source_sha256,offset,snapshot,sha256，末项为前四键紧凑非 ASCII
转义 UTF-8 JSON 加 LF 的小写 sha256；CURSOR 的 * 表示 records 长度
（重演全部），否则 <sha256>:<offset>，offset 为已消费记录数（含
applied=false 的幂等记录）；offset=0 返回 t=0 初态，否则 t 取第 offset
项记录事件时刻。snapshot 键序 t,bridges；bridges 按配置序，项键序
name,root,cost,ports；ports 按名字典序，项键序 name,role,state。
LOG 须通过摘要核对、stp 语义、全部记录核对与重建日志逐字节一致，其他
模式 invalid_input/4；重演前 offset 条记录按 B+L+2U 计费（初始 t=0
收敛一次，前缀内 up 实际改变按新 U 再加同式，幂等不加），等于上限合法，
首次超过 stderr 仅 {"error":"stp_work_limit"} 加 LF 并退出 5。
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

# 5000 位游标 offset/MAX_WORK 须按不限长十进制处理；测试自身解析产物时
# 同样需关闭 3.11+ 的 int↔str 位数上限
if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(0)

import switch as switch_mod  # noqa: E402
from test_log_fdb import record  # noqa: E402

STP_KEYS = ["schema", "source_sha256", "offset", "snapshot", "sha256"]
SNAPSHOT_KEYS = ["t", "bridges"]
BRIDGE_KEYS = ["name", "root", "cost", "ports"]
PORT_KEYS = ["name", "role", "state"]


def stp_config(bridges=("B1", "B2"), delay=2, links=()):
    if not links:
        links = [
            {
                "id": "l1", "x": [bridges[0], "p1"],
                "y": [bridges[1], "p1"], "cost": 10, "up": True,
            }
        ]
    return {"bridges": list(bridges), "delay": delay, "links": links}


def link(t, lid, up):
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


def simulate_snapshot(cfg, events):
    """直接调用 stp 求前 events 后的末项快照。"""
    cfg = json.loads(json.dumps(cfg))  # 防 stp 改写链路状态
    bridges, links, delay = switch_mod.validate_stp_config(cfg)
    link_ids = {item["id"] for item in links}
    stp_events = switch_mod.validate_stp_events(events, link_ids)
    return switch_mod.stp(bridges, links, delay, stp_events)["results"][-1]


class HappyPathTests(unittest.TestCase):
    def test_star_is_records_length_with_fixed_key_order_and_digest(self):
        cfg = stp_config()
        events = [link(1, "l1", False), link(5, "l1", True)]
        log_bytes = stp_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_stp(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertTrue(out.endswith(b"\n"))
        self.assertNotIn(b", ", out)
        self.assertNotIn(b": ", out)
        self.assertEqual(after, log_bytes)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(list(doc), STP_KEYS)
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["source_sha256"], source)
        self.assertEqual(doc["offset"], 2)
        snapshot = doc["snapshot"]
        self.assertEqual(list(snapshot), SNAPSHOT_KEYS)
        self.assertEqual(snapshot["t"], 5)
        self.assertEqual(
            [entry["name"] for entry in snapshot["bridges"]], ["B1", "B2"]
        )
        for entry in snapshot["bridges"]:
            self.assertEqual(list(entry), BRIDGE_KEYS)
            self.assertIsInstance(entry["root"], str)
            self.assertTrue(
                entry["cost"] is None or isinstance(entry["cost"], int)
            )
            names = [port["name"] for port in entry["ports"]]
            self.assertEqual(names, sorted(names))
            for port in entry["ports"]:
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
        log_bytes = stp_log([link(1, "l1", False)])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        _, star_out, _, _ = run_stp(log_bytes, "*")
        code, cur_out, err, _ = run_stp(log_bytes, source + ":1")
        self.assertEqual(code, 0, err)
        self.assertEqual(cur_out, star_out)
        self.assertEqual(json.loads(cur_out.decode())["offset"], 1)

    def test_offset_zero_is_t_zero_initial_snapshot(self):
        events = [link(1, "l1", False)]
        log_bytes = stp_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_stp(log_bytes, source + ":0")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["offset"], 0)
        self.assertEqual(
            doc["snapshot"], simulate_snapshot(stp_config(), [])
        )
        self.assertEqual(doc["snapshot"]["t"], 0)
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_snapshot_t_is_offsetth_record_t_including_idempotent(self):
        events = [
            link(1, "l1", False),
            link(2, "l1", False),  # 幂等：applied=false 但仍消费
            link(5, "l1", True),
        ]
        log_bytes = stp_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        applied = [
            item["applied"]
            for item in json.loads(log_bytes.decode())["records"]
        ]
        self.assertEqual(applied, [True, False, True])
        for offset, t in ((0, 0), (1, 1), (2, 2), (3, 5)):
            code, out, err, _ = run_stp(
                log_bytes, source + ":%d" % offset
            )
            self.assertEqual(code, 0, (offset, err))
            doc = json.loads(out.decode("utf-8"))
            self.assertEqual(doc["offset"], offset)
            self.assertEqual(doc["snapshot"]["t"], t)

    def test_prefix_matches_direct_simulation_for_every_offset(self):
        cfg = stp_config(
            bridges=("B1", "B2", "B3"),
            links=[
                {"id": "l1", "x": ["B1", "p1"], "y": ["B2", "p1"],
                 "cost": 5, "up": True},
                {"id": "l2", "x": ["B2", "p2"], "y": ["B3", "p1"],
                 "cost": 7, "up": False},
            ],
        )
        events = [
            link(1, "l2", True),
            link(2, "l2", True),   # 幂等
            link(6, "l2", False),
            link(9, "l1", True),   # 幂等
        ]
        log_bytes = stp_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for offset in range(len(events) + 1):
            code, out, err, _ = run_stp(
                log_bytes, source + ":%d" % offset
            )
            self.assertEqual(code, 0, (offset, err))
            snapshot = json.loads(out.decode())["snapshot"]
            self.assertEqual(
                snapshot, simulate_snapshot(cfg, events[:offset])
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

    def test_non_ascii_bridge_names_not_escaped_in_digest(self):
        cfg = stp_config(bridges=("桥甲", "桥乙"))
        log_bytes = stp_log([link(1, "l1", False)], cfg)
        code, out, err, _ = run_stp(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertIn("桥甲".encode("utf-8"), out)
        self.assertEqual(
            json.loads(out.decode("utf-8"))["sha256"],
            digest_of(json.loads(out.decode("utf-8"))),
        )


class UsageTests(unittest.TestCase):
    def test_arg_counts(self):
        log_bytes = stp_log([link(0, "l1", False)])
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
        log_bytes = stp_log([link(0, "l1", False)])
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
        log_bytes = stp_log([link(0, "l1", False)])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for token in ("", "0", "-1", "01", "1.0", "1 ", "x", "1e3"):
            code, _, _, _ = run_stp(log_bytes, source + ":0", token)
            self.assertEqual(code, 2, token)
            code, _, _, _ = run_stp(log_bytes, "*", token)
            self.assertEqual(code, 2, token)

    def test_arbitrary_length_decimal_max_work_accepted(self):
        log_bytes = stp_log([link(0, "l1", False)])
        code, _, err, _ = run_stp(log_bytes, "*", "9" * 60)
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_stp(log_bytes, "*", "9" * 5000)
        self.assertEqual(code, 0, err)

    def test_five_thousand_digit_cursor_offset_unbounded(self):
        log_bytes = stp_log([link(0, "l1", False)])
        code, out, err, after = run_stp(
            log_bytes,
            json.loads(log_bytes.decode())["sha256"] + ":" + "1" * 5000,
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
        log_bytes = stp_log([link(0, "l1", False)])
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_stp(bad, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_sha_mismatch_invalid_input(self):
        log_bytes = stp_log([link(0, "l1", False)])
        code, out, err, _ = run_stp(log_bytes, "0" * 64 + ":0")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_offset_beyond_record_count_invalid_input(self):
        log_bytes = stp_log([link(0, "l1", False)])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_stp(log_bytes, source + ":2")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_non_stp_mode_rejected(self):
        # fdb 模式 LOG：静态合法但非 stp 模式
        from test_log_fdb import fdb_config, learn
        log_bytes = record(fdb_config(), [learn(0, "p1", "00:00:00:00:00:01")])
        code, out, err, after = run_stp(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_tampered_records_fail_verification(self):
        # 首条链路 down 实际 applied；篡改为 false 并重算内部摘要 →
        # 全量记录核对失败
        log_bytes = stp_log([link(0, "l1", False)])
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
        code, out, err, after = run_stp(bad, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, bad)

    def test_invalid_input_before_work_limit(self):
        log_bytes = stp_log([link(0, "l1", False)])
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_stp(bad, "*", "1")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")


class WorkLimitTests(unittest.TestCase):
    def test_charge_uses_b_l_2u_formula(self):
        # B=2,L=1；初始 U=1 → 初始收敛 B+L+2U=5；down 后 U=0 再加
        # 2+1+0=3，累计 8；up 后 U=1 再加 5，累计 13。等于上限合法，
        # 首次超过报 stp_work_limit/5
        events = [link(1, "l1", False), link(5, "l1", True)]
        log_bytes = stp_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for offset, exact in ((0, 5), (1, 8), (2, 13)):
            code, _, err, _ = run_stp(
                log_bytes, source + ":%d" % offset, str(exact)
            )
            self.assertEqual(code, 0, (offset, exact, err))
            code, out, err, after = run_stp(
                log_bytes, source + ":%d" % offset, str(exact - 1)
            )
            self.assertEqual(code, 5, (offset, exact - 1))
            self.assertEqual(err, b'{"error":"stp_work_limit"}\n')
            self.assertEqual(out, b"")
            self.assertEqual(after, log_bytes)

    def test_idempotent_records_not_charged_but_consumed(self):
        # down、down(幂等)、up：工作量 5+3+5=13（幂等项不加）
        events = [
            link(1, "l1", False),
            link(2, "l1", False),
            link(5, "l1", True),
        ]
        log_bytes = stp_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        # offset=2 仅一次实际改变：5+3=8
        code, _, err, _ = run_stp(log_bytes, source + ":2", "8")
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_stp(log_bytes, source + ":2", "7")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"stp_work_limit"}\n')
        # offset=0：仅初始收敛 5
        code, out, err, _ = run_stp(log_bytes, source + ":0", "5")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out.decode())["offset"], 0)

    def test_default_max_work_is_ten_million(self):
        code, _, err, _ = run_stp(stp_log([]), "*")
        self.assertEqual(code, 0, err)


if __name__ == "__main__":
    unittest.main()
