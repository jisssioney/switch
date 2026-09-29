#!/usr/bin/env python3
"""log-link 子命令回归：按游标重演 link-state 模式 LOG 的前 offset 条事件
并给出链路状态快照。

仅用标准库；端到端驱动 `python switch.py log-link LOG CURSOR [MAX_WORK]`。
参数、资源、CURSOR 及错误顺序完全沿用 log-qos；成功产物键序固定为
schema,source_sha256,offset,snapshot,sha256，末项为前四键紧凑非 ASCII
转义 UTF-8 加 LF 的小写 sha256；snapshot 键序 t,ports，ports 按配置序，
项键序 name,state,rate,mode。CURSOR 的 * 表示 records 长度（重演全部），
否则 <sha256>:<offset>；offset=0 为 t=0 且全端口 down，否则 t 取末条
已消费记录的事件时刻，未到期协商项为 wait。state 取 down/bad/wait/up，
仅 up 时 rate 为整数、mode 取 half/full，其余皆 null。LOG 须通过摘要
核对、link-state 语义、全部记录核对与重建日志逐字节一致，其他模式
invalid_input/4；重演前 offset 项时每事件在完成截止 <=t 的协商前以
pending 数 Q 累计 Q+1，等于上限合法，首次超过 stderr 仅
{"error":"link_work_limit"} 加 LF 并退出 5。
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
from test_log_fdb import fdb_config, record  # noqa: E402

LINK_KEYS = ["schema", "source_sha256", "offset", "snapshot", "sha256"]
SNAPSHOT_KEYS = ["t", "ports"]
PORT_KEYS = ["name", "state", "rate", "mode"]
STATES = ("down", "bad", "wait", "up")


def link_config(names=("p1", "p2"), delay=10, caps=None):
    ports = []
    for index, name in enumerate(names):
        if caps is not None and name in caps:
            rates, modes = caps[name]
        else:
            rates, modes = [10, 100, 1000, 10000], ["half", "full"]
        ports.append({"name": name, "rates": rates, "modes": modes})
    return {"delay": delay, "ports": ports}


def link_event(t, port, admin=True, peer=True, rates=None, modes=None):
    return {
        "t": t,
        "port": port,
        "admin": admin,
        "peer": peer,
        "rates": [10, 100, 1000, 10000] if rates is None else rates,
        "modes": ["half", "full"] if modes is None else modes,
    }


def link_log(events, cfg=None):
    return record(cfg or link_config(), events)


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


def run_link(log_bytes, cursor, *extra):
    with tempfile.TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "in.log")
        with open(log_path, "wb") as handle:
            handle.write(log_bytes)
        proc = subprocess.run(
            [sys.executable, SWITCH, "log-link", log_path, cursor, *extra],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        with open(log_path, "rb") as handle:
            after = handle.read()
    return proc.returncode, proc.stdout, proc.stderr, after


def simulate_snapshot(cfg, events):
    """直接调用 _link_state_run(state_out=...) 求前 events 的快照。"""
    cfg = json.loads(json.dumps(cfg))
    ports, delay = switch_mod.validate_link_state_config(cfg)
    ls_events = switch_mod.validate_link_state_events(events, ports)
    state = {}
    switch_mod._link_state_run(ls_events, ports, delay, state_out=state)
    return state["snapshot"]


def by_name(ports, wanted):
    return next(port for port in ports if port["name"] == wanted)


class HappyPathTests(unittest.TestCase):
    def test_star_is_records_length_with_fixed_key_order_and_digest(self):
        events = [
            link_event(0, "p1"),
            link_event(1, "p2", rates=[100], modes=["full"]),
        ]
        log_bytes = link_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_link(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertTrue(out.endswith(b"\n"))
        self.assertNotIn(b", ", out)
        self.assertNotIn(b": ", out)
        self.assertEqual(after, log_bytes)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(list(doc), LINK_KEYS)
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["source_sha256"], source)
        self.assertEqual(doc["offset"], 2)
        snapshot = doc["snapshot"]
        self.assertEqual(list(snapshot), SNAPSHOT_KEYS)
        self.assertEqual(snapshot["t"], 1)
        self.assertEqual(
            [entry["name"] for entry in snapshot["ports"]], ["p1", "p2"]
        )
        for entry in snapshot["ports"]:
            self.assertEqual(list(entry), PORT_KEYS)
            self.assertIsInstance(entry["name"], str)
            self.assertIn(entry["state"], STATES)
            if entry["state"] == "up":
                self.assertIsInstance(entry["rate"], int)
                self.assertIn(entry["mode"], ("half", "full"))
            else:
                self.assertIsNone(entry["rate"])
                self.assertIsNone(entry["mode"])
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_star_equals_sha_cursor_at_record_count(self):
        events = [link_event(0, "p1", rates=[100], modes=["full"])]
        log_bytes = link_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        _, star_out, _, _ = run_link(log_bytes, "*")
        code, cur_out, err, _ = run_link(log_bytes, source + ":1")
        self.assertEqual(code, 0, err)
        self.assertEqual(cur_out, star_out)
        self.assertEqual(json.loads(cur_out.decode())["offset"], 1)

    def test_offset_zero_is_t0_all_down(self):
        events = [link_event(0, "p1", rates=[100], modes=["full"])]
        log_bytes = link_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_link(log_bytes, source + ":0")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["offset"], 0)
        snapshot = doc["snapshot"]
        self.assertEqual(snapshot["t"], 0)
        self.assertEqual(len(snapshot["ports"]), 2)
        for entry in snapshot["ports"]:
            self.assertEqual(entry["state"], "down")
            self.assertIsNone(entry["rate"])
            self.assertIsNone(entry["mode"])
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_partial_offsets_track_wait_settle_and_down(self):
        # delay=5：p1 t0 进入 wait；p2 t1 进入 wait；t5 事件先完成 p1
        # 协商（up），随后 admin/peer 拉低使 p1 立即 down
        cfg = link_config(delay=5)
        events = [
            link_event(0, "p1", rates=[100], modes=["full"]),
            link_event(1, "p2", rates=[10], modes=["half"]),
            link_event(5, "p1", admin=False, peer=True,
                       rates=[100], modes=["full"]),
        ]
        log_bytes = link_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]

        def snap_at(offset):
            code, out, err, _ = run_link(
                log_bytes, source + ":%d" % offset
            )
            self.assertEqual(code, 0, (offset, err))
            doc = json.loads(out.decode("utf-8"))
            self.assertEqual(doc["offset"], offset)
            return doc["snapshot"]

        s0 = snap_at(0)
        self.assertEqual(s0["t"], 0)
        self.assertEqual([p["state"] for p in s0["ports"]], ["down", "down"])
        s1 = snap_at(1)
        self.assertEqual(s1["t"], 0)
        self.assertEqual([p["state"] for p in s1["ports"]], ["wait", "down"])
        s2 = snap_at(2)
        self.assertEqual(s2["t"], 1)
        self.assertEqual([p["state"] for p in s2["ports"]], ["wait", "wait"])
        # 未到期项 rate/mode 恒 null
        self.assertIsNone(by_name(s2["ports"], "p1")["rate"])
        s3 = snap_at(3)
        self.assertEqual(s3["t"], 5)
        p1 = by_name(s3["ports"], "p1")
        p2 = by_name(s3["ports"], "p2")
        self.assertEqual(p1["state"], "down")
        self.assertIsNone(p1["rate"])
        # p2 协商截止为 t6，t5 仍 wait
        self.assertEqual(p2["state"], "wait")
        self.assertIsNone(p2["mode"])

    def test_settled_port_is_up_with_chosen_rate_and_mode(self):
        # 共同速率取最大值；共同模式含 full 取 full，否则 half
        cfg = link_config(delay=3)
        events = [
            link_event(0, "p1", rates=[100, 1000], modes=["half"]),
            link_event(3, "p2", rates=[100], modes=["full"]),
        ]
        log_bytes = link_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_link(log_bytes, source + ":2")
        self.assertEqual(code, 0, err)
        ports = json.loads(out.decode())["snapshot"]["ports"]
        p1, p2 = by_name(ports, "p1"), by_name(ports, "p2")
        self.assertEqual((p1["state"], p1["rate"], p1["mode"]),
                         ("up", 1000, "half"))
        self.assertEqual((p2["state"], p2["rate"], p2["mode"]),
                         ("wait", None, None))

    def test_bad_state_when_no_common_rate_or_mode(self):
        cfg = link_config(delay=3)
        events = [
            link_event(0, "p1", rates=[10000], modes=["full"]),
        ]
        # 端口能力仅 10/100 → 无共同速率即 bad
        cfg["ports"][0]["rates"] = [10, 100]
        log_bytes = link_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_link(log_bytes, source + ":1")
        self.assertEqual(code, 0, err)
        p1 = by_name(json.loads(out.decode())["snapshot"]["ports"], "p1")
        self.assertEqual(p1["state"], "bad")
        self.assertIsNone(p1["rate"])
        self.assertIsNone(p1["mode"])

    def test_ports_follow_config_order(self):
        cfg = link_config(names=("p3", "p1", "p2"))
        events = [link_event(0, "p1")]
        log_bytes = link_log(events, cfg)
        code, out, err, _ = run_link(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(
            [entry["name"] for entry in
             json.loads(out.decode())["snapshot"]["ports"]],
            ["p3", "p1", "p2"],
        )

    def test_prefix_matches_direct_simulation_for_every_offset(self):
        cfg = link_config(delay=4)
        events = [
            link_event(0, "p1", rates=[100], modes=["full"]),
            link_event(2, "p2", rates=[1000], modes=["full"]),
            link_event(4, "p1", rates=[1000], modes=["full"]),
            link_event(6, "p2", admin=False, peer=False,
                       rates=[1000], modes=["full"]),
        ]
        log_bytes = link_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for offset in range(len(events) + 1):
            code, out, err, _ = run_link(
                log_bytes, source + ":%d" % offset
            )
            self.assertEqual(code, 0, (offset, err))
            got = json.loads(out.decode())["snapshot"]
            self.assertEqual(got, simulate_snapshot(cfg, events[:offset]))

    def test_empty_log_star_and_zero_identical(self):
        log_bytes = link_log([])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        outputs = []
        for cursor in ("*", source + ":0"):
            code, out, err, _ = run_link(log_bytes, cursor)
            self.assertEqual(code, 0, err)
            doc = json.loads(out.decode("utf-8"))
            self.assertEqual(doc["offset"], 0)
            self.assertEqual(doc["snapshot"]["t"], 0)
            outputs.append(out)
        self.assertEqual(outputs[0], outputs[1])

    def test_digest_uses_raw_unescaped_utf8(self):
        cfg = link_config(names=("口1", "口2"), delay=2)
        events = [link_event(0, "口1", rates=[100], modes=["full"])]
        log_bytes = link_log(events, cfg)
        code, out, err, _ = run_link(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertIn("口1".encode("utf-8"), out)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["sha256"], digest_of(doc))


class UsageTests(unittest.TestCase):
    def test_arg_counts(self):
        log_bytes = link_log([link_event(0, "p1")])
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "in.log")
            with open(path, "wb") as handle:
                handle.write(log_bytes)
            for tokens in ([], [path], [path, "*", "1", "2"]):
                proc = subprocess.run(
                    [sys.executable, SWITCH, "log-link", *tokens],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                self.assertEqual(proc.returncode, 2, tokens)

    def test_bad_cursor_tokens(self):
        log_bytes = link_log([link_event(0, "p1")])
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
            code, _, _, _ = run_link(log_bytes, cursor)
            self.assertEqual(code, 2, cursor)

    def test_bad_max_work_tokens(self):
        log_bytes = link_log([link_event(0, "p1")])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for token in ("", "0", "-1", "01", "1.0", "1 ", "x", "1e3"):
            code, _, _, _ = run_link(log_bytes, source + ":0", token)
            self.assertEqual(code, 2, token)
            code, _, _, _ = run_link(log_bytes, "*", token)
            self.assertEqual(code, 2, token)

    def test_arbitrary_length_decimal_max_work_accepted(self):
        log_bytes = link_log([link_event(0, "p1")])
        code, _, err, _ = run_link(log_bytes, "*", "9" * 60)
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_link(log_bytes, "*", "9" * 5000)
        self.assertEqual(code, 0, err)

    def test_five_thousand_digit_cursor_offset_unbounded(self):
        log_bytes = link_log([link_event(0, "p1")])
        code, out, err, after = run_link(
            log_bytes, json.loads(log_bytes.decode("utf-8"))["sha256"]
            + ":" + "1" * 5000
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
                [sys.executable, SWITCH, "log-link", missing, "*"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(proc.returncode, 3)
        self.assertIn(b"file_not_found", proc.stderr)
        self.assertEqual(proc.stdout, b"")

    def test_log_limit_before_invalid_input(self):
        oversized = b"{" + b" " * (16 * 1024 * 1024)
        code, out, err, after = run_link(oversized, "*")
        self.assertEqual(code, 5)
        self.assertIn(b"log_limit", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, oversized)

    def test_bad_internal_sha_invalid_input(self):
        log_bytes = link_log([link_event(0, "p1")])
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_link(bad, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_sha_mismatch_invalid_input(self):
        log_bytes = link_log([link_event(0, "p1")])
        code, out, err, _ = run_link(log_bytes, "0" * 64 + ":0")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_offset_beyond_record_count_invalid_input(self):
        log_bytes = link_log([link_event(0, "p1")])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_link(log_bytes, source + ":2")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_fdb_mode_rejected(self):
        events = [
            {"t": 0, "port": "p1", "mac": "00:00:00:00:00:01", "vlan": 1},
        ]
        log_bytes = record(fdb_config(), events)
        code, out, err, after = run_link(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_link_forward_mode_rejected(self):
        # link-forward 配置含 ports,age,max_frame,delay 四键，非 link-state
        cfg = {
            "age": 100,
            "max_frame": 1518,
            "delay": 5,
            "ports": [
                {
                    "name": "p1", "mode": "access", "pvid": 1,
                    "allowed": [1], "untagged": [1],
                    "rates": [100], "modes": ["full"],
                },
            ],
        }
        events = [link_event(0, "p1", rates=[100], modes=["full"])]
        log_bytes = record(cfg, events)
        code, out, err, after = run_link(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_tampered_records_fail_verification(self):
        # 首条 up 协商 applied=true；篡改为 false 并重算内部摘要 → 记录
        # 核对失败
        events = [link_event(0, "p1", rates=[100], modes=["full"])]
        log_bytes = link_log(events)
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
        code, out, err, after = run_link(bad, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, bad)

    def test_invalid_input_before_work_limit(self):
        log_bytes = link_log([link_event(0, "p1")])
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_link(bad, "*", "1")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")


class WorkLimitTests(unittest.TestCase):
    def test_charge_uses_pending_count_plus_one(self):
        # delay=100：t0 p1 进入 wait（Q=0 计 1，累计 1）；t1 p2 进入 wait
        # （到期项处理前 Q=1 计 2，累计 3）。等于上限合法，首次超过报
        # link_work_limit/5
        cfg = link_config(delay=100)
        events = [
            link_event(0, "p1", rates=[100], modes=["full"]),
            link_event(1, "p2", rates=[100], modes=["full"]),
        ]
        log_bytes = link_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, _, err, _ = run_link(log_bytes, source + ":2", "3")
        self.assertEqual(code, 0, err)
        code, out, err, after = run_link(
            log_bytes, source + ":2", "2"
        )
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"link_work_limit"}\n')
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)
        # offset=1 仅计 1：同一上限 1 合法，证明只计前 offset 项
        code, _, err, _ = run_link(log_bytes, source + ":1", "1")
        self.assertEqual(code, 0, err)

    def test_q_counted_before_settling_due_negotiations(self):
        # delay=5：t0 p1 wait；t5 事件先以 Q=1 计 Q+1=2（累计 3），再完成
        # p1 协商，随后事件幂等 up。上限 2 在第二个事件首次超过
        cfg = link_config(delay=5)
        events = [
            link_event(0, "p1", rates=[100], modes=["full"]),
            link_event(5, "p1", rates=[100], modes=["full"]),
        ]
        log_bytes = link_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, _, err, _ = run_link(log_bytes, source + ":2", "3")
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_link(log_bytes, source + ":2", "2")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"link_work_limit"}\n')

    def test_offset_zero_costs_nothing(self):
        log_bytes = link_log([link_event(0, "p1")])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_link(log_bytes, source + ":0", "1")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out.decode())["offset"], 0)

    def test_default_max_work_is_ten_million(self):
        code, _, err, _ = run_link(link_log([]), "*")
        self.assertEqual(code, 0, err)


if __name__ == "__main__":
    unittest.main()
