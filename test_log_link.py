#!/usr/bin/env python3
"""log-link 子命令回归：按游标重演 link-state 模式 LOG 的前 offset 条事件
并给出该时刻的端口协商状态快照。

仅用标准库；端到端驱动 `python switch.py log-link LOG CURSOR [MAX_WORK]`。
参数、资源、CURSOR 及错误顺序完全沿用 log-qos；成功产物键序固定为
schema,source_sha256,offset,snapshot,sha256，末项为前四键紧凑非 ASCII
转义 UTF-8 JSON 加 LF 的小写 sha256；CURSOR 的 * 表示 records 长度
（重演全部），否则 <sha256>:<offset>，offset 为已消费记录数（含
applied=false 记录）；offset=0 为 t=0 且全端口 down，否则 snapshot.t
取第 offset 项记录的 t，协商未到期口为 wait。snapshot 键序 t,ports；
ports 按配置序，项键序 name,state,rate,mode；state 取
down/bad/wait/up，仅 up 时 rate 为整数、mode 取 half/full，其余为 null。
LOG 须通过内部摘要核对、link-state 语义、全部记录核对与重建日志逐字节
一致，仅接受 link-state 模式，否则 invalid_input/4；重演前 offset 项按
link-state 工作量公式计费（每事件处理到期项前以 pending 数 Q 累计
Q+1），等于上限合法，首次超过 stderr 仅 {"error":"link_work_limit"}
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

LINK_KEYS = ["schema", "source_sha256", "offset", "snapshot", "sha256"]
SNAPSHOT_KEYS = ["t", "ports"]
PORT_KEYS = ["name", "state", "rate", "mode"]


def ls_config(delay=5):
    # p1 支持 100/1000、half/full；p2 仅 1000/full
    return {
        "ports": [
            {"name": "p1", "rates": [100, 1000], "modes": ["half", "full"]},
            {"name": "p2", "rates": [1000], "modes": ["full"]},
        ],
        "delay": delay,
    }


def evt(t, port, admin, peer, rates, modes):
    return {
        "t": t, "port": port, "admin": admin, "peer": peer,
        "rates": rates, "modes": modes,
    }


def up_evt(t, port, rates=(1000,), modes=("full",)):
    return evt(t, port, True, True, list(rates), list(modes))


def down_evt(t, port):
    return evt(t, port, False, True, [1000], ["full"])


def ls_log(events, cfg=None):
    return record(cfg or ls_config(), events)


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


def direct_snapshot(cfg, events, offset):
    """直接调用 link-state 求前 offset 项后的全端口快照（offset=0 为 t=0
    全 down）。"""
    config = copy.deepcopy(cfg)
    ports, delay = switch_mod.validate_link_state_config(config)
    checked = switch_mod.validate_link_state_events(
        copy.deepcopy(events), ports
    )
    prefix = checked[:offset]
    state = {}
    switch_mod._link_state_run(prefix, ports, delay, snapshot_out=state)
    t = 0 if offset == 0 else prefix[-1][0]
    return {"t": t, "ports": state["ports"]}


def build_events():
    # delay=5：
    #  t=1 p1 up 1000/full → wait（协商至 t=6），Q0 计费 1（累 1）
    #  t=2 p2 up 1000/full → wait（协商至 t=7），Q1 计费 2（累 3）
    #  t=3 p1 重复同一目标 → applied=false，仍 wait，Q2 计费 3（累 6）
    #  t=6 p1 到期 up 当刻改广告 100/half → 重新 wait（至 t=11），Q2 计3（累9）
    #  t=7 p2 到期 up 当刻 admin=false → 立即 down，Q1 计费 2（累 11→12）
    #  t=8 p1 广告 10000（无共同速率）→ 立即 bad，Q0 计费 1（累 13→14）
    #  t=9 p1 再广告 100/half → wait（至 t=14），Q0 计费 1（累 15）
    #  t=14 p1 到期 up100/half；p2 幂等 down（applied=false），Q0 计1（累17）
    return [
        up_evt(1, "p1"),
        up_evt(2, "p2"),
        up_evt(3, "p1"),
        up_evt(6, "p1", rates=(100,), modes=("half",)),
        down_evt(7, "p2"),
        evt(8, "p1", True, True, [10000], ["full"]),
        up_evt(9, "p1", rates=(100,), modes=("half",)),
        down_evt(14, "p2"),
    ]


# 各 offset 的累计工作量（见上）
WORK_TOTALS = {
    0: 0, 1: 1, 2: 3, 3: 6, 4: 9, 5: 12, 6: 14, 7: 15, 8: 17,
}


class HappyPathTests(unittest.TestCase):
    def setUp(self):
        self.events = build_events()
        self.log_bytes = ls_log(self.events)
        self.source = json.loads(
            self.log_bytes.decode("utf-8")
        )["sha256"]

    def test_star_is_records_length_with_fixed_key_order_and_digest(self):
        code, out, err, after = run_link(self.log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertTrue(out.endswith(b"\n"))
        self.assertNotIn(b", ", out)
        self.assertNotIn(b": ", out)
        self.assertEqual(after, self.log_bytes)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(list(doc), LINK_KEYS)
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["source_sha256"], self.source)
        self.assertEqual(doc["offset"], len(self.events))
        snapshot = doc["snapshot"]
        self.assertEqual(list(snapshot), SNAPSHOT_KEYS)
        self.assertEqual([p["name"] for p in snapshot["ports"]], ["p1", "p2"])
        for port in snapshot["ports"]:
            self.assertEqual(list(port), PORT_KEYS)
            self.assertIn(port["state"], ("down", "bad", "wait", "up"))
            if port["state"] == "up":
                self.assertIsInstance(port["rate"], int)
                self.assertIn(port["mode"], ("half", "full"))
            else:
                self.assertIsNone(port["rate"])
                self.assertIsNone(port["mode"])
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_star_equals_sha_cursor_at_record_count(self):
        _, star_out, _, _ = run_link(self.log_bytes, "*")
        n = len(self.events)
        code, cur_out, err, _ = run_link(
            self.log_bytes, self.source + ":%d" % n
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(cur_out, star_out)
        self.assertEqual(json.loads(cur_out.decode())["offset"], n)

    def test_offset_zero_is_t0_all_down(self):
        code, out, err, _ = run_link(self.log_bytes, self.source + ":0")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["offset"], 0)
        self.assertEqual(
            doc["snapshot"],
            {"t": 0, "ports": [
                {"name": "p1", "state": "down", "rate": None, "mode": None},
                {"name": "p2", "state": "down", "rate": None, "mode": None},
            ]},
        )
        self.assertEqual(
            doc["snapshot"], direct_snapshot(ls_config(), self.events, 0)
        )
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_every_offset_matches_direct_run_with_all_states(self):
        cfg = ls_config()
        expected_state = {
            1: {"p1": "wait", "p2": "down"},
            2: {"p1": "wait", "p2": "wait"},
            3: {"p1": "wait", "p2": "wait"},
            4: {"p1": "wait", "p2": "wait"},
            5: {"p1": "wait", "p2": "down"},
            6: {"p1": "bad", "p2": "down"},
            7: {"p1": "wait", "p2": "down"},
            8: {"p1": "up", "p2": "down"},
        }
        expected_t = {1: 1, 2: 2, 3: 3, 4: 6, 5: 7, 6: 8, 7: 9, 8: 14}
        for offset in range(9):
            code, out, err, _ = run_link(
                self.log_bytes, self.source + ":%d" % offset
            )
            self.assertEqual(code, 0, (offset, err))
            doc = json.loads(out.decode("utf-8"))
            self.assertEqual(doc["offset"], offset)
            snapshot = doc["snapshot"]
            self.assertEqual(
                snapshot, direct_snapshot(cfg, self.events, offset)
            )
            if offset:
                self.assertEqual(snapshot["t"], expected_t[offset])
                states = {p["name"]: p["state"] for p in snapshot["ports"]}
                self.assertEqual(states, expected_state[offset])
            # offset=8：p1 协商完成，up 带速率/双工
            if offset == 8:
                p1 = snapshot["ports"][0]
                self.assertEqual(
                    p1, {"name": "p1", "state": "up",
                         "rate": 100, "mode": "half"}
                )
            self.assertEqual(doc["sha256"], digest_of(doc))

    def test_idempotent_records_consumed_but_change_nothing(self):
        # offset=2 与 3 仅隔一条幂等 wait：端口状态完全相同、t 不同
        _, out2, _, _ = run_link(self.log_bytes, self.source + ":2")
        _, out3, _, _ = run_link(self.log_bytes, self.source + ":3")
        snap2 = json.loads(out2.decode())["snapshot"]
        snap3 = json.loads(out3.decode())["snapshot"]
        self.assertEqual(snap2["t"], 2)
        self.assertEqual(snap3["t"], 3)
        self.assertEqual(snap2["ports"], snap3["ports"])

    def test_deadline_settles_pending_to_up(self):
        # offset=4（t=6）p1 重新协商仍 wait，p2 未到期 wait；offset=5
        # （t=7）p2 到期后立刻 down；offset=8（t=14）p1 到期为 up
        def ports_at(offset):
            _, out, _, _ = run_link(
                self.log_bytes, self.source + ":%d" % offset
            )
            return json.loads(out.decode())["snapshot"]["ports"]

        self.assertEqual([p["state"] for p in ports_at(4)], ["wait", "wait"])
        self.assertEqual([p["state"] for p in ports_at(5)], ["wait", "down"])
        self.assertEqual([p["state"] for p in ports_at(8)], ["up", "down"])

    def test_ports_follow_config_order(self):
        cfg = ls_config()
        cfg["ports"] = list(reversed(cfg["ports"]))
        log_bytes = ls_log([down_evt(0, "p1")], cfg)
        code, out, err, _ = run_link(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(
            [p["name"] for p in json.loads(out.decode())["snapshot"]["ports"]],
            ["p2", "p1"],
        )

    def test_empty_log_star_and_zero_identical(self):
        log_bytes = ls_log([])
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

    def test_non_ascii_digest_uses_unescaped_utf8(self):
        cfg = {
            "ports": [
                {"name": "口1", "rates": [1000], "modes": ["full"]},
            ],
            "delay": 2,
        }
        events = [up_evt(1, "口1")]
        log_bytes = ls_log(events, cfg)
        code, out, err, _ = run_link(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertNotIn(b"\\u", out)
        self.assertIn("口".encode("utf-8"), out)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["sha256"], digest_of(doc))


class UsageTests(unittest.TestCase):
    def test_arg_counts(self):
        log_bytes = ls_log([down_evt(0, "p1")])
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
        log_bytes = ls_log([down_evt(0, "p1")])
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
        log_bytes = ls_log([down_evt(0, "p1")])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for token in ("", "0", "-1", "01", "1.0", "1 ", "x", "1e3"):
            code, _, _, _ = run_link(log_bytes, source + ":0", token)
            self.assertEqual(code, 2, token)
            code, _, _, _ = run_link(log_bytes, "*", token)
            self.assertEqual(code, 2, token)

    def test_arbitrary_length_decimal_max_work_accepted(self):
        log_bytes = ls_log([down_evt(0, "p1")])
        code, _, err, _ = run_link(log_bytes, "*", "9" * 60)
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_link(log_bytes, "*", "9" * 5000)
        self.assertEqual(code, 0, err)

    def test_five_thousand_digit_cursor_offset_unbounded(self):
        log_bytes = ls_log([down_evt(0, "p1")])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_link(
            log_bytes, source + ":" + "1" * 5000
        )
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)


class ErrorPrecedenceTests(unittest.TestCase):
    def setUp(self):
        self.log_bytes = ls_log(build_events())
        self.source = json.loads(
            self.log_bytes.decode("utf-8")
        )["sha256"]

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
        doc = json.loads(self.log_bytes.decode("utf-8"))
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_link(bad, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_sha_mismatch_invalid_input(self):
        code, out, err, _ = run_link(self.log_bytes, "0" * 64 + ":0")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_offset_beyond_record_count_invalid_input(self):
        code, out, err, after = run_link(
            self.log_bytes, self.source + ":99"
        )
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, self.log_bytes)

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
        # link-forward 配置形状（四键）静态合法但非 link-state 模式
        cfg = {
            "ports": [
                {"name": "p1", "mode": "access", "pvid": 1,
                 "allowed": [1], "untagged": [1],
                 "rates": [1000], "modes": ["full"]},
            ],
            "age": 100,
            "max_frame": 1518,
            "delay": 2,
        }
        events = [down_evt(0, "p1")]
        log_bytes = record(cfg, events)
        code, out, err, after = run_link(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_tampered_records_fail_verification(self):
        # 幂等记录 applied=false 篡改为 true 并重算内部摘要 → 记录核对失败
        doc = json.loads(self.log_bytes.decode("utf-8"))
        # 第 3 条（t=3）原本 applied=false
        self.assertFalse(doc["records"][2]["applied"])
        doc["records"][2]["applied"] = True
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

    def test_tampered_output_bytes_fail_rebuild(self):
        # 仅改动 output 并重算内部摘要：全量重演重建字节不一致 → 4
        doc = json.loads(self.log_bytes.decode("utf-8"))
        doc["records"][0]["output"]["state"] = "up"
        doc["records"][0]["output"]["rate"] = 1000
        doc["records"][0]["output"]["mode"] = "full"
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
        code, out, err, _ = run_link(bad, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_invalid_input_before_work_limit(self):
        code, out, err, _ = run_link(
            self.log_bytes, "0" * 64 + ":0", "1"
        )
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")


class WorkLimitTests(unittest.TestCase):
    def setUp(self):
        self.log_bytes = ls_log(build_events())
        self.source = json.loads(
            self.log_bytes.decode("utf-8")
        )["sha256"]

    def test_formula_boundaries_for_every_prefix(self):
        for offset, total in WORK_TOTALS.items():
            # 等于上限合法（offset=0 工作量恒 0，任意正上限皆合法）
            bound = max(total, 1)
            code, _, err, _ = run_link(
                self.log_bytes, self.source + ":%d" % offset, str(bound)
            )
            self.assertEqual(code, 0, (offset, total, err))
            if total > 1:
                # MAX_WORK 仅接受正十进制，total=1 无更小的正上限可测
                code, out, err, after = run_link(
                    self.log_bytes, self.source + ":%d" % offset,
                    str(total - 1),
                )
                self.assertEqual(code, 5, (offset, total))
                self.assertEqual(err, b'{"error":"link_work_limit"}\n')
                self.assertEqual(out, b"")
                self.assertEqual(after, self.log_bytes)

    def test_offset_zero_never_hits_limit(self):
        for token in ("1",):
            code, _, err, _ = run_link(
                self.log_bytes, self.source + ":0", token
            )
            self.assertEqual(code, 0, err)

    def test_work_counts_only_prefix_records(self):
        # offset=4 累计 9 合法；同样上限对 offset=8（累计 17）超限
        code, _, err, _ = run_link(self.log_bytes, self.source + ":4", "9")
        self.assertEqual(code, 0, err)
        code, _, _, _ = run_link(self.log_bytes, self.source + ":8", "9")
        self.assertEqual(code, 5)

    def test_star_uses_full_records_work(self):
        code, _, err, _ = run_link(
            self.log_bytes, "*", str(WORK_TOTALS[8])
        )
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_link(
            self.log_bytes, "*", str(WORK_TOTALS[8] - 1)
        )
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"link_work_limit"}\n')

    def test_default_max_work_is_ten_million(self):
        code, _, err, _ = run_link(self.log_bytes, "*")
        self.assertEqual(code, 0, err)


if __name__ == "__main__":
    unittest.main()
