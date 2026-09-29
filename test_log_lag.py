#!/usr/bin/env python3
"""log-lag 子命令回归：按游标重演 lag-check 模式 LOG 的前 offset 条事件并
给出该时刻的 LAG 成员快照。

仅用标准库；端到端驱动 `python switch.py log-lag LOG CURSOR [MAX_WORK]`。
参数、资源、CURSOR 及错误顺序完全沿用 log-qos；成功产物键序固定为
schema,source_sha256,offset,snapshot,sha256，末项为前四键紧凑非 ASCII
转义 UTF-8 JSON 加 LF 的小写 sha256；CURSOR 的 * 表示 records 长度
（重演全部），否则 <sha256>:<offset>，offset 为已消费记录数；offset=0
时 snapshot.t=0，否则取末条已消费记录的 t。snapshot 键序 t,lags；lags
按配置序，项键序 name,members；members 按组内序，项键序
name,up,available；up 初始 true 并由成员事件更新，available 仅当 up、
端口配置 up 且该口在 t 时 STP 为 forwarding。LOG 须通过内部摘要核对、
lag-check 语义、全部记录核对与重建日志逐字节一致，仅接受 lag-check
模式，否则 invalid_input/4；重演前 offset 项按 lag-check 工作量公式
（与 lag 同口径）计费，等于上限合法，首次超过 stderr 仅
{"error":"lag_work_limit"} 加 LF 并退出 5；失败 stdout 为空且 LOG 只读。
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
from test_log_fdb import fdb_config, record  # noqa: E402

LAG_KEYS = ["schema", "source_sha256", "offset", "snapshot", "sha256"]
SNAPSHOT_KEYS = ["t", "lags"]
GROUP_KEYS = ["name", "members"]
MEMBER_KEYS = ["name", "up", "available"]
BCAST = "ff:ff:ff:ff:ff:ff"


def make_port(name, mode="access", pvid=1, allowed=None, untagged=None,
              up=True):
    if allowed is None:
        allowed = [pvid]
    if untagged is None:
        untagged = [] if mode == "trunk" else [pvid]
    return {
        "name": name,
        "mode": mode,
        "pvid": pvid,
        "allowed": allowed,
        "untagged": untagged,
        "up": up,
    }


def make_config():
    # B=2、L=1、P=5、M=2、delay=2、初始 U=1；p1 为跨桥 trunk 链路口，
    # p2/p3 边缘口，p4/p5 为同一 LAG 成员
    return {
        "bridges": ["b1", "b2"],
        "links": [
            {"id": "L1", "x": ["b1", "p1"], "y": ["b2", "p1"],
             "cost": 1, "up": True},
        ],
        "delay": 2,
        "bridge": "b1",
        "ports": [
            make_port("p1", mode="trunk", allowed=[1, 2], untagged=[]),
            make_port("p2"),
            make_port("p3"),
            make_port("p4"),
            make_port("p5"),
        ],
        "age": 100,
        "storm": {
            "window": 10,
            "limits": {"broadcast": 2, "multicast": 2, "unknown": 2},
            "move_limit": 2,
            "hold": 50,
        },
        "lags": [{"name": "LG1", "members": ["p4", "p5"], "hash": ["src"]}],
        "max_frame": 1518,
    }


def good_frame(t, port, src, dst=BCAST, vlan=None):
    return {
        "t": t, "port": port, "src": src, "dst": dst, "vlan": vlan,
        "length": 100, "fcs": True, "alignment": True,
    }


def bad_frame(t, port, src, dst=BCAST, vlan=None):
    # length=10 < 64：runt 坏帧
    return {
        "t": t, "port": port, "src": src, "dst": dst, "vlan": vlan,
        "length": 10, "fcs": True, "alignment": True,
    }


def member_event(t, member, up):
    return {"t": t, "member": member, "up": up}


def link_event(t, lid, up):
    return {"t": t, "id": lid, "up": up}


def lag_log(events, cfg=None):
    return record(cfg or make_config(), events)


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


def run_lag(log_bytes, cursor, *extra):
    with tempfile.TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "in.log")
        with open(log_path, "wb") as handle:
            handle.write(log_bytes)
        proc = subprocess.run(
            [sys.executable, SWITCH, "log-lag", log_path, cursor, *extra],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        with open(log_path, "rb") as handle:
            after = handle.read()
    return proc.returncode, proc.stdout, proc.stderr, after


def direct_snapshot(cfg, events, offset):
    """直接调用 forward_lag_check 求前 offset 项事件后的快照。"""
    config = copy.deepcopy(cfg)
    (
        bridges, links, delay, bridge, ports, age, storm, lags, max_frame,
    ) = switch_mod.validate_lag_check_config(config)
    link_ids = {link["id"] for link in links}
    checked = switch_mod.validate_lag_check_events(
        copy.deepcopy(events), ports, link_ids, lags
    )
    state = {}
    switch_mod.forward_lag_check(
        bridges, links, delay, bridge, ports, age, storm, lags, max_frame,
        checked[:offset], state_out=state,
    )
    return state["snapshot"]


def by_group(snapshot, name):
    return next(group for group in snapshot["lags"] if group["name"] == name)


def member_map(group):
    return {member["name"]: member for member in group["members"]}


class HappyPathTests(unittest.TestCase):
    def test_star_is_records_length_with_fixed_key_order_and_digest(self):
        events = [
            good_frame(1, "p2", "00:00:00:00:00:01"),
            member_event(4, "p4", False),
        ]
        log_bytes = lag_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_lag(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertTrue(out.endswith(b"\n"))
        self.assertNotIn(b", ", out)
        self.assertNotIn(b": ", out)
        self.assertEqual(after, log_bytes)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(list(doc), LAG_KEYS)
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["source_sha256"], source)
        self.assertEqual(doc["offset"], 2)
        snapshot = doc["snapshot"]
        self.assertEqual(list(snapshot), SNAPSHOT_KEYS)
        self.assertEqual(snapshot["t"], 4)
        self.assertEqual(len(snapshot["lags"]), 1)
        group = snapshot["lags"][0]
        self.assertEqual(list(group), GROUP_KEYS)
        self.assertEqual(group["name"], "LG1")
        self.assertEqual(
            [member["name"] for member in group["members"]], ["p4", "p5"]
        )
        for member in group["members"]:
            self.assertEqual(list(member), MEMBER_KEYS)
            self.assertIsInstance(member["up"], bool)
            self.assertIsInstance(member["available"], bool)
        members = member_map(group)
        self.assertFalse(members["p4"]["up"])
        self.assertFalse(members["p4"]["available"])
        self.assertTrue(members["p5"]["up"])
        self.assertTrue(members["p5"]["available"])
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_star_equals_sha_cursor_at_record_count(self):
        events = [good_frame(1, "p2", "00:00:00:00:00:01")]
        log_bytes = lag_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        _, star_out, _, _ = run_lag(log_bytes, "*")
        code, cur_out, err, _ = run_lag(log_bytes, source + ":1")
        self.assertEqual(code, 0, err)
        self.assertEqual(cur_out, star_out)
        self.assertEqual(json.loads(cur_out.decode())["offset"], 1)

    def test_offset_zero_is_initial_state_t_zero_all_members_up(self):
        events = [
            good_frame(1, "p2", "00:00:00:00:00:01"),
            member_event(4, "p4", False),
        ]
        log_bytes = lag_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_lag(log_bytes, source + ":0")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        snapshot = doc["snapshot"]
        self.assertEqual(snapshot["t"], 0)
        for member in snapshot["lags"][0]["members"]:
            self.assertTrue(member["up"])
            # p4/p5 为边缘口：up 即 forwarding，初始即可用
            self.assertTrue(member["available"])
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_member_events_update_up_and_available(self):
        events = [
            member_event(4, "p4", False),
            member_event(5, "p4", False),  # 幂等
            member_event(6, "p4", True),
        ]
        log_bytes = lag_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]

        def at(offset):
            code, out, err, _ = run_lag(log_bytes, source + ":%d" % offset)
            self.assertEqual(code, 0, (offset, err))
            return member_map(json.loads(out.decode())["snapshot"]["lags"][0])

        self.assertEqual((at(0)["p4"]["up"], at(0)["p4"]["available"]),
                         (True, True))
        self.assertEqual((at(1)["p4"]["up"], at(1)["p4"]["available"]),
                         (False, False))
        self.assertEqual((at(2)["p4"]["up"], at(2)["p4"]["available"]),
                         (False, False))
        self.assertEqual((at(3)["p4"]["up"], at(3)["p4"]["available"]),
                         (True, True))
        # 各 offset 的 t 为末条已消费记录的 t
        for offset, t in ((1, 4), (2, 5), (3, 6)):
            code, out, err, _ = run_lag(log_bytes, source + ":%d" % offset)
            self.assertEqual(json.loads(out.decode())["snapshot"]["t"], t)

    def test_port_config_down_keeps_up_true_but_available_false(self):
        cfg = make_config()
        cfg["ports"][3]["up"] = False  # p4 配置 down
        events = [good_frame(1, "p2", "00:00:00:00:00:01")]
        log_bytes = lag_log(events, cfg)
        code, out, err, _ = run_lag(log_bytes, "*")
        self.assertEqual(code, 0, err)
        members = member_map(json.loads(out.decode())["snapshot"]["lags"][0])
        # 无成员事件：动态 up 仍为 true，但端口配置 down → 不可用
        self.assertTrue(members["p4"]["up"])
        self.assertFalse(members["p4"]["available"])
        self.assertTrue(members["p5"]["available"])

    def test_stp_forwarding_gates_member_on_link(self):
        # LAG 成员 p4 位于跨桥链路口：delay=2，t<2*delay=4 时
        # designated 口仍在 discarding/learning，available=false
        cfg = make_config()
        cfg["links"] = [
            {"id": "L1", "x": ["b1", "p4"], "y": ["b2", "p1"],
             "cost": 1, "up": True},
        ]
        cfg["lags"] = [
            {"name": "LG1", "members": ["p3", "p4"], "hash": ["src"]},
        ]
        events = [
            good_frame(1, "p2", "00:00:00:00:00:01"),
            good_frame(5, "p2", "00:00:00:00:00:02"),
        ]
        log_bytes = lag_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]

        def at(offset):
            code, out, err, _ = run_lag(log_bytes, source + ":%d" % offset)
            self.assertEqual(code, 0, (offset, err))
            group = json.loads(out.decode())["snapshot"]["lags"][0]
            return member_map(group)

        for offset in (0, 1):
            members = at(offset)
            self.assertTrue(members["p3"]["available"])  # 边缘口
            self.assertFalse(members["p4"]["available"])  # STP 未放行
        members = at(2)
        self.assertTrue(members["p4"]["available"])  # t=5 ≥ 4 已 forwarding

    def test_link_down_event_gates_member_on_link(self):
        # 成员 p4 位于跨桥链路口：t=5 已 forwarding，t=6 链路 down 后
        # 动态成员 up 不变但 available=false（port_status 为 disabled）
        cfg = make_config()
        cfg["links"] = [
            {"id": "L1", "x": ["b1", "p4"], "y": ["b2", "p1"],
             "cost": 1, "up": True},
        ]
        cfg["lags"] = [
            {"name": "LG1", "members": ["p3", "p4"], "hash": ["src"]},
        ]
        events = [
            good_frame(5, "p2", "00:00:00:00:00:01"),
            link_event(6, "L1", False),
        ]
        log_bytes = lag_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_lag(log_bytes, source + ":2")
        self.assertEqual(code, 0, err)
        members = member_map(json.loads(out.decode())["snapshot"]["lags"][0])
        self.assertTrue(members["p4"]["up"])  # 动态成员 up 不受链路影响
        self.assertFalse(members["p4"]["available"])  # 链路 down → disabled

    def test_lags_and_members_follow_config_order(self):
        cfg = make_config()
        # 配置序：LG2 在前（成员 p5,p4），LG1 在后（成员 p2,p3）
        cfg["lags"] = [
            {"name": "LG2", "members": ["p5", "p4"], "hash": ["src"]},
            {"name": "LG1", "members": ["p2", "p3"], "hash": ["src"]},
        ]
        events = [good_frame(1, "p2", "00:00:00:00:00:01")]
        log_bytes = lag_log(events, cfg)
        code, out, err, _ = run_lag(log_bytes, "*")
        self.assertEqual(code, 0, err)
        groups = json.loads(out.decode())["snapshot"]["lags"]
        self.assertEqual([g["name"] for g in groups], ["LG2", "LG1"])
        self.assertEqual(
            [m["name"] for m in groups[0]["members"]], ["p5", "p4"]
        )
        self.assertEqual(
            [m["name"] for m in groups[1]["members"]], ["p2", "p3"]
        )

    def test_t_is_last_consumed_record_t_regardless_of_kind(self):
        events = [
            member_event(3, "p4", False),
            bad_frame(7, "p2", "00:00:00:00:00:01"),
        ]
        log_bytes = lag_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for offset, t in ((0, 0), (1, 3), (2, 7)):
            code, out, err, _ = run_lag(log_bytes, source + ":%d" % offset)
            self.assertEqual(code, 0, (offset, err))
            self.assertEqual(
                json.loads(out.decode())["snapshot"]["t"], t, offset
            )

    def test_prefix_matches_direct_simulation_for_every_offset(self):
        cfg = make_config()
        events = [
            good_frame(1, "p2", "00:00:00:00:00:01"),
            member_event(4, "p4", False),
            bad_frame(5, "p3", "00:00:00:00:00:02"),
            member_event(6, "p4", True),
        ]
        log_bytes = lag_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for offset in range(len(events) + 1):
            code, out, err, _ = run_lag(log_bytes, source + ":%d" % offset)
            self.assertEqual(code, 0, (offset, err))
            got = json.loads(out.decode())["snapshot"]
            self.assertEqual(got, direct_snapshot(cfg, events, offset))

    def test_non_ascii_lag_name_digest_uses_raw_utf8(self):
        cfg = make_config()
        cfg["lags"] = [
            {"name": "LG口", "members": ["p4", "p5"], "hash": ["src"]},
        ]
        events = [good_frame(1, "p2", "00:00:00:00:00:01")]
        log_bytes = lag_log(events, cfg)
        code, out, err, _ = run_lag(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertNotIn(b"\\u", out)  # 非 ASCII 转义关闭：原文 UTF-8 直出
        self.assertIn("口".encode("utf-8"), out)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["snapshot"]["lags"][0]["name"], "LG口")
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_empty_log_star_and_zero_identical(self):
        log_bytes = lag_log([])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        outputs = []
        for cursor in ("*", source + ":0"):
            code, out, err, _ = run_lag(log_bytes, cursor)
            self.assertEqual(code, 0, err)
            doc = json.loads(out.decode("utf-8"))
            self.assertEqual(doc["offset"], 0)
            self.assertEqual(doc["snapshot"]["t"], 0)
            outputs.append(out)
        self.assertEqual(outputs[0], outputs[1])


class UsageTests(unittest.TestCase):
    def test_arg_counts(self):
        log_bytes = lag_log([good_frame(1, "p2", "00:00:00:00:00:01")])
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "in.log")
            with open(path, "wb") as handle:
                handle.write(log_bytes)
            for tokens in ([], [path], [path, "*", "1", "2"]):
                proc = subprocess.run(
                    [sys.executable, SWITCH, "log-lag", *tokens],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                self.assertEqual(proc.returncode, 2, tokens)

    def test_bad_cursor_tokens(self):
        log_bytes = lag_log([good_frame(1, "p2", "00:00:00:00:00:01")])
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
            code, _, _, _ = run_lag(log_bytes, cursor)
            self.assertEqual(code, 2, cursor)

    def test_bad_max_work_tokens(self):
        log_bytes = lag_log([good_frame(1, "p2", "00:00:00:00:00:01")])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for token in ("", "0", "-1", "01", "1.0", "1 ", "x", "1e3"):
            code, _, _, _ = run_lag(log_bytes, source + ":0", token)
            self.assertEqual(code, 2, token)
            code, _, _, _ = run_lag(log_bytes, "*", token)
            self.assertEqual(code, 2, token)

    def test_arbitrary_length_decimal_max_work_accepted(self):
        log_bytes = lag_log([good_frame(1, "p2", "00:00:00:00:00:01")])
        code, _, err, _ = run_lag(log_bytes, "*", "9" * 60)
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_lag(log_bytes, "*", "9" * 5000)
        self.assertEqual(code, 0, err)

    def test_five_thousand_digit_cursor_offset_unbounded(self):
        log_bytes = lag_log([good_frame(1, "p2", "00:00:00:00:00:01")])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_lag(
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
                [sys.executable, SWITCH, "log-lag", missing, "*"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(proc.returncode, 3)
        self.assertIn(b"file_not_found", proc.stderr)
        self.assertEqual(proc.stdout, b"")

    def test_log_limit_before_invalid_input(self):
        oversized = b"{" + b" " * (16 * 1024 * 1024)
        code, out, err, after = run_lag(oversized, "*")
        self.assertEqual(code, 5)
        self.assertIn(b"log_limit", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, oversized)

    def test_bad_internal_sha_invalid_input(self):
        log_bytes = lag_log([good_frame(1, "p2", "00:00:00:00:00:01")])
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_lag(bad, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_sha_mismatch_invalid_input(self):
        log_bytes = lag_log([good_frame(1, "p2", "00:00:00:00:00:01")])
        code, out, err, _ = run_lag(log_bytes, "0" * 64 + ":0")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_offset_beyond_record_count_invalid_input(self):
        log_bytes = lag_log([good_frame(1, "p2", "00:00:00:00:00:01")])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_lag(log_bytes, source + ":2")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_fdb_mode_rejected(self):
        events = [
            {"t": 0, "port": "p1", "mac": "00:00:00:00:00:01", "vlan": 1},
        ]
        log_bytes = record(fdb_config(), events)
        code, out, err, after = run_lag(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_plain_lag_mode_rejected(self):
        # lag（无 max_frame）模式 LOG：静态合法但非 lag-check 模式
        cfg = make_config()
        del cfg["max_frame"]
        events = [
            {
                "t": 1, "port": "p2", "src": "00:00:00:00:00:01",
                "dst": BCAST, "vlan": None,
            },
        ]
        log_bytes = record(cfg, events)
        code, out, err, after = run_lag(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_tampered_records_fail_verification(self):
        # 成员项仅 up 实际改变时 applied=true；篡改为 false 并重算内部摘要
        events = [member_event(4, "p4", False)]
        log_bytes = lag_log(events)
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
        code, out, err, after = run_lag(bad, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, bad)

    def test_invalid_input_before_work_limit(self):
        log_bytes = lag_log([good_frame(1, "p2", "00:00:00:00:00:01")])
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_lag(bad, "*", "1")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")


class WorkLimitTests(unittest.TestCase):
    def test_frame_charge_uses_lag_check_formula(self):
        # base config：B=2,L=1,U=1 → 初始 2+1+2=5；P=5,M=2，每帧计
        # K+H+Q+1+P+M = 8；坏帧仍按帧计费。offset=1 累计 13，等于上限
        # 合法，12 首次超过报 lag_work_limit/5
        good = good_frame(1, "p2", "00:00:00:00:00:01")
        bad = bad_frame(2, "p2", "00:00:00:00:00:02")
        log_bytes = lag_log([good, bad])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, _, err, _ = run_lag(log_bytes, source + ":1", "13")
        self.assertEqual(code, 0, err)
        code, out, err, after = run_lag(log_bytes, source + ":1", "12")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"lag_work_limit"}\n')
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_work_counts_only_prefix_events(self):
        # 两条坏帧均不改变任何状态（K=H=Q=0），各计 8：offset=2 累计
        # 5+8+8=21。等于上限合法，20 首次超过
        events = [
            bad_frame(1, "p2", "00:00:00:00:00:01"),
            bad_frame(2, "p2", "00:00:00:00:00:02"),
        ]
        log_bytes = lag_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, _, err, _ = run_lag(log_bytes, source + ":2", "21")
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_lag(log_bytes, source + ":2", "20")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"lag_work_limit"}\n')
        # offset=1 仅 5+8=13：同一上限 13 合法，证明只计前 offset 项
        code, _, err, _ = run_lag(log_bytes, source + ":1", "13")
        self.assertEqual(code, 0, err)
        # offset=0：仅初始收敛 5
        code, out, err, _ = run_lag(log_bytes, source + ":0", "5")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out.decode())["offset"], 0)

    def test_member_event_charges_one_not_p_m(self):
        # 好广播帧计 8（初始 5 → 13），并在 K 留下 1 个 FDB 表项、在 Q
        # 留下 1 个广播速率名额（age=100、window=10，t=4 均不过期）；成员
        # 事件无 P+M，计 K+H+Q+1 = 3 → offset=2 累计 16。等于上限合法，
        # 15 首次超过
        events = [
            good_frame(1, "p2", "00:00:00:00:00:01"),
            member_event(4, "p4", False),
        ]
        log_bytes = lag_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, _, err, _ = run_lag(log_bytes, source + ":2", "16")
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_lag(log_bytes, source + ":2", "15")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"lag_work_limit"}\n')

    def test_default_max_work_is_ten_million(self):
        code, _, err, _ = run_lag(lag_log([]), "*")
        self.assertEqual(code, 0, err)


if __name__ == "__main__":
    unittest.main()
