#!/usr/bin/env python3
"""log-storm 子命令回归：按游标重演 storm-check 模式 LOG 的前 offset 条事件
并给出该时刻的风暴抑制状态快照。

仅用标准库；端到端驱动 `python switch.py log-storm LOG CURSOR [MAX_WORK]`。
参数、资源、CURSOR 及错误顺序完全沿用 log-lag；成功产物键序固定为
schema,source_sha256,offset,snapshot,sha256，末项为前四键紧凑非 ASCII
转义 UTF-8 JSON 加 LF 的小写 sha256；CURSOR 的 * 表示 records 长度
（重演全部），否则 <sha256>:<offset>，offset 为已消费记录数；offset=0
时 snapshot.t=0，否则取末条已消费记录的 t。snapshot 键序 t,meters,
blocked；meters 按配置端口序、VLAN 升序、broadcast/multicast/unknown
序，仅列满足 t-x<window 的非空队列，项键序 port,vlan,category,times，
times 为其中 x 的原序非负整数数组；blocked 按配置端口序、VLAN 升序，
仅列 t<until 项，项键序 port,vlan,until。LOG 须通过内部摘要核对、
storm-check 语义、全部记录核对与重建日志逐字节一致，仅接受 storm-check
模式，否则 invalid_input/4；重演前 offset 项按 storm-check 工作量公式
（与 forward-stp-storm 同口径）计费，等于上限合法，首次超过 stderr 仅
{"error":"storm_work_limit"} 加 LF 并退出 5；失败 stdout 为空且 LOG 只读。
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

STORM_KEYS = ["schema", "source_sha256", "offset", "snapshot", "sha256"]
SNAPSHOT_KEYS = ["t", "meters", "blocked"]
METER_KEYS = ["port", "vlan", "category", "times"]
BLOCKED_KEYS = ["port", "vlan", "until"]
BCAST = "ff:ff:ff:ff:ff:ff"
MCAST = "01:00:00:00:00:00"


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


def make_config(ports=("p1", "p2", "p3"), window=10, limits=None,
                move_limit=2, hold=50, age=100, max_frame=1518):
    # B=2、L=1、P=len(ports)、delay=2、初始 U=1；p1 为跨桥 trunk 链路口，
    # 其余为边缘 access 口
    if limits is None:
        limits = {"broadcast": 2, "multicast": 2, "unknown": 2}
    port_defs = [
        make_port("p1", mode="trunk", allowed=[1, 2], untagged=[]),
    ] + [make_port(name) for name in ports if name != "p1"]
    return {
        "bridges": ["b1", "b2"],
        "links": [
            {"id": "L1", "x": ["b1", "p1"], "y": ["b2", "p1"],
             "cost": 1, "up": True},
        ],
        "delay": 2,
        "bridge": "b1",
        "ports": port_defs,
        "age": age,
        "storm": {
            "window": window,
            "limits": limits,
            "move_limit": move_limit,
            "hold": hold,
        },
        "max_frame": max_frame,
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


def link_event(t, lid, up):
    return {"t": t, "id": lid, "up": up}


def storm_log(events, cfg=None):
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


def run_storm(log_bytes, cursor, *extra):
    with tempfile.TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "in.log")
        with open(log_path, "wb") as handle:
            handle.write(log_bytes)
        proc = subprocess.run(
            [sys.executable, SWITCH, "log-storm", log_path, cursor, *extra],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        with open(log_path, "rb") as handle:
            after = handle.read()
    return proc.returncode, proc.stdout, proc.stderr, after


def direct_snapshot(cfg, events, offset):
    """直接调用 storm_check 求前 offset 项事件后的风暴抑制快照。"""
    config = copy.deepcopy(cfg)
    (
        bridges, links, delay, bridge, ports, age, storm, max_frame,
    ) = switch_mod.validate_storm_check_config(config)
    link_ids = {link["id"] for link in links}
    checked = switch_mod.validate_storm_check_events(
        copy.deepcopy(events), ports, link_ids
    )
    state = {}
    switch_mod.storm_check(
        bridges, links, delay, bridge, ports, age, storm, max_frame,
        checked[:offset], state_out=state,
    )
    return state["snapshot"]


def meter_index(snapshot):
    return {
        (m["port"], m["vlan"], m["category"]): m["times"]
        for m in snapshot["meters"]
    }


def blocked_map(snapshot):
    return {
        (b["port"], b["vlan"]): b["until"] for b in snapshot["blocked"]
    }


class HappyPathTests(unittest.TestCase):
    def test_star_is_records_length_with_fixed_key_order_and_digest(self):
        events = [
            good_frame(1, "p2", "00:00:00:00:00:01"),
            good_frame(5, "p2", "00:00:00:00:00:02"),
        ]
        log_bytes = storm_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_storm(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertTrue(out.endswith(b"\n"))
        self.assertNotIn(b", ", out)
        self.assertNotIn(b": ", out)
        self.assertEqual(after, log_bytes)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(list(doc), STORM_KEYS)
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["source_sha256"], source)
        self.assertEqual(doc["offset"], 2)
        snapshot = doc["snapshot"]
        self.assertEqual(list(snapshot), SNAPSHOT_KEYS)
        self.assertEqual(snapshot["t"], 5)
        self.assertEqual(len(snapshot["meters"]), 1)
        meter = snapshot["meters"][0]
        self.assertEqual(list(meter), METER_KEYS)
        self.assertEqual(meter["port"], "p2")
        self.assertEqual(meter["vlan"], 1)
        self.assertEqual(meter["category"], "broadcast")
        self.assertEqual(meter["times"], [1, 5])
        self.assertEqual(snapshot["blocked"], [])
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_star_equals_sha_cursor_at_record_count(self):
        events = [good_frame(1, "p2", "00:00:00:00:00:01")]
        log_bytes = storm_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        _, star_out, _, _ = run_storm(log_bytes, "*")
        code, cur_out, err, _ = run_storm(log_bytes, source + ":1")
        self.assertEqual(code, 0, err)
        self.assertEqual(cur_out, star_out)
        self.assertEqual(json.loads(cur_out.decode())["offset"], 1)

    def test_offset_zero_is_initial_state_t_zero_empty(self):
        events = [good_frame(1, "p2", "00:00:00:00:00:01")]
        log_bytes = storm_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_storm(log_bytes, source + ":0")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        snapshot = doc["snapshot"]
        self.assertEqual(snapshot, {"t": 0, "meters": [], "blocked": []})
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_suppressed_frame_does_not_occupy_rate_slot(self):
        # 速率上限 2：t=1、t=5 占两个广播名额，t=6 第三个广播在窗口内被
        # 抑制，times 仍为 [1,5]
        events = [
            good_frame(1, "p2", "00:00:00:00:00:01"),
            good_frame(5, "p2", "00:00:00:00:00:02"),
            good_frame(6, "p2", "00:00:00:00:00:03"),
        ]
        log_bytes = storm_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for offset, times in ((1, [1]), (2, [1, 5]), (3, [1, 5])):
            code, out, err, _ = run_storm(log_bytes, source + ":%d" % offset)
            self.assertEqual(code, 0, (offset, err))
            snapshot = json.loads(out.decode())["snapshot"]
            self.assertEqual(
                meter_index(snapshot)[("p2", 1, "broadcast")], times
            )

    def test_window_filter_drops_stale_times_at_snapshot(self):
        # 上限放宽到 5：t=1、t=5 占名额；t=11 一条幂等链路事件不动队列，
        # 快照按 t-x<window（window=10）过滤：11-1=10 越界仅留 [5]
        cfg = make_config(
            limits={"broadcast": 5, "multicast": 5, "unknown": 5}
        )
        events = [
            good_frame(1, "p2", "00:00:00:00:00:01"),
            good_frame(5, "p2", "00:00:00:00:00:02"),
            link_event(11, "L1", True),  # 幂等：不触碰速率队列
        ]
        log_bytes = storm_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_storm(log_bytes, source + ":3")
        self.assertEqual(code, 0, err)
        snapshot = json.loads(out.decode())["snapshot"]
        self.assertEqual(snapshot["t"], 11)
        self.assertEqual(
            snapshot["meters"],
            [{"port": "p2", "vlan": 1, "category": "broadcast",
              "times": [5]}],
        )

    def test_all_empty_after_window_queue_omitted(self):
        # 队列内时刻全部越窗且无新帧：该队列非空判定失败，meters 不列出
        cfg = make_config(
            limits={"broadcast": 5, "multicast": 5, "unknown": 5}
        )
        events = [
            good_frame(1, "p2", "00:00:00:00:00:01"),
            link_event(20, "L1", True),
        ]
        log_bytes = storm_log(events, cfg)
        code, out, err, _ = run_storm(log_bytes, "*")
        self.assertEqual(code, 0, err)
        snapshot = json.loads(out.decode())["snapshot"]
        self.assertEqual(snapshot["meters"], [])
        self.assertEqual(snapshot["blocked"], [])

    def test_category_order_broadcast_multicast_unknown(self):
        events = [
            good_frame(1, "p2", "00:00:00:00:00:01", dst=BCAST),
            good_frame(2, "p2", "00:00:00:00:00:01", dst=MCAST),
            good_frame(
                3, "p2", "00:00:00:00:00:01",
                dst="00:00:00:00:10:09",
            ),
        ]
        log_bytes = storm_log(events)
        code, out, err, _ = run_storm(log_bytes, "*")
        self.assertEqual(code, 0, err)
        meters = json.loads(out.decode())["snapshot"]["meters"]
        self.assertEqual(
            [(m["category"], m["times"]) for m in meters],
            [("broadcast", [1]), ("multicast", [2]), ("unknown", [3])],
        )
        for meter in meters:
            self.assertEqual(list(meter), METER_KEYS)
            self.assertTrue(all(isinstance(x, int) and x >= 0 for x in
                                meter["times"]))

    def test_vlan_and_times_order_on_trunk_port(self):
        cfg = make_config()
        cfg["ports"] = [
            make_port("p1", mode="trunk", allowed=[1, 2], untagged=[]),
            make_port("p2", mode="trunk", allowed=[1, 2], untagged=[]),
            make_port("p3"),
        ]
        events = [
            good_frame(1, "p2", "00:00:00:00:00:01", vlan=2),
            good_frame(2, "p2", "00:00:00:00:00:02", vlan=1),
            good_frame(5, "p2", "00:00:00:00:00:03", vlan=1),
        ]
        log_bytes = storm_log(events, cfg)
        code, out, err, _ = run_storm(log_bytes, "*")
        self.assertEqual(code, 0, err)
        meters = json.loads(out.decode())["snapshot"]["meters"]
        # VLAN 升序，times 保放入原序（vlan1 为 [2,5]）
        self.assertEqual(
            [(m["vlan"], m["times"]) for m in meters],
            [(1, [2, 5]), (2, [1])],
        )

    def test_meters_follow_config_port_order(self):
        events = [
            good_frame(1, "p3", "00:00:00:00:00:01"),
            good_frame(2, "p2", "00:00:00:00:00:02"),
        ]
        log_bytes = storm_log(events)
        code, out, err, _ = run_storm(log_bytes, "*")
        self.assertEqual(code, 0, err)
        meters = json.loads(out.decode())["snapshot"]["meters"]
        self.assertEqual([m["port"] for m in meters], ["p2", "p3"])

    def test_bad_and_rejected_frames_leave_meters_empty(self):
        events = [
            bad_frame(2, "p2", "00:00:00:00:00:01"),
            good_frame(3, "p2", "00:00:00:00:00:02", vlan=3),  # 准入拒绝
        ]
        log_bytes = storm_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for offset in (1, 2):
            code, out, err, _ = run_storm(log_bytes, source + ":%d" % offset)
            self.assertEqual(code, 0, (offset, err))
            snapshot = json.loads(out.decode())["snapshot"]
            self.assertEqual(snapshot["meters"], [])
        self.assertEqual(json.loads(out.decode())["snapshot"]["t"], 3)

    def test_move_blocking_blocks_port_vlan_until(self):
        # move_limit=2、hold=50：同源 MAC 在 p2/p3 间二次迁移即封锁入端
        # 口/VLAN。t=3 的第三迁移（p3→p2）在 t 时刻封锁 (p2,1) 至 53 并
        # 抑制该帧（不占广播名额）
        events = [
            good_frame(1, "p2", "00:00:00:00:00:0a"),
            good_frame(2, "p3", "00:00:00:00:00:0a"),
            good_frame(3, "p2", "00:00:00:00:00:0a"),
            good_frame(4, "p2", "00:00:00:00:00:0b"),
        ]
        log_bytes = storm_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]

        def at(offset):
            code, out, err, _ = run_storm(log_bytes, source + ":%d" % offset)
            self.assertEqual(code, 0, (offset, err))
            return json.loads(out.decode())["snapshot"]

        self.assertEqual(blocked_map(at(0)), {})
        self.assertEqual(blocked_map(at(1)), {})
        self.assertEqual(blocked_map(at(2)), {})
        snapshot = at(3)
        self.assertEqual(
            snapshot["blocked"],
            [{"port": "p2", "vlan": 1, "until": 53}],
        )
        self.assertEqual(list(snapshot["blocked"][0]), BLOCKED_KEYS)
        # 被抑制帧不占广播名额：p2 队列仍仅 [1]
        self.assertEqual(meter_index(snapshot)[("p2", 1, "broadcast")], [1])
        # 封锁期内（t=4）p2 帧一律抑制，封锁仍在；快照 t 推进到 4
        snapshot = at(4)
        self.assertEqual(blocked_map(snapshot), {("p2", 1): 53})
        self.assertEqual(meter_index(snapshot)[("p2", 1, "broadcast")], [1])

    def test_blocked_expires_at_until_and_order(self):
        # p2/p3 trunk 允许 vlan1/2：A 在 vlan1 迁移封 (p2,1) 至 53；B 在
        # vlan2 迁移封 (p3,2) 至 56；blocked 按端口序、VLAN 升序。t=56
        # 幂等链路事件触发解封后两者均到期，blocked 为空
        cfg = make_config()
        cfg["ports"] = [
            make_port("p1", mode="trunk", allowed=[1, 2], untagged=[]),
            make_port("p2", mode="trunk", allowed=[1, 2], untagged=[]),
            make_port("p3", mode="trunk", allowed=[1, 2], untagged=[]),
        ]
        events = [
            good_frame(1, "p2", "00:00:00:00:00:0a", vlan=1),
            good_frame(2, "p3", "00:00:00:00:00:0a", vlan=1),
            good_frame(3, "p2", "00:00:00:00:00:0a", vlan=1),
            good_frame(4, "p3", "00:00:00:00:00:0b", vlan=2),
            good_frame(5, "p2", "00:00:00:00:00:0b", vlan=2),
            good_frame(6, "p3", "00:00:00:00:00:0b", vlan=2),
        ]
        log_bytes = storm_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_storm(log_bytes, source + ":6")
        self.assertEqual(code, 0, err)
        blocked = json.loads(out.decode())["snapshot"]["blocked"]
        self.assertEqual(
            blocked,
            [
                {"port": "p2", "vlan": 1, "until": 53},
                {"port": "p3", "vlan": 2, "until": 56},
            ],
        )
        # t=53 时 (p2,1) 到期（until 上界不含）：仅余 (p3,2)
        events2 = events + [link_event(53, "L1", True)]
        log_bytes2 = storm_log(events2, cfg)
        source2 = json.loads(log_bytes2.decode("utf-8"))["sha256"]
        code, out, err, _ = run_storm(log_bytes2, source2 + ":7")
        self.assertEqual(code, 0, err)
        snapshot = json.loads(out.decode())["snapshot"]
        self.assertEqual(snapshot["t"], 53)
        self.assertEqual(
            snapshot["blocked"], [{"port": "p3", "vlan": 2, "until": 56}]
        )
        # t=56 全部到期
        events3 = events + [
            link_event(53, "L1", True), link_event(56, "L1", True)
        ]
        log_bytes3 = storm_log(events3, cfg)
        source3 = json.loads(log_bytes3.decode("utf-8"))["sha256"]
        code, out, err, _ = run_storm(log_bytes3, source3 + ":8")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out.decode())["snapshot"]["blocked"], [])

    def test_t_is_last_consumed_record_t_regardless_of_kind(self):
        events = [
            link_event(0, "L1", True),  # 幂等链路
            good_frame(1, "p2", "00:00:00:00:00:01"),
            bad_frame(7, "p2", "00:00:00:00:00:02"),
            link_event(8, "L1", False),  # 实际改变
        ]
        log_bytes = storm_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for offset, t in ((0, 0), (1, 0), (2, 1), (3, 7), (4, 8)):
            code, out, err, _ = run_storm(log_bytes, source + ":%d" % offset)
            self.assertEqual(code, 0, (offset, err))
            self.assertEqual(
                json.loads(out.decode())["snapshot"]["t"], t, offset
            )

    def test_prefix_matches_direct_simulation_for_every_offset(self):
        events = [
            link_event(0, "L1", True),
            good_frame(1, "p2", "00:00:00:00:00:01"),
            bad_frame(2, "p3", "00:00:00:00:00:02"),
            good_frame(3, "p2", "00:00:00:00:00:03", vlan=3),
            link_event(4, "L1", False),
            good_frame(5, "p2", "00:00:00:00:00:04"),
            good_frame(6, "p2", "00:00:00:00:00:05"),
            link_event(7, "L1", False),
        ]
        cfg = make_config()
        log_bytes = storm_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for offset in range(len(events) + 1):
            code, out, err, _ = run_storm(log_bytes, source + ":%d" % offset)
            self.assertEqual(code, 0, (offset, err))
            got = json.loads(out.decode())["snapshot"]
            self.assertEqual(got, direct_snapshot(cfg, events, offset))

    def test_non_ascii_port_name_digest_uses_raw_utf8(self):
        cfg = make_config()
        cfg["ports"] = [
            make_port("p1", mode="trunk", allowed=[1, 2], untagged=[]),
            make_port("p2"),
            make_port("口"),
        ]
        events = [good_frame(1, "口", "00:00:00:00:00:01")]
        log_bytes = storm_log(events, cfg)
        code, out, err, _ = run_storm(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertNotIn(b"\\u", out)  # 非 ASCII 转义关闭：原文 UTF-8 直出
        self.assertIn("口".encode("utf-8"), out)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["snapshot"]["meters"][0]["port"], "口")
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_empty_log_star_and_zero_identical(self):
        log_bytes = storm_log([])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        outputs = []
        for cursor in ("*", source + ":0"):
            code, out, err, _ = run_storm(log_bytes, cursor)
            self.assertEqual(code, 0, err)
            doc = json.loads(out.decode("utf-8"))
            self.assertEqual(doc["offset"], 0)
            self.assertEqual(doc["snapshot"]["t"], 0)
            outputs.append(out)
        self.assertEqual(outputs[0], outputs[1])


class UsageTests(unittest.TestCase):
    def test_arg_counts(self):
        log_bytes = storm_log([good_frame(1, "p2", "00:00:00:00:00:01")])
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "in.log")
            with open(path, "wb") as handle:
                handle.write(log_bytes)
            for tokens in ([], [path], [path, "*", "1", "2"]):
                proc = subprocess.run(
                    [sys.executable, SWITCH, "log-storm", *tokens],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                self.assertEqual(proc.returncode, 2, tokens)

    def test_bad_cursor_tokens(self):
        log_bytes = storm_log([good_frame(1, "p2", "00:00:00:00:00:01")])
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
            code, _, _, _ = run_storm(log_bytes, cursor)
            self.assertEqual(code, 2, cursor)

    def test_bad_max_work_tokens(self):
        log_bytes = storm_log([good_frame(1, "p2", "00:00:00:00:00:01")])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for token in ("", "0", "-1", "01", "1.0", "1 ", "x", "1e3"):
            code, _, _, _ = run_storm(log_bytes, source + ":0", token)
            self.assertEqual(code, 2, token)
            code, _, _, _ = run_storm(log_bytes, "*", token)
            self.assertEqual(code, 2, token)

    def test_arbitrary_length_decimal_max_work_accepted(self):
        log_bytes = storm_log([good_frame(1, "p2", "00:00:00:00:00:01")])
        code, _, err, _ = run_storm(log_bytes, "*", "9" * 60)
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_storm(log_bytes, "*", "9" * 5000)
        self.assertEqual(code, 0, err)

    def test_five_thousand_digit_cursor_offset_unbounded(self):
        log_bytes = storm_log([good_frame(1, "p2", "00:00:00:00:00:01")])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_storm(
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
                [sys.executable, SWITCH, "log-storm", missing, "*"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(proc.returncode, 3)
        self.assertIn(b"file_not_found", proc.stderr)
        self.assertEqual(proc.stdout, b"")

    def test_log_limit_before_invalid_input(self):
        oversized = b"{" + b" " * (16 * 1024 * 1024)
        code, out, err, after = run_storm(oversized, "*")
        self.assertEqual(code, 5)
        self.assertIn(b"log_limit", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, oversized)

    def test_bad_internal_sha_invalid_input(self):
        log_bytes = storm_log([good_frame(1, "p2", "00:00:00:00:00:01")])
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_storm(bad, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_sha_mismatch_invalid_input(self):
        log_bytes = storm_log([good_frame(1, "p2", "00:00:00:00:00:01")])
        code, out, err, _ = run_storm(log_bytes, "0" * 64 + ":0")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_offset_beyond_record_count_invalid_input(self):
        log_bytes = storm_log([good_frame(1, "p2", "00:00:00:00:00:01")])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_storm(log_bytes, source + ":2")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_fdb_mode_rejected(self):
        events = [
            {"t": 0, "port": "p1", "mac": "00:00:00:00:00:01", "vlan": 1},
        ]
        log_bytes = record(fdb_config(), events)
        code, out, err, after = run_storm(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_forward_stp_storm_mode_rejected(self):
        # forward-stp-storm（无 max_frame）模式 LOG：静态合法但非
        # storm-check 模式
        cfg = make_config()
        del cfg["max_frame"]
        events = [
            {"t": 1, "port": "p2", "src": "00:00:00:00:00:01",
             "dst": BCAST, "vlan": None},
        ]
        log_bytes = record(cfg, events)
        code, out, err, after = run_storm(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_stp_check_mode_rejected(self):
        # 七键（无 storm）stp-check 形状同样不得被接受
        cfg = make_config()
        plain = {
            "bridges": cfg["bridges"],
            "links": cfg["links"],
            "delay": cfg["delay"],
            "bridge": cfg["bridge"],
            "ports": cfg["ports"],
            "age": cfg["age"],
            "max_frame": cfg["max_frame"],
        }
        log_bytes = storm_log(
            [good_frame(1, "p2", "00:00:00:00:00:01")], plain
        )
        code, out, err, _ = run_storm(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_tampered_records_fail_verification(self):
        # t=0 幂等链路 applied=false，篡改为 true 并重算内部摘要
        events = [link_event(0, "L1", True)]
        log_bytes = storm_log(events)
        doc = json.loads(log_bytes.decode("utf-8"))
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
        code, out, err, after = run_storm(bad, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, bad)

    def test_invalid_input_before_work_limit(self):
        log_bytes = storm_log([good_frame(1, "p2", "00:00:00:00:00:01")])
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_storm(bad, "*", "1")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")


class WorkLimitTests(unittest.TestCase):
    def test_frame_charge_uses_storm_formula(self):
        # base config：B=2,L=1,U=1 → 初始 2+1+2=5；P=3，帧计
        # K+H+Q+P+1。好广播 t=1：K0 H0 Q0 +4 → 9，并留 K=1（FDB）、
        # Q=1（广播队列）；坏帧 t=2：1+1+4=6 → offset=2 累计 15。等于
        # 上限合法，14 首次超过报 storm_work_limit/5
        good = good_frame(1, "p2", "00:00:00:00:00:01")
        bad = bad_frame(2, "p2", "00:00:00:00:00:02")
        log_bytes = storm_log([good, bad])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, _, err, _ = run_storm(log_bytes, source + ":1", "9")
        self.assertEqual(code, 0, err)
        code, out, err, after = run_storm(log_bytes, source + ":2", "15")
        self.assertEqual(code, 0, err)
        code, out, err, after = run_storm(log_bytes, source + ":2", "14")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"storm_work_limit"}\n')
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_work_counts_only_prefix_events(self):
        events = [
            bad_frame(1, "p2", "00:00:00:00:00:01"),
            bad_frame(2, "p2", "00:00:00:00:00:02"),
        ]
        log_bytes = storm_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        # 坏帧不改状态：K=H=Q=0，各 +4 → offset=2 累计 13；等于合法，
        # 12 首次超过
        code, _, err, _ = run_storm(log_bytes, source + ":2", "13")
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_storm(log_bytes, source + ":2", "12")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"storm_work_limit"}\n')
        # offset=1 仅 5+4=9；offset=0 仅初始收敛 5
        code, _, err, _ = run_storm(log_bytes, source + ":1", "9")
        self.assertEqual(code, 0, err)
        code, out, err, _ = run_storm(log_bytes, source + ":0", "5")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out.decode())["offset"], 0)
        code, _, err, _ = run_storm(log_bytes, source + ":0", "4")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"storm_work_limit"}\n')

    def test_idempotent_and_changing_link_charges(self):
        # 幂等链路：K0 H0 Q0 +1 → 初始 5 累计 6
        log_bytes = storm_log([link_event(0, "L1", True)])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, _, err, _ = run_storm(log_bytes, source + ":1", "6")
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_storm(log_bytes, source + ":1", "5")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"storm_work_limit"}\n')
        # 实际断开（新 U=0）：K0 H0 Q0 + B+L+2U+2P+1 = 2+1+0+6+1 = 10
        # → 累计 15；14 首次超过
        log_bytes = storm_log([link_event(0, "L1", False)])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, _, err, _ = run_storm(log_bytes, source + ":1", "15")
        self.assertEqual(code, 0, err)
        code, out, err, after = run_storm(log_bytes, source + ":1", "14")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"storm_work_limit"}\n')
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_default_max_work_is_ten_million(self):
        code, _, err, _ = run_storm(storm_log([]), "*")
        self.assertEqual(code, 0, err)


if __name__ == "__main__":
    unittest.main()
