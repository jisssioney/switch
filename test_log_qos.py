#!/usr/bin/env python3
"""log-qos 子命令回归：按游标重演 qos-check/qos-decode 模式 LOG 的前
offset 条事件并给出出口队列。

仅用标准库；端到端驱动 `python switch.py log-qos LOG CURSOR [MAX_WORK]`。
参数、资源、CURSOR 及错误顺序完全沿用 log-security；成功产物键序固定为
schema,source_sha256,offset,ports,sha256，末项为前四键紧凑 UTF-8 加 LF 的
sha256；CURSOR 的 * 表示 records 长度（重演全部），否则
<sha256>:<offset>，offset=0 为初始空队列。十二键配置下帧含 src 选
qos-check、帧含 data（t/port/data 原始帧）选 qos-decode，两种帧形状混用
invalid_input/4，无帧仍选 qos-check。ports 按配置序，项键序
name,queues,current,remaining；queues 依优先级 0..3 为四个 FIFO 帧号
整数数组，帧号按所有帧事件零基编号，坏帧占号但不入队；wrr 时 current 为
0..3 整数、remaining 为正整数（下次 service 续用），sp 时二者为 null。
LOG 须通过摘要核对、对应模式语义、全部记录核对与重建日志逐字节一致，
其他模式 invalid_input/4；重演前 offset 项按 qos-check 工作量公式计费
（qos-decode 原始帧先按 qos-decode 解码，坏帧、拒绝、幂等均计费），
等于上限合法，首次超过 stderr 仅 {"error":"qos_work_limit"} 加 LF 并
退出 5。
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
from test_qos import base_config, service  # noqa: E402
from test_qos_check import check_frame, config  # noqa: E402
from test_qos_decode import raw_frame  # noqa: E402

QOS_KEYS = ["schema", "source_sha256", "offset", "ports", "sha256"]
PORT_KEYS = ["name", "queues", "current", "remaining"]
BCAST = "ff:ff:ff:ff:ff:ff"


def good_frame(t, port, src, priority=0, vlan=None, dst=BCAST):
    result = check_frame(t, port, dst, priority=priority, src=src, vlan=vlan)
    return result


def bad_frame(t, port, src, vlan=None):
    return check_frame(t, port, BCAST, length=10, src=src, vlan=vlan)


def raw_good(t, port, src, **kwargs):
    return raw_frame(t, port, BCAST, src, **kwargs)


def raw_bad(t, port, src):
    # runt：长度不足，坏帧占号但不入队
    return raw_frame(t, port, BCAST, src, payload_len=0)


def sp_config():
    result = json.loads(json.dumps(base_config(weights=[1, 1, 1, 1], mode="sp")))
    result["max_frame"] = 1518
    return result


def qos_log(events, cfg=None):
    return record(cfg or config(), events)


def digest_of(doc):
    prefix = {
        "schema": doc["schema"],
        "source_sha256": doc["source_sha256"],
        "offset": doc["offset"],
        "ports": doc["ports"],
    }
    raw = (
        json.dumps(prefix, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def run_qos(log_bytes, cursor, *extra):
    with tempfile.TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "in.log")
        with open(log_path, "wb") as handle:
            handle.write(log_bytes)
        proc = subprocess.run(
            [sys.executable, SWITCH, "log-qos", log_path, cursor, *extra],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        with open(log_path, "rb") as handle:
            after = handle.read()
    return proc.returncode, proc.stdout, proc.stderr, after


def simulate_ports(cfg, events):
    """直接调用 forward_qos_check 求前 events 的出口队列快照。"""
    cfg = json.loads(json.dumps(cfg))  # 防 forward 改写链路状态
    (
        bridges, links, delay, bridge, ports, age, storm, lags, mirror,
        acl, qos, max_frame,
    ) = switch_mod.validate_qos_check_config(cfg)
    link_ids = {link["id"] for link in links}
    check_events = switch_mod.validate_qos_check_events(
        events, ports, link_ids, lags
    )
    state = {}
    switch_mod.forward_qos_check(
        bridges, links, delay, bridge, ports, age, storm, lags, mirror,
        acl, qos, max_frame, check_events, state_out=state,
    )
    return state["ports"]


def simulate_decode_ports(cfg, events):
    """直接按 qos-decode 解码后求出口队列快照。"""
    cfg = json.loads(json.dumps(cfg))
    (
        bridges, links, delay, bridge, ports, age, storm, lags, mirror,
        acl, qos, max_frame,
    ) = switch_mod.validate_qos_check_config(cfg)
    link_ids = {link["id"] for link in links}
    decode_events = switch_mod.validate_qos_decode_events(
        events, ports, link_ids, lags
    )
    state = {}
    switch_mod.qos_decode(
        bridges, links, delay, bridge, ports, age, storm, lags, mirror,
        acl, qos, max_frame, decode_events, state_out=state,
    )
    return state["ports"]


def by_name(ports, name):
    return next(port for port in ports if port["name"] == name)


class HappyPathTests(unittest.TestCase):
    def test_star_is_records_length_with_fixed_key_order_and_digest(self):
        events = [
            good_frame(0, "p1", "00:00:00:00:00:01", priority=0),
            good_frame(1, "p1", "00:00:00:00:00:02", priority=2),
        ]
        log_bytes = qos_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_qos(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertTrue(out.endswith(b"\n"))
        self.assertNotIn(b", ", out)
        self.assertNotIn(b": ", out)
        self.assertEqual(after, log_bytes)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(list(doc), QOS_KEYS)
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["source_sha256"], source)
        self.assertEqual(doc["offset"], 2)
        self.assertEqual(
            [entry["name"] for entry in doc["ports"]],
            ["p1", "p2", "p3", "p4", "p5", "p6"],
        )
        for entry in doc["ports"]:
            self.assertEqual(list(entry), PORT_KEYS)
            self.assertIsInstance(entry["name"], str)
            self.assertEqual(len(entry["queues"]), 4)
            for queue in entry["queues"]:
                self.assertIsInstance(queue, list)
                self.assertTrue(all(isinstance(x, int) for x in queue))
            self.assertIsInstance(entry["current"], int)
            self.assertIn(entry["current"], (0, 1, 2, 3))
            self.assertIsInstance(entry["remaining"], int)
            self.assertGreater(entry["remaining"], 0)
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_star_equals_sha_cursor_at_record_count(self):
        events = [good_frame(0, "p1", "00:00:00:00:00:01")]
        log_bytes = qos_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        _, star_out, _, _ = run_qos(log_bytes, "*")
        code, cur_out, err, _ = run_qos(log_bytes, source + ":1")
        self.assertEqual(code, 0, err)
        self.assertEqual(cur_out, star_out)
        self.assertEqual(json.loads(cur_out.decode())["offset"], 1)

    def test_offset_zero_is_initial_wrr_state(self):
        events = [good_frame(0, "p1", "00:00:00:00:00:01")]
        log_bytes = qos_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_qos(log_bytes, source + ":0")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["offset"], 0)
        for entry in doc["ports"]:
            self.assertEqual(entry["queues"], [[], [], [], []])
            # 初始服务 3 队，配额为 weights[3]（base 权重全 1）
            self.assertEqual(entry["current"], 3)
            self.assertEqual(entry["remaining"], 1)
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_partial_offset_replays_only_prefix(self):
        events = [
            good_frame(0, "p1", "00:00:00:00:00:01", priority=0),  # fid0 q0
            good_frame(1, "p1", "00:00:00:00:00:02", priority=1),  # fid1 q1
            bad_frame(2, "p1", "00:00:00:00:00:03"),               # fid2 坏
            good_frame(3, "p1", "00:00:00:00:00:04", priority=3),  # fid3 q3
        ]
        log_bytes = qos_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        expected = [
            [[], [], [], []],
            [[0], [], [], []],
            [[0], [1], [], []],
            [[0], [1], [], []],          # 坏帧占号但不入队
            [[0], [1], [], [3]],
        ]
        for offset in range(5):
            code, out, err, _ = run_qos(log_bytes, source + ":%d" % offset)
            self.assertEqual(code, 0, (offset, err))
            doc = json.loads(out.decode("utf-8"))
            self.assertEqual(doc["offset"], offset)
            self.assertEqual(by_name(doc["ports"], "p2")["queues"],
                             expected[offset])

    def test_bad_frame_consumes_id_but_not_queued(self):
        events = [
            good_frame(0, "p1", "00:00:00:00:00:01"),  # fid0
            bad_frame(1, "p1", "00:00:00:00:00:02"),   # fid1 坏帧
            good_frame(2, "p1", "00:00:00:00:00:03"),  # fid2
        ]
        log_bytes = qos_log(events)
        code, out, err, _ = run_qos(log_bytes, "*")
        self.assertEqual(code, 0, err)
        p2 = by_name(json.loads(out.decode())["ports"], "p2")
        self.assertEqual(p2["queues"][0], [0, 2])

    def test_wrr_current_remaining_continuation(self):
        # 全部优先级映射到队列 3，weights[3]=4；六帧后连续两次 service(2)
        cfg = json.loads(json.dumps(
            base_config(weights=[1, 2, 3, 4], qos_map=[3] * 8)
        ))
        cfg["max_frame"] = 1518
        events = [
            good_frame(i, "p1", "00:00:00:00:00:%02x" % (i + 1))
            for i in range(6)
        ]
        events += [service(6, "p2", 2), service(7, "p2", 2)]
        log_bytes = qos_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]

        def p2_at(offset):
            code, out, err, _ = run_qos(log_bytes, source + ":%d" % offset)
            self.assertEqual(code, 0, (offset, err))
            return by_name(json.loads(out.decode())["ports"], "p2")

        self.assertEqual(p2_at(0)["queues"][3], [])
        self.assertEqual(p2_at(6)["queues"][3], [0, 1, 2, 3, 4, 5])
        self.assertEqual(p2_at(6)["current"], 3)
        self.assertEqual(p2_at(6)["remaining"], 4)
        after_first = p2_at(7)
        self.assertEqual(after_first["queues"][3], [2, 3, 4, 5])
        # count 用尽而 rem 未尽且队非空：(3,2) 保留续用
        self.assertEqual((after_first["current"], after_first["remaining"]),
                         (3, 2))
        after_second = p2_at(8)
        self.assertEqual(after_second["queues"][3], [4, 5])
        # 续服务后 rem 用尽：推进到 2 队并重置配额 weights[2]=3
        self.assertEqual((after_second["current"], after_second["remaining"]),
                         (2, 3))

    def test_sp_mode_current_remaining_null(self):
        cfg = sp_config()
        events = [
            good_frame(0, "p1", "00:00:00:00:00:01", priority=2),
            service(1, "p2", 1),
        ]
        log_bytes = qos_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for offset in range(3):
            code, out, err, _ = run_qos(log_bytes, source + ":%d" % offset)
            self.assertEqual(code, 0, (offset, err))
            p2 = by_name(json.loads(out.decode())["ports"], "p2")
            self.assertIsNone(p2["current"])
            self.assertIsNone(p2["remaining"])

    def test_ports_follow_config_order(self):
        cfg = config()
        cfg["ports"] = [cfg["ports"][i] for i in (2, 0, 1, 4, 3, 5)]
        events = [good_frame(0, "p1", "00:00:00:00:00:01")]
        log_bytes = qos_log(events, cfg)
        code, out, err, _ = run_qos(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(
            [entry["name"] for entry in json.loads(out.decode())["ports"]],
            ["p3", "p1", "p2", "p5", "p4", "p6"],
        )

    def test_prefix_matches_direct_simulation_for_every_offset(self):
        cfg = config()
        events = [
            good_frame(0, "p1", "00:00:00:00:00:01", priority=0),
            bad_frame(1, "p1", "00:00:00:00:00:02"),
            good_frame(2, "p1", "00:00:00:00:00:03", priority=3),
            service(3, "p2", 1),
        ]
        log_bytes = qos_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for offset in range(len(events) + 1):
            code, out, err, _ = run_qos(log_bytes, source + ":%d" % offset)
            self.assertEqual(code, 0, (offset, err))
            got = json.loads(out.decode())["ports"]
            self.assertEqual(got, simulate_ports(cfg, events[:offset]))

    def test_empty_log_star_and_zero_identical(self):
        log_bytes = qos_log([])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        outputs = []
        for cursor in ("*", source + ":0"):
            code, out, err, _ = run_qos(log_bytes, cursor)
            self.assertEqual(code, 0, err)
            doc = json.loads(out.decode("utf-8"))
            self.assertEqual(doc["offset"], 0)
            outputs.append(out)
        self.assertEqual(outputs[0], outputs[1])


class QosDecodeLogTests(unittest.TestCase):
    def qos_decode_log(self, events, cfg=None):
        return record(cfg or config(), events)

    def test_decode_star_queues_and_digest(self):
        events = [
            raw_good(0, "p1", "00:00:00:00:00:01"),
            raw_good(1, "p1", "00:00:00:00:00:02"),
        ]
        log_bytes = self.qos_decode_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_qos(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertEqual(after, log_bytes)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(list(doc), QOS_KEYS)
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["source_sha256"], source)
        self.assertEqual(doc["offset"], 2)
        p2 = by_name(doc["ports"], "p2")
        # 未标记帧 priority 解码为 0，两帧均入 p2 的 0 队
        self.assertEqual(p2["queues"], [[0, 1], [], [], []])
        for entry in doc["ports"]:
            self.assertEqual(list(entry), PORT_KEYS)
            self.assertIsInstance(entry["current"], int)
            self.assertIn(entry["current"], (0, 1, 2, 3))
            self.assertIsInstance(entry["remaining"], int)
            self.assertGreater(entry["remaining"], 0)
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_decode_tagged_priority_selects_queue(self):
        # p1 改 trunk（allowed 含 vlan1、无 untagged）：带 priority=3 的
        # vlan1 标签帧准入，洪泛到 access vlan1 的 p2，按 qos_map[3]=3
        # 入 p2 的 3 队
        cfg = config()
        cfg["ports"][0] = {
            "name": "p1", "mode": "trunk", "pvid": 1,
            "allowed": [1], "untagged": [], "up": True,
        }
        events = [raw_good(0, "p1", "00:00:00:00:00:01",
                           vlan=1, priority=3)]
        log_bytes = self.qos_decode_log(events, cfg)
        code, out, err, _ = run_qos(log_bytes, "*")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        p2 = by_name(doc["ports"], "p2")
        self.assertEqual(p2["queues"][3], [0])

    def test_decode_bad_frame_consumes_id_but_not_queued(self):
        events = [
            raw_good(0, "p1", "00:00:00:00:00:01"),  # fid0
            raw_bad(1, "p1", "00:00:00:00:00:02"),   # fid1 runt
            raw_good(2, "p1", "00:00:00:00:00:03"),  # fid2
        ]
        log_bytes = self.qos_decode_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        expected = [
            [[], [], [], []],
            [[0], [], [], []],
            [[0], [], [], []],          # 坏帧占号但不入队
            [[0, 2], [], [], []],
        ]
        for offset in range(4):
            code, out, err, _ = run_qos(log_bytes, source + ":%d" % offset)
            self.assertEqual(code, 0, (offset, err))
            doc = json.loads(out.decode("utf-8"))
            self.assertEqual(doc["offset"], offset)
            self.assertEqual(by_name(doc["ports"], "p2")["queues"],
                             expected[offset])

    def test_decode_prefix_matches_direct_simulation_every_offset(self):
        cfg = config()
        events = [
            raw_good(0, "p1", "00:00:00:00:00:01", priority=0),
            raw_bad(1, "p1", "00:00:00:00:00:02"),
            raw_good(2, "p1", "00:00:00:00:00:03"),
            service(3, "p2", 1),
        ]
        log_bytes = self.qos_decode_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for offset in range(len(events) + 1):
            code, out, err, _ = run_qos(log_bytes, source + ":%d" % offset)
            self.assertEqual(code, 0, (offset, err))
            got = json.loads(out.decode("utf-8"))["ports"]
            self.assertEqual(got, simulate_decode_ports(cfg, events[:offset]))

    def test_decode_wrr_service_continuation(self):
        # 未标记帧 priority=0；qos_map 默认把 0 映射到 0 队。改用全 3 映射
        # 使全部入 3 队，weights[3]=4，六帧后连续两次 service(2)
        cfg = json.loads(json.dumps(
            base_config(weights=[1, 2, 3, 4], qos_map=[3] * 8)
        ))
        cfg["max_frame"] = 1518
        events = [
            raw_good(i, "p1", "00:00:00:00:00:%02x" % (i + 1))
            for i in range(6)
        ]
        events += [service(6, "p2", 2), service(7, "p2", 2)]
        log_bytes = self.qos_decode_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]

        def p2_at(offset):
            code, out, err, _ = run_qos(log_bytes, source + ":%d" % offset)
            self.assertEqual(code, 0, (offset, err))
            return by_name(json.loads(out.decode("utf-8"))["ports"], "p2")

        self.assertEqual(p2_at(6)["queues"][3], [0, 1, 2, 3, 4, 5])
        self.assertEqual((p2_at(6)["current"], p2_at(6)["remaining"]),
                         (3, 4))
        self.assertEqual(p2_at(7)["queues"][3], [2, 3, 4, 5])
        self.assertEqual((p2_at(7)["current"], p2_at(7)["remaining"]),
                         (3, 2))
        self.assertEqual(p2_at(8)["queues"][3], [4, 5])
        self.assertEqual((p2_at(8)["current"], p2_at(8)["remaining"]),
                         (2, 3))

    def test_decode_sp_mode_null_scheduler(self):
        cfg = sp_config()
        events = [
            raw_good(0, "p1", "00:00:00:00:00:01"),
            service(1, "p2", 1),
        ]
        log_bytes = self.qos_decode_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for offset in range(3):
            code, out, err, _ = run_qos(log_bytes, source + ":%d" % offset)
            self.assertEqual(code, 0, (offset, err))
            p2 = by_name(json.loads(out.decode("utf-8"))["ports"], "p2")
            self.assertIsNone(p2["current"])
            self.assertIsNone(p2["remaining"])

    def test_no_frame_events_still_route_qos_check(self):
        # 仅 service 项（无帧）：模式按帧形状判定，无帧沿用 qos-check
        events = [service(0, "p2", 1)]
        log_bytes = self.qos_decode_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_qos(log_bytes, source + ":1")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out.decode("utf-8"))["offset"], 1)
        self.assertEqual(after, log_bytes)

    def test_tampered_decode_records_fail_verification(self):
        events = [raw_good(0, "p1", "00:00:00:00:00:01")]
        log_bytes = self.qos_decode_log(events)
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
        code, out, err, after = run_qos(bad, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, bad)


class DecodeWorkLimitTests(unittest.TestCase):
    def test_decode_frames_billed_by_qos_check_formula(self):
        # 同 qos-check：base config 初始 C=1；好帧/坏帧（runt）各计 22，
        # offset=1 累计 23：等于上限合法，22 首次超过报 qos_work_limit/5
        good = raw_good(0, "p1", "00:00:00:00:00:01")
        bad = raw_bad(1, "p1", "00:00:00:00:00:02")
        log_bytes = record(config(), [good, bad])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_qos(log_bytes, source + ":1", "23")
        self.assertEqual(code, 0, err)
        code, out, err, after = run_qos(log_bytes, source + ":1", "22")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"qos_work_limit"}\n')
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_decode_admission_reject_still_billed(self):
        # access p1 收 priority=7 带标签帧被准入拒绝：不入队、不改变状态，
        # 仍按帧计 22
        rejected = raw_good(0, "p1", "00:00:00:00:00:01",
                            vlan=1, priority=7)
        log_bytes = record(config(), [rejected])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_qos(log_bytes, source + ":1", "23")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(by_name(doc["ports"], "p2")["queues"],
                         [[], [], [], []])
        code, _, err, _ = run_qos(log_bytes, source + ":1", "22")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"qos_work_limit"}\n')

    def test_decode_work_counts_only_prefix(self):
        events = [
            raw_bad(0, "p1", "00:00:00:00:00:01"),
            raw_bad(1, "p1", "00:00:00:00:00:02"),
        ]
        log_bytes = record(config(), events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, _, err, _ = run_qos(log_bytes, source + ":2", "45")
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_qos(log_bytes, source + ":2", "44")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"qos_work_limit"}\n')
        code, _, err, _ = run_qos(log_bytes, source + ":1", "23")
        self.assertEqual(code, 0, err)
        code, out, err, _ = run_qos(log_bytes, source + ":0", "1")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out.decode("utf-8"))["offset"], 0)


class UsageTests(unittest.TestCase):
    def test_arg_counts(self):
        log_bytes = qos_log([good_frame(0, "p1", "00:00:00:00:00:01")])
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "in.log")
            with open(path, "wb") as handle:
                handle.write(log_bytes)
            for tokens in ([], [path], [path, "*", "1", "2"]):
                proc = subprocess.run(
                    [sys.executable, SWITCH, "log-qos", *tokens],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                self.assertEqual(proc.returncode, 2, tokens)

    def test_bad_cursor_tokens(self):
        log_bytes = qos_log([good_frame(0, "p1", "00:00:00:00:00:01")])
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
            code, _, _, _ = run_qos(log_bytes, cursor)
            self.assertEqual(code, 2, cursor)

    def test_bad_max_work_tokens(self):
        log_bytes = qos_log([good_frame(0, "p1", "00:00:00:00:00:01")])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for token in ("", "0", "-1", "01", "1.0", "1 ", "x", "1e3"):
            code, _, _, _ = run_qos(log_bytes, source + ":0", token)
            self.assertEqual(code, 2, token)
            code, _, _, _ = run_qos(log_bytes, "*", token)
            self.assertEqual(code, 2, token)

    def test_arbitrary_length_decimal_max_work_accepted(self):
        log_bytes = qos_log([good_frame(0, "p1", "00:00:00:00:00:01")])
        code, _, err, _ = run_qos(log_bytes, "*", "9" * 60)
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_qos(log_bytes, "*", "9" * 5000)
        self.assertEqual(code, 0, err)

    def test_five_thousand_digit_cursor_offset_unbounded(self):
        log_bytes = qos_log([good_frame(0, "p1", "00:00:00:00:00:01")])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_qos(
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
                [sys.executable, SWITCH, "log-qos", missing, "*"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(proc.returncode, 3)
        self.assertIn(b"file_not_found", proc.stderr)
        self.assertEqual(proc.stdout, b"")

    def test_log_limit_before_invalid_input(self):
        oversized = b"{" + b" " * (16 * 1024 * 1024)
        code, out, err, after = run_qos(oversized, "*")
        self.assertEqual(code, 5)
        self.assertIn(b"log_limit", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, oversized)

    def test_bad_internal_sha_invalid_input(self):
        log_bytes = qos_log([good_frame(0, "p1", "00:00:00:00:00:01")])
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_qos(bad, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_sha_mismatch_invalid_input(self):
        log_bytes = qos_log([good_frame(0, "p1", "00:00:00:00:00:01")])
        code, out, err, _ = run_qos(log_bytes, "0" * 64 + ":0")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_offset_beyond_record_count_invalid_input(self):
        log_bytes = qos_log([good_frame(0, "p1", "00:00:00:00:00:01")])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_qos(log_bytes, source + ":2")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_fdb_mode_rejected(self):
        events = [
            {"t": 0, "port": "p1", "mac": "00:00:00:00:00:01", "vlan": 1},
        ]
        log_bytes = record(fdb_config(), events)
        code, out, err, after = run_qos(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_plain_qos_mode_rejected(self):
        # qos（无 max_frame）模式 LOG：静态合法但非 qos-check 模式
        cfg = json.loads(json.dumps(base_config(weights=[1, 1, 1, 1])))
        events = [
            {
                "t": 0, "port": "p1", "src": "00:00:00:00:00:01",
                "dst": BCAST, "vlan": None, "ethertype": 0x0800,
                "priority": 0,
            },
        ]
        log_bytes = record(cfg, events)
        code, out, err, after = run_qos(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_qos_decode_mode_accepted(self):
        # qos-decode（t/port/data 原始帧）LOG：配置形状同 qos-check，
        # log-qos 按帧形状选 qos-decode 并给出出口队列
        events = [raw_good(0, "p1", "00:00:00:00:00:01")]
        log_bytes = record(config(), events)
        code, out, err, after = run_qos(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertEqual(after, log_bytes)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(list(doc), QOS_KEYS)
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["source_sha256"],
                         json.loads(log_bytes.decode("utf-8"))["sha256"])
        self.assertEqual(doc["offset"], 1)
        self.assertEqual(by_name(doc["ports"], "p2")["queues"][0], [0])
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_mixed_frame_shapes_rejected(self):
        # 同一 LOG 内 src 帧与 data 帧混用：静态摘要合法但模式判定
        # invalid_input/4，stdout 空、LOG 不动
        src_frame = good_frame(0, "p1", "00:00:00:00:00:01")
        log_bytes = record(config(), [src_frame])
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["records"].append({
            "t": 1, "version": 0,
            "event": {"t": 1, "port": "p1", "data": "00"},
            "applied": True, "output": None,
        })
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
        code, out, err, after = run_qos(bad, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, bad)

    def test_tampered_records_fail_verification(self):
        # 帧恒 applied=true；篡改为 false 并重算内部摘要 → 记录核对失败
        events = [good_frame(0, "p1", "00:00:00:00:00:01")]
        log_bytes = qos_log(events)
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
        code, out, err, after = run_qos(bad, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, bad)

    def test_invalid_input_before_work_limit(self):
        log_bytes = qos_log([good_frame(0, "p1", "00:00:00:00:00:01")])
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_qos(bad, "*", "1")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")


class WorkLimitTests(unittest.TestCase):
    def test_frame_charge_uses_qos_check_formula(self):
        # base config：B=1,L=0,U=0 → 初始 C=1；P=6,M=2,R=1。坏帧仍按帧计
        # X+3P+M+R+1 = 0+18+2+1+1 = 22，累计 23；等于上限合法，首次超过
        # 报 qos_work_limit/5
        good = good_frame(0, "p1", "00:00:00:00:00:01")
        bad = bad_frame(1, "p1", "00:00:00:00:00:02")
        log_bytes = qos_log([good, bad])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_qos(log_bytes, source + ":1", "23")
        self.assertEqual(code, 0, err)
        code, out, err, after = run_qos(log_bytes, source + ":1", "22")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"qos_work_limit"}\n')
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_work_counts_only_prefix_events(self):
        # 两条坏帧均不改变任何状态（X=0、N=0），各计 22：offset=2 累计
        # 1+22+22=45。等于上限合法，44 首次超过
        events = [
            bad_frame(0, "p1", "00:00:00:00:00:01"),
            bad_frame(1, "p1", "00:00:00:00:00:02"),
        ]
        log_bytes = qos_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, _, err, _ = run_qos(log_bytes, source + ":2", "45")
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_qos(log_bytes, source + ":2", "44")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"qos_work_limit"}\n')
        # offset=1 仅初始 1+22=23：同一上限 23 合法，证明只计前 offset 项
        code, _, err, _ = run_qos(log_bytes, source + ":1", "23")
        self.assertEqual(code, 0, err)
        # offset=0：仅初始收敛 1
        code, out, err, _ = run_qos(log_bytes, source + ":0", "1")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out.decode())["offset"], 0)

    def test_default_max_work_is_ten_million(self):
        code, _, err, _ = run_qos(qos_log([]), "*")
        self.assertEqual(code, 0, err)


if __name__ == "__main__":
    unittest.main()
