#!/usr/bin/env python3
"""qos-pfc-decode 子命令回归：802.1Qbb 优先级流控的确定性仿真。

CONFIG 在 qos-wire-decode 每口再加 pfc（严格递增的 0..7 子序，空数组表示
不支持 PFC）；事件仍只接受 link/advance/原始帧。目的 01:80:c2:00:00:01、
以太类型 0x8808、操作码 0x0101 的未标记好帧按 PFC 处理：恰 64 字节，含两
字节 class-enable 与按优先级 0..7 排列的八个两字节 quanta，其余字节全零，
否则 malformed_pfc（计时器不变）。链路须 up/全双工且置位优先级均获入端口
pfc 允许，否则 pfc_unsupported 且任何项不生效。非零 quanta 置截止时刻
t+ceil(quanta*512000/rate)，零值清除，未置位项不变。数据帧按 qos.map 入
四队列；队列暂停到全局 PAUSE 与映射到该队列的有效 PFC 截止最大值，在发帧
不抢占。端口汇总增加 pfc_frames、pfc_unsupported_frames 与八项
pfc_duration_ns。

仅用标准库；端到端驱动 `python switch.py qos-pfc-decode CONFIG EVENTS`。
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
SWITCH = os.path.join(HERE, "switch.py")

BCAST = "ff:ff:ff:ff:ff:ff"
MAC1 = "00:00:00:00:00:01"
MAC2 = "00:00:00:00:00:02"
PAUSE_DST = "01:80:c2:00:00:01"


def port(name, pvid=1, mode="trunk", rates=None, modes=None,
         queue_bytes=1000000, flow_control=True, pfc=(3,)):
    return {
        "name": name,
        "mode": mode,
        "pvid": pvid,
        "allowed": [pvid],
        "untagged": [],
        "rates": [1000] if rates is None else rates,
        "modes": ["full"] if modes is None else modes,
        "queue_bytes": queue_bytes,
        "flow_control": flow_control,
        "pfc": list(pfc),
    }


def qos(mode="sp", weights=None, drop="tail", cap=100000, mapping=None):
    return {
        "map": [0, 1, 2, 3, 0, 1, 2, 3] if mapping is None else mapping,
        "cap": cap,
        "mode": mode,
        "weights": [1, 1, 1, 1] if weights is None else weights,
        "drop": drop,
    }


def config(q=None, ports=None, age=100, max_frame=1518, delay=10):
    return {
        "ports": ports if ports is not None else [port("p1"), port("p2")],
        "age": age,
        "max_frame": max_frame,
        "delay": delay,
        "qos": q if q is not None else qos(),
    }


def link(t, p, rates=(1000,), modes=("full",)):
    return {
        "t": t, "port": p, "admin": True, "peer": True,
        "rates": list(rates), "modes": list(modes),
    }


def advance(t):
    return {"t": t, "advance": True}


def mac_bytes(mac):
    return bytes(int(x, 16) for x in mac.split(":"))


def raw_frame(t, p, dst=BCAST, src=MAC1, prio=0, vlan=1, payload_len=46):
    if vlan is None:
        head = mac_bytes(dst) + mac_bytes(src) + (0x0800).to_bytes(2, "big")
    else:
        tci = (prio << 13) | vlan
        head = (
            mac_bytes(dst) + mac_bytes(src) + b"\x81\x00"
            + tci.to_bytes(2, "big") + (0x0800).to_bytes(2, "big")
        )
    body = head + b"\x00" * payload_len
    fcs = (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little")
    return {"t": t, "port": p, "data": (body + fcs).hex()}


def pause_event(t, p, quanta, src=MAC1):
    body = (
        mac_bytes(PAUSE_DST) + mac_bytes(src) + b"\x88\x08"
        + (1).to_bytes(2, "big") + quanta.to_bytes(2, "big") + b"\x00" * 42
    )
    fcs = (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little")
    return {"t": t, "port": p, "data": (body + fcs).hex()}


def pfc_event(t, p, enable=(), quanta8=None, src=MAC1, tail=b"\x00" * 26):
    """构造 PFC 帧（opcode 0x0101）。enable 为置位优先级，quanta8 为八量子。"""
    en = 0
    for prio in enable:
        en |= 1 << (7 - prio)
    if quanta8 is None:
        quanta8 = [0] * 8
    body = (
        mac_bytes(PAUSE_DST) + mac_bytes(src) + b"\x88\x08"
        + (0x0101).to_bytes(2, "big") + en.to_bytes(2, "big")
        + b"".join(q.to_bytes(2, "big") for q in quanta8) + tail
    )
    fcs = (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little")
    return {"t": t, "port": p, "data": (body + fcs).hex()}


def run_cli(config_doc, events, *limits):
    with tempfile.TemporaryDirectory() as tmp:
        cfg = os.path.join(tmp, "config.json")
        evt = os.path.join(tmp, "events.json")
        with open(cfg, "wb") as handle:
            handle.write(json.dumps(config_doc).encode("utf-8"))
        with open(evt, "wb") as handle:
            handle.write(json.dumps(events).encode("utf-8"))
        proc = subprocess.run(
            [sys.executable, SWITCH, "qos-pfc-decode", cfg, evt,
             *[str(x) for x in limits]],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    return proc


def run(config_doc, events, *limits):
    proc = run_cli(config_doc, events, *limits)
    assert proc.returncode == 0, (
        proc.returncode, proc.stderr.decode("utf-8")
    )
    return json.loads(proc.stdout.decode("utf-8"))


def tx(out):
    return [r for r in out["results"] if "start" in r and "reason" not in r]


WIRE_TAGGED = 88  # 68 字节帧 + 20 字节线缆开销
DUR = WIRE_TAGGED * 8  # 1000 Mbps 下 704 ns


def up(extra=()):
    return [link(0, "p1"), link(0, "p2")] + list(extra)


class ConfigValidationTests(unittest.TestCase):
    def test_valid_pfc_shapes(self):
        for value in ([], [0], [7], [0, 3, 7], [1, 2, 4, 6]):
            doc = config(ports=[port("p1", pfc=value), port("p2", pfc=value)])
            proc = run_cli(doc, [])
            self.assertEqual(proc.returncode, 0, (value, proc.stderr))

    def test_bad_pfc_field(self):
        base = config()
        bad_values = (
            [8], [-1], [0, 0], [3, 2], [1, 3, 2], "x", 3, True, None,
            {}, [0.5],
        )
        for value in bad_values:
            doc = json.loads(json.dumps(base))
            doc["ports"][0]["pfc"] = value
            proc = run_cli(doc, [])
            self.assertEqual(proc.returncode, 4, value)
            self.assertEqual(proc.stdout, b"")
            self.assertEqual(proc.stderr.strip(), b'{"error":"invalid_input"}')

    def test_missing_pfc_key_is_invalid(self):
        doc = config()
        del doc["ports"][1]["pfc"]
        proc = run_cli(doc, [])
        self.assertEqual(proc.returncode, 4)
        self.assertEqual(proc.stdout, b"")

    def test_extra_pfc_key_is_invalid_for_qos_wire(self):
        # pfc 字段不属于 qos-wire-decode：原入口行为保持不变
        with tempfile.TemporaryDirectory() as tmp:
            cfg = os.path.join(tmp, "c.json")
            evt = os.path.join(tmp, "e.json")
            with open(cfg, "w") as h:
                h.write(json.dumps(config()))
            with open(evt, "w") as h:
                h.write(json.dumps([]))
            proc = subprocess.run(
                [sys.executable, SWITCH, "qos-wire-decode", cfg, evt],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(proc.returncode, 4)

    def test_service_event_is_invalid(self):
        proc = run_cli(config(), [link(0, "p1"),
                                  {"t": 1, "port": "p2", "count": 1}])
        self.assertEqual(proc.returncode, 4)
        self.assertEqual(proc.stdout, b"")


class PfcFrameTests(unittest.TestCase):
    def test_valid_pfc_output_shape(self):
        doc = config(ports=[port("p1", pfc=(0, 3, 7)),
                            port("p2", pfc=(0, 3, 7))])
        events = up([
            pfc_event(100, "p2", enable=(0, 3, 7),
                      quanta8=[10, 0, 0, 20, 0, 0, 0, 5]),
        ])
        out = run(doc, events)
        rec = next(r for r in out["results"] if r.get("action") == "pfc")
        self.assertEqual(rec["port"], "p2")
        self.assertEqual(
            [i["priority"] for i in rec["items"]], [0, 3, 7]
        )
        self.assertEqual(rec["items"][0],
                         {"priority": 0, "quanta": 10, "until": 5220})
        self.assertEqual(rec["items"][1],
                         {"priority": 3, "quanta": 20, "until": 10340})
        self.assertEqual(rec["items"][2],
                         {"priority": 7, "quanta": 5, "until": 2660})
        p2 = out["ports"][1]
        self.assertEqual(p2["pfc_frames"], 1)
        self.assertEqual(p2["pfc_unsupported_frames"], 0)
        self.assertEqual(p2["rx_frames"], 1)  # PFC 计入接收
        # PFC 不转发：无转发/入队结果
        self.assertFalse(any("class" in r for r in out["results"]))

    def test_zero_quanta_clears_deadline(self):
        events = up([
            pfc_event(100, "p2", enable=(3,), quanta8=[0, 0, 0, 10] + [0] * 4),
            pfc_event(200, "p2", enable=(3,), quanta8=[0] * 8),
        ])
        out = run(config(), events)
        recs = [r for r in out["results"] if r.get("action") == "pfc"]
        self.assertEqual(recs[0]["items"][0]["until"], 5220)
        self.assertEqual(recs[1]["items"][0]["until"], None)

    def test_unenabled_priorities_unchanged(self):
        # 第二帧只置位 p3；先前置位的 p2 截止时刻不被触碰
        doc = config(ports=[port("p1", pfc=(2, 3)), port("p2", pfc=(2, 3))])
        events = up([
            pfc_event(100, "p2", enable=(2, 3),
                      quanta8=[0, 0, 50, 50] + [0] * 4),
            pfc_event(200, "p2", enable=(3,),
                      quanta8=[0, 0, 0, 7] + [0] * 4),
        ])
        out = run(doc, events)
        recs = [r for r in out["results"] if r.get("action") == "pfc"]
        self.assertEqual([i["priority"] for i in recs[1]["items"]], [3])
        self.assertEqual(recs[1]["items"][0]["until"], 3784)
        # p2 的长截止仍在：其阻塞时长统计保持增长
        self.assertGreater(out["ports"][1]["pfc_duration_ns"][2], 0)

    def test_malformed_nonzero_tail(self):
        bad = pfc_event(
            100, "p2", enable=(3,), quanta8=[0, 0, 0, 10] + [0] * 4,
            tail=b"\x01" + b"\x00" * 25,
        )
        out = run(config(), up([bad]))
        actions = [r.get("action") for r in out["results"] if "action" in r]
        self.assertEqual(actions, ["malformed_pfc"])
        p2 = out["ports"][1]
        self.assertEqual(p2["pfc_frames"], 0)
        self.assertEqual(p2["pfc_unsupported_frames"], 0)

    def test_malformed_wrong_length_above_runt(self):
        # 68 字节好帧、opcode 0x0101：长度既非 64 又不属 runt/giant，按
        # malformed_pfc 分类，计时器不变
        en = (1 << 4).to_bytes(2, "big")
        quanta = b"".join(
            (10).to_bytes(2, "big") if i == 3 else b"\x00\x00"
            for i in range(8)
        )
        body = (
            mac_bytes(PAUSE_DST) + mac_bytes(MAC1) + b"\x88\x08\x01\x01"
            + en + quanta + b"\x00" * 30
        )
        self.assertEqual(len(body), 64)
        fcs = (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little")
        event = {"t": 100, "port": "p2", "data": (body + fcs).hex()}
        out = run(config(), up([event]))
        actions = [r.get("action") for r in out["results"] if "action" in r]
        self.assertEqual(actions, ["malformed_pfc"])

    def test_malformed_does_not_change_timers(self):
        # 先一个有效 PFC，再一个 malformed：等待数据帧仍只受首个截止门控
        good = pfc_event(100, "p2", enable=(3,),
                         quanta8=[0, 0, 0, 10] + [0] * 4)
        bad = pfc_event(
            200, "p2", enable=(3,), quanta8=[0] * 8,
            tail=b"\x01" + b"\x00" * 25,
        )
        events = [link(0, "p1"), link(0, "p2"), good, bad,
                  raw_frame(300, "p1", src=MAC2, prio=3), advance(100000)]
        out = run(config(), events)
        records = tx(out)
        self.assertEqual(records[0]["start"], 5220)
        self.assertEqual(out["ports"][1]["pfc_frames"], 1)

    def test_runt_pfc_shape_is_runt(self):
        # 短于 64 字节的 PFC 形态帧优先按既有 runt 规则分类
        en = (1 << 4).to_bytes(2, "big")
        body = (
            mac_bytes(PAUSE_DST) + mac_bytes(MAC1) + b"\x88\x08\x01\x01"
            + en + b"\x00" * 20
        )
        fcs = (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little")
        event = {"t": 100, "port": "p2", "data": (body + fcs).hex()}
        out = run(config(), up([event]))
        self.assertEqual(
            [(r.get("class"), r.get("action"))
             for r in out["results"] if "class" in r],
            [("runt", "drop")],
        )

    def test_bad_fcs_takes_precedence(self):
        event = pfc_event(100, "p2", enable=(3,),
                          quanta8=[0, 0, 0, 10] + [0] * 4)
        data = bytearray.fromhex(event["data"])
        data[-1] ^= 0xFF
        event["data"] = data.hex()
        out = run(config(), up([event]))
        self.assertEqual(
            [(r.get("class"), r.get("action"))
             for r in out["results"] if "class" in r],
            [("bad_fcs", "drop")],
        )
        self.assertEqual(out["ports"][1]["pfc_frames"], 0)

    def test_pfc_does_not_learn_source(self):
        # PFC 源 MAC1 不得学习：随后 p2 发往 MAC1 的帧应洪泛到 p1
        events = up([
            pfc_event(100, "p1", enable=(3,),
                      quanta8=[0, 0, 0, 10] + [0] * 4),
            raw_frame(200, "p2", dst=MAC1, src=MAC2, prio=0),
        ])
        out = run(config(), events)
        decisions = [r for r in out["results"] if "class" in r]
        self.assertEqual(decisions[-1]["action"], "flood")
        self.assertEqual([x["name"] for x in decisions[-1]["ports"]], ["p1"])


class PfcUnsupportedTests(unittest.TestCase):
    def _unsupported(self, doc, event, pre=()):
        out = run(doc, list(pre) + [event])
        rec = next(
            r for r in out["results"] if r.get("action") == "pfc_unsupported"
        )
        return rec, out

    def test_priority_not_allowed(self):
        doc = config(ports=[port("p1", pfc=[3]), port("p2", pfc=[3])])
        rec, out = self._unsupported(
            doc, pfc_event(100, "p2", enable=(2,),
                           quanta8=[0, 0, 10] + [0] * 5),
            pre=[link(0, "p1"), link(0, "p2")],
        )
        self.assertEqual(rec["port"], "p2")
        p2 = out["ports"][1]
        self.assertEqual(p2["pfc_frames"], 1)
        self.assertEqual(p2["pfc_unsupported_frames"], 1)

    def test_empty_pfc_array_unsupported(self):
        doc = config(ports=[port("p1", pfc=[]), port("p2", pfc=[])])
        _rec, out = self._unsupported(
            doc, pfc_event(100, "p2", enable=(0,),
                           quanta8=[10] + [0] * 7),
            pre=[link(0, "p1"), link(0, "p2")],
        )
        self.assertEqual(out["ports"][1]["pfc_duration_ns"], [0] * 8)

    def test_half_duplex_unsupported(self):
        doc = config(ports=[
            port("p1", modes=["half"]), port("p2", modes=["half"]),
        ])
        _rec, out = self._unsupported(
            doc, pfc_event(100, "p2", enable=(3,),
                           quanta8=[0, 0, 0, 10] + [0] * 4),
            pre=[link(0, "p1", modes=("half",)),
                 link(0, "p2", modes=("half",))],
        )

    def test_link_down_unsupported(self):
        # 无 link 事件：端口 down，PFC 不支持且无任何门控效果
        out = run(config(), [
            pfc_event(100, "p2", enable=(3,),
                      quanta8=[0, 0, 0, 10] + [0] * 4),
        ])
        self.assertTrue(
            any(r.get("action") == "pfc_unsupported" for r in out["results"])
        )
        self.assertEqual(out["ports"][1]["pfc_duration_ns"], [0] * 8)

    def test_unsupported_is_atomic(self):
        # 帧中 p3 允许、p2 不允许：任何项都不生效；随后两队列帧均不被门控
        doc = config(ports=[
            port("p1", pfc=(3,)), port("p2", pfc=(3,)),
        ])
        events = [
            link(0, "p1"), link(0, "p2"),
            pfc_event(100, "p2", enable=(2, 3),
                      quanta8=[0, 0, 100, 100] + [0] * 4),
            raw_frame(200, "p1", src=MAC2, prio=2),
            raw_frame(300, "p1", src="00:00:00:00:00:03", prio=3),
            advance(100000),
        ]
        out = run(doc, events)
        records = tx(out)
        # 无 PFC 生效：首帧 200 即开始，两帧连续发送
        self.assertEqual([r["start"] for r in records], [200, 200 + DUR])
        self.assertEqual(out["ports"][1]["pfc_duration_ns"], [0] * 8)


class GatingTests(unittest.TestCase):
    def test_pfc_delays_waiting_copy_of_mapped_queue(self):
        events = up([
            raw_frame(100, "p1", prio=3),
            pfc_event(200, "p2", enable=(3,),
                      quanta8=[0, 0, 0, 10] + [0] * 4),
            raw_frame(300, "p1", src=MAC2, prio=3),
            advance(100000),
        ])
        out = run(config(), events)
        records = tx(out)
        # until = 200 + ceil(10*512000/1000) = 5320；在发帧 100..804 不动
        self.assertEqual(records[0]["start"], 100)
        self.assertEqual(records[1]["start"], 5320)

    def test_pfc_does_not_gate_other_queues(self):
        # p3 PFC 只门控队列 3；p2 数据帧入队列 2，正常发送
        events = up([
            raw_frame(50, "p1", prio=2),
            pfc_event(100, "p2", enable=(3,),
                      quanta8=[0, 0, 0, 100] + [0] * 4),
            raw_frame(150, "p1", src=MAC2, prio=2),
            advance(100000),
        ])
        out = run(config(), events)
        self.assertEqual(
            [(r["queue"], r["start"]) for r in tx(out)],
            [(2, 50), (2, 50 + DUR)],
        )
        # p3 门控仍按显式时钟区间累计（口径同全局 PAUSE：与有无帧无关），
        # 但起点在发的 q2 帧 [50,754) 不抢占，实际区间 51300-754=50546
        self.assertEqual(out["ports"][1]["pfc_duration_ns"][3], 50546)

    def test_pfc_received_on_ingress_gates_its_egress(self):
        # PFC 到达 p1：洪泛到 p1 的数据副本被门控
        events = [
            link(0, "p1"), link(0, "p2"),
            raw_frame(50, "p2", prio=3),
            pfc_event(100, "p1", enable=(3,),
                      quanta8=[0, 0, 0, 10] + [0] * 4),
            raw_frame(150, "p2", src=MAC2, prio=3),
            advance(100000),
        ]
        out = run(config(), events)
        records = [r for r in tx(out) if r["port"] == "p1"]
        self.assertEqual(records[1]["start"], 5220)

    def test_two_priorities_same_queue_use_max(self):
        # p3 与 p7 都映射队列 3；门控取较大截止（p7 until 10340）
        doc = config(ports=[port("p1", pfc=(3, 7)), port("p2", pfc=(3, 7))])
        events = up([
            pfc_event(100, "p2", enable=(3, 7),
                      quanta8=[0, 0, 0, 10, 0, 0, 0, 20]),
            raw_frame(200, "p1", prio=3),
            advance(100000),
        ])
        out = run(doc, events)
        records = tx(out)
        self.assertEqual(records[0]["start"], 10340)

    def test_global_pause_and_pfc_use_max(self):
        # 全局 PAUSE until=1224，PFC p3（t=300 到达）until=51500；门控取 PFC
        events = up([
            raw_frame(100, "p1", prio=3),
            pause_event(200, "p2", 2),
            pfc_event(300, "p2", enable=(3,),
                      quanta8=[0, 0, 0, 100] + [0] * 4),
            raw_frame(400, "p1", src=MAC2, prio=3),
            advance(60000),
        ])
        out = run(config(), events)
        self.assertEqual(tx(out)[1]["start"], 51500)
        p2 = out["ports"][1]
        # 全局 PAUSE 与 PFC 统计各自独立：PAUSE 计墙钟区间 [804,1224)=420，
        # PFC 计其决定的显式区间（自其到达起，在发帧不抢占）51500-804
        self.assertEqual(p2["pause_duration_ns"], 420)
        self.assertEqual(p2["pfc_duration_ns"][3], 50696)

    def test_zero_quanta_recovers_queue(self):
        events = up([
            raw_frame(100, "p1", prio=3),
            pfc_event(200, "p2", enable=(3,),
                      quanta8=[0, 0, 0, 1000] + [0] * 4),
            pfc_event(300, "p2", enable=(3,), quanta8=[0] * 8),
            raw_frame(400, "p1", src=MAC2, prio=3),
            advance(100000),
        ])
        out = run(config(), events)
        # 清除后第二副本紧随在发帧完成（804）之后
        self.assertEqual([r["start"] for r in tx(out)], [100, 100 + DUR])

    def test_priority_handoff_within_queue(self):
        # p4（长）先决定队列 0；清除后 p0（短）接管，时长分段归属
        doc = config(ports=[port("p1", pfc=(0, 4)), port("p2", pfc=(0, 4))])
        events = up([
            pfc_event(100, "p2", enable=(0, 4),
                      quanta8=[10, 0, 0, 0, 100] + [0] * 3),
            pfc_event(200, "p2", enable=(4,), quanta8=[0] * 8),
            advance(60000),
        ])
        out = run(doc, events)
        p2 = out["ports"][1]["pfc_duration_ns"]
        # p4 决定 [100,200)（被零值清除）；p0 自 200 接管至 5220
        self.assertEqual(p2[4], 100)
        self.assertEqual(p2[0], 5220 - 200)

    def test_sp_scheduling_resumes_after_pfc_expiry(self):
        events = up([
            raw_frame(100, "p1", prio=0),
            raw_frame(101, "p1", src=MAC2, prio=3),
            pfc_event(200, "p2", enable=(3,),
                      quanta8=[0, 0, 0, 10] + [0] * 4),
            advance(100000),
        ])
        out = run(config(), events)
        # 队列 3 被门控到 5320；队列 0 先在 100 发送，队列 3 随后发送
        self.assertEqual([r["queue"] for r in tx(out)], [0, 3])
        self.assertEqual([r["start"] for r in tx(out)], [100, 5320])

    def test_no_auto_drain_during_pfc_window(self):
        events = up([
            pfc_event(100, "p2", enable=(3,),
                      quanta8=[0, 0, 0, 100] + [0] * 4),
            raw_frame(200, "p1", prio=3),
        ])
        out = run(config(), events)
        self.assertEqual(tx(out), [])
        self.assertEqual(
            out["ports"][1]["queues"][3],
            {"frames": 1, "bytes": WIRE_TAGGED, "sent": 0, "dropped": 0},
        )


class DurationTests(unittest.TestCase):
    def test_duration_excludes_inflight_frame(self):
        # 在发帧 [100,804) 不抢占；PFC 200 到达，截止 5320，等待帧实际阻塞
        # 自 804 起：5320-804 = 4516
        events = up([
            raw_frame(100, "p1", prio=3),
            pfc_event(200, "p2", enable=(3,),
                      quanta8=[0, 0, 0, 10] + [0] * 4),
            raw_frame(300, "p1", src=MAC2, prio=3),
            advance(100000),
        ])
        out = run(config(), events)
        self.assertEqual(out["ports"][1]["pfc_duration_ns"][3], 4516)

    def test_duration_full_window_without_inflight(self):
        # PFC 到达时发送器空闲：整个 quanta 窗口都在阻塞
        events = up([
            raw_frame(100, "p1", prio=3),
            advance(5000),
            pfc_event(6000, "p2", enable=(3,),
                      quanta8=[0, 0, 0, 10] + [0] * 4),
            raw_frame(7000, "p1", src=MAC2, prio=3),
            advance(20000),
        ])
        out = run(config(), events)
        self.assertEqual(out["ports"][1]["pfc_duration_ns"][3], 5120)

    def test_duration_only_observed_clock_intervals(self):
        # 无 advance 跨越截止时刻：只统计显式时钟覆盖到的部分
        events = up([
            pfc_event(100, "p2", enable=(3,),
                      quanta8=[0, 0, 0, 100] + [0] * 4),
            advance(200),
        ])
        out = run(config(), events)
        self.assertEqual(out["ports"][1]["pfc_duration_ns"][3], 100)

    def test_eight_duration_slots(self):
        out = run(config(), up())
        self.assertEqual(out["ports"][0]["pfc_duration_ns"], [0] * 8)
        self.assertEqual(out["ports"][1]["pfc_duration_ns"], [0] * 8)


class OutputContractTests(unittest.TestCase):
    def test_fixed_key_orders(self):
        doc = config(ports=[port("p1", pfc=(3, 7)), port("p2", pfc=(3, 7))])
        events = up([
            raw_frame(100, "p1", prio=3),
            pfc_event(200, "p2", enable=(3, 7),
                      quanta8=[0, 0, 0, 10, 0, 0, 0, 5]),
            advance(100000),
        ])
        proc = run_cli(doc, events)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        raw = proc.stdout
        doc = json.loads(raw)
        self.assertEqual(list(doc), ["results", "ports"])
        self.assertEqual(
            list(doc["ports"][0]),
            ["name", "queues", "rx_frames", "rx_bytes",
             "tx_frames", "tx_bytes", "collision_frames",
             "collision_bytes", "queue_full_frames", "queue_full_bytes",
             "quota_full_frames", "quota_full_bytes", "link_down_frames",
             "link_down_bytes", "pause_frames", "pause_unsupported_frames",
             "pause_duration_ns", "pfc_frames", "pfc_unsupported_frames",
             "pfc_duration_ns"],
        )
        pfc_rec = next(r for r in doc["results"] if r.get("action") == "pfc")
        self.assertEqual(list(pfc_rec), ["t", "port", "action", "items"])
        self.assertEqual(list(pfc_rec["items"][0]),
                         ["priority", "quanta", "until"])
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b": ", raw)

    def test_deterministic(self):
        events = up([
            raw_frame(100, "p1", prio=3),
            pfc_event(200, "p2", enable=(3,),
                      quanta8=[0, 0, 0, 10] + [0] * 4),
            raw_frame(300, "p1", src=MAC2, prio=3),
            advance(100000),
        ])
        a = run_cli(config(), events).stdout
        b = run_cli(config(), events).stdout
        self.assertEqual(a, b)


class ResourceAndErrorTests(unittest.TestCase):
    def test_file_not_found(self):
        proc = subprocess.run(
            [sys.executable, SWITCH, "qos-pfc-decode", "/nope/c", "/nope/e"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr.strip(), b'{"error":"file_not_found"}')

    def test_resource_limits(self):
        events = up([raw_frame(100, "p1", prio=3), advance(5000)])
        cases = (
            ((10, 1000000, 1000000, 1000000, 1000000), "config_limit"),
            ((1000000, 10, 1000000, 1000000, 1000000), "data_limit"),
            ((1000000, 1000000, 2, 1000000, 1000000), "item_limit"),
            ((1000000, 1000000, 1000000, 10, 1000000), "output_limit"),
        )
        for limits, error in cases:
            proc = run_cli(config(), events, *limits)
            self.assertEqual(proc.returncode, 5, (limits, error))
            self.assertEqual(proc.stdout, b"")
            self.assertEqual(
                proc.stderr.strip(),
                ('{"error":"%s"}' % error).encode("utf-8"),
            )

    def test_work_limit(self):
        events = up()
        proc = run_cli(
            config(), events, 1000000, 1000000, 1000000, 1000000, 1
        )
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(
            proc.stderr.strip(), b'{"error":"qos_pfc_work_limit"}'
        )

    def test_usage_arity(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = os.path.join(tmp, "c.json")
            evt = os.path.join(tmp, "e.json")
            with open(cfg, "w") as handle:
                handle.write(json.dumps(config()))
            with open(evt, "w") as handle:
                handle.write(json.dumps([]))
            for extra in (("1",), ("1", "2", "3"),
                          ("1", "2", "3", "4", "5", "6"), ("0", "9")):
                proc = subprocess.run(
                    [sys.executable, SWITCH, "qos-pfc-decode", cfg, evt,
                     *extra],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                self.assertEqual(
                    (proc.returncode, proc.stderr),
                    (2, b'{"error":"usage"}\n'),
                    extra,
                )


if __name__ == "__main__":
    unittest.main()
