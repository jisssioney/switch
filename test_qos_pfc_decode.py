#!/usr/bin/env python3
"""qos-pfc-decode 子命令回归：802.1Qbb 优先级流控的确定性仿真。

CONFIG 在 qos-wire-decode（端口模式/协商/queue_bytes/flow_control/老化/
最大帧 + 顶层 qos）基础上，每口再声明 pfc（0..7 的严格递增数组，空数组
表示不支持）；事件仍仅接受 link/advance/{t,port,data} 原始帧。目的 MAC
01:80:c2:00:00:01、以太类型 0x8808、操作码 0x0101 的未标记好帧按 PFC
处理：恰 64 字节、class-enable 两字节、八优先级各两字节 quanta、保留
字节全零；置位优先级非零 quanta 设截止时刻，零值清除；队列暂停至全局
PAUSE 与映射到该队列的有效 PFC 截止时刻最大值，在发帧不被抢占。

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
PAUSE_DST = "01:80:c2:00:00:01"
ALL_PFC = list(range(8))


def port(name, pvid=1, mode="trunk", rates=None, modes=None,
         queue_bytes=1000000, flow_control=True, pfc=None):
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
        "pfc": list(ALL_PFC) if pfc is None else pfc,
    }


def qos(mode="sp", weights=None, drop="tail", cap=100000,
        mapping=None):
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


def pfc_event(t, p, enabled, quanta, src=MAC1, reserved=b""):
    """构造 PFC 帧：enabled 为置位优先级列表，quanta 为八项整数列表。"""
    class_enable = 0
    for priority in enabled:
        class_enable |= 1 << (7 - priority)
    body = bytearray(
        mac_bytes(PAUSE_DST) + mac_bytes(src) + b"\x88\x08"
        + (0x0101).to_bytes(2, "big")
        + class_enable.to_bytes(2, "big")
    )
    assert len(quanta) == 8
    for q in quanta:
        body += q.to_bytes(2, "big")
    tail = bytearray(26)
    tail[0:len(reserved)] = reserved
    body += tail
    assert len(body) == 60
    fcs = (zlib.crc32(bytes(body)) & 0xFFFFFFFF).to_bytes(4, "little")
    return {"t": t, "port": p, "data": (bytes(body) + fcs).hex()}


def pause_event(t, p, quanta, src=MAC1):
    body = (
        mac_bytes(PAUSE_DST) + mac_bytes(src) + b"\x88\x08"
        + (1).to_bytes(2, "big") + quanta.to_bytes(2, "big") + b"\x00" * 42
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


def pfc_results(out):
    return [r for r in out["results"] if r.get("action") == "pfc"]


WIRE_TAGGED = 88
DUR = WIRE_TAGGED * 8  # 1000 Mbps 下 704 ns


class PfcFrameRecognitionTests(unittest.TestCase):
    def test_valid_pfc_emits_entries_ascending(self):
        events = [
            link(0, "p1"), link(0, "p2"),
            pfc_event(100, "p1", [3, 0, 6],
                      [5, 0, 0, 7, 0, 0, 9, 0]),
            advance(100000),
        ]
        out = run(config(), events)
        recs = pfc_results(out)
        self.assertEqual(len(recs), 1)
        rec = recs[0]
        self.assertEqual(rec["port"], "p1")
        # 置位项按优先级升序；until = t + ceil(quanta*512000/1000)
        self.assertEqual(
            rec["priorities"],
            [
                {"priority": 0, "quanta": 5, "until": 2660},
                {"priority": 3, "quanta": 7, "until": 3684},
                {"priority": 6, "quanta": 9, "until": 4708},
            ],
        )
        p1 = out["ports"][0]
        self.assertEqual(p1["pfc_frames"], 1)
        self.assertEqual(p1["pfc_unsupported_frames"], 0)
        self.assertEqual(p1["rx_frames"], 1)  # PFC 计入接收
        # PFC 帧不学习、不转发、不入队
        self.assertEqual(
            [r for r in out["results"] if "class" in r], []
        )
        self.assertTrue(all(q["frames"] == 0 for q in p1["queues"]))

    def test_unset_bits_absent_zero_quanta_until_null(self):
        events = [
            link(0, "p1"), link(0, "p2"),
            pfc_event(100, "p1", [0, 2], [0, 0, 0, 0, 0, 0, 0, 0]),
        ]
        out = run(config(), events)
        self.assertEqual(
            pfc_results(out)[0]["priorities"],
            [
                {"priority": 0, "quanta": 0, "until": None},
                {"priority": 2, "quanta": 0, "until": None},
            ],
        )

    def test_nonzero_reserved_is_malformed(self):
        events = [
            link(0, "p1"), link(0, "p2"),
            raw_frame(100, "p1"),
            raw_frame(110, "p1", src="00:00:00:00:00:02"),
            pfc_event(200, "p2", [0], [5, 0, 0, 0, 0, 0, 0, 0],
                      reserved=b"\x01"),
            advance(100000),
        ]
        out = run(config(), events)
        actions = [r.get("action") for r in out["results"] if "action" in r]
        self.assertIn("malformed_pfc", actions)
        self.assertNotIn("pfc", actions)
        p2 = out["ports"][1]
        self.assertEqual(p2["pfc_frames"], 0)
        self.assertEqual(p2["pfc_unsupported_frames"], 0)
        self.assertEqual(p2["pfc_duration_ns"], [0] * 8)
        # 计时器不变：等待副本紧随在发帧，不被夹时刻
        self.assertEqual([r["start"] for r in tx(out)], [100, 100 + DUR])

    def test_wrong_length_good_pfc_is_malformed(self):
        # 66 字节好帧、PFC 操作码：长度不为 64 -> malformed_pfc
        class_enable = 1 << 7
        body = bytearray(
            mac_bytes(PAUSE_DST) + mac_bytes(MAC1) + b"\x88\x08"
            + (0x0101).to_bytes(2, "big")
            + class_enable.to_bytes(2, "big")
        )
        for q in [5] + [0] * 7:
            body += q.to_bytes(2, "big")
        body += b"\x00" * 30  # 16+16+30 = 62，+4 FCS = 66 字节
        fcs = (zlib.crc32(bytes(body)) & 0xFFFFFFFF).to_bytes(4, "little")
        bad = {"t": 100, "port": "p1",
               "data": (bytes(body) + fcs).hex()}
        out = run(config(), [link(0, "p1"), link(0, "p2"), bad])
        self.assertEqual(
            [r.get("action") for r in out["results"] if "action" in r],
            ["malformed_pfc"],
        )

    def test_runt_pfc_shape_classified_as_runt(self):
        # 短帧即使操作码为 0x0101 也按既有短帧规则分类
        class_enable = 1 << 7
        body = bytearray(
            mac_bytes(PAUSE_DST) + mac_bytes(MAC1) + b"\x88\x08"
            + (0x0101).to_bytes(2, "big")
            + class_enable.to_bytes(2, "big")
        )
        body += b"\x00" * 20  # 16+16+20 = 52，+4 FCS = 56 字节 -> runt
        fcs = (zlib.crc32(bytes(body)) & 0xFFFFFFFF).to_bytes(4, "little")
        bad = {"t": 100, "port": "p1",
               "data": (bytes(body) + fcs).hex()}
        out = run(config(), [link(0, "p1"), link(0, "p2"), bad])
        classes = [r["class"] for r in out["results"] if "class" in r]
        self.assertEqual(classes, ["runt"])
        self.assertEqual(pfc_results(out), [])

    def test_bad_fcs_pfc_shape_is_bad_fcs(self):
        good = pfc_event(100, "p1", [0], [5, 0, 0, 0, 0, 0, 0, 0])
        raw = bytearray(bytes.fromhex(good["data"]))
        raw[-1] ^= 0xFF
        bad = {"t": 100, "port": "p1", "data": bytes(raw).hex()}
        out = run(config(), [link(0, "p1"), link(0, "p2"), bad])
        classes = [r["class"] for r in out["results"] if "class" in r]
        self.assertEqual(classes, ["bad_fcs"])

    def test_tagged_pfc_shape_is_data_frame(self):
        # 单层 802.1Q 标签把以太类型推后：不识别为控制帧，按数据帧洪泛
        tci = (0 << 13) | 1
        body = (
            mac_bytes(PAUSE_DST) + mac_bytes(MAC1) + b"\x81\x00"
            + tci.to_bytes(2, "big") + b"\x88\x08"
            + (0x0101).to_bytes(2, "big") + b"\x00" * 42
        )
        fcs = (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little")
        tagged = {"t": 100, "port": "p1", "data": (body + fcs).hex()}
        out = run(config(), [link(0, "p1"), link(0, "p2"), tagged])
        decisions = [r for r in out["results"] if "class" in r]
        self.assertEqual(decisions[-1]["action"], "flood")
        self.assertEqual(pfc_results(out), [])

    def test_pause_opcode_still_global_pause(self):
        events = [
            link(0, "p1"), link(0, "p2"),
            pause_event(100, "p1", 10), advance(100000),
        ]
        out = run(config(), events)
        recs = [r for r in out["results"] if r.get("action") == "pause"]
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["until"], 5220)
        self.assertEqual(out["ports"][0]["pause_frames"], 1)
        self.assertEqual(out["ports"][0]["pfc_frames"], 0)


class PfcUnsupportedTests(unittest.TestCase):
    def test_half_duplex_unsupported(self):
        ports = [port("p1", modes=["half"]), port("p2")]
        events = [
            link(0, "p1", modes=("half",)), link(0, "p2"),
            pfc_event(100, "p1", [0], [5, 0, 0, 0, 0, 0, 0, 0]),
        ]
        out = run(config(ports=ports), events)
        self.assertEqual(
            [r.get("action") for r in out["results"] if "action" in r],
            ["pfc_unsupported"],
        )
        p1 = out["ports"][0]
        self.assertEqual(p1["pfc_frames"], 1)
        self.assertEqual(p1["pfc_unsupported_frames"], 1)
        self.assertEqual(p1["pfc_duration_ns"], [0] * 8)

    def test_half_transmitting_pfc_unsupported_not_collision(self):
        ports = [port("p1", modes=["half"]), port("p2", modes=["half"])]
        events = [
            link(0, "p1", modes=("half",)), link(0, "p2", modes=("half",)),
            raw_frame(100, "p2"),
            pfc_event(200, "p1", [0], [5, 0, 0, 0, 0, 0, 0, 0]),
            advance(100000),
        ]
        out = run(config(ports=ports), events)
        self.assertFalse(
            any(r.get("reason") == "collision" for r in out["results"])
        )
        self.assertTrue(
            any(r.get("action") == "pfc_unsupported"
                for r in out["results"])
        )

    def test_link_down_unsupported(self):
        out = run(
            config(),
            [pfc_event(100, "p1", [0], [5, 0, 0, 0, 0, 0, 0, 0])],
        )
        self.assertTrue(
            any(r.get("action") == "pfc_unsupported"
                for r in out["results"])
        )

    def test_empty_pfc_array_unsupported(self):
        ports = [port("p1", pfc=[]), port("p2")]
        events = [
            link(0, "p1"), link(0, "p2"),
            pfc_event(100, "p1", [0], [5, 0, 0, 0, 0, 0, 0, 0]),
        ]
        out = run(config(ports=ports), events)
        self.assertTrue(
            any(r.get("action") == "pfc_unsupported"
                for r in out["results"])
        )

    def test_disabled_priority_unsupported_whole_frame(self):
        # p1 仅允许优先级 1、3；帧置位 3 与 4 -> 整帧不生效
        ports = [port("p1", pfc=[1, 3]), port("p2")]
        events = [
            link(0, "p1"), link(0, "p2"),
            pfc_event(100, "p1", [3, 4],
                      [0, 0, 0, 7, 9, 0, 0, 0]),
        ]
        out = run(config(ports=ports), events)
        self.assertEqual(pfc_results(out), [])
        self.assertTrue(
            any(r.get("action") == "pfc_unsupported"
                for r in out["results"])
        )
        self.assertEqual(out["ports"][0]["pfc_duration_ns"], [0] * 8)


class PfcSchedulingTests(unittest.TestCase):
    def test_deadline_clamps_mapped_waiting_copy(self):
        events = [
            link(0, "p1"), link(0, "p2"),
            raw_frame(100, "p1", prio=0),
            raw_frame(110, "p1", src="00:00:00:00:00:02", prio=0),
            pfc_event(150, "p2", [0], [5, 0, 0, 0, 0, 0, 0, 0]),
            advance(100000),
        ]
        out = run(config(), events)
        records = tx(out)
        # until = 150+2560 = 2710；在发帧 100..804 不动，等待副本夹到 2710
        self.assertEqual(records[0]["start"], 100)
        self.assertEqual(records[1]["start"], 2710)
        p2 = out["ports"][1]
        self.assertEqual(p2["pfc_frames"], 1)
        # 实际阻塞：发送线 804 空出至 2710
        self.assertEqual(p2["pfc_duration_ns"][0], 2710 - 804)
        self.assertEqual(sum(p2["pfc_duration_ns"]), 2710 - 804)

    def test_rate_scales_deadline(self):
        ports = [port("p1", rates=[100]), port("p2", rates=[100])]
        events = [
            link(0, "p1", rates=(100,)), link(0, "p2", rates=(100,)),
            pfc_event(100, "p1", [0], [5, 0, 0, 0, 0, 0, 0, 0]),
        ]
        out = run(config(ports=ports), events)
        self.assertEqual(pfc_results(out)[0]["priorities"][0]["until"],
                         100 + 25600)

    def test_zero_quanta_clears_deadline(self):
        events = [
            link(0, "p1"), link(0, "p2"),
            raw_frame(100, "p1"),
            raw_frame(110, "p1", src="00:00:00:00:00:02"),
            pfc_event(200, "p2", [0], [100, 0, 0, 0, 0, 0, 0, 0]),
            pfc_event(300, "p2", [0], [0, 0, 0, 0, 0, 0, 0, 0]),
            advance(100000),
        ]
        out = run(config(), events)
        self.assertEqual(
            [r["start"] for r in tx(out)], [100, 100 + DUR]
        )
        clear = pfc_results(out)[1]
        self.assertEqual(
            clear["priorities"], [{"priority": 0, "quanta": 0,
                                   "until": None}]
        )
        # 截止时刻在到期前被清除：无显式阻塞区间
        self.assertEqual(out["ports"][1]["pfc_duration_ns"][0], 0)

    def test_shorter_deadline_overwrites(self):
        events = [
            link(0, "p1"), link(0, "p2"),
            raw_frame(100, "p1"),
            raw_frame(110, "p1", src="00:00:00:00:00:02"),
            pfc_event(200, "p2", [0], [100, 0, 0, 0, 0, 0, 0, 0]),
            pfc_event(300, "p2", [0], [2, 0, 0, 0, 0, 0, 0, 0]),
            advance(100000),
        ]
        out = run(config(), events)
        recs = pfc_results(out)
        self.assertEqual([r["priorities"][0]["until"] for r in recs],
                         [51400, 1324])
        self.assertEqual([r["start"] for r in tx(out)], [100, 1324])

    def test_unset_priority_unchanged(self):
        events = [
            link(0, "p1"), link(0, "p2"),
            raw_frame(100, "p1"),
            raw_frame(110, "p1", src="00:00:00:00:00:02"),
            # 仅置位 0；队列 3 的副本不受影响
            pfc_event(150, "p2", [0], [100, 0, 0, 0, 0, 0, 0, 0]),
            raw_frame(160, "p1", src="00:00:00:00:00:03", prio=3),
            advance(100000),
        ]
        out = run(config(), events)
        # SP 下：p0 在发 [100,804)；p0 等待副本被夹到 51350；
        # p3 副本在 804 优先发送
        self.assertEqual([r["queue"] for r in tx(out)], [0, 3, 0])
        self.assertEqual([r["start"] for r in tx(out)],
                         [100, 804, 51350])

    def test_queue_holds_max_of_pause_and_pfc(self):
        events = [
            link(0, "p1"), link(0, "p2"),
            raw_frame(100, "p1"),
            raw_frame(110, "p1", src="00:00:00:00:00:02"),
            # 全局 PAUSE 至 5320，PFC p0 至 2710 -> 队列 0 停到 5320
            pause_event(200, "p2", 10),
            pfc_event(250, "p2", [0], [5, 0, 0, 0, 0, 0, 0, 0]),
            advance(100000),
        ]
        out = run(config(), events)
        self.assertEqual([r["start"] for r in tx(out)], [100, 5320])

        # 反向：PFC 截止时刻晚于全局 PAUSE
        events = [
            link(0, "p1"), link(0, "p2"),
            raw_frame(100, "p1"),
            raw_frame(110, "p1", src="00:00:00:00:00:02"),
            pause_event(200, "p2", 2),       # 至 1224
            pfc_event(250, "p2", [0], [20, 0, 0, 0, 0, 0, 0, 0]),  # 至 10490
            advance(100000),
        ]
        out = run(config(), events)
        self.assertEqual([r["start"] for r in tx(out)], [100, 10490])

    def test_priorities_sharing_queue_take_max(self):
        # 8 个优先级全部映射到队列 0：p0 与 p1 的截止时刻取最大
        mapping = [0] * 8
        events = [
            link(0, "p1"), link(0, "p2"),
            raw_frame(100, "p1"),
            raw_frame(110, "p1", src="00:00:00:00:00:02", prio=1),
            pfc_event(200, "p2", [0, 1],
                      [5, 9, 0, 0, 0, 0, 0, 0]),  # 2760 / 4820
            advance(100000),
        ]
        out = run(config(q=qos(mapping=mapping)), events)
        self.assertEqual([r["start"] for r in tx(out)], [100, 4808])

    def test_pfc_independent_of_flow_control_flag(self):
        # 802.1Qbb 只看 pfc 允许列表，flow_control=False 不影响 PFC
        ports = [port("p1", flow_control=False), port("p2")]
        events = [
            link(0, "p1"), link(0, "p2"),
            pfc_event(100, "p1", [0], [5, 0, 0, 0, 0, 0, 0, 0]),
        ]
        out = run(config(ports=ports), events)
        self.assertEqual(len(pfc_results(out)), 1)

    def test_sp_resumes_after_pfc_expiry(self):
        events = [
            link(0, "p1"), link(0, "p2"),
            raw_frame(100, "p1", prio=0),
            raw_frame(101, "p1", src="00:00:00:00:00:09", prio=0),
            pfc_event(150, "p2", [0], [5, 0, 0, 0, 0, 0, 0, 0]),
            raw_frame(200, "p1", src="00:00:00:00:00:02", prio=3),
            advance(100000),
        ]
        out = run(config(), events)
        # p0 在发 [100,804)；随后 SP 先发 p3（804），p0 等待副本等到 2710
        self.assertEqual([r["queue"] for r in tx(out)], [0, 3, 0])
        starts = [r["start"] for r in tx(out)]
        self.assertEqual(starts, [100, 804, 2710])

    def test_wrr_resumes_after_pfc_expiry(self):
        events = [
            link(0, "p1"), link(0, "p2"),
            raw_frame(100, "p1", prio=0),
            raw_frame(101, "p1", src="00:00:00:00:00:09", prio=0),
            raw_frame(102, "p1", src="00:00:00:00:00:02", prio=3),
            pfc_event(150, "p2", [0], [5, 0, 0, 0, 0, 0, 0, 0]),
            advance(100000),
        ]
        out = run(config(q=qos(mode="wrr")), events)
        # p0 在发 [100,804)；其完成后续用 WRR 发 p3（804）；p0 等到 2710
        self.assertEqual([r["queue"] for r in tx(out)], [0, 3, 0])
        self.assertEqual([r["start"] for r in tx(out)], [100, 804, 2710])

    def test_duration_settled_by_advance_only(self):
        # 末事件不 advance 到截止时刻之后：阻塞区间不结算（仅在显式时钟）
        events = [
            link(0, "p1"), link(0, "p2"),
            raw_frame(100, "p1"),
            pfc_event(150, "p2", [0], [100, 0, 0, 0, 0, 0, 0, 0]),
            advance(1000),  # 远早于 51350
        ]
        out = run(config(), events)
        self.assertEqual(out["ports"][1]["pfc_duration_ns"][0], 1000 - 804)
        # 再推进到截止时刻之后：剩余区间完整入账
        events.append(advance(100000))
        out = run(config(), events)
        self.assertEqual(out["ports"][1]["pfc_duration_ns"][0],
                         51350 - 804)

    def test_link_down_clears_pfc(self):
        events = [
            link(0, "p1"), link(0, "p2"),
            pfc_event(100, "p2", [0], [100, 0, 0, 0, 0, 0, 0, 0]),
            {"t": 200, "port": "p2", "admin": False, "peer": True,
             "rates": [1000], "modes": ["full"]},
        ]
        out = run(config(), events)
        p2 = out["ports"][1]
        # 截止时刻随链路离开 up 清除；截至 down 事件时钟的实际阻塞区间
        # （100..200）已按显式时钟入账，其余优先级始终为 0
        self.assertEqual(p2["pfc_duration_ns"], [100, 0, 0, 0, 0, 0, 0, 0])


class OutputContractTests(unittest.TestCase):
    def test_fixed_key_orders(self):
        events = [
            link(0, "p1"), link(0, "p2"),
            pfc_event(100, "p1", [0, 3],
                      [5, 0, 0, 7, 0, 0, 0, 0]),
        ]
        proc = run_cli(config(), events)
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
        self.assertEqual(
            list(pfc_results(doc)[0]),
            ["t", "port", "action", "priorities"],
        )
        self.assertEqual(
            list(pfc_results(doc)[0]["priorities"][0]),
            ["priority", "quanta", "until"],
        )
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b": ", raw)

    def test_deterministic(self):
        events = [
            link(0, "p1"), link(0, "p2"),
            raw_frame(100, "p1"),
            pfc_event(150, "p2", [0, 3],
                      [5, 0, 0, 7, 0, 0, 0, 0]),
            raw_frame(200, "p1", src="00:00:00:00:00:02", prio=3),
            advance(90000),
        ]
        a = run_cli(config(), events).stdout
        b = run_cli(config(), events).stdout
        self.assertEqual(a, b)


class ValidationAndResourceTests(unittest.TestCase):
    def test_bad_pfc_field(self):
        bad_values = [
            [8], [-1], [1, 1], [2, 1], True, 3, "01",
            [0, 1.5], [None],
        ]
        for value in bad_values:
            doc = config(ports=[port("p1", pfc=value), port("p2")])
            proc = run_cli(doc, [])
            self.assertEqual(proc.returncode, 4, value)
            self.assertEqual(proc.stdout, b"", value)

    def test_pfc_wrong_field_set(self):
        base = config()
        doc = json.loads(json.dumps(base))
        del doc["ports"][0]["pfc"]
        proc = run_cli(doc, [])
        self.assertEqual(proc.returncode, 4)
        doc = json.loads(json.dumps(base))
        doc["ports"][0]["pfc_extra"] = []
        proc = run_cli(doc, [])
        self.assertEqual(proc.returncode, 4)

    def test_empty_pfc_array_valid(self):
        doc = config(ports=[port("p1", pfc=[]), port("p2", pfc=[])])
        proc = run_cli(doc, [])
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_service_event_invalid(self):
        proc = run_cli(config(), [link(0, "p1"),
                                  {"t": 1, "port": "p2", "count": 1}])
        self.assertEqual(proc.returncode, 4)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr.strip(), b'{"error":"invalid_input"}')

    def test_file_not_found(self):
        proc = subprocess.run(
            [sys.executable, SWITCH, "qos-pfc-decode", "/nope/c", "/nope/e"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr.strip(), b'{"error":"file_not_found"}')

    def test_resource_limits(self):
        events = [
            link(0, "p1"), link(0, "p2"),
            pfc_event(100, "p1", [0], [5, 0, 0, 0, 0, 0, 0, 0]),
        ]
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
        events = [link(0, "p1"), link(0, "p2"),
                  pfc_event(100, "p1", [0], [5, 0, 0, 0, 0, 0, 0, 0])]
        proc = run_cli(
            config(), events, 1000000, 1000000, 1000000, 1000000, 2
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
