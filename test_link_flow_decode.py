#!/usr/bin/env python3
"""link-flow-decode 子命令回归。

link-flow-decode 使用 link-wire-decode 的配置与混合事件（link/advance/
{t,port,data} 原始帧、显式时钟、queue_bytes），但每口额外声明布尔
flow_control。合法 PAUSE 帧（未带标签、目的 01:80:c2:00:00:01、类型
0x8808、操作码 0x0001、长度 64、保留字节全零、FCS 正确）在入端口本地
终止：不学习、不参与 VLAN 转发；端口 up/full 且启用流控时暂停发送到
t+ceil(quanta*512000/rate)，已开始帧继续完成，未开始副本整体后移且
顺序不变，新副本接队尾，非零覆盖、零值在当前帧完成后恢复，链路离开
up 清除暂停；否则 pause_unsupported 且不改队列；控制帧非法输出
malformed_pause。坏 FCS/短帧/超长帧沿用既有分类优先级。

仅用标准库；端到端驱动 `python switch.py link-flow-decode CONFIG EVENTS`。
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
PAUSE_DST = "01:80:c2:00:00:01"
MAC1 = "00:00:00:00:00:01"
MAC2 = "00:00:00:00:00:02"


def port(name, pvid=1, allowed=None, untagged=None, mode="access",
         rates=None, modes=None, queue_bytes=1000000, flow_control=True):
    if allowed is None:
        allowed = [pvid] if mode == "access" else sorted(
            set([pvid] + (untagged or []))
        )
    if untagged is None:
        untagged = [pvid] if mode == "access" else []
    return {
        "name": name,
        "mode": mode,
        "pvid": pvid,
        "allowed": allowed,
        "untagged": untagged,
        "rates": [10, 100, 1000, 10000] if rates is None else rates,
        "modes": ["half", "full"] if modes is None else modes,
        "queue_bytes": queue_bytes,
        "flow_control": flow_control,
    }


def config(ports=None, age=100, max_frame=1518, delay=10):
    return {
        "ports": ports if ports is not None else [port("p1"), port("p2")],
        "age": age,
        "max_frame": max_frame,
        "delay": delay,
    }


def link(t, p, admin=True, peer=True, rates=None, modes=None):
    return {
        "t": t,
        "port": p,
        "admin": admin,
        "peer": peer,
        "rates": [10, 100, 1000, 10000] if rates is None else rates,
        "modes": ["half", "full"] if modes is None else modes,
    }


def advance(t):
    return {"t": t, "advance": True}


def mac_bytes(mac):
    return bytes(int(part, 16) for part in mac.split(":"))


def raw_frame(t, p, dst=BCAST, src=MAC1, ethertype=0x0800, payload=b"",
              fcs_good=True):
    body = mac_bytes(dst) + mac_bytes(src) + ethertype.to_bytes(2, "big") \
        + payload
    fcs = (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little")
    if not fcs_good:
        fcs = b"\xff\xff\xff\xff"
    return {"t": t, "port": p, "data": (body + fcs).hex()}


def data_event(t, p, dst=BCAST, src=MAC2, payload_len=46):
    return raw_frame(
        t, p, dst, src, 0x0800, b"\x00" * payload_len, True
    )


def pause_event(t, p, quanta, opcode=0x0001, reserved_byte=0, pad=42):
    body = (
        mac_bytes(PAUSE_DST) + mac_bytes(MAC1) + b"\x88\x08"
        + opcode.to_bytes(2, "big") + quanta.to_bytes(2, "big")
        + bytes([reserved_byte]) * pad
    )
    fcs = (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little")
    return {"t": t, "port": p, "data": (body + fcs).hex()}


def raw_pause_event(t, p, body_no_fcs):
    fcs = (zlib.crc32(body_no_fcs) & 0xFFFFFFFF).to_bytes(4, "little")
    return {"t": t, "port": p, "data": (body_no_fcs + fcs).hex()}


def _pause_prefix():
    return mac_bytes(PAUSE_DST) + mac_bytes(MAC1) + b"\x88\x08"


def pause_body_opcode(opcode, quanta=10, pad=42):
    return _pause_prefix() + opcode.to_bytes(2, "big") \
        + quanta.to_bytes(2, "big") + b"\x00" * pad


def pause_body_reserved(value, quanta=10, pad=42):
    return _pause_prefix() + b"\x00\x01" + quanta.to_bytes(2, "big") \
        + bytes([value]) * pad


def pause_body_len(total_with_fcs, quanta=10, reserved=0):
    # 返回总长 total_with_fcs 的帧体（不含 FCS），保持目的/类型/操作码
    target_body = total_with_fcs - 4
    fixed = _pause_prefix() + b"\x00\x01" + quanta.to_bytes(2, "big")
    return fixed + bytes([reserved]) * (target_body - len(fixed))


def write_inputs(config_doc, events):
    tmp = tempfile.mkdtemp()
    cfg = os.path.join(tmp, "config.json")
    evt = os.path.join(tmp, "events.json")
    with open(cfg, "wb") as handle:
        handle.write(json.dumps(config_doc).encode("utf-8"))
    with open(evt, "wb") as handle:
        handle.write(json.dumps(events).encode("utf-8"))
    return tmp, cfg, evt


def run_cli(config_doc, events, *limits):
    tmp, cfg, evt = write_inputs(config_doc, events)
    proc = subprocess.run(
        [sys.executable, SWITCH, "link-flow-decode", cfg, evt,
         *[str(x) for x in limits]],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    missing = subprocess.run(
        [sys.executable, SWITCH, "link-flow-decode",
         os.path.join(tmp, "nope.json"), evt],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return proc, missing


def run_flow(config_doc, events, *limits):
    proc, _ = run_cli(config_doc, events, *limits)
    assert proc.returncode == 0, (
        proc.returncode, proc.stderr.decode("utf-8")
    )
    return json.loads(proc.stdout.decode("utf-8"))


def up_pair(**port_kw):
    ports = [
        port("p1", rates=[1000], modes=["full"], **port_kw),
        port("p2", rates=[1000], modes=["full"], **port_kw),
    ]
    return config(ports, delay=10), [link(0, "p1"), link(0, "p2")]


class PauseBasicTests(unittest.TestCase):
    def test_pause_terminates_locally_no_flood(self):
        # PAUSE 从 p1 入站：结果为 pause，不产生 class/flood，p2 不收
        cfg, ev = up_pair()
        out = run_flow(cfg, ev + [pause_event(100, "p1", 10),
                                 advance(1000000)])
        pause_results = [r for r in out["results"]
                         if r.get("action") == "pause"]
        self.assertEqual(len(pause_results), 1)
        self.assertNotIn("class", pause_results[0])
        self.assertEqual(pause_results[0]["port"], "p1")
        self.assertEqual(pause_results[0]["quanta"], 10)
        # until = 100 + ceil(10*512000/1000) = 100 + 5120
        self.assertEqual(pause_results[0]["until"], 5220)
        classes = [r for r in out["results"] if "class" in r]
        self.assertEqual(classes, [])
        p1, p2 = out["ports"]
        self.assertEqual(p1["pause_frames"], 1)
        self.assertEqual(p1["rx_frames"], 1)  # PAUSE 计入接收
        self.assertEqual(p2["rx_frames"], 0)
        # 无发送但暂停窗口完整生效：实际暂停时长 = until - t = 5120
        self.assertEqual(p1["pause_duration_ns"], 5120)

    def test_quanta_zero_emits_null_until(self):
        cfg, ev = up_pair()
        out = run_flow(cfg, ev + [pause_event(100, "p1", 0)])
        rec = next(r for r in out["results"] if r.get("action") == "pause")
        self.assertEqual(rec["quanta"], 0)
        self.assertIsNone(rec["until"])
        self.assertEqual(out["ports"][0]["pause_frames"], 1)

    def test_pause_does_not_learn_source_mac(self):
        # PAUSE 源 MAC1（自 p1）不得学习：随后 p2 发目的 MAC1 的单播帧应
        # 洪泛（未知单播），而非定向到 p1
        cfg, ev = up_pair()
        events = ev + [
            pause_event(100, "p1", 0),
            raw_frame(200, "p2", MAC1, MAC2, 0x0800, b"\x00" * 46),
        ]
        out = run_flow(cfg, events)
        decisions = [r for r in out["results"] if "class" in r]
        self.assertEqual(decisions[-1]["action"], "flood")
        self.assertEqual([x["name"] for x in decisions[-1]["ports"]], ["p1"])

    def test_pause_shifts_queued_keeps_inflight(self):
        # 数据自 p2 入站洪泛到 p1（84 线字节，速率 1000 -> 672ns）。
        # t=100 第一帧，p1 在发 [100,772)；t=200 PAUSE quanta=10 至 5320：
        # 已开始帧 772 完成不动；t=300 第二帧副本后移到 5320 开始。
        cfg, ev = up_pair()
        events = ev + [
            data_event(100, "p2"),
            pause_event(200, "p1", 10),
            data_event(300, "p2"),
            advance(1000000),
        ]
        out = run_flow(cfg, events)
        comps = [r for r in out["results"] if "start" in r]
        self.assertEqual([(r["t"], r["start"], r["bytes"]) for r in comps],
                         [(772, 100, 84), (5992, 5320, 84)])
        p1 = out["ports"][0]
        # 实际暂停时长：在发帧 772 完成起等待到 5320
        self.assertEqual(p1["pause_duration_ns"], 5320 - 772)

    def test_nonzero_overwrites_deadline(self):
        # quanta=100（至 51400）后再 quanta=2（至 1424）：截止时刻被覆盖为
        # 更小值；队列副本按新截止时刻重排，实际暂停时长到 1424 为止。
        cfg, ev = up_pair()
        events = ev + [
            data_event(100, "p2"),
            pause_event(200, "p1", 100),
            data_event(300, "p2"),
            pause_event(400, "p1", 2),
            advance(1000000),
        ]
        out = run_flow(cfg, events)
        recs = [r for r in out["results"] if r.get("action") == "pause"]
        self.assertEqual([r["until"] for r in recs], [51400, 1424])
        comps = [r for r in out["results"] if "start" in r]
        # 在发帧 772 完成；第二副本先被推到 51400，覆盖后拉回 1424（保序）
        self.assertEqual(comps[0]["start"], 100)
        self.assertEqual(comps[1]["start"], 1424)
        p1 = out["ports"][0]
        # 400 时刻在发帧仍未完成（772），首次实际推迟自 772 到 1424
        self.assertEqual(p1["pause_duration_ns"], 1424 - 772)

    def test_zero_resumes_after_current_frame(self):
        # 长暂停后零值：未开始副本提前到在发帧完成之后，暂停即解除。
        cfg, ev = up_pair()
        events = ev + [
            data_event(100, "p2"),
            pause_event(200, "p1", 1000),
            data_event(300, "p2"),
            pause_event(400, "p1", 0),
            advance(1000000),
        ]
        out = run_flow(cfg, events)
        recs = [r for r in out["results"] if r.get("action") == "pause"]
        self.assertEqual([r["until"] for r in recs], [512200, None])
        comps = [r for r in out["results"] if "start" in r]
        self.assertEqual(comps[0]["start"], 100)   # 在发帧不动
        self.assertEqual(comps[1]["start"], 772)  # 零值后紧随在发帧
        p1 = out["ports"][0]
        # 该窗口无副本在 200..772 等待（在发帧始终在发），实际暂停时长 0
        self.assertEqual(p1["pause_duration_ns"], 0)

    def test_new_copy_appends_behind_adjusted_tail(self):
        # PAUSE 后两副本都被推到截止时刻之后；第三副本接在调整后的队尾。
        cfg, ev = up_pair()
        events = ev + [
            data_event(100, "p2"),
            pause_event(200, "p1", 100),
            data_event(300, "p2"),
            data_event(400, "p2"),
            advance(1000000),
        ]
        out = run_flow(cfg, events)
        comps = [r for r in out["results"] if "start" in r]
        starts = [r["start"] for r in comps]
        self.assertEqual(starts[0], 100)
        self.assertEqual(starts[1], 51400)
        self.assertEqual(starts[2], 51400 + 672)

    def test_advance_settles_pause_expiry_and_tx(self):
        # advance 到截止时刻之前不结算，之后结算发送完成；末事件后不排空。
        cfg, ev = up_pair()
        events = ev + [
            data_event(100, "p2"),
            pause_event(200, "p1", 10),
            data_event(300, "p2"),
            advance(1000),  # 在发帧 772 完成，第二副本仍等到 5220
        ]
        out = run_flow(cfg, events)
        comps = [r for r in out["results"] if "start" in r]
        self.assertEqual(len(comps), 1)  # 仅在发帧完成，未自动排空
        out2 = run_flow(cfg, events + [advance(1000000)])
        self.assertEqual(len([r for r in out2["results"] if "start" in r]), 2)


class PauseUnsupportedTests(unittest.TestCase):
    def _unsupported(self, cfg, events, state_links=None):
        out = run_flow(config(cfg, delay=10) if isinstance(cfg, list) else cfg,
                       (state_links or []) + events)
        rec = next(r for r in out["results"]
                   if r.get("action") == "pause_unsupported")
        return rec, out

    def test_flow_control_disabled(self):
        cfg = config([
            port("p1", rates=[1000], modes=["full"], flow_control=False),
            port("p2", rates=[1000], modes=["full"]),
        ])
        rec, out = self._unsupported(cfg, [pause_event(100, "p1", 10)],
                                     [link(0, "p1"), link(0, "p2")])
        self.assertEqual(rec["port"], "p1")
        p1 = out["ports"][0]
        self.assertEqual(p1["pause_frames"], 1)
        self.assertEqual(p1["pause_unsupported_frames"], 1)
        self.assertEqual(p1["pause_duration_ns"], 0)

    def test_half_duplex(self):
        cfg = config([
            port("p1", rates=[1000], modes=["half"]),
            port("p2", rates=[1000], modes=["full"]),
        ])
        links = [link(0, "p1", modes=["half"]), link(0, "p2")]
        _, out = self._unsupported(cfg, [pause_event(100, "p1", 10)], links)
        self.assertEqual(out["ports"][0]["pause_unsupported_frames"], 1)

    def test_half_transmitting_pause_is_unsupported_not_collision(self):
        # half 口正在发送时收到 PAUSE：本地终止为 unsupported，不得像普通
        # 帧那样触发碰撞（在发副本必须正常完成、队列不变）
        cfg = config([
            port("p1", rates=[1000], modes=["half"]),
            port("p2", rates=[1000], modes=["full"]),
        ])
        links = [link(0, "p1", modes=["half"]), link(0, "p2")]
        events = links + [
            data_event(100, "p2"),
            pause_event(200, "p1", 10),
            advance(1000000),
        ]
        out = run_flow(cfg, events)
        self.assertFalse(any(r.get("reason") == "collision"
                             for r in out["results"]))
        self.assertTrue(any(r.get("action") == "pause_unsupported"
                            for r in out["results"]))
        # 在发副本正常完成
        self.assertEqual(out["ports"][0]["tx_frames"], 1)
        self.assertEqual(out["ports"][0]["collision_frames"], 0)

    def test_down_port(self):
        cfg = config()
        rec, out = self._unsupported(cfg, [pause_event(100, "p1", 10)])
        self.assertEqual(rec["port"], "p1")
        self.assertEqual(out["ports"][0]["pause_unsupported_frames"], 1)

    def test_wait_port(self):
        # 协商中（delay 未到）：状态 wait，仍消费为 unsupported
        cfg = config([
            port("p1", rates=[1000], modes=["full"]),
            port("p2", rates=[1000], modes=["full"]),
        ], delay=1000)
        links = [link(0, "p1"), link(0, "p2")]
        rec, out = self._unsupported(cfg, [pause_event(100, "p1", 10)], links)
        self.assertEqual(rec["port"], "p1")

    def test_does_not_touch_queue(self):
        cfg = config([
            port("p1", rates=[1000], modes=["full"], flow_control=False),
            port("p2", rates=[1000], modes=["full"]),
        ])
        links = [link(0, "p1"), link(0, "p2")]
        base = run_flow(cfg, links + [
            data_event(100, "p2"), data_event(300, "p2"), advance(1000000)])
        with_pause = run_flow(cfg, links + [
            data_event(100, "p2"), pause_event(200, "p1", 10),
            data_event(300, "p2"), advance(1000000)])
        base_comps = [r for r in base["results"] if "start" in r]
        paus_comps = [r for r in with_pause["results"] if "start" in r]
        self.assertEqual(base_comps, paus_comps)


class MalformedPauseTests(unittest.TestCase):
    def setUp(self):
        self.cfg, self.links = up_pair()

    def _run(self, body):
        out = run_flow(self.cfg, self.links + [raw_pause_event(100, "p1", body)])
        return out["results"], out["ports"][0]

    def test_bad_opcode(self):
        body = pause_body_opcode(0x0002)
        results, p1 = self._run(body)
        self.assertTrue(any(r.get("action") == "malformed_pause"
                            for r in results))
        self.assertEqual(p1["pause_frames"], 0)
        self.assertEqual(p1["pause_unsupported_frames"], 0)

    def test_bad_reserved(self):
        results, _ = self._run(pause_body_reserved(1))
        self.assertTrue(any(r.get("action") == "malformed_pause"
                            for r in results))

    def test_bad_length(self):
        # 合法 FCS、目的/类型正确，但长度非 64（这里 60 字节为 runt，按
        # 既有分类优先级应是 runt 而非 malformed_pause）
        results, _ = self._run(pause_body_len(60))
        self.assertTrue(any(r.get("class") == "runt" for r in results))
        self.assertFalse(any(r.get("action") == "malformed_pause"
                             for r in results))

    def test_good_length_bad_reserved_is_malformed_not_drop(self):
        # 64 字节且 FCS 正确，仅保留字节非零：malformed_pause
        results, p1 = self._run(pause_body_reserved(1, pad=42))
        rec = next(r for r in results if r.get("action"))
        self.assertEqual(rec["action"], "malformed_pause")
        self.assertEqual(p1["rx_frames"], 1)

    def test_non_64_good_fcs_length_is_malformed(self):
        # 68 字节、FCS 正确（非 runt/giant）：长度非法 -> malformed_pause
        results, p1 = self._run(pause_body_len(68))
        rec = next(r for r in results if r.get("action"))
        self.assertEqual(rec["action"], "malformed_pause")
        self.assertEqual(p1["pause_frames"], 0)


class ClassificationPriorityTests(unittest.TestCase):
    def setUp(self):
        self.cfg, self.links = up_pair()

    def test_bad_fcs_pause_dst_is_bad_fcs(self):
        # 恰 64 字节但 FCS 错误：bad_fcs 优先于 PAUSE 识别（非 good 不终止）
        ev = raw_frame(100, "p1", PAUSE_DST, MAC1, 0x8808,
                       b"\x00\x01\x00\x0a" + b"\x00" * 42, fcs_good=False)
        out = run_flow(self.cfg, self.links + [ev])
        self.assertTrue(any(r.get("class") == "bad_fcs"
                            for r in out["results"]))
        self.assertFalse(any("pause" in r.get("action", "")
                             for r in out["results"]))

    def test_runt_pause_dst_is_runt(self):
        body = pause_body_len(60)
        out = run_flow(self.cfg, self.links + [raw_pause_event(100, "p1", body)])
        self.assertTrue(any(r.get("class") == "runt"
                            for r in out["results"]))

    def test_giant_pause_dst_is_giant(self):
        body = pause_body_len(2000)
        out = run_flow(self.cfg, self.links + [raw_pause_event(100, "p1", body)])
        self.assertTrue(any(r.get("class") == "giant"
                            for r in out["results"]))

    def test_tagged_8808_is_not_pause_and_forwards(self):
        # 带 VLAN 标签的 0x8808 不是 PAUSE：正常学习转发
        dst = mac_bytes(PAUSE_DST) + mac_bytes(MAC1)
        head = dst + b"\x81\x00" + (1).to_bytes(2, "big") + b"\x88\x08"
        payload = b"\x00\x01\x00\x0a" + b"\x00" * 38
        body = head + payload
        fcs = (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little")
        ev = {"t": 100, "port": "p1", "data": (body + fcs).hex()}
        out = run_flow(self.cfg, self.links + [ev, advance(100000)])
        self.assertFalse(any(r.get("action", "").startswith("pause")
                             for r in out["results"]))
        self.assertTrue(any(r.get("class") == "good"
                            for r in out["results"]))

    def test_non_pause_ethertype_to_pause_mac_forwards(self):
        # 目的为慢协议 MAC 但类型不是 0x8808：普通数据帧
        ev = raw_frame(100, "p1", PAUSE_DST, MAC1, 0x0800, b"\x00" * 46)
        out = run_flow(self.cfg, self.links + [ev, advance(100000)])
        self.assertTrue(any(r.get("class") == "good"
                            for r in out["results"]))
        self.assertFalse(any("pause" in r.get("action", "")
                             for r in out["results"]))


class LinkStateTests(unittest.TestCase):
    def test_link_down_clears_pause_and_drops_copies(self):
        cfg, links = up_pair()
        events = links + [
            data_event(100, "p2"),
            pause_event(200, "p1", 1000),
            data_event(300, "p2"),
            link(400, "p1", admin=False),
        ]
        out = run_flow(cfg, events)
        downs = [r for r in out["results"]
                 if r.get("reason") == "link_down"]
        # 在发副本与被暂停推后 的副本均以 link_down 丢弃
        self.assertEqual(len(downs), 2)
        p1 = out["ports"][0]
        # 暂停曾生效区间：在发帧 772 起到 400 离 up（400 < 772 故为 0）
        self.assertEqual(p1["pause_frames"], 1)
        # 重新 up 后旧暂停不再影响发送
        events2 = events + [
            link(500, "p1"),
            data_event(2000, "p2"),
            advance(1000000),
        ]
        out2 = run_flow(cfg, events2)
        comps = [r for r in out2["results"] if "start" in r]
        # 重协商 delay=10，p1 于 510 up；2000 的副本自 2000 即可开始
        self.assertTrue(any(c["start"] == 2000 for c in comps))

    def test_pause_unsupported_after_link_down_still_consumed(self):
        cfg = config()
        out = run_flow(cfg, [pause_event(50, "p1", 10)])
        p1 = out["ports"][0]
        self.assertEqual(p1["pause_frames"], 1)
        self.assertEqual(p1["pause_unsupported_frames"], 1)


class OrderingAndStatsTests(unittest.TestCase):
    def test_same_time_port_order_advance_last(self):
        cfg = config()
        events = [
            advance(0), pause_event(0, "p2", 10),
            link(0, "p2"), link(0, "p1"),
        ]
        out = run_flow(cfg, events)
        states = [r["port"] for r in out["results"] if "state" in r]
        self.assertEqual(states, ["p1", "p2"])

    def test_result_key_order_fixed(self):
        cfg, links = up_pair()
        out = run_flow(cfg, links + [pause_event(100, "p1", 10)])
        rec = next(r for r in out["results"] if r.get("action") == "pause")
        self.assertEqual(list(rec), ["t", "port", "action", "quanta", "until"])
        proc, _ = run_cli(cfg, links + [pause_event(100, "p1", 10)])
        # 紧凑 JSON 中 pause 记录键序须固定
        self.assertIn(
            b'"action":"pause","quanta":10,"until":', proc.stdout
        )

    def test_port_stats_key_order(self):
        cfg, links = up_pair()
        out = run_flow(cfg, links + [pause_event(100, "p1", 10)])
        p1 = out["ports"][0]
        self.assertEqual(
            list(p1),
            [
                "name", "rx_frames", "rx_bytes", "tx_frames", "tx_bytes",
                "collision_frames", "collision_bytes",
                "queue_full_frames", "queue_full_bytes",
                "link_down_frames", "link_down_bytes",
                "pause_frames", "pause_unsupported_frames",
                "pause_duration_ns",
            ],
        )


class DeterminismTests(unittest.TestCase):
    def test_repeat_byte_identical(self):
        cfg, links = up_pair()
        events = links + [
            data_event(100, "p2"), pause_event(200, "p1", 10),
            data_event(300, "p2"), advance(1000000),
        ]
        proc_a, _ = run_cli(cfg, events)
        proc_b, _ = run_cli(cfg, events)
        self.assertEqual(proc_a.stdout, proc_b.stdout)


class ValidationTests(unittest.TestCase):
    def _assert4(self, cfg, events):
        proc, _ = run_cli(cfg, events)
        self.assertEqual(proc.returncode, 4, proc.stderr)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b'{"error":"invalid_input"}\n')

    def test_missing_flow_control_invalid(self):
        cfg_doc = config()
        for pdoc in cfg_doc["ports"]:
            del pdoc["flow_control"]
        self._assert4(cfg_doc, [])

    def test_non_bool_flow_control_invalid(self):
        cfg_doc = config()
        cfg_doc["ports"][0]["flow_control"] = "yes"
        self._assert4(cfg_doc, [])
        cfg_doc = config()
        cfg_doc["ports"][0]["flow_control"] = 1
        self._assert4(cfg_doc, [])

    def test_extra_port_key_invalid(self):
        cfg_doc = config()
        cfg_doc["ports"][0]["extra"] = True
        self._assert4(cfg_doc, [])

    def test_partial_flow_control_invalid(self):
        cfg_doc = config()
        del cfg_doc["ports"][1]["flow_control"]
        self._assert4(cfg_doc, [])

    def test_abstract_frame_shape_rejected(self):
        cfg = config()
        self._assert4(cfg, [
            link(0, "p1"),
            {"t": 100, "port": "p1", "src": MAC1, "dst": BCAST,
             "vlan": None, "length": 64, "fcs": True, "alignment": True},
        ])

    def test_data_shell_rules_still_apply(self):
        cfg = config()
        # PAUSE 形状但 hex 非法仍是整次输入错误
        good = pause_event(100, "p1", 10)
        self._assert4(cfg, [dict(good, data="zz")])
        # 未知端口
        self._assert4(cfg, [pause_event(0, "ghost", 10)])

    def test_t_not_monotonic(self):
        cfg = config()
        self._assert4(cfg, [pause_event(10, "p1", 1), pause_event(9, "p1", 1)])


class ResourceAndErrorTests(unittest.TestCase):
    def test_missing_file_exit3(self):
        cfg = config()
        _, missing = run_cli(cfg, [])
        self.assertEqual(missing.returncode, 3)
        self.assertEqual(missing.stdout, b"")
        self.assertIn(b"file_not_found", missing.stderr)

    def test_usage_exit2(self):
        tmp, cfg, evt = write_inputs(config(), [])
        for argv in (
            ["link-flow-decode", cfg],
            ["link-flow-decode", cfg, evt, "1"],
            ["link-flow-decode", cfg, evt, "0"],
        ):
            proc = subprocess.run(
                [sys.executable, SWITCH, *argv],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(proc.returncode, 2, argv)
            self.assertIn(b"usage", proc.stderr)

    def test_limits_exit5(self):
        cfg = config()
        events = [link(0, "p1"), link(1, "p2")]
        proc, _ = run_cli(cfg, events, 100, 1000000)
        self.assertEqual(proc.returncode, 5)
        self.assertIn(b"config_limit", proc.stderr)
        proc, _ = run_cli(cfg, events, 1000000, 5)
        self.assertEqual(proc.returncode, 5)
        self.assertIn(b"data_limit", proc.stderr)
        proc, _ = run_cli(cfg, events, 1000000, 1000000, 1, 1000000)
        self.assertEqual(proc.returncode, 5)
        self.assertIn(b"item_limit", proc.stderr)
        proc, _ = run_cli(cfg, events, 1000000, 1000000, 1000000, 10)
        self.assertEqual(proc.returncode, 5)
        self.assertIn(b"output_limit", proc.stderr)
        self.assertEqual(proc.stdout, b"")

    def test_work_limit_formula(self):
        # W 初值 P=2；首个 link：settle +1、link 结果 +1 => 4
        cfg = config()
        events = [link(0, "p1")]
        proc, _ = run_cli(cfg, events,
                          1000000, 1000000, 1000000, 1000000, 4)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        proc, _ = run_cli(cfg, events,
                          1000000, 1000000, 1000000, 1000000, 3)
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr,
                         b'{"error":"link_flow_work_limit"}\n')

    def test_pause_shift_charges_per_moved_copy(self):
        # 精确计费：三数据帧令 p1 队列为 A[100,772)、B[772,1444)、
        # C[1444,2116)；t=500 PAUSE(quanta=100，until=51700) 后移 B、C
        # 两个未开始副本（A 在发不动）。
        # W = P2 + 事件7 + 结果(2 link + 3 数据*2 + 1 pause + 3 发送=12)
        #     + 后移副本 2 = 23；不含后移计费则为 21。
        cfg, links = up_pair()
        events = links + [
            data_event(100, "p2"),
            data_event(300, "p2"),
            data_event(400, "p2"),
            pause_event(500, "p1", 100),
            advance(1000000),
        ]
        for limit, ok in ((21, False), (22, False), (23, True)):
            proc, _ = run_cli(
                cfg, events,
                1000000, 1000000, 1000000, 1000000, limit,
            )
            self.assertEqual(proc.returncode, 0 if ok else 5, limit)
            if not ok:
                self.assertEqual(proc.stdout, b"")
                self.assertEqual(
                    proc.stderr, b'{"error":"link_flow_work_limit"}\n'
                )


if __name__ == "__main__":
    unittest.main()
