#!/usr/bin/env python3
"""link-wire 子命令回归：link-forward 协商/检查/VLAN/FDB + 确定性线速数据面。

仅用标准库；通过 `python switch.py link-wire CONFIG EVENTS` 端到端驱动。
- 配置契约同 link-forward，另要求每口非负整数 queue_bytes（字节）。
- 事件沿用 link/frame 对象，另接受 {"t":int,"advance":true}。
- 线上字节 = 帧长（打标签 +4/剥标签 -4）+ 8 前导码与定界符 + 12 帧间隔；
  发送时长 = ceil(线上字节*8000/速率) 纳秒；同口 FIFO 串行。
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SWITCH = os.path.join(HERE, "switch.py")

BCAST = "ff:ff:ff:ff:ff:ff"


def port(name, pvid=1, allowed=None, untagged=None, mode="access",
         rates=None, modes=None):
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
    }


def config(ports=None, age=100, max_frame=1518, delay=10, queue_bytes=None):
    ports = ports if ports is not None else [port("p1"), port("p2")]
    if queue_bytes is None:
        queue_bytes = {p["name"]: 1000000 for p in ports}
    return {
        "ports": ports,
        "age": age,
        "max_frame": max_frame,
        "delay": delay,
        "queue_bytes": queue_bytes,
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


def frame(t, p, src, dst=BCAST, vlan=None, length=100, fcs=True,
          alignment=True):
    return {
        "t": t,
        "port": p,
        "src": src,
        "dst": dst,
        "vlan": vlan,
        "length": length,
        "fcs": fcs,
        "alignment": alignment,
    }


def advance(t):
    return {"t": t, "advance": True}


def run_cli(config_doc, events, *limits):
    with tempfile.TemporaryDirectory() as tmp:
        cfg = os.path.join(tmp, "config.json")
        evt = os.path.join(tmp, "events.json")
        with open(cfg, "wb") as handle:
            handle.write(json.dumps(config_doc).encode("utf-8"))
        with open(evt, "wb") as handle:
            handle.write(json.dumps(events).encode("utf-8"))
        proc = subprocess.run(
            [sys.executable, SWITCH, "link-wire", cfg, evt,
             *[str(x) for x in limits]],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        missing = subprocess.run(
            [sys.executable, SWITCH, "link-wire",
             os.path.join(tmp, "nope.json"), evt],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    return proc, missing


def run(config_doc, events, *limits):
    proc, _ = run_cli(config_doc, events, *limits)
    assert proc.returncode == 0, (
        proc.returncode, proc.stderr.decode("utf-8")
    )
    return json.loads(proc.stdout.decode("utf-8"))


def events_of(out, kind):
    return [r for r in out["results"] if r.get("event") == kind]


def wire_duration(wire_bytes, rate):
    return (wire_bytes * 8000 + rate - 1) // rate


class WireTimingTests(unittest.TestCase):
    def test_overhead_and_ceil_duration(self):
        # 无标签帧 length=100：线上 100+20=120；10G 下 96ns 整除
        events = [
            link(0, "p1", rates=[10000], modes=["full"]),
            link(0, "p2", rates=[10000], modes=["full"]),
            frame(10, "p1", "00:00:00:00:00:01", length=100),
            advance(106),
        ]
        out = run(config(), events)
        done = events_of(out, "tx_done")
        self.assertEqual(len(done), 1)
        self.assertEqual(done[0]["bytes"], 120)
        self.assertEqual(done[0]["t"], 10 + 96)
        # length=101 -> 121 字节；121*8000/10000=96.8 -> 向上取整 97
        events[-2]["length"] = 101
        out = run(config(), events)
        done = events_of(out, "tx_done")
        self.assertEqual(done[0]["bytes"], 121)
        self.assertEqual(done[0]["t"], 10 + 97)

    def test_rates_scale_duration(self):
        for rate, ns in ((10, 96000), (100, 9600), (1000, 960),
                         (10000, 96)):
            cfg = config([
                port("p1", rates=[rate], modes=["full"]),
                port("p2", rates=[rate], modes=["full"]),
            ])
            events = [
                link(0, "p1", rates=[rate], modes=["full"]),
                link(0, "p2", rates=[rate], modes=["full"]),
                frame(10, "p1", "00:00:00:00:00:01"),
                advance(10 + ns),
            ]
            out = run(cfg, events)
            self.assertEqual(events_of(out, "tx_done")[0]["t"], 10 + ns)

    def test_tag_add_strip_lengths(self):
        # 入站无标签（length=100）：出口打标签 124、剥标签场景不可能，
        # 无标签出口 120；入站带标签（length=100 已含 4 字节标签）：
        # 出口留标签 120、剥标签 116
        hyb = port("p2", mode="hybrid", pvid=2, allowed=[1, 2],
                   untagged=[2], rates=[10000], modes=["full"])
        cfg = config([
            port("p1", mode="access", pvid=1, allowed=[1], untagged=[1],
                 rates=[10000], modes=["full"]),
            hyb,
        ])
        events = [
            link(0, "p1", rates=[10000], modes=["full"]),
            link(0, "p2", rates=[10000], modes=["full"]),
            # pvid=1 无标签入站；p2 的 vlan1 不在 untagged -> 添加标签
            frame(10, "p1", "00:00:00:00:00:01"),
            advance(200),
        ]
        out = run(cfg, events)
        self.assertEqual(events_of(out, "tx_done")[0]["bytes"], 124)
        # 带标签入站 -> p2 vlan1 出口仍打标签：不变 120
        events[2] = frame(10, "p1", "00:00:00:00:00:01", vlan=1)
        out = run(cfg, events)
        self.assertEqual(events_of(out, "tx_done")[0]["bytes"], 120)
        # 带标签入站 -> 出口剥标签：116
        cfg = config([
            port("p1", mode="trunk", pvid=1, allowed=[1, 2], untagged=[],
                 rates=[10000], modes=["full"]),
            port("p2", mode="hybrid", pvid=1, allowed=[1, 2],
                 untagged=[1], rates=[10000], modes=["full"]),
        ])
        out = run(cfg, events)
        self.assertEqual(events_of(out, "tx_done")[0]["bytes"], 116)

    def test_serial_queue_start_is_max_enqueue_prev_end(self):
        # 两帧背靠背入同一出口 p2：第二帧开始 = 上一帧结束
        events = [
            link(0, "p1", rates=[10000], modes=["full"]),
            link(0, "p2", rates=[10000], modes=["full"]),
            frame(10, "p1", "00:00:00:00:00:01"),      # [10,106)
            frame(20, "p1", "00:00:00:00:00:01"),      # [106,202)
            advance(500),
        ]
        out = run(config(), events)
        dones = events_of(out, "tx_done")
        self.assertEqual([d["t"] for d in dones], [106, 202])
        # 入队晚于上一帧结束时：开始取入队时刻
        events = [
            link(0, "p1", rates=[10000], modes=["full"]),
            link(0, "p2", rates=[10000], modes=["full"]),
            frame(10, "p1", "00:00:00:00:00:01"),      # [10,106)
            frame(300, "p1", "00:00:00:00:00:01"),     # [300,396)
            advance(500),
        ]
        out = run(config(), events)
        self.assertEqual([d["t"] for d in events_of(out, "tx_done")],
                         [106, 396])


class NegotiationTests(unittest.TestCase):
    def test_wait_bad_down_states(self):
        events = [
            link(0, "p1", rates=[1000], modes=["full"]),
            link(10, "p1", rates=[1000], modes=["full"]),
        ]
        out = run(config(delay=10), events)
        self.assertEqual(out["results"][0]["state"], "wait")
        self.assertEqual(out["results"][1]["state"], "up")
        self.assertEqual(out["results"][1]["rate"], 1000)
        self.assertEqual(out["results"][1]["mode"], "full")

    def test_frame_during_wait_dropped_no_copy(self):
        events = [
            link(0, "p1"),
            frame(5, "p1", "00:00:00:00:00:01"),
            advance(1000),
        ]
        out = run(config(delay=10), events)
        self.assertEqual(out["results"][1]["action"], "drop")
        self.assertEqual(events_of(out, "tx_done"), [])


class AdvanceTests(unittest.TestCase):
    def test_advance_settles_without_input_record(self):
        events = [
            link(0, "p1", rates=[10000], modes=["full"]),
            link(0, "p2", rates=[10000], modes=["full"]),
            frame(10, "p1", "00:00:00:00:00:01"),
            advance(50),   # 未到 106：无完成
            advance(106),  # 结算 tx_done
        ]
        out = run(config(), events)
        self.assertEqual(
            [r.get("event") for r in out["results"]],
            [None, None, None, "tx_done"],
        )
        self.assertEqual(events_of(out, "tx_done")[0]["t"], 106)

    def test_no_auto_drain_after_last_event(self):
        events = [
            link(0, "p1", rates=[10], modes=["full"]),
            link(0, "p2", rates=[10], modes=["full"]),
            frame(10, "p1", "00:00:00:00:00:01"),
        ]  # 副本在 [10,96010)，无后续 advance：不得排空
        out = run(config(), events)
        self.assertEqual(events_of(out, "tx_done"), [])
        stats = {p["name"]: p for p in out["ports"]}
        self.assertEqual(stats["p2"]["tx"], 0)
        self.assertEqual(stats["p2"]["tx_bytes"], 0)
        self.assertEqual(stats["p1"]["rx"], 1)

    def test_advance_settles_negotiation_too(self):
        events = [
            link(0, "p1"),
            link(0, "p2"),
            advance(10),  # 协商完成；随后无事件，不产生转发
            frame(11, "p1", "00:00:00:00:00:01"),
            advance(200),
        ]
        out = run(config(delay=10), events)
        # t=11 的帧泛洪到已 up 的 p2
        self.assertEqual(out["results"][2]["action"], "flood")


class CompletionOrderTests(unittest.TestCase):
    def test_same_end_time_config_port_order(self):
        cfg = config([port("p1"), port("p2"), port("p3")])
        events = [
            link(0, "p1", rates=[10000], modes=["full"]),
            link(0, "p2", rates=[10000], modes=["full"]),
            link(0, "p3", rates=[10000], modes=["full"]),
            frame(10, "p1", "00:00:00:00:00:01"),  # 副本到 p2,p3 同 end=106
            advance(106),
        ]
        out = run(cfg, events)
        dones = events_of(out, "tx_done")
        self.assertEqual([d["port"] for d in dones], ["p2", "p3"])

    def test_interleaved_completions_merge_by_end_time(self):
        # p2 慢速 10M（96000ns），p3 快速 10G（96ns）；同一帧泛洪：
        # p3 先完成，p2 后完成
        cfg = config([
            port("p1", rates=[10000], modes=["full"]),
            port("p2", rates=[10], modes=["full"]),
            port("p3", rates=[10000], modes=["full"]),
        ])
        events = [
            link(0, "p1", rates=[10000], modes=["full"]),
            link(0, "p2", rates=[10], modes=["full"]),
            link(0, "p3", rates=[10000], modes=["full"]),
            frame(10, "p1", "00:00:00:00:00:01"),
            advance(100000),
        ]
        out = run(cfg, events)
        dones = [(d["port"], d["t"]) for d in events_of(out, "tx_done")]
        self.assertEqual(dones, [("p3", 106), ("p2", 96010)])

    def test_completion_at_t_precedes_input_at_t(self):
        cfg = config([
            port("p1", rates=[10000], modes=["full"]),
            port("p2", rates=[10000], modes=["full"]),
        ])
        events = [
            link(0, "p1", rates=[10000], modes=["full"]),
            link(0, "p2", rates=[10000], modes=["full"]),
            frame(10, "p1", "00:00:00:00:00:01"),  # p2 副本 [10,106)
            # t=106 既是完成时刻又是入帧时刻：先结算完成（学习 01）
            frame(106, "p2", "00:00:00:00:00:02",
                  dst="00:00:00:00:00:01"),       # 单播命中 p1
            advance(500),
        ]
        out = run(cfg, events)
        kinds = [(r.get("event"), r.get("action")) for r in out["results"]]
        self.assertEqual(kinds[-3][0], "tx_done")
        self.assertEqual(kinds[-2][1], "unicast")


class HalfDuplexCollisionTests(unittest.TestCase):
    def _half_cfg(self, rate=10, n=2):
        return config(
            [port("p%d" % i, rates=[rate], modes=["half"])
             for i in range(1, n + 1)],
            age=100000000,
        )

    def test_collision_kills_both_and_counts_bytes(self):
        cfg = self._half_cfg()
        events = [
            link(0, "p1", rates=[10], modes=["half"]),
            link(0, "p2", rates=[10], modes=["half"]),
            frame(10, "p2", "00:00:00:00:00:02"),  # p1 副本 [10,92810)
            frame(20, "p1", "00:00:00:00:00:01"),  # 碰撞
            advance(1000000),
        ]
        out = run(cfg, events)
        coll = events_of(out, "collision")
        self.assertEqual(len(coll), 1)
        # 入站帧线上 120 + 发送副本线上 116（剥标签）= 236
        self.assertEqual(coll[0],
                         {"t": 20, "port": "p1",
                          "event": "collision", "bytes": 236})
        p1 = out["ports"][0]
        self.assertEqual(p1["collision"], 1)
        self.assertEqual(p1["collision_bytes"], 236)
        self.assertEqual(p1["rx"], 0)       # 入站帧终止不计 rx
        self.assertEqual(p1["tx"], 0)       # 副本终止不计 tx
        self.assertEqual(p1["drop"], 0)     # 碰撞不计 drop
        self.assertEqual(events_of(out, "tx_done"), [])

    def test_collision_frame_not_classified(self):
        # 哪怕入站帧是 runt，发送区间内仍按碰撞处理（物理层先于检查）
        cfg = self._half_cfg()
        events = [
            link(0, "p1", rates=[10], modes=["half"]),
            link(0, "p2", rates=[10], modes=["half"]),
            frame(10, "p2", "00:00:00:00:00:02"),
            frame(20, "p1", "00:00:00:00:00:01", length=10),  # runt
        ]
        out = run(cfg, events)
        self.assertEqual(len(events_of(out, "collision")), 1)
        classes = [r.get("class") for r in out["results"]
                   if r.get("class") is not None]
        self.assertEqual(classes, ["good"])
        self.assertEqual(out["ports"][0]["runt"], 0)

    def test_full_duplex_no_collision_while_sending(self):
        cfg = config([
            port("p1", rates=[10], modes=["full"]),
            port("p2", rates=[10000], modes=["full"]),
            port("p3", rates=[10000], modes=["full"]),
        ], age=100000000)
        events = [
            link(0, "p1", rates=[10], modes=["full"]),
            link(0, "p2", rates=[10000], modes=["full"]),
            link(0, "p3", rates=[10000], modes=["full"]),
            frame(10, "p2", "00:00:00:00:00:02"),  # p1 副本长发送
            frame(50, "p1", "00:00:00:00:00:01"),  # p1 full：正常收发
            advance(200000),
        ]
        out = run(cfg, events)
        self.assertEqual(events_of(out, "collision"), [])
        p1 = out["ports"][0]
        self.assertEqual(p1["rx"], 1)
        self.assertEqual(p1["tx"], 1)

    def test_collision_at_exact_end_is_completion(self):
        cfg = self._half_cfg(rate=10000)
        events = [
            link(0, "p1", rates=[10000], modes=["half"]),
            link(0, "p2", rates=[10000], modes=["half"]),
            frame(10, "p2", "00:00:00:00:00:02"),  # p1 副本 [10,103)
            frame(103, "p1", "00:00:00:00:00:01"),  # end==t：先完成
            advance(500),
        ]
        out = run(cfg, events)
        self.assertEqual(events_of(out, "collision"), [])
        self.assertEqual(len(events_of(out, "tx_done")), 1)

    def test_queued_copies_rescheduled_from_collision_time(self):
        cfg = config([
            port("p1", rates=[10], modes=["half"]),
            port("p2", rates=[10000], modes=["full"]),
        ], age=100000000)
        events = [
            link(0, "p1", rates=[10], modes=["half"]),
            link(0, "p2", rates=[10000], modes=["full"]),
            frame(10, "p2", "00:00:00:00:00:02"),  # p1 [10,92810)
            frame(20, "p2", "00:00:00:00:02"),     # p1 排队 [92810,185610)
            frame(30, "p1", "00:00:00:00:00:01"),  # 碰撞：首副本终止，
            #                                        次副本自 30 重排
            advance(200000),
        ]
        out = run(cfg, events)
        dones = events_of(out, "tx_done")
        self.assertEqual(len(dones), 1)
        self.assertEqual(dones[0]["t"], 30 + wire_duration(116, 10))

    def test_collision_killed_frame_not_learned(self):
        cfg = self._half_cfg()
        events = [
            link(0, "p1", rates=[10], modes=["half"]),
            link(0, "p2", rates=[10], modes=["half"]),
            frame(10, "p1", "00:00:00:00:00:01"),  # p2 副本 [10,92810)
            frame(20, "p2", "00:00:00:00:00:02"),  # 碰撞：两副本皆终止
            advance(100000),
            # 01 的唯一副本已被杀：未学习；02 入站帧也终止未学习
            frame(100000, "p2", "00:00:00:00:00:09",
                  dst="00:00:00:00:00:01"),        # 应泛洪而非单播
        ]
        out = run(cfg, events)
        classes = [r for r in out["results"] if r.get("class") is not None]
        self.assertEqual(classes[-1]["action"], "flood")


class QueueLimitTests(unittest.TestCase):
    def test_exact_limit_accepted_one_byte_over_dropped(self):
        wire = 116  # 剥标签：length100 - 4 + 20
        cfg = config(queue_bytes={"p1": 1000000, "p2": wire})
        events = [
            link(0, "p1", rates=[10000], modes=["full"]),
            link(0, "p2", rates=[10000], modes=["full"]),
            frame(10, "p1", "00:00:00:00:00:01"),
        ]
        out = run(cfg, events)
        self.assertEqual(events_of(out, "queue_full"), [])
        # 第二帧令总和 2*116 > 116
        events.append(frame(11, "p1", "00:00:00:00:00:01"))
        out = run(cfg, events)
        qf = events_of(out, "queue_full")
        self.assertEqual(len(qf), 1)
        self.assertEqual(qf[0]["bytes"], wire)
        self.assertEqual(qf[0]["port"], "p2")
        p2 = out["ports"][1]
        self.assertEqual(p2["queue_full"], 1)
        self.assertEqual(p2["queue_bytes"], wire)
        self.assertEqual(p2["drop"], 1)

    def test_queue_full_isolated_per_egress(self):
        # 泛洪到 p2、p3；p2 队列满只丢 p2 副本，p3 照常发送
        cfg = config(
            [port("p1"), port("p2"), port("p3")],
            queue_bytes={"p1": 1000000, "p2": 1, "p3": 1000000},
        )
        events = [
            link(0, "p1", rates=[10000], modes=["full"]),
            link(0, "p2", rates=[10000], modes=["full"]),
            link(0, "p3", rates=[10000], modes=["full"]),
            frame(10, "p1", "00:00:00:00:00:01"),
            advance(500),
        ]
        out = run(cfg, events)
        qf = events_of(out, "queue_full")
        self.assertEqual([d["port"] for d in qf], ["p2"])
        self.assertEqual(
            [d["port"] for d in events_of(out, "tx_done")], ["p3"]
        )
        cls = [r for r in out["results"] if r.get("class") is not None][0]
        self.assertEqual([p["name"] for p in cls["ports"]], ["p3"])

    def test_completed_copy_frees_queue_space(self):
        cfg = config(queue_bytes={"p1": 1000000, "p2": 116})
        events = [
            link(0, "p1", rates=[10000], modes=["full"]),
            link(0, "p2", rates=[10000], modes=["full"]),
            frame(10, "p1", "00:00:00:00:00:01"),  # 填满
            frame(11, "p1", "00:00:00:00:00:01"),  # queue_full
            advance(106),                           # 首副本完成，腾空间
            frame(107, "p1", "00:00:00:00:00:01"),  # 重新入队成功
            advance(500),
        ]
        out = run(cfg, events)
        self.assertEqual(len(events_of(out, "queue_full")), 1)
        self.assertEqual(len(events_of(out, "tx_done")), 2)

    def test_zero_queue_drops_every_copy(self):
        cfg = config(queue_bytes={"p1": 0, "p2": 0})
        events = [
            link(0, "p1"),
            link(0, "p2"),
            frame(10, "p1", "00:00:00:00:00:01"),
        ]
        out = run(cfg, events)
        self.assertEqual(len(events_of(out, "queue_full")), 1)
        self.assertEqual(events_of(out, "tx_done"), [])

    def test_queue_full_frame_not_learned_when_all_copies_dropped(self):
        cfg = config(queue_bytes={"p1": 1000000, "p2": 1})
        events = [
            link(0, "p1", rates=[10000], modes=["full"]),
            link(0, "p2", rates=[10000], modes=["full"]),
            frame(10, "p1", "00:00:00:00:00:01"),  # 唯一出口 p2 队列满
            frame(20, "p2", "00:00:00:00:00:02",
                  dst="00:00:00:00:00:01"),         # 未学习 -> 泛洪/无命中
        ]
        out = run(cfg, events)
        cls = [r for r in out["results"] if r.get("class") is not None]
        self.assertEqual(cls[0]["ports"], [])
        self.assertEqual(cls[1]["action"], "flood")


class LinkDownTests(unittest.TestCase):
    def test_down_mid_transmission_aggregates_drops(self):
        cfg = config([
            port("p1", rates=[10], modes=["half"]),
            port("p2", rates=[10], modes=["half"]),
        ], age=100000000)
        events = [
            link(0, "p1", rates=[10], modes=["half"]),
            link(0, "p2", rates=[10], modes=["half"]),
            frame(10, "p1", "00:00:00:00:00:01"),  # p2 [10,92810)
            link(20, "p2", admin=False),
        ]
        out = run(cfg, events)
        ld = events_of(out, "link_down")
        self.assertEqual(
            ld[0],
            {"t": 20, "port": "p2", "event": "link_down",
             "frames": 1, "bytes": 116},
        )
        p2 = out["ports"][1]
        self.assertEqual(p2["link_down"], 1)
        self.assertEqual(p2["link_down_bytes"], 116)
        self.assertEqual(p2["drop"], 1)
        self.assertEqual(p2["tx"], 0)
        # link_down 记录先于同刻协商状态记录
        idx = [i for i, r in enumerate(out["results"])
               if r.get("event") == "link_down"][0]
        self.assertEqual(out["results"][idx + 1]["state"], "down")

    def test_completion_at_t_settles_before_link_down(self):
        cfg = config(rates_kw := None) if False else config()
        cfg = config([
            port("p1", rates=[10000], modes=["full"]),
            port("p2", rates=[10000], modes=["full"]),
        ])
        events = [
            link(0, "p1", rates=[10000], modes=["full"]),
            link(0, "p2", rates=[10000], modes=["full"]),
            frame(10, "p1", "00:00:00:00:00:01"),  # p2 [10,106)
            link(106, "p2", admin=False),          # 先完成再 down
        ]
        out = run(cfg, events)
        self.assertEqual(len(events_of(out, "tx_done")), 1)
        self.assertEqual(events_of(out, "link_down"), [])
        self.assertEqual(out["ports"][1]["tx"], 1)

    def test_wait_transition_also_drops_and_clears_fdb(self):
        cfg = config([
            port("p1", rates=[100, 1000], modes=["full"]),
            port("p2", rates=[10000], modes=["full"]),
            port("p3", rates=[10000], modes=["full"]),
        ], age=100000000)
        events = [
            link(0, "p1", rates=[1000], modes=["full"]),
            link(0, "p2", rates=[10000], modes=["full"]),
            link(0, "p3", rates=[10000], modes=["full"]),
            frame(10, "p1", "00:00:00:00:00:01"),  # 副本到 p2
            link(20, "p2", rates=[100], modes=["full"]),  # up->wait
            frame(30, "p1", "00:00:00:00:00:01"),  # p2 wait：只泛洪 p3
            advance(500),
        ]
        out = run(cfg, events)
        self.assertEqual(len(events_of(out, "link_down")), 1)
        cls = [r for r in out["results"] if r.get("class") is not None]
        self.assertEqual([p["name"] for p in cls[-1]["ports"]], ["p3"])


class LearningTests(unittest.TestCase):
    def test_learning_deferred_until_first_completion(self):
        cfg = config([
            port("p1", rates=[10000], modes=["full"]),
            port("p2", rates=[10000], modes=["full"]),
        ], age=100000000)
        events = [
            link(0, "p1", rates=[10000], modes=["full"]),
            link(0, "p2", rates=[10000], modes=["full"]),
            frame(10, "p1", "00:00:00:00:00:01"),  # 完成于 106
            frame(105, "p2", "00:00:00:00:00:02",
                  dst="00:00:00:00:00:01"),         # 尚未学习 -> 泛洪
            frame(107, "p2", "00:00:00:00:00:02",
                  dst="00:00:00:00:00:01"),         # 已学习 -> 单播
            advance(500),
        ]
        out = run(cfg, events)
        cls = [r for r in out["results"] if r.get("class") is not None]
        self.assertEqual(cls[1]["action"], "flood")
        self.assertEqual(cls[2]["action"], "unicast")

    def test_aging_uses_completion_timestamp(self):
        # 完成时刻 106；age=100：t=205（差 99）命中，t=206（差 100）老化
        cfg = config([
            port("p1", rates=[10000], modes=["full"]),
            port("p2", rates=[10000], modes=["full"]),
        ], age=100)
        base = [
            link(0, "p1", rates=[10000], modes=["full"]),
            link(0, "p2", rates=[10000], modes=["full"]),
            frame(10, "p1", "00:00:00:00:00:01"),
            advance(106),
        ]
        out = run(cfg, base + [
            frame(205, "p2", "00:00:00:00:00:02",
                  dst="00:00:00:00:00:01"),
        ])
        cls = [r for r in out["results"] if r.get("class") is not None]
        self.assertEqual(cls[-1]["action"], "unicast")
        out = run(cfg, base + [
            frame(206, "p2", "00:00:00:00:00:02",
                  dst="00:00:00:00:00:01"),
        ])
        cls = [r for r in out["results"] if r.get("class") is not None]
        self.assertEqual(cls[-1]["action"], "flood")


class ClassificationTests(unittest.TestCase):
    def test_bad_frames_dropped_before_queue(self):
        events = [
            link(0, "p1"),
            frame(10, "p1", "00:00:00:00:00:01", length=10),   # runt
            frame(11, "p1", "00:00:00:00:00:01", length=9999), # giant
            frame(12, "p1", "00:00:00:00:00:01",
                  alignment=False),                            # alignment
            frame(13, "p1", "00:00:00:00:00:01", fcs=False),  # bad_fcs
        ]
        out = run(config([port("p1")], max_frame=1518), events)
        classes = [r["class"] for r in out["results"][1:]]
        self.assertEqual(
            classes, ["runt", "giant", "alignment", "bad_fcs"]
        )
        self.assertEqual(events_of(out, "tx_done"), [])
        p1 = out["ports"][0]
        self.assertEqual(p1["rx"], 4)
        self.assertEqual(p1["rx_bytes"], 4 * 20 + 10 + 9999 + 100 + 100)
        self.assertEqual(p1["drop"], 4)

    def test_tagged_frame_on_access_rejected(self):
        events = [
            link(0, "p1"),
            frame(10, "p1", "00:00:00:00:00:01", vlan=2),
        ]
        out = run(config([port("p1", pvid=1)]), events)
        self.assertEqual(out["results"][1]["action"], "drop")
        self.assertEqual(out["results"][1]["ports"], [])

    def test_good_frame_no_egress_counts_vlan_drop(self):
        events = [
            link(0, "p1"),
            frame(10, "p1", "00:00:00:00:00:01"),
        ]
        out = run(config([port("p1")]), events)
        self.assertEqual(out["results"][1]["action"], "drop")
        self.assertEqual(out["vlans"][0]["drop"], 1)
        self.assertEqual(out["vlans"][0]["rx"], 1)


class OutputContractTests(unittest.TestCase):
    def test_key_orders_and_compact_bytes(self):
        cfg = config([
            port("p1", rates=[10000], modes=["half"]),
            port("p2", rates=[10000], modes=["full"]),
        ])
        events = [
            link(0, "p1", rates=[10000], modes=["half"]),
            link(0, "p2", rates=[10000], modes=["full"]),
            frame(10, "p1", "00:00:00:00:00:01"),
            advance(200),
        ]
        proc, _ = run_cli(cfg, events)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        raw = proc.stdout
        decoded = json.loads(raw.decode("utf-8").rstrip("\n"))
        self.assertEqual(list(decoded), ["results", "ports", "vlans"])
        self.assertEqual(
            list(decoded["results"][0]),
            ["t", "port", "state", "rate", "mode"],
        )
        self.assertEqual(
            list(decoded["results"][2]),
            ["t", "class", "action", "ports"],
        )
        self.assertEqual(
            list(decoded["results"][3]),
            ["t", "port", "event", "src", "dst", "vlan", "bytes"],
        )
        self.assertEqual(
            list(decoded["ports"][0]),
            ["name", "rx", "tx", "drop", "good", "runt", "giant",
             "alignment", "bad_fcs", "collision", "queue_full", "link_down",
             "rx_bytes", "tx_bytes", "collision_bytes", "queue_bytes",
             "link_down_bytes"],
        )
        self.assertEqual(list(decoded["vlans"][0]),
                         ["vlan", "rx", "tx", "drop"])
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b": ", raw)

    def test_auxiliary_record_key_orders(self):
        # collision / queue_full / link_down 各自固定键序
        cfg = config([
            port("p1", rates=[10], modes=["half"]),
            port("p2", rates=[10], modes=["half"]),
        ], age=100000000,
            queue_bytes={"p1": 1000000, "p2": 1})
        events = [
            link(0, "p1", rates=[10], modes=["half"]),
            link(0, "p2", rates=[10], modes=["half"]),
            frame(10, "p1", "00:00:00:00:00:01"),  # p2 queue_full
            frame(20, "p2", "00:00:00:00:00:02"),  # p1 collision
            link(30, "p1", admin=False),            # p1 无副本，不出 link_down
        ]
        # 单独构造 link_down 场景
        cfg2 = config([
            port("p1", rates=[10], modes=["half"]),
            port("p2", rates=[10], modes=["half"]),
        ])
        events2 = [
            link(0, "p1", rates=[10], modes=["half"]),
            link(0, "p2", rates=[10], modes=["half"]),
            frame(10, "p1", "00:00:00:00:00:01"),
            link(20, "p2", admin=False),
        ]
        out = run(cfg, events)
        self.assertEqual(
            list(events_of(out, "collision")[0]),
            ["t", "port", "event", "bytes"],
        )
        self.assertEqual(
            list(events_of(out, "queue_full")[0]),
            ["t", "port", "event", "src", "dst", "vlan", "bytes"],
        )
        out2 = run(cfg2, events2)
        self.assertEqual(
            list(events_of(out2, "link_down")[0]),
            ["t", "port", "event", "frames", "bytes"],
        )


class ValidationTests(unittest.TestCase):
    def _assert_exit4(self, cfg, events):
        proc, _ = run_cli(cfg, events)
        self.assertEqual(proc.returncode, 4, proc.stderr)
        self.assertEqual(proc.stdout, b"")
        self.assertIn(b"invalid_input", proc.stderr)

    def test_queue_bytes_required(self):
        cfg = config()
        del cfg["queue_bytes"]
        self._assert_exit4(cfg, [])
        bad = dict(cfg)
        bad["queue_bytes"] = [1, 2]
        self._assert_exit4(bad, [])

    def test_queue_bytes_keys_and_values(self):
        good = config()
        self._assert_exit4(
            {**good, "queue_bytes": {"p1": 100}}, [])          # 缺 p2
        self._assert_exit4(
            {**good, "queue_bytes": {"p1": 1, "p2": 2,
                                     "p3": 3}}, [])            # 多 p3
        self._assert_exit4(
            {**good, "queue_bytes": {"p1": -1, "p2": 0}}, [])  # 负
        self._assert_exit4(
            {**good, "queue_bytes": {"p1": True,
                                     "p2": 0}}, [])            # 布尔
        self._assert_exit4(
            {**good, "queue_bytes": {"p1": "1",
                                     "p2": 0}}, [])            # 字符串
        # 零合法
        proc, _ = run_cli(good, [])
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_link_forward_config_contract_retained(self):
        good = port("p1")
        bad = dict(good)
        bad["up"] = True
        self._assert_exit4(config([bad]), [])
        self._assert_exit4(config(**{"delay": 0}), [])
        self._assert_exit4(config(**{"max_frame": 9217}), [])
        self._assert_exit4(config([port("p1"), port("p1")]), [])

    def test_advance_event_strict(self):
        cfg = config()
        for bad in (
            {"t": 0},
            {"t": 0, "advance": False},
            {"t": 0, "advance": 1},
            {"t": 0, "advance": True, "extra": 1},
            {"advance": True},
            {"t": -1, "advance": True},
        ):
            self._assert_exit4(cfg, [bad])

    def test_monotonic_t_across_all_event_types(self):
        cfg = config()
        self._assert_exit4(cfg, [advance(5), frame(4, "p1",
                                                  "00:00:00:00:00:01")])
        self._assert_exit4(cfg, [link(5, "p1"), advance(4)])
        # 相等时刻合法（单调不减）
        proc, _ = run_cli(cfg, [advance(5), advance(5)])
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_event_shapes_strict(self):
        cfg = config()
        good_link = link(0, "p1")
        good_frame = frame(0, "p1", "00:00:00:00:00:01")
        for bad in ({}, {**good_link, "extra": 1},
                    {**good_frame, "extra": 1}):
            self._assert_exit4(cfg, [bad])

    def test_events_must_be_list(self):
        self._assert_exit4(config(), {"x": 1})


class DeterminismTests(unittest.TestCase):
    def test_byte_identical_repeated_runs(self):
        cfg = config([
            port("p1", rates=[10, 100], modes=["half"]),
            port("p2", rates=[10000], modes=["full"]),
            port("p3", rates=[10000], modes=["full"]),
        ])
        events = [
            link(0, "p1", rates=[100], modes=["half"]),
            link(0, "p2", rates=[10000], modes=["full"]),
            link(0, "p3", rates=[10000], modes=["full"]),
            frame(10, "p1", "00:00:00:00:00:01"),
            frame(20, "p1", "00:00:00:00:00:03",
                  dst="00:00:00:00:00:09"),
            advance(500),
            frame(600, "p2", "00:00:00:00:00:02"),
            link(700, "p2", admin=False),
            advance(2000),
        ]
        proc_a, _ = run_cli(cfg, events)
        proc_b, _ = run_cli(cfg, events)
        self.assertEqual(proc_a.stdout, proc_b.stdout)


class ResourceAndErrorTests(unittest.TestCase):
    def test_missing_file_exit3(self):
        proc, missing = run_cli(config(), [])
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(missing.returncode, 3)
        self.assertEqual(missing.stdout, b"")
        self.assertIn(b"file_not_found", missing.stderr)

    def test_config_and_data_limit_exit5(self):
        events = [link(0, "p1")]
        proc, _ = run_cli(config(), events, 100, 1000000)
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(proc.stdout, b"")
        self.assertIn(b"config_limit", proc.stderr)
        proc, _ = run_cli(config(), events, 1000000, 5)
        self.assertEqual(proc.returncode, 5)
        self.assertIn(b"data_limit", proc.stderr)
        self.assertEqual(proc.stdout, b"")

    def test_item_limit_exit5(self):
        events = [link(i, "p1") for i in range(3)]
        proc, _ = run_cli(config(), events, 1000000, 1000000, 2, 1000000)
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(proc.stdout, b"")
        self.assertIn(b"item_limit", proc.stderr)
        proc, _ = run_cli(config(), events[:2], 1000000, 1000000, 2,
                          1000000)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_output_limit_exit5_empty_stdout(self):
        events = [link(0, "p1"), link(1, "p2")]
        proc, _ = run_cli(config(), events, 1000000, 1000000, 1000000, 10)
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(proc.stdout, b"")
        self.assertIn(b"output_limit", proc.stderr)

    def test_usage_exit2(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = os.path.join(tmp, "c.json")
            evt = os.path.join(tmp, "e.json")
            with open(cfg, "wb") as handle:
                handle.write(b"{}")
            with open(evt, "wb") as handle:
                handle.write(b"[]")
            for argv in (
                ["link-wire", cfg],
                ["link-wire", cfg, evt, "1"],
                ["link-wire", cfg, evt, "1", "2", "3"],
                ["link-wire", cfg, evt, "0"],
            ):
                proc = subprocess.run(
                    [sys.executable, SWITCH, *argv],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.assertEqual(proc.returncode, 2, argv)
                self.assertEqual(proc.stdout, b"")
                self.assertIn(b"usage", proc.stderr)

    def test_no_partial_state_on_validation_failure(self):
        bad_events = [
            link(0, "p1"),
            frame(10, "p1", "00:00:00:00:00:01"),
            frame(11, "ghost", "00:00:00:00:00:02"),
        ]
        proc, _ = run_cli(config(), bad_events)
        self.assertEqual(proc.returncode, 4)
        self.assertEqual(proc.stdout, b"")

    def test_semantic_failure_precedes_work_limit(self):
        cfg = config([dict(port("p1"), mode="nope"), port("p2")])
        proc, _ = run_cli(cfg, [link(0, "p1")], 1000000, 1000000,
                          1000000, 1000000, 1)
        self.assertEqual(proc.returncode, 4)
        self.assertEqual(proc.stdout, b"")
        self.assertIn(b"invalid_input", proc.stderr)

    def test_work_limit_precedes_output_limit(self):
        events = [link(0, "p1"), link(1, "p2")]
        proc, _ = run_cli(config(), events, 1000000, 1000000, 1000000, 1, 1)
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(
            proc.stderr, b'{"error":"link_wire_work_limit"}\n'
        )


class WorkLimitTests(unittest.TestCase):
    def test_initial_work_is_port_count(self):
        cfg = config([port("p1"), port("p2"), port("p3")])
        proc, _ = run_cli(cfg, [], 1000000, 1000000, 1000000, 1000000, 3)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        proc, _ = run_cli(cfg, [], 1000000, 1000000, 1000000, 1000000, 2)
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(
            proc.stderr, b'{"error":"link_wire_work_limit"}\n'
        )

    def test_all_event_types_billed_same_formula(self):
        # P=2：W 初值 2；每事件加 F+5；F 仅 frame 项后 +1
        cfg = config()
        # [link, advance, frame]：2 + 5 + 5 + 6 = 18
        events = [link(0, "p1"), advance(1),
                  frame(2, "p1", "00:00:00:00:00:01")]
        proc, _ = run_cli(cfg, events, 1000000, 1000000, 1000000, 1000000, 18)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        proc, _ = run_cli(cfg, events, 1000000, 1000000, 1000000, 1000000, 17)
        self.assertEqual(proc.returncode, 5)
        # [frame, advance, link]：F 仅在 frame 后增长 -> 2+5+6+6 = 19
        events = [frame(0, "p1", "00:00:00:00:00:01"), advance(1),
                  link(2, "p1")]
        proc, _ = run_cli(cfg, events, 1000000, 1000000, 1000000, 1000000, 19)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        proc, _ = run_cli(cfg, events, 1000000, 1000000, 1000000, 1000000, 18)
        self.assertEqual(proc.returncode, 5)

    def test_fifth_limit_usage_and_long_decimal(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = os.path.join(tmp, "c.json")
            evt = os.path.join(tmp, "e.json")
            with open(cfg, "wb") as handle:
                handle.write(json.dumps(config()).encode("utf-8"))
            with open(evt, "wb") as handle:
                handle.write(json.dumps([link(0, "p1")]).encode("utf-8"))
            for bad in ("0", "01", "-1", "1.0", "x"):
                proc = subprocess.run(
                    [sys.executable, SWITCH, "link-wire", cfg, evt,
                     "1000000", "1000000", "1000000", "1000000", bad],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.assertEqual(proc.returncode, 2, bad)
                self.assertIn(b"usage", proc.stderr)
            proc = subprocess.run(
                [sys.executable, SWITCH, "link-wire", cfg, evt,
                 "1000000", "1000000", "1000000", "1000000", "9" * 100],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
