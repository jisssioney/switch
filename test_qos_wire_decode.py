#!/usr/bin/env python3
"""qos-wire-decode 子命令回归。

qos-wire-decode 的配置复用 link-flow-decode 的端口模式、协商（rates/modes/
delay）、总字节缓存（queue_bytes）、流控（flow_control）、老化与最大帧，
另加入 qos-decode 的优先级映射（map）、四队列帧限额（cap）、sp/wrr 权重
调度与 tail/weighted 丢弃；每口再声明 queue_quota 给出四个队列各自的字节
缓存。事件只接受 link/advance/{t,port,data} 原始帧（service 一律非法）。
合法帧经既有分类、VLAN 归属与 link-wire 转发判定后，各出口副本按最终
802.1Q 优先级入四个出口队列，同时受本队列字节限额与端口总字节限额约束，
拒绝只影响该出口；发送器在空闲或 advance 结算完成点按 sp/wrr 选取下一副本
线速发送。链路降级、半双工冲突与 802.3x PAUSE 的影响沿用 link-flow-decode。

仅用标准库；端到端驱动 `python switch.py qos-wire-decode CONFIG EVENTS`。
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
import zlib
from collections import defaultdict, deque

HERE = os.path.dirname(os.path.abspath(__file__))
SWITCH = os.path.join(HERE, "switch.py")

BCAST = "ff:ff:ff:ff:ff:ff"
PAUSE_DST = "01:80:c2:00:00:01"
MAC1 = "00:00:00:00:00:01"


def port(name, pvid=1, allowed=None, untagged=None, mode="access",
         rates=None, modes=None, queue_bytes=1000000, queue_quota=None,
         flow_control=True):
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
        "queue_quota": [1000000] * 4 if queue_quota is None else queue_quota,
        "flow_control": flow_control,
    }


def trunk(name, pvid=1, vlans=(1,)):
    return port(
        name, pvid=pvid, mode="trunk", allowed=list(vlans), untagged=[]
    )


def config(ports=None, age=100, max_frame=1518, delay=10, mode="sp",
           weights=None, drop="tail", cap=1000, qos_map=None):
    return {
        "ports": ports if ports is not None else [port("p1"), port("p2")],
        "age": age,
        "max_frame": max_frame,
        "delay": delay,
        "qos": {
            "map": [0, 1, 2, 3, 0, 1, 2, 3] if qos_map is None else qos_map,
            "cap": cap,
            "mode": mode,
            "weights": [1, 1, 1, 1] if weights is None else weights,
            "drop": drop,
        },
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


def up_pair(rates=(1000,), modes=("full",), delay=10, **pkw):
    cfg = config(
        [port("p1", rates=list(rates), modes=list(modes), **pkw),
         port("p2", rates=list(rates), modes=list(modes), **pkw)],
        delay=delay,
    )
    return cfg, [
        link(0, "p1", rates=list(rates), modes=list(modes)),
        link(0, "p2", rates=list(rates), modes=list(modes)),
    ]


def advance(t):
    return {"t": t, "advance": True}


def mac_bytes(mac):
    return bytes(int(part, 16) for part in mac.split(":"))


def raw_frame(t, p, dst=BCAST, src=MAC1, vlan=None, priority=0,
              ethertype=0x0800, payload_len=46, fcs_good=True):
    d = mac_bytes(dst)
    s = mac_bytes(src)
    if vlan is None:
        head = d + s + ethertype.to_bytes(2, "big")
    else:
        tci = (priority << 13) | vlan
        head = d + s + b"\x81\x00" + tci.to_bytes(2, "big") + \
            ethertype.to_bytes(2, "big")
    body = head + b"\x00" * payload_len
    fcs = (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little")
    if not fcs_good:
        fcs = b"\xff\xff\xff\xff"
    return {"t": t, "port": p, "data": (body + fcs).hex()}


def data_event(t, p, dst=BCAST, src=MAC1, payload_len=46, vlan=None,
               priority=0, fcs_good=True):
    return raw_frame(t, p, dst, src, vlan=vlan, priority=priority,
                     payload_len=payload_len, fcs_good=fcs_good)


def pause_event(t, p, quanta, opcode=0x0001, pad=42):
    body = (
        mac_bytes(PAUSE_DST) + mac_bytes(MAC1) + b"\x88\x08"
        + opcode.to_bytes(2, "big") + quanta.to_bytes(2, "big")
        + b"\x00" * pad
    )
    fcs = (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little")
    return {"t": t, "port": p, "data": (body + fcs).hex()}


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
        [sys.executable, SWITCH, "qos-wire-decode", cfg, evt,
         *[str(x) for x in limits]],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    missing = subprocess.run(
        [sys.executable, SWITCH, "qos-wire-decode",
         os.path.join(tmp, "nope.json"), evt],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return proc, missing


def run(config_doc, events, *limits):
    proc, _ = run_cli(config_doc, events, *limits)
    assert proc.returncode == 0, (
        proc.returncode, proc.stderr.decode("utf-8")
    )
    return json.loads(proc.stdout.decode("utf-8"))


def tx_sequence(out, mode="sp"):
    """重放入队/完成记录还原每完成项的队列。

    每口跟踪在发副本所在队列 head；入队时发送器空闲则成 head，否则进对应
    # 等待队；完成弹出 head，再按 sp（最高非空）选取下一 head。本文件 WRR
    # 场景下选取结果同样为最高非空队，故统一口径。
    """
    waiting = defaultdict(lambda: [deque(), deque(), deque(), deque()])
    head = {}
    seq = []
    for r in out["results"]:
        if "queue" in r and "start" not in r and "reason" not in r:
            if head.get(r["port"]) is None:
                head[r["port"]] = r["queue"]
            else:
                waiting[r["port"]][r["queue"]].append(True)
        elif "start" in r and "reason" not in r and "state" not in r:
            q = head[r["port"]]
            qs = waiting[r["port"]]
            nxt = next((i for i in (3, 2, 1, 0) if qs[i]), None)
            head[r["port"]] = nxt
            if nxt is not None:
                qs[nxt].popleft()
            seq.append(("tx", r["port"], q, r["start"]))
        elif r.get("reason") in ("queue_full", "queue_quota"):
            seq.append(("drop", r["port"], r["queue"], r["reason"]))
    return seq


class LineRateTests(unittest.TestCase):
    def test_untagged_bcast_line_rate_and_records(self):
        cfg, links = up_pair()
        out = run(cfg, links + [data_event(20, "p1"), advance(1000000)])
        enq = next(r for r in out["results"]
                   if "queue" in r and "start" not in r)
        self.assertEqual(enq, {"t": 20, "port": "p2", "vlan": None,
                               "queue": 0, "bytes": 84})
        tx = next(r for r in out["results"] if "start" in r
                  and "reason" not in r and "state" not in r)
        # 84 字节（64+20 开销）@1000Mbps：ceil(84*8000/1000)=672ns
        self.assertEqual(tx, {"t": 692, "port": "p2",
                              "start": 20, "bytes": 84})
        p2 = out["ports"][1]
        self.assertEqual(p2["tx_frames"], 1)
        self.assertEqual(p2["tx_bytes"], 84)
        self.assertEqual(p2["queues"][0]["sent"], 1)
        self.assertTrue(all(q["frames"] == 0 and q["bytes"] == 0
                            for q in p2["queues"]))

    def test_tagged_priority_selects_queue(self):
        cfg, links = up_pair()
        cfg["ports"] = [trunk("p1"), trunk("p2")]
        out = run(cfg, links + [
            data_event(20, "p1", vlan=1, priority=7), advance(1000000)
        ])
        enq = next(r for r in out["results"] if "queue" in r)
        self.assertEqual(enq["queue"], 3)  # map[7]=3
        self.assertEqual(enq["vlan"], 1)   # trunk 出端口保留标签：88 字节

    def test_custom_map(self):
        cfg, links = up_pair()
        cfg["ports"] = [trunk("p1"), trunk("p2")]
        cfg["qos"]["map"] = [2] * 8
        out = run(cfg, links + [
            data_event(20, "p1", vlan=1, priority=0), advance(1000000)
        ])
        self.assertEqual(
            next(r for r in out["results"] if "queue" in r)["queue"], 2
        )

    def test_no_automatic_drain_after_last_event(self):
        cfg, links = up_pair()
        # 无 advance：帧已开始发送但未完成，不计 tx，仍保留为排队状态
        out = run(cfg, links + [data_event(20, "p1")])
        self.assertFalse(any("start" in r and "state" not in r
                             for r in out["results"]))
        p2 = out["ports"][1]
        self.assertEqual(p2["tx_frames"], 0)
        self.assertEqual(p2["queues"][0]["frames"], 1)
        self.assertEqual(p2["queues"][0]["bytes"], 84)


class SchedulingTests(unittest.TestCase):
    def _trunk_cfg(self, **kw):
        c = config(**kw)
        c["ports"] = [trunk("p1"), trunk("p2")]
        return c

    def test_sp_highest_nonempty_first(self):
        # 低速口令后续帧在发送器忙时入队：填充 q0 帧先在发，另一个 q0 与
        # 一个 q3 在其完成点等待；SP 完成点先取最高非空队 q3，再取 q0
        cfg, links = up_pair(rates=(10,))
        cfg["ports"] = [trunk("p1"), trunk("p2")]
        cfg["qos"]["mode"] = "sp"
        events = links + [
            data_event(20, "p1", vlan=1, priority=0),
            data_event(21, "p1", vlan=1, priority=0,
                       src="00:00:00:00:00:02"),
            data_event(22, "p1", vlan=1, priority=3,
                       src="00:00:00:00:00:03"),
            advance(3000000),
        ]
        out = run(cfg, events)
        self.assertEqual(
            [q for _, _, q, _ in tx_sequence(out)], [0, 3, 0]
        )

    def test_wrr_weights_round_robin(self):
        # weights=[1,2,3,4] 口径同 qos-decode 持久 WRR
        cfg, links = up_pair()
        cfg["ports"] = [trunk("p1"), trunk("p2")]
        cfg["qos"]["mode"] = "wrr"
        cfg["qos"]["weights"] = [1, 2, 3, 4]
        events = list(links)
        for i, pr in enumerate([3, 3, 3, 2, 2, 2, 1, 1, 1, 0, 0, 0]):
            events.append(data_event(
                20, "p1", vlan=1, priority=pr,
                src="00:00:00:00:%02x:01" % (i + 1),
            ))
        events.append(advance(1000000))
        out = run(cfg, events)
        self.assertEqual([q for _, _, q, _ in tx_sequence(out)],
                         [3, 3, 3, 2, 2, 2, 1, 1, 1, 0, 0, 0])
        for q in range(4):
            self.assertEqual(out["ports"][1]["queues"][q]["sent"], 3)

    def test_wrr_state_persists_across_idle_time(self):
        cfg, links = up_pair()
        cfg["ports"] = [trunk("p1"), trunk("p2")]
        cfg["qos"]["mode"] = "wrr"
        cfg["qos"]["weights"] = [1, 1, 1, 4]
        events = list(links)
        # 首批仅 q3 两帧（rem 4：选取后保留 3，再选取后队空推进到 q2）
        events += [
            data_event(20, "p1", vlan=1, priority=3),
            data_event(20, "p1", vlan=1, priority=3,
                       src="00:00:00:00:00:02"),
            advance(2000),
            # 之后 q2 帧到达：推进后当前队为 q2
            data_event(3000, "p1", vlan=1, priority=2,
                       src="00:00:00:00:00:03"),
            advance(1000000),
        ]
        out = run(cfg, events)
        self.assertEqual([q for _, _, q, _ in tx_sequence(out)], [3, 3, 2])


class AdmissionTests(unittest.TestCase):
    def _trunk(self, cap=1000, drop="tail", weights=None,
               total=1000000, quota=None):
        c = config(
            [trunk("p1"), trunk("p2")], mode="sp", drop=drop, cap=cap,
            weights=weights,
        )
        c["ports"][1]["queue_bytes"] = total
        if quota is not None:
            c["ports"][1]["queue_quota"] = quota
        return c

    def test_tail_total_frame_cap(self):
        cfg = self._trunk(cap=2)
        events = [link(0, "p1", rates=[10000], modes=["full"]),
                  link(0, "p2", rates=[10000], modes=["full"])]
        for i in range(4):  # 10Mbps：全部留队，首帧在发
            events.append(data_event(
                20 + i, "p1", vlan=1, priority=3,
                src="00:00:00:00:%02x:01" % (i + 1),
            ))
        out = run(cfg, events)
        drops = [r for r in out["results"] if r.get("reason")]
        self.assertEqual(len(drops), 2)
        self.assertTrue(all(r["reason"] == "queue_full" for r in drops))
        self.assertEqual(out["ports"][1]["queue_full_frames"], 2)
        self.assertEqual(out["ports"][1]["queues"][3]["dropped"], 2)

    def test_weighted_queue_quota_frames(self):
        # cap=5、等权 => 每队配额 ceil(5/4)=2；6 个 q3 帧接纳 2、丢 4
        cfg = self._trunk(cap=5, drop="weighted", weights=[1, 1, 1, 1])
        events = [link(0, "p1", rates=[10000], modes=["full"]),
                  link(0, "p2", rates=[10000], modes=["full"])]
        for i in range(6):
            events.append(data_event(
                20 + i, "p1", vlan=1, priority=3,
                src="00:00:00:00:%02x:01" % (i + 1),
            ))
        out = run(cfg, events)
        drops = [r for r in out["results"] if r.get("reason")]
        self.assertEqual(len(drops), 4)
        self.assertTrue(all(r["reason"] == "queue_quota" for r in drops))
        q3 = out["ports"][1]["queues"][3]
        self.assertEqual(q3["dropped"], 4)
        self.assertEqual(q3["frames"] + q3["sent"], 2)

    def test_per_queue_byte_quota(self):
        # 每队列字节缓存 90：88 字节首帧接纳，次帧超出本队列限额
        cfg = self._trunk(quota=[90, 90, 90, 90])
        events = [link(0, "p1", rates=[10000], modes=["full"]),
                  link(0, "p2", rates=[10000], modes=["full"])]
        events += [
            data_event(20, "p1", vlan=1, priority=3),
            data_event(21, "p1", vlan=1, priority=3,
                       src="00:00:00:00:00:02"),
        ]
        out = run(cfg, events)
        drops = [r for r in out["results"] if r.get("reason")]
        self.assertEqual([r["reason"] for r in drops], ["queue_quota"])

    def test_total_byte_buffer(self):
        # 总字节缓存 100、各队限额充足：88 字节首帧接纳，次帧触发 queue_full
        cfg = self._trunk(total=100)
        events = [link(0, "p1", rates=[10000], modes=["full"]),
                  link(0, "p2", rates=[10000], modes=["full"])]
        events += [
            data_event(20, "p1", vlan=1, priority=3),
            data_event(21, "p1", vlan=1, priority=3,
                       src="00:00:00:00:00:02"),
        ]
        out = run(cfg, events)
        drops = [r for r in out["results"] if r.get("reason")]
        self.assertEqual([r["reason"] for r in drops], ["queue_full"])
        self.assertEqual(out["ports"][1]["queue_full_bytes"], 88)

    def test_rejection_only_affects_that_egress(self):
        # p1 入、广播到 p2/p3/p4；p3 字节缓存极小仅自己受影响
        cfg = config([
            port("p1"), port("p2"), port("p3", queue_bytes=0,
                                         queue_quota=[0, 0, 0, 0]),
            port("p4"),
        ])
        events = [
            link(0, "p1", rates=[10000], modes=["full"]),
            link(0, "p2", rates=[10000], modes=["full"]),
            link(0, "p3", rates=[10000], modes=["full"]),
            link(0, "p4", rates=[10000], modes=["full"]),
            data_event(20, "p1"),
        ]
        out = run(cfg, events)
        good = next(r for r in out["results"] if "class" in r)
        # 分类结果列出全部预期出口；接纳与否由随后的入队/丢弃记录区分
        self.assertEqual([p["name"] for p in good["ports"]],
                         ["p2", "p3", "p4"])
        enq = [r["port"] for r in out["results"]
               if "queue" in r and "reason" not in r]
        self.assertEqual(enq, ["p2", "p4"])
        drops = [r for r in out["results"] if r.get("reason")]
        self.assertEqual([(r["port"], r["reason"]) for r in drops],
                         [("p3", "queue_quota")])


class PauseTests(unittest.TestCase):
    def test_pause_defers_waiting_frame_not_inflight(self):
        cfg, links = up_pair()
        events = links + [
            data_event(100, "p1"),       # p2 发送 [100,772)
            pause_event(200, "p2", 100),  # until=51400，在发帧不动
            data_event(300, "p1",
                       src="00:00:00:00:00:02"),  # 等待帧
            advance(1000000),
        ]
        out = run(cfg, events)
        pause = next(r for r in out["results"] if r.get("action") == "pause")
        self.assertEqual(pause["quanta"], 100)
        self.assertEqual(pause["until"], 51400)
        tx = [r for r in out["results"] if "start" in r
              and "reason" not in r and "state" not in r]
        self.assertEqual([(r["start"], r["t"]) for r in tx],
                         [(100, 772), (51400, 52072)])
        # 暂停实际生效 [772,51400)
        self.assertEqual(out["ports"][1]["pause_duration_ns"], 51400 - 772)
        self.assertEqual(out["ports"][1]["pause_frames"], 1)

    def test_zero_quanta_resumes_committed_waiting_head(self):
        cfg, links = up_pair()
        events = links + [
            pause_event(20, "p2", 65535),    # 长暂停
            data_event(30, "p1"),            # 队头被门到 until，尚未开始
            pause_event(40, "p2", 0),        # 零值：当前帧完成后恢复
            advance(1000000),
        ]
        out = run(cfg, events)
        zero = [r for r in out["results"]
                if r.get("action") == "pause" and r["quanta"] == 0]
        self.assertEqual(zero[0]["until"], None)
        tx = [r for r in out["results"] if "start" in r
              and "reason" not in r and "state" not in r]
        # 队头释放时刻回到入队时刻 30，立即发送
        self.assertEqual([r["start"] for r in tx], [30])

    def test_half_duplex_pause_unsupported(self):
        cfg, links = up_pair(modes=("half",))
        out = run(cfg, links + [pause_event(20, "p1", 100)])
        r = next(x for x in out["results"]
                 if x.get("action") == "pause_unsupported")
        self.assertEqual(r["port"], "p1")
        self.assertEqual(out["ports"][0]["pause_unsupported_frames"], 1)
        self.assertEqual(out["ports"][0]["pause_frames"], 1)

    def test_flow_control_disabled(self):
        cfg, links = up_pair(flow_control=False)
        out = run(cfg, links + [pause_event(20, "p1", 100)])
        self.assertTrue(any(r.get("action") == "pause_unsupported"
                            for r in out["results"]))

    def test_malformed_pause_bad_opcode(self):
        cfg, links = up_pair()
        out = run(cfg, links + [pause_event(20, "p1", 100, opcode=0x0002)])
        r = next(x for x in out["results"]
                 if x.get("action") == "malformed_pause")
        self.assertEqual(r["port"], "p1")
        self.assertEqual(out["ports"][0]["pause_frames"], 0)

    def test_malformed_pause_bad_reserved(self):
        body = (
            mac_bytes(PAUSE_DST) + mac_bytes(MAC1) + b"\x88\x08\x00\x01"
            + (10).to_bytes(2, "big") + b"\x01" + b"\x00" * 41
        )
        fcs = (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little")
        bad = {"t": 20, "port": "p1", "data": (body + fcs).hex()}
        cfg, links = up_pair()
        out = run(cfg, links + [bad])
        self.assertTrue(any(r.get("action") == "malformed_pause"
                            for r in out["results"]))

    def test_pause_nonzero_overwrites_deadline(self):
        cfg, links = up_pair()
        events = links + [
            pause_event(20, "p2", 65535),
            pause_event(30, "p2", 1),       # 覆盖为短截止
            data_event(40, "p1"),
            advance(1000000),
        ]
        out = run(cfg, events)
        untils = [r["until"] for r in out["results"]
                  if r.get("action") == "pause"]
        self.assertEqual(untils[-1], 30 + (512000 + 1000 - 1) // 1000)
        tx = [r for r in out["results"] if "start" in r
              and "reason" not in r and "state" not in r]
        self.assertEqual(tx[0]["start"], untils[-1])


class CollisionAndLinkTests(unittest.TestCase):
    def test_half_duplex_collision(self):
        cfg, links = up_pair(modes=("half",))
        events = links + [
            data_event(20, "p2"),   # p2 入、p1 half 口开始发送 [20,692)
            data_event(100, "p1",
                       src="00:00:00:00:00:02"),  # p1 自发自收区间 => 冲突
        ]
        out = run(cfg, events)
        col = next(r for r in out["results"] if r.get("reason") == "collision")
        self.assertEqual(col["port"], "p1")
        self.assertEqual(col["start"], 20)
        self.assertEqual(col["bytes"], 84)
        self.assertEqual(col["inbound"], 84)
        p1 = out["ports"][0]
        self.assertEqual(p1["collision_frames"], 2)
        self.assertEqual(p1["collision_bytes"], 168)
        self.assertEqual(p1["tx_frames"], 0)

    def test_link_down_drops_inflight_and_waiting(self):
        # 10Mbps 出口：首帧在发，次帧等待（start 未决）；链路 down 全清
        cfg, links = up_pair(rates=(10,))
        events = links + [
            data_event(20, "p1"),
            data_event(21, "p1", src="00:00:00:00:00:02"),
            link(100, "p2", admin=False, peer=True, rates=[10],
                 modes=["full"]),
        ]
        out = run(cfg, events)
        downs = [r for r in out["results"]
                 if r.get("reason") == "link_down"]
        self.assertEqual(len(downs), 2)
        self.assertEqual(downs[0]["start"], 20)      # 在发副本带开始时刻
        self.assertIsNone(downs[1]["start"])         # 等待副本尚未开始
        p2 = out["ports"][1]
        self.assertEqual(p2["link_down_frames"], 2)
        self.assertEqual(p2["link_down_bytes"], 168)
        self.assertTrue(all(q["frames"] == 0 for q in p2["queues"]))

    def test_link_down_clears_pause(self):
        cfg, links = up_pair()
        events = links + [
            pause_event(20, "p2", 65535),
            link(30, "p2", admin=False, peer=True),
            # 重新 up：协商完成后发帧不应受旧暂停影响
            link(200, "p2", admin=True, peer=True),
            data_event(1000, "p1"),
            advance(2000000),
        ]
        out = run(cfg, events)
        tx = [r for r in out["results"] if "start" in r
              and "reason" not in r and "state" not in r]
        self.assertEqual([r["start"] for r in tx], [1000])

    def test_runt_giant_bad_fcs(self):
        cfg, links = up_pair()
        events = links + [
            data_event(20, "p1", payload_len=42),           # runt
            data_event(21, "p1", payload_len=1501,
                       src="00:00:00:00:00:02"),            # giant
            data_event(22, "p1", fcs_good=False,
                       src="00:00:00:00:00:03"),            # bad_fcs
        ]
        out = run(cfg, events)
        classes = [r["class"] for r in out["results"]
                   if "class" in r]
        self.assertEqual(classes, ["runt", "giant", "bad_fcs"])
        # 分类计数经结果项体现；端口统计沿用 link-flow-decode 的链路计数
        self.assertEqual(out["ports"][0]["rx_frames"], 3)

    def test_tagged_frame_on_access_rejected(self):
        cfg, links = up_pair()
        out = run(cfg, links + [data_event(20, "p1", vlan=1, priority=7)])
        r = next(x for x in out["results"] if "class" in x)
        self.assertEqual(r["action"], "drop")
        self.assertEqual(r["ports"], [])


class OutputContractTests(unittest.TestCase):
    def test_top_and_record_key_orders(self):
        cfg, links = up_pair()
        proc, _ = run_cli(cfg, links + [data_event(20, "p1"),
                                        advance(1000000)])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        raw = proc.stdout
        doc = json.loads(raw.decode())
        self.assertEqual(list(doc), ["results", "ports"])
        self.assertEqual(list(doc["ports"][0]),
                         ["name", "queues", "rx_frames", "rx_bytes",
                          "tx_frames", "tx_bytes", "collision_frames",
                          "collision_bytes", "queue_full_frames",
                          "queue_full_bytes", "link_down_frames",
                          "link_down_bytes", "pause_frames",
                          "pause_unsupported_frames", "pause_duration_ns"])
        self.assertEqual(list(doc["ports"][0]["queues"][0]),
                         ["frames", "bytes", "sent", "dropped"])
        enq = next(r for r in doc["results"] if "queue" in r)
        self.assertEqual(list(enq), ["t", "port", "vlan", "queue", "bytes"])
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b': ', raw)

    def test_repeat_byte_identical(self):
        cfg, links = up_pair()
        events = links + [
            data_event(20, "p1"),
            data_event(21, "p1", src="00:00:00:00:00:02"),
            pause_event(50, "p2", 10),
            advance(1000000),
        ]
        a, _ = run_cli(cfg, events)
        b, _ = run_cli(cfg, events)
        self.assertEqual(a.stdout, b.stdout)


class ValidationTests(unittest.TestCase):
    def _exit4(self, events, cfg=None):
        c = cfg if cfg is not None else config()
        proc, _ = run_cli(c, events)
        self.assertEqual(proc.returncode, 4)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr.strip(), b'{"error":"invalid_input"}')

    def test_service_event_is_illegal(self):
        self._exit4([{"t": 0, "port": "p1", "count": 1}])

    def test_abstract_frame_shape_rejected(self):
        self._exit4([{
            "t": 0, "port": "p1", "src": MAC1, "dst": BCAST, "vlan": None,
            "length": 64, "fcs": True, "alignment": True,
        }])

    def test_missing_qos_invalid(self):
        cfg = config()
        del cfg["qos"]
        self._exit4([], cfg=cfg)

    def test_missing_queue_quota_invalid(self):
        cfg = config([port("p1"), port("p2")])
        del cfg["ports"][0]["queue_quota"]
        self._exit4([], cfg=cfg)

    def test_bad_queue_quota_invalid(self):
        cfg = config([port("p1"), port("p2")])
        cfg["ports"][0]["queue_quota"] = [1, 2, 3]
        self._exit4([], cfg=cfg)
        cfg = config([port("p1"), port("p2")])
        cfg["ports"][0]["queue_quota"] = [1, 2, 3, -1]
        self._exit4([], cfg=cfg)

    def test_bad_qos_fields_invalid(self):
        base = config()
        for mut in (
            lambda c: c["qos"].update(map=[0] * 7),
            lambda c: c["qos"].update(map=[4] * 8),
            lambda c: c["qos"].update(cap=0),
            lambda c: c["qos"].update(mode="rr"),
            lambda c: c["qos"].update(weights=[1, 1, 1, 0]),
            lambda c: c["qos"].update(drop="red"),
        ):
            cfg = json.loads(json.dumps(base))
            mut(cfg)
            self._exit4([], cfg=cfg)

    def test_double_tag_rejected(self):
        frame = raw_frame(0, "p1", vlan=1)
        raw = bytes.fromhex(frame["data"])
        frame["data"] = (raw[:16] + b"\x81\x00\x10\x00" + raw[16:]).hex()
        self._exit4([frame])

    def test_t_not_monotonic(self):
        self._exit4([advance(2), advance(1)])

    def test_missing_file_exit3(self):
        _, _, evt = write_inputs(config(), [])
        proc = subprocess.run(
            [sys.executable, SWITCH, "qos-wire-decode", "/nope/c", evt],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr.strip(), b'{"error":"file_not_found"}')

    def test_usage_exit2(self):
        _, cfg, evt = write_inputs(config(), [])
        for argv in (
            ["qos-wire-decode", cfg],
            ["qos-wire-decode", cfg, evt, "1"],
            ["qos-wire-decode", cfg, evt, "0"],
        ):
            proc = subprocess.run(
                [sys.executable, SWITCH, *argv],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(proc.returncode, 2, argv)
            self.assertIn(b"usage", proc.stderr)


class ResourceAndWorkTests(unittest.TestCase):
    def test_limits_exit5(self):
        cfg, links = up_pair()
        events = links
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
        # W 初值 P=2；两 link 各计事件 1 + 结果 1 => 6；
        # 数据帧：事件 1 + 分类结果 1 + 入队结果 1 + 调度选取 1 => 10；
        # advance：事件 1 + 发送完成结果 1 => 12
        cfg, links = up_pair()
        events = links + [data_event(20, "p1"), advance(1000000)]
        proc, _ = run_cli(cfg, events,
                          1000000, 1000000, 1000000, 1000000, 12)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        proc, _ = run_cli(cfg, events,
                          1000000, 1000000, 1000000, 1000000, 11)
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr,
                         b'{"error":"qos_wire_work_limit"}\n')

    def test_full_validation_before_work(self):
        # 非法输入先于工作量预演拒绝：stdout 必须为空
        frame = raw_frame(0, "p1", vlan=1)
        raw = bytes.fromhex(frame["data"])
        frame["data"] = (raw[:16] + b"\x81\x00\x10\x00" + raw[16:]).hex()
        proc, _ = run_cli(
            config(), [frame], 1000000, 1000000, 1000000, 1000000, 1
        )
        self.assertEqual(proc.returncode, 4)
        self.assertEqual(proc.stdout, b"")


if __name__ == "__main__":
    unittest.main()
