#!/usr/bin/env python3
"""qos-wire-decode 子命令回归：四优先级队列在线速链路上的确定性发送。

CONFIG 在 link-flow-decode（端口模式/协商/queue_bytes/flow_control/老化/
最大帧）顶层再加 qos（map/cap/mode/weights/drop，形状同 qos-decode）；
事件仅接受 link/advance/{t,port,data} 原始帧（service 非法）。出口副本
按最终 802.1Q 优先级入四队列，受本队列与端口总字节限额约束；发送器空闲
点按 sp（最高非空）或 wrr（续用权重轮次、跳过空队列）选取；协商、半双工
冲突与 802.3x PAUSE 沿用 link-flow-decode；末事件后不自动排空。

仅用标准库；端到端驱动 `python switch.py qos-wire-decode CONFIG EVENTS`。
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


def port(name, pvid=1, mode="trunk", rates=None, modes=None,
         queue_bytes=1000000, flow_control=True):
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


def link_down(t, p):
    return {
        "t": t, "port": p, "admin": False, "peer": True,
        "rates": [1000], "modes": ["full"],
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


def run_cli(config_doc, events, *limits):
    with tempfile.TemporaryDirectory() as tmp:
        cfg = os.path.join(tmp, "config.json")
        evt = os.path.join(tmp, "events.json")
        with open(cfg, "wb") as handle:
            handle.write(json.dumps(config_doc).encode("utf-8"))
        with open(evt, "wb") as handle:
            handle.write(json.dumps(events).encode("utf-8"))
        proc = subprocess.run(
            [sys.executable, SWITCH, "qos-wire-decode", cfg, evt,
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


class SchedulerTests(unittest.TestCase):
    def test_sp_prefers_highest_nonempty_waiting_queue(self):
        events = [
            link(0, "p1"), link(0, "p2"),
            raw_frame(100, "p1", prio=0),
            raw_frame(101, "p1", src="00:00:00:00:00:02", prio=0),
            raw_frame(102, "p1", src="00:00:00:00:00:03", prio=3),
            advance(5000),
        ]
        out = run(config(), events)
        self.assertEqual([r["queue"] for r in tx(out)], [0, 3, 0])
        self.assertEqual(
            [r["start"] for r in tx(out)], [100, 100 + DUR, 100 + 2 * DUR]
        )
        # 时长按协商速率与帧长（含开销）向上取整
        self.assertEqual(tx(out)[0]["t"], 100 + DUR)

    def test_sp_single_waiting_copy_picked_at_completion(self):
        events = [
            link(0, "p1"), link(0, "p2"),
            raw_frame(100, "p1", prio=0),
            raw_frame(101, "p1", src="00:00:00:00:00:02", prio=3),
            advance(5000),
        ]
        out = run(config(), events)
        self.assertEqual(
            [(r["queue"], r["start"]) for r in tx(out)],
            [(0, 100), (3, 100 + DUR)],
        )

    def test_wrr_round_order_and_skip_empty(self):
        events = [link(0, "p1"), link(0, "p2"), raw_frame(100, "p1", prio=0)]
        for i, prio in enumerate((3, 2, 1, 0, 3, 2, 1)):
            events.append(
                raw_frame(101, "p1",
                          src="00:00:00:00:00:%02x" % (i + 2), prio=prio)
            )
        events.append(advance(20000))
        out = run(config(q=qos(mode="wrr")), events)
        self.assertEqual(
            [r["queue"] for r in tx(out)], [0, 3, 2, 1, 0, 3, 2, 1]
        )
        # 空队列被跳过，轮次状态续用
        events = [link(0, "p1"), link(0, "p2"), raw_frame(100, "p1", prio=3)]
        for i, prio in enumerate((1, 3, 1)):
            events.append(
                raw_frame(101, "p1",
                          src="00:00:00:00:00:%02x" % (i + 2), prio=prio)
            )
        events.append(advance(20000))
        out = run(config(q=qos(mode="wrr")), events)
        self.assertEqual([r["queue"] for r in tx(out)], [3, 1, 3, 1])

    def test_wrr_state_continues_across_idle_period(self):
        events = [
            link(0, "p1"), link(0, "p2"),
            raw_frame(100, "p1", prio=3),
            raw_frame(101, "p1", src="00:00:00:00:00:02", prio=3),
            advance(20000),
            raw_frame(30000, "p1", src="00:00:00:00:00:03", prio=1),
            advance(40000),
        ]
        out = run(config(q=qos(mode="wrr")), events)
        self.assertEqual([r["queue"] for r in tx(out)], [3, 3, 1])

    def test_tail_per_queue_byte_limit_quota_full(self):
        events = [
            link(0, "p1"), link(0, "p2"),
            raw_frame(100, "p1", prio=0),
            raw_frame(101, "p1", src="00:00:00:00:00:02", prio=0),
            advance(5000),
        ]
        out = run(config(q=qos(cap=100)), events)
        reasons = [r["reason"] for r in out["results"] if "reason" in r]
        self.assertEqual(reasons, ["quota_full"])
        self.assertEqual(out["ports"][1]["quota_full_frames"], 1)
        self.assertEqual(out["ports"][1]["quota_full_bytes"], WIRE_TAGGED)

    def test_total_buffer_queue_full(self):
        events = [
            link(0, "p1"), link(0, "p2"),
            raw_frame(100, "p1", prio=0),
            raw_frame(101, "p1", src="00:00:00:00:00:02", prio=0),
            advance(5000),
        ]
        out = run(
            config(q=qos(cap=1000000), ports=[
                port("p1", queue_bytes=1000000),
                port("p2", queue_bytes=90),
            ]),
            events,
        )
        reasons = [r["reason"] for r in out["results"] if "reason" in r]
        self.assertEqual(reasons, ["queue_full"])

    def test_weighted_drop_uses_weight_quotas(self):
        events = [
            link(0, "p1"), link(0, "p2"),
            raw_frame(100, "p1", prio=0), advance(5000),
        ]
        out = run(config(q=qos(drop="weighted", weights=[1, 1, 1, 1],
                               cap=120)), events)
        # 每队列配额 ceil(120/4)=30 < 88 字节副本
        reasons = [r["reason"] for r in out["results"] if "reason" in r]
        self.assertEqual(reasons, ["quota_full"])

    def test_drop_only_affects_that_egress_copy(self):
        # p2 总字节缓存小于单副本（88 字节）不影响同帧向 p3 的副本
        ports = [port("p1"), port("p2", queue_bytes=80), port("p3")]
        events = [
            link(0, "p1"), link(0, "p2"), link(0, "p3"),
            raw_frame(100, "p1"), advance(5000),
        ]
        out = run(config(q=qos(cap=1000000), ports=ports), events)
        reasons = [
            (r["port"], r["reason"])
            for r in out["results"] if "reason" in r
        ]
        self.assertEqual(reasons, [("p2", "queue_full")])
        sent_ports = {r["port"] for r in tx(out)}
        self.assertEqual(sent_ports, {"p3"})


class LinkSemanticsTests(unittest.TestCase):
    def test_pause_delays_waiting_copy(self):
        events = [
            link(0, "p1"), link(0, "p2"),
            raw_frame(100, "p1"),
            raw_frame(150, "p1", src="00:00:00:00:00:02"),
            pause_event(200, "p2", 10),
            advance(100000),
        ]
        out = run(config(), events)
        records = tx(out)
        # until = 200 + ceil(10*512000/1000) = 5320；在发帧 100..804 不动，
        # 等待副本开始时刻夹到 5320
        self.assertEqual(records[0]["start"], 100)
        self.assertEqual(records[1]["start"], 5320)
        self.assertEqual(out["ports"][1]["pause_frames"], 1)

    def test_zero_quanta_recovers_after_current_frame(self):
        events = [
            link(0, "p1"), link(0, "p2"),
            raw_frame(100, "p1"),
            raw_frame(150, "p1", src="00:00:00:00:00:02"),
            pause_event(200, "p2", 1000),
            pause_event(300, "p2", 0),
            advance(100000),
        ]
        out = run(config(), events)
        self.assertEqual(
            [r["start"] for r in tx(out)], [100, 100 + DUR]
        )
        pause_results = [r for r in out["results"]
                         if r.get("action") == "pause"]
        self.assertEqual(pause_results[1]["until"], None)

    def test_malformed_pause_is_runtime_result(self):
        body = (
            mac_bytes(PAUSE_DST) + mac_bytes(MAC1) + b"\x88\x08\x00\x02"
            + (10).to_bytes(2, "big") + b"\x00" * 42
        )
        fcs = (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little")
        bad = {"t": 100, "port": "p1", "data": (body + fcs).hex()}
        out = run(config(), [link(0, "p1"), bad])
        actions = [r.get("action") for r in out["results"] if "action" in r]
        self.assertEqual(actions, ["malformed_pause"])

    def test_half_duplex_collision(self):
        ports = [
            port("p1", modes=["half"]),
            port("p2", modes=["half"]),
        ]
        events = [
            link(0, "p1", modes=("half",)), link(0, "p2", modes=("half",)),
            raw_frame(100, "p2"),  # 洪泛到 p1，p1 正在发送
            raw_frame(200, "p1", src="00:00:00:00:00:09"),
            advance(5000),
        ]
        out = run(config(ports=ports), events)
        collisions = [r for r in out["results"]
                      if r.get("reason") == "collision"]
        self.assertEqual(len(collisions), 1)
        self.assertEqual(collisions[0]["port"], "p1")
        self.assertIn("queue", collisions[0])
        self.assertEqual(out["ports"][0]["collision_frames"], 2)

    def test_link_down_clears_all_queues_as_link_down(self):
        events = [
            link(0, "p1"), link(0, "p2"),
            raw_frame(100, "p1", prio=0),
            raw_frame(101, "p1", src="00:00:00:00:00:02", prio=3),
            link_down(200, "p2"),
            advance(5000),
        ]
        out = run(config(), events)
        dropped = [r for r in out["results"]
                   if r.get("reason") == "link_down"]
        self.assertEqual(len(dropped), 2)
        self.assertEqual({r["queue"] for r in dropped}, {0, 3})
        for qi in range(4):
            self.assertEqual(out["ports"][1]["queues"][qi]["frames"], 0)
            self.assertEqual(out["ports"][1]["queues"][qi]["bytes"], 0)

    def test_no_auto_drain_after_last_event(self):
        events = [link(0, "p1"), link(0, "p2"), raw_frame(100, "p1")]
        out = run(config(), events)
        self.assertEqual(tx(out), [])
        # 已入队但未结算的副本仍计入各队列剩余帧/字节
        self.assertEqual(
            out["ports"][1]["queues"][0],
            {"frames": 1, "bytes": WIRE_TAGGED, "sent": 0, "dropped": 0},
        )


class OutputContractTests(unittest.TestCase):
    def test_fixed_key_orders(self):
        events = [
            link(0, "p1"), link(0, "p2"),
            raw_frame(100, "p1"), advance(5000),
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
             "pause_duration_ns"],
        )
        self.assertEqual(
            list(doc["ports"][0]["queues"][0]),
            ["frames", "bytes", "sent", "dropped"],
        )
        enqueue = next(
            r for r in doc["results"]
            if "vlan" in r and "reason" not in r and "class" not in r
        )
        self.assertEqual(list(enqueue), ["t", "port", "vlan", "bytes",
                                         "queue"])
        self.assertEqual(list(tx(doc)[0]),
                         ["t", "port", "start", "bytes", "queue"])
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b": ", raw)

    def test_deterministic(self):
        events = [
            link(0, "p1"), link(0, "p2"),
            raw_frame(100, "p1"),
            raw_frame(101, "p1", src="00:00:00:00:00:02", prio=3),
            advance(9000),
        ]
        a = run_cli(config(), events).stdout
        b = run_cli(config(), events).stdout
        self.assertEqual(a, b)


class ValidationAndResourceTests(unittest.TestCase):
    def test_service_event_is_invalid(self):
        proc = run_cli(config(), [link(0, "p1"),
                                  {"t": 1, "port": "p2", "count": 1}])
        self.assertEqual(proc.returncode, 4)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr.strip(), b'{"error":"invalid_input"}')

    def test_member_and_abstract_frame_events_invalid(self):
        proc = run_cli(config(), [{"t": 1, "member": "p2", "up": True}])
        self.assertEqual(proc.returncode, 4)
        abstract = {
            "t": 1, "port": "p1", "src": MAC1, "dst": BCAST, "vlan": None,
            "length": 64, "fcs": True, "alignment": True,
        }
        proc = run_cli(config(), [abstract])
        self.assertEqual(proc.returncode, 4)

    def test_bad_config(self):
        base = config()
        bad_docs = []
        doc = json.loads(json.dumps(base))
        del doc["qos"]
        bad_docs.append(doc)
        for mutate in (
            lambda c: c["qos"].__setitem__("map", [0] * 7),
            lambda c: c["qos"].__setitem__("weights", [1, 1, 1, 0]),
            lambda c: c["qos"].__setitem__("mode", "rr"),
            lambda c: c["qos"].__setitem__("drop", "red"),
            lambda c: c["qos"].__setitem__("cap", 0),
        ):
            doc = json.loads(json.dumps(base))
            mutate(doc)
            bad_docs.append(doc)
        for doc in bad_docs:
            proc = run_cli(doc, [])
            self.assertEqual(proc.returncode, 4, doc)
            self.assertEqual(proc.stdout, b"")

    def test_file_not_found(self):
        proc = subprocess.run(
            [sys.executable, SWITCH, "qos-wire-decode", "/nope/c", "/nope/e"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr.strip(), b'{"error":"file_not_found"}')

    def test_resource_limits(self):
        events = [link(0, "p1"), link(0, "p2"), raw_frame(100, "p1"),
                  advance(5000)]
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
        events = [link(0, "p1"), link(0, "p2"), raw_frame(100, "p1")]
        proc = run_cli(
            config(), events, 1000000, 1000000, 1000000, 1000000, 2
        )
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(
            proc.stderr.strip(), b'{"error":"qos_wire_work_limit"}'
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
                    [sys.executable, SWITCH, "qos-wire-decode", cfg, evt,
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
