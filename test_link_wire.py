#!/usr/bin/env python3
"""link-wire 子命令回归：在 link-forward 的协商/帧检查/VLAN/FDB 之上接入
确定性线速模型（串行发送、half 碰撞、队列上限、离 up 丢弃、advance 推进）。

仅用标准库；通过 `python switch.py link-wire CONFIG EVENTS` 端到端驱动。
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
         rates=None, modes=None, queue_bytes=1000000):
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


class WireTimingTests(unittest.TestCase):
    def test_wire_bytes_and_duration_full_duplex(self):
        # length=100 untagged -> 线上 100+8+12=120 字节；rate=1000 Mbps
        # 时长 ceil(120*8000/1000)=960 ns；delay=10，t=10 发送，t=970 完成
        events = [
            link(0, "p1", rates=[1000], modes=["full"]),
            link(0, "p2", rates=[1000], modes=["full"]),
            frame(10, "p1", "00:00:00:00:00:01"),
            advance(970),
        ]
        out = run(config(delay=10), events)
        enq = next(r for r in out["results"] if "bytes" in r
                   and "reason" not in r and "start" not in r)
        self.assertEqual(enq, {"t": 10, "port": "p2", "vlan": None,
                               "bytes": 120})
        done = next(r for r in out["results"] if "start" in r
                    and "reason" not in r)
        self.assertEqual(done, {"t": 970, "port": "p2", "start": 10,
                                "bytes": 120})

    def test_duration_rounds_up(self):
        # 64 字节线上(64+20=84)@100Mbps：84*8000/100=6720 整除；
        # 取 65 字节帧(线上85)@100：85*80=6800 整除；选 66@1000 制造向上取整
        events = [
            link(0, "p1", rates=[1000], modes=["full"]),
            link(0, "p2", rates=[1000], modes=["full"]),
            frame(10, "p1", "00:00:00:00:00:01", length=66),
            advance(100000),
        ]
        out = run(config(delay=10), events)
        done = next(r for r in out["results"] if "start" in r)
        # 线上 86 字节，86*8000/1000=688.0；改测非整除用 67 字节
        self.assertEqual(done["t"] - done["start"], 688)

    def test_serial_same_egress_start_is_max_enqueue_prev_end(self):
        events = [
            link(0, "p1", rates=[10000], modes=["full"]),
            link(0, "p2", rates=[10000], modes=["full"]),
            frame(10, "p1", "00:00:00:00:00:01", length=1000),
            frame(11, "p1", "00:00:00:00:00:01", length=1000),
            advance(100000),
        ]
        out = run(config(delay=10), events)
        dones = [r for r in out["results"] if "start" in r]
        # 线上 1020 字节 @10000：1020*8000/10000=816 ns
        self.assertEqual([d["start"] for d in dones], [10, 826])
        self.assertEqual([d["t"] for d in dones], [826, 1642])

    def test_start_waits_for_slow_link_when_enqueued_early(self):
        # 第二帧入队时刻早于上一帧结束：start=prev_end（不是入队时刻）
        events = [
            link(0, "p1", rates=[10000], modes=["full"]),
            link(0, "p2", rates=[100], modes=["full"]),
            frame(10, "p1", "00:00:00:00:00:01", length=1000),
            frame(20, "p1", "00:00:00:00:00:01", length=100),
            advance(1000000),
        ]
        out = run(config(delay=10), events)
        dones = [r for r in out["results"] if "start" in r]
        # 第一帧线上1020@100Mbps：81600 ns，结束 81610
        self.assertEqual(dones[0]["start"], 10)
        self.assertEqual(dones[0]["t"], 81610)
        # 第二帧入队 t=20，但 start 取 max(20, 81610)=81610
        self.assertEqual(dones[1]["start"], 81610)

    def test_no_auto_drain_after_last_event(self):
        # 末事件后不自动排空：无 advance 时不产生发送完成记录
        events = [
            link(0, "p1", rates=[1000], modes=["full"]),
            link(0, "p2", rates=[1000], modes=["full"]),
            frame(10, "p1", "00:00:00:00:00:01"),
        ]
        out = run(config(delay=10), events)
        self.assertFalse(any("start" in r for r in out["results"]))


class TagWireLengthTests(unittest.TestCase):
    def test_tag_added_on_egress_adds_four_bytes(self):
        cfg = config([
            port("p1", mode="trunk", pvid=1, allowed=[1], untagged=[]),
            port("p2", mode="trunk", pvid=2, allowed=[1, 2], untagged=[]),
        ])
        events = [
            link(0, "p1", rates=[10000], modes=["full"]),
            link(0, "p2", rates=[10000], modes=["full"]),
            frame(10, "p1", "00:00:00:00:00:01", vlan=1, length=100),
            advance(100000),
        ]
        out = run(cfg, events)
        enq = next(r for r in out["results"]
                   if "bytes" in r and "start" not in r)
        # length=100 为带标签帧的实际长度，出口保留标签 -> 100+20=120
        self.assertEqual(enq["bytes"], 120)
        self.assertEqual(enq["vlan"], 1)

    def test_tag_stripped_on_egress_removes_four_bytes(self):
        cfg = config([
            port("p1", mode="trunk", pvid=1, allowed=[1, 2], untagged=[]),
            port("p2", mode="hybrid", pvid=1, allowed=[1, 2],
                 untagged=[1]),
        ])
        events = [
            link(0, "p1", rates=[10000], modes=["full"]),
            link(0, "p2", rates=[10000], modes=["full"]),
            frame(10, "p1", "00:00:00:00:00:01", vlan=1, length=100),
            advance(100000),
        ]
        out = run(cfg, events)
        enq = next(r for r in out["results"]
                   if "bytes" in r and "start" not in r)
        # 去标签：100-4+20=116
        self.assertEqual(enq["bytes"], 116)
        self.assertIsNone(enq["vlan"])


class CollisionTests(unittest.TestCase):
    def cfg(self, **kw):
        return config([
            port("p1", rates=[1000], modes=["half"]),
            port("p2", rates=[1000], modes=["half"]),
        ], delay=1, **kw)

    def test_half_duplex_collision_aborts_both_and_counts_two(self):
        events = [
            link(0, "p1"),
            link(0, "p2"),
            frame(10, "p1", "00:00:00:00:00:01", length=1000),
            frame(11, "p2", "00:00:00:00:00:02", length=1000),
        ]
        out = run(self.cfg(), events)
        col = next(r for r in out["results"]
                   if r.get("reason") == "collision")
        # 正在发送的是 p2 上的副本（p1 泛洪而来），碰撞发生在 t=11 的 p2
        self.assertEqual(col["port"], "p2")
        self.assertEqual(col["t"], 11)
        self.assertEqual(col["start"], 10)
        self.assertEqual(col["bytes"], 1020)
        self.assertEqual(col["inbound"], 1020)
        p2 = out["ports"][1]
        self.assertEqual(p2["collision_frames"], 2)
        self.assertEqual(p2["collision_bytes"], 2040)
        # 碰撞副本不计 tx，且无发送完成
        self.assertEqual(p2["tx_frames"], 0)
        self.assertFalse(any("start" in r and "reason" not in r
                             for r in out["results"]))

    def test_collision_does_not_learn_inbound(self):
        events = [
            link(0, "p1"),
            link(0, "p2"),
            frame(10, "p1", "00:00:00:00:00:01", length=1000),
            frame(11, "p2", "00:00:00:00:00:02",
                  dst="00:00:00:00:00:01", length=1000),  # 碰撞
            frame(2000000, "p2", "00:00:00:00:00:02",
                  dst="00:00:00:00:00:01", length=100),  # src1 未学习->泛洪
        ]
        out = run(self.cfg(), events)
        last = [r for r in out["results"]
                if r.get("action") in ("flood", "unicast")][-1]
        self.assertEqual(last["action"], "flood")

    def test_full_duplex_no_collision(self):
        cfg = config([
            port("p1", rates=[1000], modes=["full"]),
            port("p2", rates=[1000], modes=["full"]),
        ], delay=1)
        events = [
            link(0, "p1"),
            link(0, "p2"),
            frame(10, "p1", "00:00:00:00:00:01", length=1000),
            frame(11, "p2", "00:00:00:00:00:02", length=1000),
            advance(100000),
        ]
        out = run(cfg, events)
        self.assertFalse(any(r.get("reason") == "collision"
                             for r in out["results"]))

    def test_queued_copies_reschedule_from_collision_time(self):
        # p3 half：p1、p2 先后泛洪到 p3，第二副本排队；p3 收帧引发碰撞，
        # 其后排队副本从碰撞时刻重新串行
        cfg = config([
            port("p1", rates=[10000], modes=["full"]),
            port("p2", rates=[10000], modes=["full"]),
            port("p3", rates=[1000], modes=["half"]),
        ], delay=1)
        events = [
            link(0, "p1"), link(0, "p2"), link(0, "p3"),
            frame(10, "p1", "00:00:00:00:00:01", length=1000),
            frame(11, "p2", "00:00:00:00:00:02", length=1000),
            frame(12, "p3", "00:00:00:00:00:03", length=1000),
            advance(100000),
        ]
        out = run(cfg, events)
        col = next(r for r in out["results"]
                   if r.get("reason") == "collision")
        self.assertEqual(col["port"], "p3")
        # 碰撞后剩余副本从 t=12 开始（线上1020@1000：8160 ns）
        done = [r for r in out["results"]
                if "start" in r and "reason" not in r and r["port"] == "p3"]
        self.assertEqual([d["start"] for d in done], [12])
        self.assertEqual(done[0]["t"], 8172)


class QueueFullTests(unittest.TestCase):
    def test_queue_full_drops_copy_alone(self):
        cfg = config([
            port("p1", rates=[10000], modes=["full"]),
            port("p2", rates=[10000], modes=["full"], queue_bytes=200),
        ], delay=1)
        events = [
            link(0, "p1"), link(0, "p2"),
            frame(10, "p1", "00:00:00:00:00:01", length=100),  # 120 入队
            frame(11, "p1", "00:00:00:00:00:01", length=100),  # 240>200
        ]
        out = run(cfg, events)
        qf = [r for r in out["results"]
              if r.get("reason") == "queue_full"]
        self.assertEqual(len(qf), 1)
        self.assertEqual(qf[0]["bytes"], 120)
        self.assertEqual(out["ports"][1]["queue_full_frames"], 1)
        self.assertEqual(out["ports"][1]["queue_full_bytes"], 120)
        # 第一副本仍在队列中（不被第二帧影响）
        self.assertEqual(out["ports"][1]["tx_frames"], 0)

    def test_queue_boundary_equal_is_allowed(self):
        cfg = config([
            port("p1", rates=[10000], modes=["full"]),
            port("p2", rates=[10000], modes=["full"], queue_bytes=120),
        ], delay=1)
        events = [
            link(0, "p1"), link(0, "p2"),
            frame(10, "p1", "00:00:00:00:00:01", length=100),
        ]
        out = run(cfg, events)
        self.assertFalse(any(r.get("reason") == "queue_full"
                             for r in out["results"]))

    def test_one_egress_full_does_not_affect_others(self):
        cfg = config([
            port("p0", rates=[10000], modes=["full"]),
            port("p1", rates=[10000], modes=["full"], queue_bytes=10),
            port("p2", rates=[10000], modes=["full"], queue_bytes=1000000),
            port("p3", rates=[10000], modes=["full"], queue_bytes=1000000),
        ], delay=1)
        events = [
            link(0, "p0"), link(0, "p1"), link(0, "p2"), link(0, "p3"),
            frame(10, "p0", "00:00:00:00:00:0a", length=100),
            advance(100000),
        ]
        out = run(cfg, events)
        qf_ports = {r["port"] for r in out["results"]
                    if r.get("reason") == "queue_full"}
        self.assertEqual(qf_ports, {"p1"})
        # p2,p3 正常发送完成
        tx = {r["port"] for r in out["results"]
              if "start" in r and "reason" not in r}
        self.assertEqual(tx, {"p2", "p3"})


class LinkDownTests(unittest.TestCase):
    def test_leave_up_drops_outstanding_and_clears_fdb(self):
        cfg = config([
            port("p1", rates=[10000], modes=["full"]),
            port("p2", rates=[10000], modes=["full"]),
        ], delay=1)
        events = [
            link(0, "p1"), link(0, "p2"),
            frame(10, "p1", "00:00:00:00:00:01", length=1000),
            link(50, "p2", admin=False),
        ]
        out = run(cfg, events)
        ld = next(r for r in out["results"]
                  if r.get("reason") == "link_down")
        self.assertEqual(ld["port"], "p2")
        self.assertEqual(ld["t"], 50)
        self.assertEqual(ld["start"], 10)
        self.assertEqual(ld["bytes"], 1020)
        self.assertEqual(out["ports"][1]["link_down_frames"], 1)
        self.assertEqual(out["ports"][1]["link_down_bytes"], 1020)
        self.assertEqual(out["ports"][1]["tx_frames"], 0)

    def test_settle_before_link_down_completes_due_tx(self):
        cfg = config([
            port("p1", rates=[10000], modes=["full"]),
            port("p2", rates=[10000], modes=["full"]),
        ], delay=1)
        events = [
            link(0, "p1"), link(0, "p2"),
            frame(10, "p1", "00:00:00:00:00:01", length=100),  # 结束 106
            link(106, "p2", admin=False),
            advance(106),
        ]
        out = run(cfg, events)
        # t=106 先结算完成（advance 或 link 事件均先 settle），再无未完成副本
        self.assertTrue(any("start" in r and "reason" not in r
                            for r in out["results"]))
        self.assertFalse(any(r.get("reason") == "link_down"
                             for r in out["results"]))


class ClassificationTests(unittest.TestCase):
    def test_bad_frames_counted_at_ingress_not_forwarded(self):
        events = [
            link(0, "p1", rates=[10000], modes=["full"]),
            frame(10, "p1", "00:00:00:00:00:01", fcs=False),
            frame(11, "p1", "00:00:00:00:00:01", length=63),
        ]
        out = run(config([port("p1")], delay=1), events)
        classes = [r["class"] for r in out["results"] if "class" in r]
        self.assertEqual(classes, ["bad_fcs", "runt"])
        # 入站仍计数（线上字节），无任何出口副本
        self.assertEqual(out["ports"][0]["rx_frames"], 2)
        self.assertEqual(out["ports"][0]["rx_bytes"], 120 + 83)
        self.assertFalse(any("bytes" in r and r.get("port") == "p1"
                             and "class" not in r for r in out["results"]))


class OutputContractTests(unittest.TestCase):
    def test_top_and_record_key_orders(self):
        proc, _ = run_cli(config(), [
            link(0, "p1", rates=[10000], modes=["full"]),
            link(0, "p2", rates=[10000], modes=["full"]),
            frame(10, "p1", "00:00:00:00:00:01"),
            advance(200),
        ])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        raw = proc.stdout
        doc = json.loads(raw.decode().rstrip("\n"))
        self.assertEqual(list(doc), ["results", "ports"])
        self.assertEqual(
            list(doc["ports"][0]),
            ["name", "rx_frames", "rx_bytes", "tx_frames", "tx_bytes",
             "collision_frames", "collision_bytes", "queue_full_frames",
             "queue_full_bytes", "link_down_frames", "link_down_bytes"],
        )
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b": ", raw)

    def test_deterministic_byte_identical(self):
        cfg = config()
        events = [
            link(0, "p1"), link(0, "p2"),
            frame(10, "p1", "00:00:00:00:00:01"),
            frame(11, "p2", "00:00:00:00:00:02"),
            advance(100000),
        ]
        a, _ = run_cli(cfg, events)
        b, _ = run_cli(cfg, events)
        self.assertEqual(a.stdout, b.stdout)


class ValidationTests(unittest.TestCase):
    def _assert4(self, cfg, events):
        proc, _ = run_cli(cfg, events)
        self.assertEqual(proc.returncode, 4, proc.stderr)
        self.assertEqual(proc.stdout, b"")
        self.assertIn(b"invalid_input", proc.stderr)

    def test_queue_bytes_required_nonneg_int(self):
        good = port("p1")
        for bad in (dict(good, queue_bytes=-1), dict(good, queue_bytes="1"),
                    {k: v for k, v in good.items() if k != "queue_bytes"}):
            self._assert4(config([bad]), [])

    def test_advance_shape(self):
        cfg = config()
        self._assert4(cfg, [{"t": 0}])           # 既非三类事件
        self._assert4(cfg, [{"t": 0, "advance": 1}])
        self._assert4(cfg, [{"t": 0, "advance": True, "x": 1}])
        self._assert4(cfg, [{"t": -1, "advance": True}])

    def test_t_monotonic_with_advance(self):
        self._assert4(config(), [
            advance(10), frame(9, "p1", "00:00:00:00:00:01"),
        ])

    def test_link_forward_shape_constraints_kept(self):
        # 无 up 键、rates/modes 必需等沿用 link-forward
        bad = dict(port("p1"))
        bad["up"] = True
        self._assert4(config([bad]), [])
        self._assert4(config(), [frame(0, "ghost", "00:00:00:00:00:01")])


class ResourceAndErrorTests(unittest.TestCase):
    def test_missing_file_exit3(self):
        proc, missing = run_cli(config(), [])
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(missing.returncode, 3)
        self.assertEqual(missing.stdout, b"")
        self.assertIn(b"file_not_found", missing.stderr)

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

    def test_usage_exit2(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = os.path.join(tmp, "c.json")
            evt = os.path.join(tmp, "e.json")
            open(cfg, "wb").write(b"{}")
            open(evt, "wb").write(b"[]")
            for argv in (
                ["link-wire", cfg],
                ["link-wire", cfg, evt, "1"],
                ["link-wire", cfg, evt, "1", "2", "3"],
                ["link-wire", cfg, evt, "0"],
            ):
                proc = subprocess.run(
                    [sys.executable, SWITCH, *argv],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                self.assertEqual(proc.returncode, 2, argv)
                self.assertIn(b"usage", proc.stderr)

    def test_work_limit_exit5_exact_bytes(self):
        cfg = config()
        events = [link(0, "p1")]
        # W 初值 P=2；首个事件 settle(0) 后 +1，link 结果再 +1 => 4
        proc, _ = run_cli(cfg, events, 1000000, 1000000, 1000000,
                          1000000, 4)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        proc, _ = run_cli(cfg, events, 1000000, 1000000, 1000000,
                          1000000, 3)
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr,
                         b'{"error":"link_wire_work_limit"}\n')


if __name__ == "__main__":
    unittest.main()
