#!/usr/bin/env python3
"""link-wire-decode 子命令回归。

link-wire-decode 使用与 link-wire 相同的 CONFIG（含 queue_bytes）与结果
结构；EVENTS 中 link 与 advance 保持原语义，帧事件改为仅含 t、port、data
（小写偶数位十六进制的完整以太帧）。每个原始帧按 frame-decode 口径解释为
单层 802.1Q 帧（alignment 恒真，分类退化为 runt/giant/bad_fcs/good），
其余排队、20 字节线路开销、半双工碰撞、链路中断清队列与 queue_bytes 限制
完全沿用 link-wire。核心不变量：同一原始帧准确转换为抽象帧后调用
link-wire，stdout 与 link-wire-decode 逐字节一致。

仅用标准库；端到端驱动 `python switch.py link-wire-decode CONFIG EVENTS`。
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


def advance(t):
    return {"t": t, "advance": True}


def mac_bytes(mac):
    return bytes(int(part, 16) for part in mac.split(":"))


def raw_frame(t, p, dst=BCAST, src=MAC1, vlan=None, payload_len=46,
              fcs_good=True, extra=b""):
    """构造完整以太帧（dst/src/[8100 TCI]/ethertype/payload/FCS）。

    默认 untagged payload 46 字节 => 帧长 64；tagged 用 payload_len=42。
    返回帧事件 {t,port,data} 与 (length,fcs_good)，后者用于构造等价抽象帧。
    """
    head = mac_bytes(dst) + mac_bytes(src)
    if vlan is None:
        head += b"\x08\x00"
    else:
        head += b"\x81\x00" + vlan.to_bytes(2, "big") + b"\x08\x00"
    body = head + b"\x00" * payload_len + extra
    fcs = (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little")
    if not fcs_good:
        fcs = b"\xff\xff\xff\xff"
    raw = body + fcs
    return {"t": t, "port": p, "data": raw.hex()}, len(raw), fcs_good


def raw_event(*args, **kwargs):
    event, _, _ = raw_frame(*args, **kwargs)
    return event


def abstract_frame(t, p, src, dst, vlan, length, fcs_good, alignment=True):
    return {
        "t": t, "port": p, "src": src, "dst": dst, "vlan": vlan,
        "length": length, "fcs": fcs_good, "alignment": alignment,
    }


def write_inputs(config_doc, events):
    tmp = tempfile.mkdtemp()
    cfg = os.path.join(tmp, "config.json")
    evt = os.path.join(tmp, "events.json")
    with open(cfg, "wb") as handle:
        handle.write(json.dumps(config_doc).encode("utf-8"))
    with open(evt, "wb") as handle:
        handle.write(json.dumps(events).encode("utf-8"))
    return tmp, cfg, evt


def run_cli(which, config_doc, events, *limits):
    tmp, cfg, evt = write_inputs(config_doc, events)
    proc = subprocess.run(
        [sys.executable, SWITCH, which, cfg, evt,
         *[str(x) for x in limits]],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    missing = subprocess.run(
        [sys.executable, SWITCH, which, os.path.join(tmp, "nope.json"), evt],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return proc, missing


def run_decode(config_doc, events, *limits):
    proc, _ = run_cli("link-wire-decode", config_doc, events, *limits)
    assert proc.returncode == 0, (
        proc.returncode, proc.stderr.decode("utf-8")
    )
    return proc.stdout


class ByteIdentityTests(unittest.TestCase):
    """输出必须与同一原始帧准确转换后调用 link-wire 逐字节一致。"""

    def _pair(self, cfg, dec_events, abs_events):
        a, _ = run_cli("link-wire-decode", cfg, dec_events)
        b, _ = run_cli("link-wire", cfg, abs_events)
        self.assertEqual(a.returncode, 0, a.stderr)
        self.assertEqual(b.returncode, 0, b.stderr)
        return a.stdout, b.stdout

    def test_good_tagged_bad_runt_giant_full_picture(self):
        cfg = config([
            port("p1"),
            port("p2", mode="trunk", pvid=2, allowed=[1, 2], untagged=[]),
        ])
        e1, l1, f1 = raw_frame(10, "p1", BCAST, MAC1, None, 46)
        e2, l2, f2 = raw_frame(11, "p1", BCAST, MAC1, 1, 42)
        e3, l3, f3 = raw_frame(12, "p1", BCAST, MAC1, None, 46, fcs_good=False)
        e4, l4, f4 = raw_frame(13, "p1", BCAST, MAC1, None, 42)  # 60 字节 runt
        e5, l5, f5 = raw_frame(14, "p1", BCAST, MAC1, None, 2000 - 18)
        dec = [
            link(0, "p1", rates=[1000], modes=["full"]),
            link(0, "p2", rates=[1000], modes=["full"]),
            e1, e2, e3, e4, e5, advance(100000),
        ]
        abs_events = [
            link(0, "p1", rates=[1000], modes=["full"]),
            link(0, "p2", rates=[1000], modes=["full"]),
            abstract_frame(10, "p1", MAC1, BCAST, None, l1, f1),
            abstract_frame(11, "p1", MAC1, BCAST, 1, l2, f2),
            abstract_frame(12, "p1", MAC1, BCAST, None, l3, f3),
            abstract_frame(13, "p1", MAC1, BCAST, None, l4, f4),
            abstract_frame(14, "p1", MAC1, BCAST, None, l5, f5),
            advance(100000),
        ]
        a, b = self._pair(cfg, dec, abs_events)
        self.assertEqual(a, b)
        out = json.loads(a.decode())
        classes = [r["class"] for r in out["results"] if "class" in r]
        self.assertEqual(classes, ["good", "good", "bad_fcs", "runt", "giant"])

    def test_tag_strip_byte_identity(self):
        cfg = config([
            port("p1", mode="trunk", pvid=1, allowed=[1, 2], untagged=[]),
            port("p2", mode="hybrid", pvid=1, allowed=[1, 2],
                 untagged=[1]),
        ])
        e, length, fcs = raw_frame(10, "p1", BCAST, MAC1, 1, 42)
        dec = [
            link(0, "p1", rates=[10000], modes=["full"]),
            link(0, "p2", rates=[10000], modes=["full"]),
            e, advance(100000),
        ]
        abs_events = [
            link(0, "p1", rates=[10000], modes=["full"]),
            link(0, "p2", rates=[10000], modes=["full"]),
            abstract_frame(10, "p1", MAC1, BCAST, 1, length, fcs),
            advance(100000),
        ]
        a, b = self._pair(cfg, dec, abs_events)
        self.assertEqual(a, b)
        out = json.loads(a.decode())
        enq = next(r for r in out["results"]
                   if "bytes" in r and "start" not in r)
        # 入站带标签 length=64，去标签出站：64-4+20=80
        self.assertEqual(enq["bytes"], 80)
        self.assertIsNone(enq["vlan"])

    def test_half_duplex_collision_byte_identity(self):
        cfg = config([
            port("p1", rates=[1000], modes=["half"]),
            port("p2", rates=[1000], modes=["half"]),
        ], delay=1)
        e1, l1, f1 = raw_frame(10, "p1", BCAST, MAC1, None, 1000 - 18)
        e2, l2, f2 = raw_frame(11, "p2", BCAST, MAC2, None, 1000 - 18)
        dec = [link(0, "p1"), link(0, "p2"), e1, e2]
        abs_events = [
            link(0, "p1"), link(0, "p2"),
            abstract_frame(10, "p1", MAC1, BCAST, None, l1, f1),
            abstract_frame(11, "p2", MAC2, BCAST, None, l2, f2),
        ]
        a, b = self._pair(cfg, dec, abs_events)
        self.assertEqual(a, b)
        out = json.loads(a.decode())
        col = next(r for r in out["results"]
                   if r.get("reason") == "collision")
        self.assertEqual(col["port"], "p2")
        self.assertEqual(col["bytes"], l1 + 20)
        self.assertEqual(col["inbound"], l2 + 20)
        self.assertEqual(out["ports"][1]["collision_frames"], 2)

    def test_queue_full_and_link_down_byte_identity(self):
        cfg = config([
            port("p1", rates=[10000], modes=["full"]),
            port("p2", rates=[10000], modes=["full"], queue_bytes=200),
        ], delay=1)
        e1, l1, f1 = raw_frame(10, "p1", BCAST, MAC1, None, 100 - 18)
        e2, l2, f2 = raw_frame(11, "p1", BCAST, MAC1, None, 100 - 18)
        dec = [link(0, "p1"), link(0, "p2"), e1, e2,
               link(50, "p2", admin=False)]
        abs_events = [
            link(0, "p1"), link(0, "p2"),
            abstract_frame(10, "p1", MAC1, BCAST, None, l1, f1),
            abstract_frame(11, "p1", MAC1, BCAST, None, l2, f2),
            link(50, "p2", admin=False),
        ]
        a, b = self._pair(cfg, dec, abs_events)
        self.assertEqual(a, b)
        out = json.loads(a.decode())
        reasons = [r.get("reason") for r in out["results"]
                   if r.get("reason") in ("queue_full", "link_down")]
        self.assertIn("queue_full", reasons)
        self.assertIn("link_down", reasons)

    def test_empty_events(self):
        cfg = config()
        a = run_decode(cfg, [])
        b = run_decode(cfg, [])
        self.assertEqual(a, b)
        self.assertTrue(a.endswith(b"\n"))


class DeterminismTests(unittest.TestCase):
    def test_repeat_byte_identical(self):
        cfg = config()
        e, _, _ = raw_frame(10, "p1")
        events = [link(0, "p1"), link(0, "p2"), e, advance(100000)]
        a = run_decode(cfg, events)
        b = run_decode(cfg, events)
        self.assertEqual(a, b)


class ValidationTests(unittest.TestCase):
    def _assert4(self, cfg, events):
        proc, _ = run_cli("link-wire-decode", cfg, events)
        self.assertEqual(proc.returncode, 4, proc.stderr)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b'{"error":"invalid_input"}\n')

    def setUp(self):
        self.cfg = config()

    def test_dst_all_zero_invalid(self):
        self._assert4(self.cfg, [
            link(0, "p1"),
            raw_event(10, "p1", dst="00:00:00:00:00:00", src=MAC1),
        ])

    def test_src_all_zero_invalid(self):
        self._assert4(self.cfg, [
            raw_event(10, "p1", dst=BCAST, src="00:00:00:00:00:00"),
        ])

    def test_src_multicast_invalid(self):
        self._assert4(self.cfg, [
            raw_event(10, "p1", dst=BCAST, src="01:00:00:00:00:01"),
        ])

    def test_bad_hex_invalid(self):
        good = raw_event(10, "p1")
        for data in ("", "abc", "0g", "AB", "aabbc"):  # 空/奇数位/非小写hex/大写
            bad = dict(good, data=data)
            self._assert4(self.cfg, [bad])

    def test_uppercase_hex_invalid(self):
        good = raw_event(10, "p1")
        self._assert4(self.cfg, [dict(good, data=good["data"].upper()[:2]
                                      + good["data"][2:])])

    def test_too_short_untagged_invalid(self):
        # 无标签帧短于 18 字节（无法容纳必要头部与 FCS）：整次非法
        e, _, _ = raw_frame(10, "p1", payload_len=0)  # 恰好 18，合法
        self.assertEqual(len(bytes.fromhex(e["data"])), 18)
        proc, _ = run_cli("link-wire-decode", self.cfg, [e])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        short = dict(e, data=e["data"][:-2])  # 17 字节
        self._assert4(self.cfg, [short])

    def test_too_short_tagged_invalid(self):
        # 带标签帧短于 22 字节：整次非法（虽已含 8100）
        e, _, _ = raw_frame(10, "p1", vlan=1, payload_len=0)  # 恰好 22
        self.assertEqual(len(bytes.fromhex(e["data"])), 22)
        proc, _ = run_cli("link-wire-decode", self.cfg, [e])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        short = dict(e, data=e["data"][:-2])  # 21 字节
        self._assert4(self.cfg, [short])

    def test_double_tag_invalid(self):
        e = raw_event(10, "p1", vlan=1, payload_len=42)
        raw = bytes.fromhex(e["data"])
        # 在首 TCI 之后再插一层 81 00 标签 -> 双标签
        double = dict(e, data=(raw[:16] + b"\x81\x00\x10\x00"
                               + raw[16:]).hex())
        self._assert4(self.cfg, [double])

    def test_no_partial_results_on_late_invalid(self):
        # 第二个事件非法：不得产生部分结果，stdout 为空
        good = raw_event(10, "p1")
        bad = raw_event(11, "p1", src="00:00:00:00:00:00")
        proc, _ = run_cli("link-wire-decode", self.cfg, [
            link(0, "p1"), good, bad,
        ])
        self.assertEqual(proc.returncode, 4)
        self.assertEqual(proc.stdout, b"")

    def test_abstract_frame_shape_rejected(self):
        # 混入 link-wire 抽象帧（九键）属形状错误
        self._assert4(self.cfg, [
            link(0, "p1"),
            abstract_frame(10, "p1", MAC1, BCAST, None, 64, True),
        ])

    def test_unknown_port_and_bad_link(self):
        self._assert4(self.cfg, [raw_event(0, "ghost")])
        self._assert4(self.cfg, [{"t": 0, "advance": 1}])
        self._assert4(self.cfg, [link(0, "ghost")])

    def test_t_not_monotonic(self):
        e10 = raw_event(10, "p1")
        e9 = raw_event(9, "p1")
        self._assert4(self.cfg, [e10, e9])
        self._assert4(self.cfg, [advance(10), raw_event(9, "p1")])

    def test_config_without_queue_bytes_invalid(self):
        lf_cfg = {
            "age": 100, "max_frame": 1518, "delay": 5,
            "ports": [
                {"name": "p1", "mode": "access", "pvid": 1,
                 "allowed": [1], "untagged": [1],
                 "rates": [1000], "modes": ["full"]},
            ],
        }
        self._assert4(lf_cfg, [])


class ProcessingOrderTests(unittest.TestCase):
    def test_same_time_port_order_advance_last(self):
        cfg = config()
        e_p2 = raw_event(0, "p2", src=MAC2)
        events = [
            advance(0), e_p2, link(0, "p2"), link(0, "p1"),
        ]
        out = json.loads(run_decode(cfg, events).decode())
        # p1 link 状态结果先于 p2 各项；advance 不产生自身结果。同口同刻
        # 帧先于链路：p2 帧 rx（drop，口未 up）在 p2 状态结果之前
        states = [(r["port"], r.get("state")) for r in out["results"]
                  if "state" in r]
        self.assertEqual([s[0] for s in states], ["p1", "p2"])


class ResourceAndErrorTests(unittest.TestCase):
    def test_missing_file_exit3(self):
        cfg = config()
        _, missing = run_cli("link-wire-decode", cfg, [])
        self.assertEqual(missing.returncode, 3)
        self.assertEqual(missing.stdout, b"")
        self.assertIn(b"file_not_found", missing.stderr)

    def test_limits_exit5(self):
        cfg = config()
        events = [link(0, "p1"), link(1, "p2")]
        proc, _ = run_cli("link-wire-decode", cfg, events, 100, 1000000)
        self.assertEqual(proc.returncode, 5)
        self.assertIn(b"config_limit", proc.stderr)
        proc, _ = run_cli("link-wire-decode", cfg, events, 1000000, 5)
        self.assertEqual(proc.returncode, 5)
        self.assertIn(b"data_limit", proc.stderr)
        proc, _ = run_cli(
            "link-wire-decode", cfg, events, 1000000, 1000000, 1, 1000000
        )
        self.assertEqual(proc.returncode, 5)
        self.assertIn(b"item_limit", proc.stderr)
        proc, _ = run_cli(
            "link-wire-decode", cfg, events, 1000000, 1000000, 1000000, 10
        )
        self.assertEqual(proc.returncode, 5)
        self.assertIn(b"output_limit", proc.stderr)
        self.assertEqual(proc.stdout, b"")

    def test_usage_exit2(self):
        tmp, cfg, evt = write_inputs(config(), [])
        for argv in (
            ["link-wire-decode", cfg],
            ["link-wire-decode", cfg, evt, "1"],
            ["link-wire-decode", cfg, evt, "1", "2", "3"],
            ["link-wire-decode", cfg, evt, "0"],
        ):
            proc = subprocess.run(
                [sys.executable, SWITCH, *argv],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(proc.returncode, 2, argv)
            self.assertIn(b"usage", proc.stderr)

    def test_work_limit_same_formula_as_link_wire(self):
        # 解码为纯函数不计费：W 初值 P=2；首个 link 事件 settle(0) 后 +1，
        # link 结果再 +1 => 4（与 link-wire 完全相同）
        cfg = config()
        events = [link(0, "p1")]
        proc, _ = run_cli(
            "link-wire-decode", cfg, events,
            1000000, 1000000, 1000000, 1000000, 4,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        proc, _ = run_cli(
            "link-wire-decode", cfg, events,
            1000000, 1000000, 1000000, 1000000, 3,
        )
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr,
                         b'{"error":"link_wire_work_limit"}\n')

    def test_work_limit_over_has_empty_stdout(self):
        cfg = config()
        e, _, _ = raw_frame(10, "p1")
        events = [link(0, "p1"), e]
        proc, _ = run_cli(
            "link-wire-decode", cfg, events,
            1000000, 1000000, 1000000, 1000000, 1,
        )
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(proc.stdout, b"")


if __name__ == "__main__":
    unittest.main()
