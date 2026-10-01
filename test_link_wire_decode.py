#!/usr/bin/env python3
"""link-wire-decode 子命令回归：CONFIG 与结果结构同 link-wire，EVENTS 中
link/advance 保持原语义，帧事件仅含 t、port、data（小写偶数位十六进制的
完整以太帧）。原始帧按现有 frame-decode 口径解释为单层 802.1Q 帧：目的全
零、源全零或组播、非法十六进制、短到无法容纳必要头部与 FCS、双层标签均
使整次操作 invalid_input/4 且无部分结果；错误 FCS、长度<64、>max_frame
为可处理坏帧，分别以 bad_fcs/runt/giant 进入 link-wire 既有丢弃与计数。
有效帧的 VLAN、源目的 MAC、实际字节长度全部由 data 得出；标签增删、20
字节线路开销、半双工碰撞、链路中断清队列、queue_bytes 与 advance 语义均
沿用 link-wire，输出与把同一原始帧准确转换后调用 link-wire 逐字节一致。

仅用标准库；通过 `python switch.py link-wire-decode CONFIG EVENTS` 端到端
驱动。
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

from test_link_wire import advance  # noqa: E402
from test_link_wire import config  # noqa: E402
from test_link_wire import frame  # noqa: E402
from test_link_wire import link  # noqa: E402
from test_link_wire import port  # noqa: E402

BCAST = "ff:ff:ff:ff:ff:ff"
MAC1 = "00:00:00:00:00:01"
MAC2 = "00:00:00:00:00:02"
ETYPE = 0x0800


def mac_bytes(mac):
    return bytes(int(part, 16) for part in mac.split(":"))


def raw_bytes(dst=BCAST, src=MAC1, vlan=None, payload_len=46,
              ethertype=ETYPE, bad_fcs=False):
    """组装完整以太帧（含 FCS）；默认 60 字节体 + 4 字节 FCS = 64 字节。"""
    body = mac_bytes(dst) + mac_bytes(src)
    if vlan is not None:
        body += b"\x81\x00" + (vlan & 0x0FFF).to_bytes(2, "big")
    body += ethertype.to_bytes(2, "big") + b"\x00" * payload_len
    fcs = (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little")
    if bad_fcs:
        fcs = b"\x00\x00\x00\x00" if fcs != b"\x00\x00\x00\x00" else b"\xff" * 4
    return body + fcs


def raw_frame(t, p, *args, **kwargs):
    return {"t": t, "port": p, "data": raw_bytes(*args, **kwargs).hex()}


def abstract_from_raw(event):
    """把原始帧事件准确转换为 link-wire 抽象帧事件（入口同一口径）。"""
    raw = bytes.fromhex(event["data"])
    dst = ":".join("%02x" % b for b in raw[0:6])
    src = ":".join("%02x" % b for b in raw[6:12])
    if raw[12:14] == b"\x81\x00":
        vlan = (raw[14] << 8 | raw[15]) & 0x0FFF
    else:
        vlan = None
    fcs = raw[-4:] == (zlib.crc32(raw[:-4]) & 0xFFFFFFFF).to_bytes(
        4, "little"
    )
    return {
        "t": event["t"],
        "port": event["port"],
        "src": src,
        "dst": dst,
        "vlan": vlan,
        "length": len(raw),
        "fcs": fcs,
        "alignment": True,
    }


def write_inputs(cfg_doc, events, sub, tmp, *limits):
    cfg = os.path.join(tmp, "config.json")
    evt = os.path.join(tmp, "events.json")
    with open(cfg, "wb") as handle:
        handle.write(json.dumps(cfg_doc).encode("utf-8"))
    with open(evt, "wb") as handle:
        handle.write(json.dumps(events).encode("utf-8"))
    proc = subprocess.run(
        [sys.executable, SWITCH, sub, cfg, evt,
         *[str(x) for x in limits]],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return proc


class EquivalenceTests(unittest.TestCase):
    def _assert_equivalent(self, cfg_doc, raw_events, abstract_events):
        with tempfile.TemporaryDirectory() as tmp:
            direct = write_inputs(cfg_doc, abstract_events, "link-wire", tmp)
            decoded = write_inputs(
                cfg_doc, raw_events, "link-wire-decode", tmp
            )
        self.assertEqual(direct.returncode, 0, direct.stderr)
        self.assertEqual(decoded.returncode, 0, decoded.stderr)
        self.assertEqual(decoded.stdout, direct.stdout)

    def test_good_broadcast_matches_link_wire(self):
        cfg = config(delay=10)
        raw_events = [
            link(0, "p1", rates=[1000], modes=["full"]),
            link(0, "p2", rates=[1000], modes=["full"]),
            raw_frame(10, "p1"),
            advance(970),
        ]
        abstract = [
            link(0, "p1", rates=[1000], modes=["full"]),
            link(0, "p2", rates=[1000], modes=["full"]),
            frame(10, "p1", MAC1, length=64),
            advance(970),
        ]
        self._assert_equivalent(cfg, raw_events, abstract)

    def test_mixed_good_bad_runt_giant(self):
        cfg = config(delay=10)
        raws = [
            link(0, "p1", rates=[1000], modes=["full"]),
            link(0, "p2", rates=[1000], modes=["full"]),
            raw_frame(10, "p1"),
            raw_frame(20, "p1", bad_fcs=True),
            # 18 字节最短可解析帧：<64 为 runt
            {"t": 30, "port": "p1",
             "data": (b"\xff" * 6 + mac_bytes(MAC1) + b"\x08\x00"
                      + b"\x00\x00\x00\x00").hex()},
            # 1519 字节好帧：>max_frame(1518) 为 giant
            raw_frame(40, "p1", payload_len=1519 - 14 - 4),
            advance(100000),
        ]
        abstract = []
        for event in raws:
            abstract.append(
                event if "data" not in event else abstract_from_raw(event)
            )
        self._assert_equivalent(cfg, raws, abstract)

    def test_tag_added_and_stripped_lengths(self):
        # trunk 口 untagged 必为空；hybrid 口可剥标签
        cfg = config([
            port("p1", mode="trunk", pvid=1, allowed=[1], untagged=[]),
            port("p2", mode="trunk", pvid=2, allowed=[1, 2], untagged=[]),
            port("p3", mode="hybrid", pvid=1, allowed=[1, 2],
                 untagged=[1]),
        ])
        raws = [
            link(0, "p1", rates=[10000], modes=["full"]),
            link(0, "p2", rates=[10000], modes=["full"]),
            link(0, "p3", rates=[10000], modes=["full"]),
            # 无标签 100 字节：p1 pvid=1，p2 带标签出口 -> 104
            raw_frame(10, "p1", vlan=None, payload_len=100 - 14 - 4,
                      dst="00:00:00:00:00:02"),
            # 带 VLAN 1 标签 100 字节：p3 untagged 含 1，剥标签 -> 96
            raw_frame(20, "p1", vlan=1, payload_len=100 - 18 - 4,
                      dst="00:00:00:00:00:03"),
            advance(100000),
        ]
        abstract = [
            link(0, "p1", rates=[10000], modes=["full"]),
            link(0, "p2", rates=[10000], modes=["full"]),
            link(0, "p3", rates=[10000], modes=["full"]),
            frame(10, "p1", MAC1, dst="00:00:00:00:00:02",
                  vlan=None, length=100),
            frame(20, "p1", MAC1, dst="00:00:00:00:00:03",
                  vlan=1, length=100),
            advance(100000),
        ]
        self._assert_equivalent(cfg, raws, abstract)

    def test_half_duplex_collision_and_reschedule(self):
        cfg = config([
            port("p1", rates=[100], modes=["half"]),
            port("p2", rates=[100], modes=["half"]),
        ])
        raws = [
            link(0, "p1", rates=[100], modes=["half"]),
            link(0, "p2", rates=[100], modes=["half"]),
            raw_frame(10, "p1", payload_len=100 - 14 - 4),  # 100 字节
            raw_frame(20, "p1", payload_len=100 - 14 - 4),
            # p1 正半双工发送期间再收帧 -> 碰撞
            raw_frame(30, "p1", payload_len=100 - 14 - 4),
            advance(1000000),
        ]
        abstract = [
            link(0, "p1", rates=[100], modes=["half"]),
            link(0, "p2", rates=[100], modes=["half"]),
            frame(10, "p1", MAC1, length=100),
            frame(20, "p1", MAC1, length=100),
            frame(30, "p1", MAC1, length=100),
            advance(1000000),
        ]
        self._assert_equivalent(cfg, raws, abstract)

    def test_link_down_drain_and_queue_full(self):
        cfg = config([
            port("p1", rates=[1000], modes=["full"], queue_bytes=200),
            port("p2", rates=[1000], modes=["full"], queue_bytes=200),
        ])
        raws = [
            link(0, "p1", rates=[1000], modes=["full"]),
            link(0, "p2", rates=[1000], modes=["full"]),
            raw_frame(10, "p1", payload_len=100 - 14 - 4),
            raw_frame(11, "p1", payload_len=100 - 14 - 4),
            raw_frame(12, "p1", payload_len=100 - 14 - 4),
            # 队列满后断链：未完成副本以 link_down 清空
            link(20, "p2", admin=False, peer=True, rates=[1000],
                 modes=["full"]),
        ]
        abstract = [
            link(0, "p1", rates=[1000], modes=["full"]),
            link(0, "p2", rates=[1000], modes=["full"]),
            frame(10, "p1", MAC1, length=100),
            frame(11, "p1", MAC1, length=100),
            frame(12, "p1", MAC1, length=100),
            link(20, "p2", admin=False, peer=True, rates=[1000],
                 modes=["full"]),
        ]
        self._assert_equivalent(cfg, raws, abstract)


class DecodedFieldsTests(unittest.TestCase):
    def test_vlan_and_lengths_derive_from_data(self):
        cfg = config([
            port("p1", mode="trunk", pvid=1, allowed=[1, 2], untagged=[]),
            port("p2", mode="trunk", pvid=2, allowed=[1, 2], untagged=[]),
        ])
        events = [
            link(0, "p1", rates=[10000], modes=["full"]),
            link(0, "p2", rates=[10000], modes=["full"]),
            # 带标签帧 TCI=0x0002：VLAN 2
            raw_frame(10, "p1", vlan=2, payload_len=80),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            proc = write_inputs(cfg, events, "link-wire-decode", tmp)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout)
        decision = next(r for r in out["results"] if r.get("action"))
        self.assertEqual(decision["action"], "flood")
        self.assertEqual(decision["ports"], [{"name": "p2", "vlan": 2}])
        enq = next(
            r for r in out["results"]
            if "bytes" in r and "reason" not in r and "start" not in r
        )
        # 80 字节载荷：18+80+4=102 字节，p2 带标签出口仍为 102，+20=122
        self.assertEqual(enq["bytes"], 122)

    def test_alignment_always_treated_normal(self):
        # decode 无对齐概念：64 字节、FCS 正确即 good，不存在 alignment 类
        cfg = config()
        events = [
            link(0, "p1", rates=[1000], modes=["full"]),
            raw_frame(10, "p1"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            proc = write_inputs(cfg, events, "link-wire-decode", tmp)
        out = json.loads(proc.stdout)
        decision = next(r for r in out["results"] if r.get("class"))
        self.assertEqual(decision["class"], "good")
        self.assertNotIn(
            "alignment", json.dumps(out)
        )

    def test_result_structure_identical_to_link_wire(self):
        cfg = config()
        events = [
            link(0, "p1", rates=[1000], modes=["full"]),
            link(0, "p2", rates=[1000], modes=["full"]),
            raw_frame(10, "p1"),
            advance(970),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            proc = write_inputs(cfg, events, "link-wire-decode", tmp)
        out = json.loads(proc.stdout)
        self.assertEqual(set(out), {"results", "ports"})
        self.assertEqual(
            set(out["ports"][0]),
            {"name", "rx_frames", "rx_bytes", "tx_frames", "tx_bytes",
             "collision_frames", "collision_bytes", "queue_full_frames",
             "queue_full_bytes", "link_down_frames", "link_down_bytes"},
        )


class InvalidInputTests(unittest.TestCase):
    def _assert4(self, cfg_doc, events):
        with tempfile.TemporaryDirectory() as tmp:
            proc = write_inputs(cfg_doc, events, "link-wire-decode", tmp)
        self.assertEqual(proc.returncode, 4, proc.stderr)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b'{"error":"invalid_input"}\n')

    def test_zero_dst_rejected(self):
        self._assert4(config(), [
            raw_frame(0, "p1", dst="00:00:00:00:00:00"),
        ])

    def test_zero_src_rejected(self):
        self._assert4(config(), [
            raw_frame(0, "p1", src="00:00:00:00:00:00"),
        ])

    def test_multicast_src_rejected(self):
        self._assert4(config(), [
            raw_frame(0, "p1", src="01:00:5e:00:00:01"),
        ])

    def test_bad_hex_rejected(self):
        good = raw_bytes().hex()
        for bad in (good[:-1], good[:-2] + "zz", good.upper()):
            self._assert4(config(), [{"t": 0, "port": "p1", "data": bad}])

    def test_too_short_rejected(self):
        # 17 字节（短到无法容纳必要头部与 FCS）非法；18 字节可解析（runt）
        seventeen = (b"\xff" * 6 + mac_bytes(MAC1) + b"\x08\x00"
                     + b"\x00" * 3).hex()
        self._assert4(config(), [{"t": 0, "port": "p1", "data": seventeen}])

    def test_tagged_frame_too_short_rejected(self):
        # 偏移 12 为 8100 但总长不足 22
        short = (
            b"\xff" * 6 + mac_bytes(MAC1) + b"\x81\x00\x00\x01\x08\x00"
            + b"\x00\x00"
        ).hex()
        self._assert4(config(), [{"t": 0, "port": "p1", "data": short}])

    def test_double_tag_rejected(self):
        doubled = (
            b"\xff" * 6 + mac_bytes(MAC1) + b"\x81\x00\x00\x01\x81\x00"
            b"\x08\x00" + b"\x00" * 40
        )
        fcs = (zlib.crc32(doubled) & 0xFFFFFFFF).to_bytes(4, "little")
        self._assert4(
            config(), [{"t": 0, "port": "p1", "data": (doubled + fcs).hex()}]
        )

    def test_abstract_frame_shape_rejected(self):
        # 不能混入 link-wire 的抽象帧形状（八键）
        good_link = link(0, "p1", rates=[1000], modes=["full"])
        abstract = frame(10, "p1", MAC1, length=64)
        self._assert4(config(), [good_link, abstract])
        self._assert4(config(), [
            good_link, abstract, raw_frame(20, "p1"),
        ])

    def test_t_not_monotonic_across_kinds(self):
        self._assert4(config(), [
            advance(10), raw_frame(9, "p1"),
        ])

    def test_unknown_port_rejected(self):
        self._assert4(config(), [
            {"t": 0, "port": "ghost", "data": raw_bytes().hex()},
        ])

    def test_events_not_list_and_frame_not_object(self):
        self._assert4(config(), "nope")
        self._assert4(config(), [42])

    def test_no_partial_result(self):
        # 首个事件合法、第二个非法：整次操作无任何输出
        events = [
            link(0, "p1", rates=[1000], modes=["full"]),
            {"t": 10, "port": "p1", "data": "zz"},
        ]
        self._assert4(config(), events)


class BadFramePathTests(unittest.TestCase):
    def _run(self, events):
        with tempfile.TemporaryDirectory() as tmp:
            proc = write_inputs(config(), events, "link-wire-decode", tmp)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    def test_bad_fcs_dropped_and_counted(self):
        out = self._run([raw_frame(10, "p1", bad_fcs=True)])
        decision = next(r for r in out["results"] if r.get("class"))
        self.assertEqual(decision,
                         {"t": 10, "class": "bad_fcs", "action": "drop",
                          "ports": []})
        # 坏帧仍计入 rx（线上长度 = 帧长 + 20）
        self.assertEqual(out["ports"][0]["rx_frames"], 1)
        self.assertEqual(out["ports"][0]["rx_bytes"], 84)
        self.assertEqual(out["ports"][0]["tx_frames"], 0)

    def test_runt_dropped_and_counted(self):
        # 18 字节最短帧：runt；线上 38 字节
        data = (b"\xff" * 6 + mac_bytes(MAC1) + b"\x08\x00"
                + b"\x00\x00\x00\x00").hex()
        out = self._run([{"t": 10, "port": "p1", "data": data}])
        decision = next(r for r in out["results"] if r.get("class"))
        self.assertEqual(decision["class"], "runt")
        self.assertEqual(decision["action"], "drop")
        self.assertEqual(out["ports"][0]["rx_bytes"], 38)

    def test_giant_dropped_and_counted(self):
        out = self._run([raw_frame(10, "p1", payload_len=1519 - 14 - 4)])
        decision = next(r for r in out["results"] if r.get("class"))
        self.assertEqual(decision["class"], "giant")
        self.assertEqual(decision["action"], "drop")
        self.assertEqual(out["ports"][0]["rx_bytes"], 1519 + 20)


class DeterminismTests(unittest.TestCase):
    def test_repeated_runs_byte_identical(self):
        cfg = config()
        events = [
            link(0, "p1", rates=[1000], modes=["full"]),
            link(0, "p2", rates=[1000], modes=["full"]),
            raw_frame(10, "p1"),
            raw_frame(20, "p1", dst=MAC2),
            raw_frame(30, "p1", bad_fcs=True),
            advance(100000),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            a = write_inputs(cfg, events, "link-wire-decode", tmp)
            b = write_inputs(cfg, events, "link-wire-decode", tmp)
        self.assertEqual(a.stdout, b.stdout)


class ResourceAndErrorTests(unittest.TestCase):
    def test_missing_file_exit3(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = os.path.join(tmp, "config.json")
            with open(cfg, "wb") as handle:
                handle.write(json.dumps(config()).encode("utf-8"))
            missing = subprocess.run(
                [sys.executable, SWITCH, "link-wire-decode", cfg,
                 os.path.join(tmp, "nope.json")],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(missing.returncode, 3)
        self.assertEqual(missing.stdout, b"")
        self.assertIn(b"file_not_found", missing.stderr)

    def test_usage_exit2(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = os.path.join(tmp, "c.json")
            evt = os.path.join(tmp, "e.json")
            with open(cfg, "wb") as handle:
                handle.write(b"{}")
            with open(evt, "wb") as handle:
                handle.write(b"[]")
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

    def test_limits_exit5_same_as_link_wire(self):
        good = raw_bytes().hex()
        events = [
            link(0, "p1", rates=[1000], modes=["full"]),
            {"t": 10, "port": "p1", "data": good},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            proc = write_inputs(
                config(), events, "link-wire-decode", tmp, 100, 16 << 20
            )
            self.assertEqual(proc.returncode, 5)
            self.assertIn(b"config_limit", proc.stderr)
            proc = write_inputs(
                config(), events, "link-wire-decode", tmp, 1 << 20, 5
            )
            self.assertEqual(proc.returncode, 5)
            self.assertIn(b"data_limit", proc.stderr)
            proc = write_inputs(
                config(), events, "link-wire-decode", tmp,
                1 << 20, 1 << 20, 1, 1 << 20,
            )
            self.assertEqual(proc.returncode, 5)
            self.assertIn(b"item_limit", proc.stderr)
            proc = write_inputs(
                config(), events, "link-wire-decode", tmp,
                1 << 20, 1 << 20, 100000, 10,
            )
            self.assertEqual(proc.returncode, 5)
            self.assertIn(b"output_limit", proc.stderr)

    def test_work_limit_parity_with_link_wire(self):
        # 仅一个 link 事件：W 初值 P=2，结算 +1、link 记录 +1 => 4；
        # decode 与 link-wire 共用同一计费公式
        events = [link(0, "p1", rates=[1000], modes=["full"])]
        with tempfile.TemporaryDirectory() as tmp:
            ok = write_inputs(
                config(), events, "link-wire-decode", tmp,
                1 << 20, 1 << 20, 1 << 20, 1 << 20, 4,
            )
            bad = write_inputs(
                config(), events, "link-wire-decode", tmp,
                1 << 20, 1 << 20, 1 << 20, 1 << 20, 3,
            )
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertEqual(bad.returncode, 5)
        self.assertEqual(bad.stdout, b"")
        self.assertEqual(bad.stderr,
                         b'{"error":"link_wire_work_limit"}\n')


if __name__ == "__main__":
    unittest.main()
