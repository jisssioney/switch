#!/usr/bin/env python3
"""security-decode 子命令回归：原始帧解码（802.1Q/CRC32）与 security-check 语义。

仅用标准库；通过 `python switch.py security-decode CONFIG EVENTS` 端到端驱动。
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
sys.path.insert(0, HERE)

from test_record import base_config as record_base_config  # noqa: E402
from test_record import service  # noqa: E402

BCAST = "ff:ff:ff:ff:ff:ff"


def raw_frame(t, port, dst, src, vlan=None, priority=0, ethertype=0x0800,
              payload_len=46, bad_fcs=False):
    """构造单层 802.1Q 原始帧（默认 good：长度>=64、FCS 正确）。"""
    d = bytes(int(x, 16) for x in dst.split(":"))
    s = bytes(int(x, 16) for x in src.split(":"))
    if vlan is None:
        head = d + s + ethertype.to_bytes(2, "big")
    else:
        tci = (priority << 13) | vlan
        head = d + s + b"\x81\x00" + tci.to_bytes(2, "big") + \
            ethertype.to_bytes(2, "big")
    body = head + b"\x00" * payload_len
    fcs = (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little")
    if bad_fcs:
        fcs = b"\xff\xff\xff\xff"
    return {"t": t, "port": port, "data": (body + fcs).hex()}


def double_tag(frame):
    raw = bytes.fromhex(frame["data"])
    frame["data"] = (raw[:16] + b"\x81\x00\x10\x00" + raw[16:]).hex()
    return frame


def run_cli(config, events, *limits):
    with tempfile.TemporaryDirectory() as tmp:
        cfg = os.path.join(tmp, "config.json")
        evt = os.path.join(tmp, "events.json")
        with open(cfg, "wb") as handle:
            handle.write(json.dumps(config).encode("utf-8"))
        with open(evt, "wb") as handle:
            handle.write(json.dumps(events).encode("utf-8"))
        proc = subprocess.run(
            [sys.executable, SWITCH, "security-decode", cfg, evt,
             *[str(x) for x in limits]],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    return proc.returncode, proc.stdout, proc.stderr


def run(config, events, *limits):
    code, out, err = run_cli(config, events, *limits)
    assert code == 0, (code, err.decode("utf-8"))
    return json.loads(out.decode("utf-8"))


def config():
    result = json.loads(json.dumps(record_base_config()))
    result["max_frame"] = 1518
    return result


class DecodeSemanticsTests(unittest.TestCase):
    def test_untagged_uses_priority_zero_and_pvid(self):
        # 未标记帧 priority=0、vlan 取入端口 pvid=1，good 广播 flood
        events = [
            raw_frame(0, "p1", BCAST, "00:00:00:00:00:01"),
            service(1, "p3", 1),
        ]
        out = run(config(), events)
        self.assertEqual(out["results"][0]["class"], "good")
        self.assertEqual(out["results"][0]["action"], "flood")
        self.assertEqual(out["results"][1]["frames"], [0])
        self.assertEqual(out["vlans"][0]["vlan"], 1)

    def test_tag_priority_and_vlan_decoded(self):
        # 单层标签：TCI 高 3 位 priority=7、低 12 位 vlan=1；p1 为
        # access，带标签帧被准入拒绝（good 帧但 drop）
        events = [raw_frame(0, "p1", BCAST, "00:00:00:00:00:01",
                            vlan=1, priority=7)]
        out = run(config(), events)
        self.assertEqual(out["results"][0]["class"], "good")
        self.assertEqual(out["results"][0]["action"], "drop")
        self.assertEqual(out["ports"][0]["drop"], 1)
        # 准入拒绝不计 VLAN、不产生动态绑定
        self.assertEqual(out["vlans"][0]["rx"], 0)
        self.assertEqual(out["security"][0]["learned"], [])

    def test_classes_runt_giant_bad_fcs_and_alignment_zero(self):
        cfg = config()
        events = [
            raw_frame(0, "p1", BCAST, "00:00:00:00:00:01", payload_len=42),
            raw_frame(1, "p1", BCAST, "00:00:00:00:00:02",
                      payload_len=1500),  # 14+1500+4=1518 恰好不 giant
            raw_frame(2, "p1", BCAST, "00:00:00:00:00:03",
                      payload_len=1501),  # 1519 > max_frame
            raw_frame(3, "p1", BCAST, "00:00:00:00:00:04", bad_fcs=True),
        ]
        out = run(cfg, events)
        self.assertEqual(
            [r["class"] for r in out["results"]],
            ["runt", "good", "giant", "bad_fcs"],
        )
        for r in out["results"]:
            self.assertEqual(r["action"], "drop" if r["class"] != "good"
                             else "flood")
        # 无对齐概念：alignment 计数恒为 0，且坏帧结果无 alignment class
        p1 = out["ports"][0]
        self.assertEqual(p1["alignment"], 0)
        self.assertEqual(p1["runt"], 1)
        self.assertEqual(p1["giant"], 1)
        self.assertEqual(p1["bad_fcs"], 1)

    def test_bad_frame_consumes_frame_id_but_skips_security_path(self):
        # fid0 好帧、fid1 runt、fid2 好帧；服务仅见 0、2：坏帧占号但
        # 不入队、不计 VLAN、不生成镜像、不产生动态绑定
        events = [
            raw_frame(0, "p1", BCAST, "00:00:00:00:00:01"),
            raw_frame(1, "p1", BCAST, "00:00:00:00:00:02", payload_len=0),
            raw_frame(2, "p1", BCAST, "00:00:00:00:00:03"),
            service(3, "p3", 10),
        ]
        out = run(config(), events)
        self.assertEqual(out["results"][3]["frames"], [0, 2])
        self.assertEqual(out["results"][1]["mirrors"], [])
        self.assertEqual(len(out["results"][0]["mirrors"]), 1)
        p1 = out["ports"][0]
        self.assertEqual(p1["rx"], 3)
        self.assertEqual(p1["drop"], 1)
        self.assertEqual(p1["good"], 2)
        self.assertEqual(p1["runt"], 1)
        # 坏帧不计 VLAN
        self.assertEqual(out["vlans"][0]["rx"], 2)
        # 坏帧源未绑定：仅两个好帧源动态学习
        sec = {s["port"]: s for s in out["security"]}
        self.assertEqual(
            sec["p1"]["learned"],
            [{"vlan": 1, "mac": "00:00:00:00:00:01"},
             {"vlan": 1, "mac": "00:00:00:00:00:03"}],
        )
        self.assertEqual(sec["p1"]["violations"], 0)

    def test_bad_frame_does_not_trigger_violation_or_shutdown(self):
        # limit 0 + shutdown：坏帧不违例不禁口；随后好帧违例并永久禁口
        cfg = config()
        cfg["security"][0]["limit"] = 0
        cfg["security"][0]["action"] = "shutdown"
        events = [
            raw_frame(0, "p1", BCAST, "00:00:00:00:00:01", payload_len=0),
            raw_frame(1, "p1", BCAST, "00:00:00:00:00:02"),
        ]
        out = run(cfg, events)
        sec = {s["port"]: s for s in out["security"]}
        self.assertEqual(sec["p1"]["violations"], 1)
        self.assertTrue(sec["p1"]["shutdown"])
        self.assertEqual(sec["p1"]["learned"], [])

    def test_good_frame_security_unchanged(self):
        # good 帧沿用 port-security：limit 2 下第三源违例丢帧
        events = [
            raw_frame(0, "p1", BCAST, "00:00:00:00:00:01"),
            raw_frame(1, "p1", BCAST, "00:00:00:00:00:02"),
            raw_frame(2, "p1", BCAST, "00:00:00:00:00:03"),
        ]
        out = run(config(), events)
        self.assertEqual(out["results"][2]["action"], "drop")
        sec = {s["port"]: s for s in out["security"]}
        self.assertEqual(sec["p1"]["violations"], 1)
        self.assertEqual(len(sec["p1"]["learned"]), 2)

    def test_good_frame_continues_from_vlan_admission(self):
        # good 帧在 bad 帧之后完全沿用 port-security：flood 入队、服务发出
        events = [
            raw_frame(0, "p1", BCAST, "00:00:00:00:00:01", payload_len=46),
            service(1, "p3", 1),
        ]
        out = run(config(), events)
        self.assertEqual(out["results"][0]["class"], "good")
        self.assertEqual(out["results"][0]["action"], "flood")
        self.assertEqual(out["results"][1]["frames"], [0])

    def test_link_member_service_events_unchanged(self):
        # 链路/成员/service 项沿用 security-check：member 下线清队，service 出帧
        events = [
            raw_frame(0, "p1", BCAST, "00:00:00:00:00:01"),
            {"t": 1, "member": "p5", "up": False},
            service(2, "p3", 5),
        ]
        out = run(config(), events)
        self.assertEqual(out["results"][1]["frames"], [0])
        self.assertEqual(
            list(out["results"][1]), ["t", "port", "frames", "mirrors"]
        )

    def test_key_orders(self):
        events = [
            raw_frame(0, "p1", BCAST, "00:00:00:00:00:01", payload_len=0),
            raw_frame(1, "p1", BCAST, "00:00:00:00:00:02"),
            service(2, "p3", 1),
        ]
        code, raw, err = run_cli(config(), events)
        self.assertEqual(code, 0, err)
        decoded = json.loads(raw.decode().rstrip("\n"))
        self.assertEqual(list(decoded), ["results", "ports", "vlans",
                                         "security"])
        self.assertEqual(
            list(decoded["results"][0]),
            ["t", "class", "action", "ports", "dropped", "mirrors"],
        )
        self.assertEqual(
            list(decoded["results"][1]),
            ["t", "class", "action", "ports", "dropped", "mirrors"],
        )
        self.assertEqual(
            list(decoded["ports"][0]),
            ["name", "rx", "tx", "drop", "good", "runt", "giant",
             "alignment", "bad_fcs"],
        )
        self.assertEqual(
            list(decoded["security"][0]),
            ["port", "learned", "violations", "shutdown"],
        )
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b': ', raw)


class ValidationTests(unittest.TestCase):
    def _assert_exit4(self, events, cfg=None):
        code, out, err = run_cli(config() if cfg is None else cfg, events)
        self.assertEqual(code, 4, err)
        self.assertEqual(out, b"")
        self.assertEqual(err.strip(), b'{"error":"invalid_input"}')

    def test_double_tag_rejected(self):
        self._assert_exit4(
            [double_tag(raw_frame(0, "p1", BCAST, "00:00:00:00:00:01",
                                  vlan=1))]
        )

    def test_all_zero_dst_rejected(self):
        frame = raw_frame(0, "p1", BCAST, "00:00:00:00:00:01")
        raw = bytes.fromhex(frame["data"])
        frame["data"] = (b"\x00" * 6 + raw[6:]).hex()
        self._assert_exit4([frame])

    def test_non_unicast_src_rejected(self):
        # 源全零与组播源（首字节最低位为 1）均非法
        for src in ("00:00:00:00:00:00", "01:00:00:00:00:01"):
            self._assert_exit4([raw_frame(0, "p1", BCAST, src)])

    def test_data_hex_contract(self):
        good = raw_frame(0, "p1", BCAST, "00:00:00:00:00:01")
        for data in ("abc", "AB" * 18, "zz", "00" * 17):
            bad = dict(good)
            bad["data"] = data
            self._assert_exit4([bad])

    def test_unknown_port(self):
        self._assert_exit4(
            [raw_frame(0, "p9", BCAST, "00:00:00:00:00:01")]
        )

    def test_t_not_monotonic(self):
        self._assert_exit4([
            raw_frame(1, "p1", BCAST, "00:00:00:00:00:01"),
            raw_frame(0, "p1", BCAST, "00:00:00:00:00:02"),
        ])

    def test_t_non_decreasing_across_mixed_events(self):
        # 帧与 service 混合序上 t 非降：相等合法、回退非法
        code, _, _ = run_cli(config(), [
            service(1, "p3", 1),
            raw_frame(1, "p1", BCAST, "00:00:00:00:00:01"),
        ])
        self.assertEqual(code, 0)
        self._assert_exit4([
            raw_frame(2, "p1", BCAST, "00:00:00:00:00:01"),
            service(1, "p3", 1),
        ])

    def test_mixed_frame_shapes_rejected(self):
        check_frame = {
            "t": 1, "port": "p1", "src": "00:00:00:00:00:02",
            "dst": BCAST, "vlan": None, "ethertype": 2048, "priority": 0,
            "length": 100, "fcs": True, "alignment": True,
        }
        self._assert_exit4([
            raw_frame(0, "p1", BCAST, "00:00:00:00:00:01"),
            check_frame,
        ])

    def test_bad_config_matches_security_check(self):
        # CONFIG 形状与资源沿用 security-check：缺 max_frame 即非法
        cfg = config()
        del cfg["max_frame"]
        self._assert_exit4(
            [raw_frame(0, "p1", BCAST, "00:00:00:00:00:01")], cfg=cfg
        )


class ResourceAndWorkTests(unittest.TestCase):
    def test_usage_arity(self):
        # 仅接受 0、2、4、5 个可选上限
        with tempfile.TemporaryDirectory() as tmp:
            cfg = os.path.join(tmp, "c.json")
            evt = os.path.join(tmp, "e.json")
            with open(cfg, "w") as handle:
                handle.write(json.dumps(config()))
            with open(evt, "w") as handle:
                handle.write(json.dumps(
                    [raw_frame(0, "p1", BCAST, "00:00:00:00:00:01")]
                ))
            for extra in (("1",), ("1", "2", "3"),
                          ("1", "2", "3", "4", "5", "6"), ("0", "9")):
                proc = subprocess.run(
                    [sys.executable, SWITCH, "security-decode", cfg, evt,
                     *extra],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                self.assertEqual(
                    (proc.returncode, proc.stderr),
                    (2, b'{"error":"usage"}\n'),
                    extra,
                )

    def test_bad_frame_billed_like_frame(self):
        # 同 security-check：初始 C=1；单坏帧计 19，累计 20
        bad = raw_frame(0, "p1", BCAST, "00:00:00:00:00:01", payload_len=0)
        limits = (1000000, 1000000, 1000000, 1000000)
        code, out, err = run_cli(config(), [bad], *limits, 20)
        self.assertEqual(code, 0, err)
        code, out, err = run_cli(config(), [bad], *limits, 19)
        self.assertEqual(code, 5)
        self.assertEqual(err.strip(), b'{"error":"security_work_limit"}')
        self.assertEqual(out, b"")

    def test_full_validation_before_work_and_output(self):
        # 非法帧在工作量预演与仿真前全量拒绝：stdout 空
        bad = double_tag(raw_frame(0, "p1", BCAST, "00:00:00:00:00:01",
                                   vlan=1))
        code, out, err = run_cli(
            config(), [bad], 1000000, 1000000, 1000000, 1000000, 1
        )
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err.strip(), b'{"error":"invalid_input"}')

    def test_file_not_found(self):
        proc = subprocess.run(
            [sys.executable, SWITCH, "security-decode", "/nope/c", "/nope/e"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr.strip(),
                         b'{"error":"file_not_found"}')


if __name__ == "__main__":
    unittest.main()
