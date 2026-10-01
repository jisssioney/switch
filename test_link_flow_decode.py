#!/usr/bin/env python3
"""link-flow-decode 子命令回归。

link-flow-decode 使用 link-wire-decode 的 CONFIG（含 queue_bytes）另加每
端口布尔 flow_control，事件同为 link/advance 与 {t,port,data} 原始帧混合。
未带 VLAN 标签、目的 MAC 01:80:c2:00:00:01、以太类型 0x8808、操作码
0x0001、长度 64、保留字节全零且 good 的原始帧为 802.3x PAUSE：在入端口
本地终止（不学习源 MAC、不参与 VLAN 转发），up/full 且启用流控时按
ceil(quanta*512000/rate) 暂停该口后续发送；不支持时输出
pause_unsupported，控制帧长度/操作码/保留非法输出 malformed_pause；坏
FCS、短帧、超长帧沿用既有分类优先级。

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
MAC1 = "00:00:00:00:00:01"
MAC2 = "00:00:00:00:00:02"
MAC_PAUSE_SRC = "00:00:00:00:00:09"
PAUSE_DST = "01:80:c2:00:00:01"

WIRE = 20  # 前导码/定界符 8 + 帧间隔 12


def mac_bytes(mac):
    return bytes(int(part, 16) for part in mac.split(":"))


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


def config(ports=None, age=1000000, max_frame=1518, delay=10):
    return {
        "ports": ports if ports is not None else [
            port("p1", rates=[1000], modes=["full"]),
            port("p2", rates=[1000], modes=["full"]),
        ],
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
        "rates": [1000] if rates is None else rates,
        "modes": ["full"] if modes is None else modes,
    }


def advance(t):
    return {"t": t, "advance": True}


def data_frame(t, p, dst=BCAST, src=MAC1, payload_len=46, fcs_good=True,
               ethertype=b"\x08\x00"):
    """构造普通完整以太帧；默认 64 字节 untagged。"""
    body = mac_bytes(dst) + mac_bytes(src) + ethertype + b"\x00" * payload_len
    fcs = (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little")
    if not fcs_good:
        fcs = b"\xff\xff\xff\xff"
    return {"t": t, "port": p, "data": (body + fcs).hex()}


def pause_frame(t, p, quanta, dst=PAUSE_DST, src=MAC_PAUSE_SRC,
                opcode=0x0001, length=64, bad_reserved=False, vlan=None,
                fcs_good=True):
    """构造 802.3x MAC 控制帧；默认恰好 64 字节、保留全零、FCS 正确。"""
    head = mac_bytes(dst) + mac_bytes(src)
    if vlan is None:
        head += b"\x88\x08"
    else:
        head += b"\x81\x00" + vlan.to_bytes(2, "big") + b"\x88\x08"
    head += opcode.to_bytes(2, "big") + (quanta & 0xFFFF).to_bytes(2, "big")
    body = head + b"\x00" * (length - 4 - len(head))
    if bad_reserved:
        body = body[:-1] + b"\x01"
    fcs = (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little")
    if not fcs_good:
        fcs = b"\xff\xff\xff\xff"
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


def run_cli(which, config_doc, events, *limits, config_doc_override=None,
            events_override=None):
    tmp, cfg, evt = write_inputs(config_doc, events)
    cfg_path = cfg if config_doc_override is None else config_doc_override
    evt_path = evt if events_override is None else events_override
    proc = subprocess.run(
        [sys.executable, SWITCH, which, cfg_path, evt_path,
         *[str(x) for x in limits]],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    missing = subprocess.run(
        [sys.executable, SWITCH, which, os.path.join(tmp, "nope.json"), evt],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return proc, missing


def run_flow(config_doc, events, *limits):
    proc, _ = run_cli("link-flow-decode", config_doc, events, *limits)
    assert proc.returncode == 0, (
        proc.returncode, proc.stderr.decode("utf-8")
    )
    return proc.stdout


def tx_records(out):
    return [r for r in out["results"] if "start" in r]


def pause_records(out):
    return [r for r in out["results"] if "action" in r and "quanta" in r]


class ConfigShapeTests(unittest.TestCase):
    def test_flow_control_required_per_port(self):
        # 缺少 flow_control 的配置不属于 link-flow-decode：按既有
        # link-wire-decode 路由（结果端口无 PAUSE 统计键）
        cfg = config()
        for p in cfg["ports"]:
            del p["flow_control"]
        out = json.loads(_run(
            "link-wire-decode", cfg, [link(0, "p1"), link(0, "p2")]
        ))
        self.assertNotIn("pause_frames", out["ports"][0])

    def test_flow_control_must_be_bool(self):
        cfg = config()
        cfg["ports"][0]["flow_control"] = 1
        proc, _ = run_cli("link-flow-decode", cfg, [])
        self.assertEqual(proc.returncode, 4)
        self.assertEqual(proc.stderr, b'{"error":"invalid_input"}\n')
        cfg["ports"][0]["flow_control"] = True
        cfg["ports"][1]["flow_control"] = "yes"
        proc, _ = run_cli("link-flow-decode", cfg, [])
        self.assertEqual(proc.returncode, 4)

    def test_result_port_stats_key_order(self):
        cfg = config()
        out = json.loads(run_flow(cfg, [link(0, "p1"), link(0, "p2")]))
        self.assertEqual(
            list(out["ports"][0]),
            [
                "name", "rx_frames", "rx_bytes", "tx_frames", "tx_bytes",
                "collision_frames", "collision_bytes",
                "queue_full_frames", "queue_full_bytes",
                "link_down_frames", "link_down_bytes",
                "pause_frames", "pause_unsupported_frames", "pause_ns",
            ],
        )
        self.assertEqual(list(out), ["results", "ports"])


def _run(which, config_doc, events, *limits):
    proc, _ = run_cli(which, config_doc, events, *limits)
    assert proc.returncode == 0, (which, proc.returncode, proc.stderr)
    return proc.stdout


class PauseBasicTests(unittest.TestCase):
    def test_valid_pause_terminated_with_key_order_and_stats(self):
        cfg = config()
        events = [
            link(0, "p1"), link(0, "p2"),
            pause_frame(100, "p2", 10),
        ]
        out = json.loads(run_flow(cfg, events))
        records = pause_records(out)
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(list(rec), ["t", "port", "action", "quanta", "until"])
        self.assertEqual(rec["t"], 100)
        self.assertEqual(rec["port"], "p2")
        self.assertEqual(rec["action"], "pause")
        self.assertEqual(rec["quanta"], 10)
        # until = t + ceil(10*512000/1000) = 100 + 5120
        self.assertEqual(rec["until"], 5220)
        p2 = out["ports"][1]
        self.assertEqual(p2["pause_frames"], 1)
        self.assertEqual(p2["pause_unsupported_frames"], 0)
        # PAUSE 在入端口计入接收
        self.assertEqual(p2["rx_frames"], 1)
        self.assertEqual(p2["rx_bytes"], 64 + WIRE)
        # 不产生转发结果：PAUSE 之外仅有两条 link 状态记录
        self.assertEqual(
            [r.get("action") for r in out["results"]
             if r.get("action") is not None],
            ["pause"],
        )

    def test_quanta_ceil_at_10g(self):
        cfg = config([
            port("p1", rates=[10000], modes=["full"]),
            port("p2", rates=[10000], modes=["full"]),
        ], delay=1)
        events = [
            link(0, "p1", rates=[10000]), link(0, "p2", rates=[10000]),
            pause_frame(10, "p1", 1),
        ]
        out = json.loads(run_flow(cfg, events))
        rec = pause_records(out)[0]
        # ceil(512000/10000) = ceil(51.2) = 52
        self.assertEqual(rec["until"], 10 + 52)

    def test_pause_not_learned_and_not_forwarded(self):
        # PAUSE 源 MAC 不学习：随后到 p2、目的为该 MAC 的帧须洪泛至 p1
        cfg = config()
        events = [
            link(0, "p1"), link(0, "p2"),
            pause_frame(10, "p1", 0),
            data_frame(20, "p2", dst=MAC_PAUSE_SRC, src=MAC2),
        ]
        out = json.loads(run_flow(cfg, events))
        good = [r for r in out["results"] if r.get("class") == "good"]
        self.assertEqual(len(good), 1)
        self.assertEqual(good[0]["action"], "flood")
        self.assertEqual([p["name"] for p in good[0]["ports"]], ["p1"])

    def test_tagged_pause_dst_is_normal_frame(self):
        # 带 VLAN 标签的 8808 帧不是 PAUSE：按普通 good 帧转发
        cfg = config([
            port("p1", mode="trunk", pvid=1, allowed=[1, 2], untagged=[]),
            port("p2", mode="trunk", pvid=1, allowed=[1, 2], untagged=[]),
        ])
        events = [
            link(0, "p1"), link(0, "p2"),
            pause_frame(10, "p1", 1, vlan=1, length=68),
        ]
        out = json.loads(run_flow(cfg, events))
        self.assertEqual(pause_records(out), [])
        good = [r for r in out["results"] if r.get("class") == "good"]
        self.assertEqual(good[0]["action"], "flood")


class PauseSchedulingTests(unittest.TestCase):
    def setUp(self):
        # rate 1000 Mbps：64 字节帧线路 84 字节，时长 ceil(84*8000/1000)=672
        self.cfg = config(delay=1)
        self.up = [link(0, "p1"), link(0, "p2")]
        self.duration = 672

    def test_started_frame_completes_queued_copies_shift(self):
        events = self.up + [
            data_frame(10, "p1"),   # p2 队头 [10,682)
            data_frame(20, "p1"),   # 原排程 [682,1354)
            pause_frame(100, "p2", 10),  # until=5220
            advance(6000),
        ]
        out = json.loads(run_flow(self.cfg, events))
        self.assertEqual(
            [(r["start"], r["t"]) for r in tx_records(out)],
            [(10, 682), (5220, 5220 + self.duration)],
        )
        # 暂停实际时长 5120
        self.assertEqual(out["ports"][1]["pause_ns"], 5120)

    def test_new_copy_appends_after_adjusted_tail(self):
        events = self.up + [
            data_frame(10, "p1"),
            data_frame(20, "p1"),                 # 被 PAUSE 推到 5220
            pause_frame(100, "p2", 10),
            data_frame(300, "p1"),                # 接调整后队尾 5892
            advance(7000),
        ]
        out = json.loads(run_flow(self.cfg, events))
        self.assertEqual(
            [(r["start"], r["t"]) for r in tx_records(out)],
            [(10, 682), (5220, 5892), (5892, 6564)],
        )

    def test_shift_preserves_order(self):
        events = self.up + [
            data_frame(10, "p1"),
            data_frame(11, "p1", src="00:00:00:00:00:03"),
            data_frame(12, "p1", src="00:00:00:00:00:04"),
            pause_frame(100, "p2", 10),
            advance(8000),
        ]
        out = json.loads(run_flow(self.cfg, events))
        # 队头 682 完成，其余两副本次序不变、自 5220 串行
        self.assertEqual(
            [(r["start"], r["t"]) for r in tx_records(out)],
            [(10, 682), (5220, 5892), (5892, 6564)],
        )

    def test_nonzero_overrides_old_deadline(self):
        events = self.up + [
            data_frame(10, "p1"),
            data_frame(20, "p1"),
            pause_frame(100, "p2", 100),  # until=51300，副本推至 51300
            pause_frame(200, "p2", 1),    # 覆盖：until=712，副本重排至 712
            advance(3000),
        ]
        out = json.loads(run_flow(self.cfg, events))
        self.assertEqual(
            [(r["start"], r["t"]) for r in tx_records(out)],
            [(10, 682), (712, 712 + self.duration)],
        )
        rec = pause_records(out)
        self.assertEqual([r["until"] for r in rec], [51300, 712])
        # 实际暂停：[100,200) 100ns + [200,712) 512ns
        self.assertEqual(out["ports"][1]["pause_ns"], 612)

    def test_zero_quanta_resumes_after_current_frame(self):
        events = self.up + [
            data_frame(10, "p1"),
            data_frame(20, "p1"),                  # 被推至 51300
            pause_frame(100, "p2", 100),
            pause_frame(200, "p2", 0),             # 当前帧 682 完成后恢复
            advance(3000),
        ]
        out = json.loads(run_flow(self.cfg, events))
        zero = [r for r in pause_records(out) if r["quanta"] == 0][0]
        self.assertEqual(list(zero),
                         ["t", "port", "action", "quanta", "until"])
        self.assertEqual(zero["until"], 200)
        self.assertEqual(
            [(r["start"], r["t"]) for r in tx_records(out)],
            [(10, 682), (682, 682 + self.duration)],
        )
        # 实际暂停仅 [100,200)
        self.assertEqual(out["ports"][1]["pause_ns"], 100)

    def test_pause_expiry_settled_by_advance(self):
        events = self.up + [
            data_frame(10, "p1"),
            pause_frame(100, "p2", 1),  # until=612；队头 [10,682) 不受影响
            advance(700),                # 暂停到期、队头完成
        ]
        out = json.loads(run_flow(self.cfg, events))
        self.assertEqual(
            [(r["start"], r["t"]) for r in tx_records(out)], [(10, 682)]
        )
        self.assertEqual(out["ports"][1]["pause_ns"], 512)

    def test_no_auto_drain_after_last_event(self):
        events = self.up + [
            data_frame(10, "p1"),
            pause_frame(100, "p2", 10),
        ]
        out = json.loads(run_flow(self.cfg, events))
        # 末事件后不自动排空：队头在 100 尚未完成（end 682），无发送记录；
        # 暂停段按末事件时刻 100 结算，实际时长 0
        self.assertEqual(tx_records(out), [])
        self.assertEqual(out["ports"][1]["pause_ns"], 0)

    def test_leaving_up_clears_pause(self):
        events = self.up + [
            pause_frame(100, "p2", 100),  # until=51300
            link(200, "p2", admin=False),  # 离开 up：暂停清除
            link(301, "p2"),               # delay=1，302 重新 up
            data_frame(400, "p1"),
            advance(3000),
        ]
        out = json.loads(run_flow(self.cfg, events))
        self.assertEqual(out["ports"][1]["pause_ns"], 100)
        # 新 up 后入队副本不受旧暂停影响：[400,1072)
        self.assertEqual(
            [(r["start"], r["t"]) for r in tx_records(out)], [(400, 1072)]
        )


class UnsupportedTests(unittest.TestCase):
    def _record(self, cfg, events):
        out = json.loads(run_flow(cfg, events))
        self.assertEqual(pause_records(out), [
            r for r in out["results"]
            if r.get("action") == "pause_unsupported"
        ])
        return out

    def test_flow_control_disabled(self):
        cfg = config([
            port("p1", flow_control=False),
            port("p2"),
        ])
        out = self._record(cfg, [link(0, "p1"), link(0, "p2"),
                                 pause_frame(10, "p1", 10)])
        rec = out["results"][-1]
        self.assertEqual(list(rec), ["t", "port", "action", "quanta"])
        self.assertEqual(rec["action"], "pause_unsupported")
        self.assertEqual(rec["quanta"], 10)
        self.assertEqual(out["ports"][0]["pause_unsupported_frames"], 1)
        self.assertEqual(out["ports"][0]["pause_frames"], 0)

    def test_half_duplex(self):
        cfg = config([
            port("p1", modes=["half"]),
            port("p2"),
        ])
        out = self._record(cfg, [link(0, "p1", modes=["half"]),
                                 link(0, "p2"), pause_frame(10, "p1", 10)])
        self.assertEqual(out["ports"][0]["pause_unsupported_frames"], 1)

    def test_down_and_wait(self):
        cfg = config(delay=100)
        # 未协商：down
        out = self._record(cfg, [pause_frame(10, "p1", 10)])
        self.assertEqual(out["ports"][0]["pause_unsupported_frames"], 1)
        # 协商中：wait
        out = self._record(cfg, [link(0, "p1"), pause_frame(10, "p1", 10)])
        self.assertEqual(out["ports"][0]["pause_unsupported_frames"], 1)

    def test_bad_link(self):
        cfg = config([
            port("p1", rates=[10000], modes=["full"]),
            port("p2"),
        ])
        out = self._record(cfg, [
            link(0, "p1", rates=[100], modes=["full"]),  # 无共同速率 -> bad
            link(0, "p2"),
            pause_frame(100, "p1", 10),
        ])
        self.assertEqual(out["ports"][0]["pause_unsupported_frames"], 1)

    def test_unsupported_consumed_but_queue_unchanged(self):
        cfg = config(delay=1)
        events = [
            link(0, "p1"), link(0, "p2"),
            data_frame(10, "p1"),
            data_frame(20, "p1"),
        ]
        baseline = json.loads(run_flow(cfg, events + [advance(3000)]))
        # half 口收到 PAUSE 不改 p1 队列；p1 本口是 full 这里改用关闭流控
        cfg2 = config([
            port("p1", flow_control=True),
            port("p2", flow_control=False),
        ], delay=1)
        events2 = [
            link(0, "p1"), link(0, "p2"),
            data_frame(10, "p1"),
            data_frame(20, "p1"),
            pause_frame(30, "p2", 100),  # p2 不支持：队列不动
            advance(3000),
        ]
        out = json.loads(run_flow(cfg2, events2))
        # 与无 PAUSE 的发送时刻逐点一致
        self.assertEqual(
            [(r["start"], r["t"]) for r in tx_records(out)],
            [(r["start"], r["t"]) for r in tx_records(baseline)],
        )
        self.assertEqual(out["ports"][1]["pause_unsupported_frames"], 1)
        self.assertEqual(out["ports"][1]["pause_ns"], 0)


class MalformedTests(unittest.TestCase):
    def setUp(self):
        self.cfg = config()
        self.up = [link(0, "p1"), link(0, "p2")]

    def test_bad_opcode(self):
        out = json.loads(run_flow(self.cfg, self.up + [
            pause_frame(10, "p1", 5, opcode=0x0002),
        ]))
        rec = pause_records(out)[0]
        self.assertEqual(rec["action"], "malformed_pause")
        self.assertEqual(rec["quanta"], 5)

    def test_bad_reserved(self):
        out = json.loads(run_flow(self.cfg, self.up + [
            pause_frame(10, "p1", 5, bad_reserved=True),
        ]))
        self.assertEqual(pause_records(out)[0]["action"], "malformed_pause")

    def test_bad_length_above_64_is_malformed(self):
        # 66 字节、8808/0001：超出 64 属控制帧长度非法（malformed_pause）
        out = json.loads(run_flow(self.cfg, self.up + [
            pause_frame(10, "p1", 5, length=66),
        ]))
        self.assertEqual(pause_records(out)[0]["action"], "malformed_pause")

    def test_runt_keeps_classification_priority(self):
        # 60 字节短帧：分类为 runt，不识别为控制帧
        raw = pause_frame(10, "p1", 5, length=60)
        out = json.loads(run_flow(self.cfg, self.up + [raw]))
        self.assertEqual(pause_records(out), [])
        self.assertEqual(out["results"][-1]["class"], "runt")

    def test_bad_fcs_keeps_classification_priority(self):
        out = json.loads(run_flow(self.cfg, self.up + [
            pause_frame(10, "p1", 5, fcs_good=False),
        ]))
        self.assertEqual(pause_records(out), [])
        self.assertEqual(out["results"][-1]["class"], "bad_fcs")

    def test_giant_keeps_classification_priority(self):
        out = json.loads(run_flow(self.cfg, self.up + [
            pause_frame(10, "p1", 5, length=2000),
        ]))
        self.assertEqual(pause_records(out), [])
        self.assertEqual(out["results"][-1]["class"], "giant")

    def test_malformed_is_terminated_not_forwarded(self):
        out = json.loads(run_flow(self.cfg, self.up + [
            pause_frame(10, "p1", 5, opcode=0x0003),
        ]))
        # 无 good 转发记录，端口不暂停
        self.assertNotIn("until", out["results"][-1])
        self.assertEqual(out["ports"][0]["pause_frames"], 0)
        self.assertEqual(out["ports"][0]["pause_ns"], 0)


class HalfDuplexCollisionTests(unittest.TestCase):
    def test_pause_on_half_during_tx_is_unsupported_not_collision(self):
        # PAUSE 识别先于半双工碰撞：half 口发送区间收到 PAUSE 仍按
        # pause_unsupported 消费、不改队列（不产生 collision）
        cfg = config([
            port("p1", rates=[1000], modes=["half"], flow_control=True),
            port("p2", rates=[1000], modes=["half"]),
        ], delay=1)
        events = [
            link(0, "p1"), link(0, "p2"),
            data_frame(10, "p2", src=MAC2, payload_len=1000 - 18),
            pause_frame(11, "p2", 10),
        ]
        out = json.loads(run_flow(cfg, events))
        self.assertIsNone(next(
            (r for r in out["results"] if r.get("reason") == "collision"),
            None,
        ))
        self.assertEqual(pause_records(out)[0]["action"], "pause_unsupported")


class ResourceAndErrorTests(unittest.TestCase):
    def test_missing_file_exit3(self):
        cfg = config()
        tmp = tempfile.mkdtemp()
        evt = os.path.join(tmp, "events.json")
        with open(evt, "wb") as handle:
            handle.write(b"[]")
        proc = subprocess.run(
            [sys.executable, SWITCH, "link-flow-decode",
             os.path.join(tmp, "nope.json"), evt],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(proc.stdout, b"")
        self.assertIn(b"file_not_found", proc.stderr)

    def test_limits_exit5(self):
        cfg = config()
        events = [link(0, "p1"), link(1, "p2")]
        proc, _ = run_cli("link-flow-decode", cfg, events, 100, 1000000)
        self.assertEqual(proc.returncode, 5)
        self.assertIn(b"config_limit", proc.stderr)
        proc, _ = run_cli("link-flow-decode", cfg, events, 1000000, 5)
        self.assertEqual(proc.returncode, 5)
        self.assertIn(b"data_limit", proc.stderr)
        proc, _ = run_cli(
            "link-flow-decode", cfg, events, 1000000, 1000000, 1, 1000000
        )
        self.assertEqual(proc.returncode, 5)
        self.assertIn(b"item_limit", proc.stderr)
        proc, _ = run_cli(
            "link-flow-decode", cfg, events, 1000000, 1000000, 1000000, 10
        )
        self.assertEqual(proc.returncode, 5)
        self.assertIn(b"output_limit", proc.stderr)
        self.assertEqual(proc.stdout, b"")

    def test_usage_exit2(self):
        tmp, cfg, evt = write_inputs(config(), [])
        for argv in (
            ["link-flow-decode", cfg],
            ["link-flow-decode", cfg, evt, "1"],
            ["link-flow-decode", cfg, evt, "1", "2", "3"],
            ["link-flow-decode", cfg, evt, "0"],
        ):
            proc = subprocess.run(
                [sys.executable, SWITCH, *argv],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(proc.returncode, 2, argv)
            self.assertIn(b"usage", proc.stderr)

    def test_invalid_input_exit4_empty_stdout(self):
        cfg = config()
        good = data_frame(10, "p1")
        bad = data_frame(11, "p1", src="00:00:00:00:00:00")
        proc, _ = run_cli("link-flow-decode", cfg, [
            link(0, "p1"), good, bad,
        ])
        self.assertEqual(proc.returncode, 4)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b'{"error":"invalid_input"}\n')

    def test_work_limit_charges_shifted_copies(self):
        cfg = config(delay=1)
        events = [
            link(0, "p1"), link(0, "p2"),
            data_frame(10, "p1"),
            data_frame(11, "p1"),
            data_frame(12, "p1"),
            pause_frame(100, "p2", 10),
        ]
        # 先取无上限 W：P=2 起，每事件/结果/后移副本计费
        proc, _ = run_cli(
            "link-flow-decode", cfg, events,
            1000000, 1000000, 1000000, 1000000, 100000000,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        # PAUSE 后移两个未开始副本：恰在两次后移计费的边界上
        # 统计 W：2(初值)
        # link p1: charge settle 1 + 状态结果 1 = +2
        # link p2: +2
        # 三帧各：settle 1 + good 1 + enqueue 1 = +3 => +9
        # PAUSE：settle 1 + pause 1 + 后移 2 = +4
        # 合计 2+4+9+4 = 19
        for limit, code in ((19, 0), (18, 5)):
            proc, _ = run_cli(
                "link-flow-decode", cfg, events,
                1000000, 1000000, 1000000, 1000000, limit,
            )
            self.assertEqual(proc.returncode, code, (limit, proc.stderr))
            if code == 5:
                self.assertEqual(proc.stdout, b"")
                self.assertEqual(
                    proc.stderr, b'{"error":"link_flow_work_limit"}\n'
                )


class DeterminismTests(unittest.TestCase):
    def test_repeat_byte_identical(self):
        cfg = config(delay=1)
        events = [
            link(0, "p1"), link(0, "p2"),
            data_frame(10, "p1"),
            pause_frame(100, "p2", 10),
            advance(6000),
        ]
        a = run_flow(cfg, events)
        b = run_flow(cfg, events)
        self.assertEqual(a, b)
        self.assertTrue(a.endswith(b"\n"))


if __name__ == "__main__":
    unittest.main()
