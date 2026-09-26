#!/usr/bin/env python3
"""link-forward 子命令回归：链路协商 + 802.1Q 转发联合仿真。

仅用标准库；通过 `python switch.py link-forward CONFIG EVENTS` 端到端驱动。
协商契约同 link-state；帧分类/VLAN/标签/老化/统计同 forward-check。
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


def run_cli(config_doc, events, *limits):
    with tempfile.TemporaryDirectory() as tmp:
        cfg = os.path.join(tmp, "config.json")
        evt = os.path.join(tmp, "events.json")
        with open(cfg, "wb") as handle:
            handle.write(json.dumps(config_doc).encode("utf-8"))
        with open(evt, "wb") as handle:
            handle.write(json.dumps(events).encode("utf-8"))
        proc = subprocess.run(
            [sys.executable, SWITCH, "link-forward", cfg, evt,
             *[str(x) for x in limits]],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        missing = subprocess.run(
            [sys.executable, SWITCH, "link-forward",
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


class NegotiationTests(unittest.TestCase):
    def test_wait_then_up_and_result_keys(self):
        events = [
            link(0, "p1", rates=[1000], modes=["full"]),
            link(0, "p2"),
            frame(9, "p1", "00:00:00:00:00:01"),
            frame(10, "p1", "00:00:00:00:00:01"),
        ]
        out = run(config(), events)
        self.assertEqual(
            out["results"][0],
            {"t": 0, "port": "p1", "state": "wait",
             "rate": None, "mode": None},
        )
        # delay=10：t=9 仍 wait，入帧丢弃；t=10 协商完成后泛洪到 up 的 p2
        self.assertEqual(out["results"][2]["action"], "drop")
        self.assertEqual(out["results"][3]["action"], "flood")
        self.assertEqual(
            out["results"][3]["ports"],
            [{"name": "p2", "vlan": None}],
        )
        self.assertEqual(
            list(out["results"][0]), ["t", "port", "state", "rate", "mode"]
        )

    def test_negotiated_rate_and_mode(self):
        events = [
            link(0, "p1", rates=[100, 1000], modes=["half"]),
            link(5, "p1", rates=[100, 1000], modes=["half"]),
        ]
        out = run(config(delay=5), events)
        # t=0 进入 wait；t=5 协商到期后同目标不重置，结果为 up 及选用参数
        self.assertEqual(out["results"][0]["state"], "wait")
        self.assertEqual(
            out["results"][1],
            {"t": 5, "port": "p1", "state": "up",
             "rate": 1000, "mode": "half"},
        )

    def test_bad_then_recover(self):
        # p1 仅支持 100/1000：对端 10000 无共同速率 -> bad
        cfg = config([port("p1", rates=[100, 1000]), port("p2")])
        events = [
            link(0, "p1", rates=[10000], modes=["full"]),
            link(1, "p1", rates=[10000], modes=["full"]),
            link(2, "p1", rates=[100, 1000], modes=["full"]),
            link(2, "p2"),
            frame(12, "p1", "00:00:00:00:00:01"),
        ]
        out = run(cfg, events)
        self.assertEqual(out["results"][0]["state"], "bad")
        # 目标未变（bad->bad）不重置
        self.assertEqual(out["results"][1]["state"], "bad")
        self.assertEqual(out["results"][2]["state"], "wait")
        self.assertEqual(out["results"][4]["action"], "flood")

    def test_down_immediate_and_peer_false(self):
        events = [
            link(0, "p1"),
            link(10, "p1", admin=False),
            link(10, "p2", peer=False),
        ]
        out = run(config(delay=10), events)
        self.assertEqual(out["results"][0]["state"], "wait")
        self.assertEqual(out["results"][1]["state"], "down")
        self.assertEqual(out["results"][2]["state"], "down")

    def test_deadline_due_before_each_item_even_other_port(self):
        # t=0 p1 进入 wait（deadline 10）；t=10 p2 事件先完成 p1 协商，
        # 同结果序内只追加 p2 的协商结果；p3 已 up 供泛洪观察
        cfg = config([port("p1"), port("p2"), port("p3")])
        events = [
            link(0, "p1"),
            link(0, "p3"),
            link(10, "p2"),
            frame(10, "p1", "00:00:00:00:00:01"),
        ]
        out = run(cfg, events)
        self.assertEqual(out["results"][2]["state"], "wait")  # p2
        # p1 已 up：广播泛洪到 up 的 p3，wait 的 p2 除外
        self.assertEqual(out["results"][3]["action"], "flood")
        self.assertEqual(
            out["results"][3]["ports"], [{"name": "p3", "vlan": None}]
        )


class ForwardingTests(unittest.TestCase):
    def two_access(self, **kw):
        return config([port("p1"), port("p2")], **kw)

    def test_wait_port_frame_dropped_not_learned(self):
        events = [
            link(0, "p1"),
            link(0, "p2"),
            frame(5, "p1", "00:00:00:00:00:01"),  # p1 wait，不学习
            frame(11, "p2", "00:00:00:00:00:02",
                  dst="00:00:00:00:00:01"),  # src1 未学习 -> 泛洪
        ]
        out = run(self.two_access(), events)
        self.assertEqual(out["results"][0]["state"], "wait")
        self.assertEqual(out["results"][2]["action"], "drop")
        flood = out["results"][3]
        self.assertEqual(flood["action"], "flood")
        # t=11 时 p1 已 up（deadline 10 到期）
        self.assertEqual(
            flood["ports"], [{"name": "p1", "vlan": None}]
        )

    def test_unicast_after_both_up(self):
        events = [
            link(0, "p1"),
            link(0, "p2"),
            frame(10, "p1", "00:00:00:00:00:01"),
            frame(11, "p2", "00:00:00:00:00:02",
                  dst="00:00:00:00:00:01"),
        ]
        out = run(self.two_access(), events)
        self.assertEqual(out["results"][2]["action"], "flood")
        self.assertEqual(
            out["results"][2]["ports"],
            [{"name": "p2", "vlan": None}],
        )
        self.assertEqual(out["results"][3]["action"], "unicast")
        self.assertEqual(
            out["results"][3]["ports"],
            [{"name": "p1", "vlan": None}],
        )

    def test_leave_up_clears_fdb_and_recovery_keeps_cleared(self):
        mac1 = "00:00:00:00:00:01"
        cfg = config([port("p1"), port("p2"), port("p3")])
        events = [
            link(0, "p1"),
            link(0, "p2"),
            link(0, "p3"),
            frame(10, "p1", mac1),                 # 学习 p1，泛洪 p2,p3
            frame(11, "p2", "00:00:00:00:00:02",
                  dst=mac1),                       # unicast 命中 p1
            link(12, "p1", admin=False),           # down 清 p1 FDB
            frame(13, "p2", "00:00:00:00:00:02",
                  dst=mac1),                       # 已无命中 -> 泛洪 p3
            link(14, "p1"),                        # 重新协商 wait
            frame(23, "p2", "00:00:00:00:00:02",
                  dst=mac1),                       # 恢复 up 不恢复表项
        ]
        out = run(cfg, events)
        self.assertEqual(out["results"][3]["action"], "flood")
        self.assertEqual(out["results"][4]["action"], "unicast")
        self.assertEqual(out["results"][5]["state"], "down")
        self.assertEqual(out["results"][6]["action"], "flood")
        self.assertEqual(
            out["results"][6]["ports"],
            [{"name": "p3", "vlan": None}],
        )
        self.assertEqual(out["results"][7]["state"], "wait")
        self.assertEqual(out["results"][8]["action"], "flood")
        self.assertEqual(
            out["results"][8]["ports"],
            [{"name": "p3", "vlan": None}],
        )

    def test_renegotiation_wait_clears_fdb(self):
        mac1 = "00:00:00:00:00:01"
        events = [
            link(0, "p1", rates=[100]),
            link(0, "p2", rates=[100]),
            frame(10, "p1", mac1),
            frame(11, "p2", "00:00:00:00:00:02", dst=mac1),
            link(12, "p1", rates=[1000]),          # 共同速率变 -> up 转 wait
            frame(13, "p2", "00:00:00:00:00:02", dst=mac1),
        ]
        out = run(self.two_access(), events)
        self.assertEqual(out["results"][2]["action"], "flood")
        self.assertEqual(out["results"][3]["action"], "unicast")
        self.assertEqual(out["results"][4]["state"], "wait")
        # p1 表项已清，且 p1 在 wait：无命中泛洪也无出口 -> drop
        self.assertEqual(out["results"][5]["action"], "drop")

    def test_bad_transition_clears_fdb(self):
        mac1 = "00:00:00:00:00:01"
        # p1 仅支持 100/1000，对端 10000 无共同速率
        cfg = config([
            port("p1", rates=[100, 1000]),
            port("p2"),
            port("p3"),
        ])
        events = [
            link(0, "p1", rates=[100, 1000]),
            link(0, "p2"),
            link(0, "p3"),
            frame(10, "p1", mac1),
            link(11, "p1", rates=[10000]),         # 无共同速率：up -> bad
            frame(12, "p2", "00:00:00:00:00:02", dst=mac1),
        ]
        out = run(cfg, events)
        self.assertEqual(out["results"][4]["state"], "bad")
        self.assertEqual(out["results"][5]["action"], "flood")
        self.assertEqual(
            out["results"][5]["ports"],
            [{"name": "p3", "vlan": None}],
        )

    def test_down_port_is_not_egress(self):
        events = [
            link(0, "p1"),
            frame(10, "p1", "00:00:00:00:00:01"),  # p2 仍 down
        ]
        out = run(self.two_access(), events)
        self.assertEqual(out["results"][1]["action"], "drop")
        self.assertEqual(out["results"][1]["ports"], [])

    def test_tagged_trunk_egress_and_vlan_stats(self):
        # 两端 trunk：p1 准入带标签 vlan1，p2 出口保留标签
        cfg = config([
            port("p1", mode="trunk", pvid=1, allowed=[1], untagged=[]),
            port("p2", mode="trunk", pvid=2, allowed=[1, 2], untagged=[]),
        ])
        events = [
            link(0, "p1"),
            link(0, "p2"),
            frame(10, "p1", "00:00:00:00:00:01", vlan=1),
        ]
        out = run(cfg, events)
        self.assertEqual(out["results"][2]["action"], "flood")
        self.assertEqual(
            out["results"][2]["ports"], [{"name": "p2", "vlan": 1}]
        )
        vlans = {v["vlan"]: v for v in out["vlans"]}
        self.assertEqual(vlans[1]["rx"], 1)
        self.assertEqual(vlans[1]["tx"], 1)
        self.assertEqual(vlans[1]["drop"], 0)
        self.assertEqual(vlans[2]["rx"], 0)

    def test_tagged_frame_on_access_rejected(self):
        events = [
            link(0, "p1"),
            frame(10, "p1", "00:00:00:00:00:01", vlan=2),
        ]
        out = run(config([port("p1", pvid=1)]), events)
        self.assertEqual(out["results"][1]["action"], "drop")
        # 拒绝不计 VLAN：仅 vlan1 出现在统计中且 rx 为 0
        self.assertEqual([v["vlan"] for v in out["vlans"]], [1])
        self.assertEqual(out["vlans"][0]["rx"], 0)

    def test_aging_same_as_forward_check(self):
        mac1 = "00:00:00:00:00:01"
        base = [
            link(0, "p1"),
            link(0, "p2"),
            frame(10, "p1", mac1),
        ]
        # t-seen=10，age=100：t=109 时差 99 未老化 -> 单播命中
        events = base + [
            frame(109, "p2", "00:00:00:00:00:02", dst=mac1),
        ]
        out = run(self.two_access(age=100), events)
        self.assertEqual(out["results"][3]["action"], "unicast")
        # t=110 时差 100 达到老化 -> 无命中，泛洪
        events = base + [
            frame(110, "p2", "00:00:00:00:00:02", dst=mac1),
        ]
        out = run(self.two_access(age=100), events)
        self.assertEqual(out["results"][3]["action"], "flood")

    def test_frame_classification_and_port_counters(self):
        events = [
            link(0, "p1"),
            frame(10, "p1", "00:00:00:00:00:01", length=63),      # runt
            frame(11, "p1", "00:00:00:00:00:01", length=1519),    # giant
            frame(12, "p1", "00:00:00:00:00:01", alignment=False),
            frame(13, "p1", "00:00:00:00:00:01", fcs=False),
            frame(14, "p1", "00:00:00:00:00:01"),                 # good
        ]
        out = run(config([port("p1")], max_frame=1518), events)
        classes = [r["class"] for r in out["results"][1:]]
        self.assertEqual(
            classes, ["runt", "giant", "alignment", "bad_fcs", "good"]
        )
        stats = out["ports"][0]
        self.assertEqual(stats["rx"], 5)
        # 4 个坏帧丢弃；good 广播帧无其他 up 口亦计入 drop
        self.assertEqual(stats["drop"], 5)
        self.assertEqual(stats["good"], 1)
        self.assertEqual(stats["runt"], 1)
        self.assertEqual(stats["giant"], 1)
        self.assertEqual(stats["alignment"], 1)
        self.assertEqual(stats["bad_fcs"], 1)
        self.assertEqual(stats["tx"], 0)
        # 坏帧不学习不转发：good 帧广播但无其他 up 口
        self.assertEqual(out["results"][5]["action"], "drop")


class OutputContractTests(unittest.TestCase):
    def test_key_orders_and_compact_bytes(self):
        cfg = config([port("p1"), port("p2", mode="trunk", pvid=1,
                                      allowed=[1], untagged=[])])
        events = [
            link(0, "p1"),
            link(0, "p2"),
            frame(10, "p1", "00:00:00:00:00:01"),
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
            list(decoded["ports"][0]),
            ["name", "rx", "tx", "drop", "good", "runt", "giant",
             "alignment", "bad_fcs"],
        )
        self.assertEqual(list(decoded["vlans"][0]),
                         ["vlan", "rx", "tx", "drop"])
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b": ", raw)


class ValidationTests(unittest.TestCase):
    def _assert_exit4(self, cfg, events):
        proc, _ = run_cli(cfg, events)
        self.assertEqual(proc.returncode, 4, proc.stderr)
        self.assertEqual(proc.stdout, b"")
        self.assertIn(b"invalid_input", proc.stderr)

    def test_config_extra_and_missing_keys(self):
        cfg = config()
        bad = dict(cfg)
        bad["extra"] = 1
        self._assert_exit4(bad, [])
        for key in ("ports", "age", "max_frame", "delay"):
            bad = dict(cfg)
            del bad[key]
            self._assert_exit4(bad, [])

    def test_port_up_rejected_rates_modes_required(self):
        good = port("p1")
        # 旧式/forward-check 端口的 up 键不再合法
        bad = dict(good)
        bad["up"] = True
        self._assert_exit4(config([bad]), [])
        for key in ("rates", "modes"):
            bad = dict(good)
            del bad[key]
            self._assert_exit4(config([bad]), [])

    def test_bad_rates_modes(self):
        for rates in ([], [100, 100], [100, 10], [100, 9], ["100"],
                      [100.0]):
            self._assert_exit4(config([port("p1", rates=rates)]), [])
        # 合法子集接受
        proc, _ = run_cli(config([port("p1", rates=[100, 1000])]), [])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for modes in ([], ["full", "full"], ["full", "half"], ["nope"]):
            self._assert_exit4(config([port("p1", modes=modes)]), [])

    def test_bad_delay_age_max_frame(self):
        for key, value in (("delay", 0), ("delay", -1), ("delay", "x"),
                           ("age", 0), ("age", True),
                           ("max_frame", 1517), ("max_frame", 9217)):
            self._assert_exit4(config(**{key: value}), [])

    def test_port_vlan_constraints_kept(self):
        # access 口允许多 VLAN 仍非法（约束同新式 forward）
        self._assert_exit4(
            config([port("p1", mode="access", allowed=[1, 2])]), []
        )
        # trunk 口 untagged 非空非法
        self._assert_exit4(
            config([port("p1", mode="trunk", pvid=1, allowed=[1],
                         untagged=[1])]),
            [],
        )
        # 重名口非法
        self._assert_exit4(config([port("p1"), port("p1")]), [])

    def test_events_must_be_list_t_non_decreasing(self):
        cfg = config()
        self._assert_exit4(cfg, {"x": 1})
        good = link(0, "p1")
        self._assert_exit4(
            cfg, [link(5, "p1"), frame(4, "p1", "00:00:00:00:00:01")]
        )

    def test_event_shapes_strict(self):
        cfg = config()
        good_link = link(0, "p1")
        good_frame = frame(0, "p1", "00:00:00:00:00:01")
        for bad in (
            {},
            {"t": 0, "port": "p1"},  # 既非协商项也非帧项
            {**good_link, "extra": 1},
            {**good_frame, "extra": 1},
        ):
            self._assert_exit4(cfg, [bad])
        # 协商项 admin/peer 必须为 bool
        bad = dict(good_link)
        bad["admin"] = 1
        self._assert_exit4(cfg, [bad])
        # 帧项 fcs 必须为 bool
        bad = dict(good_frame)
        bad["fcs"] = 1
        self._assert_exit4(cfg, [bad])

    def test_unknown_port_and_bad_macs(self):
        cfg = config()
        self._assert_exit4(cfg, [link(0, "nope")])
        self._assert_exit4(cfg, [frame(0, "nope", "00:00:00:00:00:01")])
        self._assert_exit4(cfg, [frame(0, "p1", "nope")])
        self._assert_exit4(
            cfg, [frame(0, "p1", "00:00:00:00:00:01", dst="nope")]
        )
        self._assert_exit4(
            cfg, [frame(0, "p1", "00:00:00:00:00:01", vlan=0)]
        )


class ResourceAndErrorTests(unittest.TestCase):
    def test_missing_file_exit3(self):
        proc, missing = run_cli(config(), [])
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(missing.returncode, 3)
        self.assertEqual(missing.stdout, b"")
        self.assertIn(b"file_not_found", missing.stderr)

    def test_config_and_data_limit_exit5(self):
        cfg = config()
        events = [link(0, "p1")]
        # 配置约大于 100 字节
        proc, _ = run_cli(cfg, events, 100, 1000000)
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(proc.stdout, b"")
        self.assertIn(b"config_limit", proc.stderr)
        proc, _ = run_cli(cfg, events, 1000000, 5)
        self.assertEqual(proc.returncode, 5)
        self.assertIn(b"data_limit", proc.stderr)
        self.assertEqual(proc.stdout, b"")

    def test_item_limit_exit5(self):
        events = [link(i, "p1") for i in range(3)]
        proc, _ = run_cli(config(), events, 1000000, 1000000, 2, 1000000)
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(proc.stdout, b"")
        self.assertIn(b"item_limit", proc.stderr)
        # 恰等于上限合法
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
                ["link-forward", cfg],                       # 缺路径
                ["link-forward", cfg, evt, "1"],             # 1 项上限
                ["link-forward", cfg, evt, "1", "2", "3"],   # 3 项
                ["link-forward", cfg, evt, "0"],             # 须 [1-9]
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
        # 末项非法时 stdout 必须为空（全量校验在前）
        bad_events = [
            link(0, "p1"),
            frame(10, "p1", "00:00:00:00:00:01"),
            frame(11, "ghost", "00:00:00:00:00:02"),
        ]
        proc, _ = run_cli(config(), bad_events)
        self.assertEqual(proc.returncode, 4)
        self.assertEqual(proc.stdout, b"")


class ModeValidationTests(unittest.TestCase):
    def test_hybrid_accepted_mixed_egress(self):
        # p1 trunk 只准入带标签帧；p2 hybrid：vlan1 去标签、vlan2 留标签
        cfg = config([
            port("p1", mode="trunk", pvid=1, allowed=[1, 2], untagged=[]),
            port("p2", mode="hybrid", pvid=1, allowed=[1, 2], untagged=[1]),
        ])
        events = [
            link(0, "p1"),
            link(0, "p2"),
            frame(10, "p1", "00:00:00:00:00:01", vlan=1),
            frame(11, "p1", "00:00:00:00:00:01", vlan=2),
        ]
        out = run(cfg, events)
        self.assertEqual(
            out["results"][2]["ports"], [{"name": "p2", "vlan": None}]
        )
        self.assertEqual(
            out["results"][3]["ports"], [{"name": "p2", "vlan": 2}]
        )

    def test_unknown_mode_invalid(self):
        proc, _ = run_cli(config([dict(port("p1"), mode="nope")]), [])
        self.assertEqual(proc.returncode, 4)
        self.assertEqual(proc.stdout, b"")
        self.assertIn(b"invalid_input", proc.stderr)

    def test_hybrid_constraints_same_as_new_forward(self):
        def assert4(doc):
            proc, _ = run_cli(doc, [])
            self.assertEqual(proc.returncode, 4, proc.stderr)
            self.assertIn(b"invalid_input", proc.stderr)

        # pvid 必须在 allowed 中
        assert4(config([port("p1", mode="hybrid", pvid=3,
                             allowed=[1, 2], untagged=[1])]))
        # untagged 必须是 allowed 子集
        assert4(config([port("p1", mode="hybrid", pvid=1,
                             allowed=[1, 2], untagged=[3])]))
        # allowed 必须严格递增
        assert4(config([port("p1", mode="hybrid", pvid=1,
                             allowed=[2, 1], untagged=[1])]))


class WorkLimitTests(unittest.TestCase):
    def _exact_bytes(self, proc):
        self.assertEqual(proc.returncode, 5, proc.stderr)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(
            proc.stderr, b'{"error":"link_forward_work_limit"}\n'
        )

    def test_initial_work_is_port_count(self):
        # P=3、零事件：W 初值 3，等于上限合法，差 1 即超限
        cfg = config([port("p1"), port("p2"), port("p3")])
        proc, _ = run_cli(cfg, [], 1000000, 1000000, 1000000, 1000000, 3)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        proc, _ = run_cli(cfg, [], 1000000, 1000000, 1000000, 1000000, 2)
        self._exact_bytes(proc)

    def test_all_events_billed_links_only(self):
        # P=2：W 初值 2；3 个协商项各加 2P+1=5 -> 17
        cfg = config([port("p1"), port("p2")])
        events = [link(0, "p1"), link(1, "p1"), link(2, "p2")]
        proc, _ = run_cli(cfg, events, 1000000, 1000000, 1000000, 1000000, 17)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        proc, _ = run_cli(cfg, events, 1000000, 1000000, 1000000, 1000000, 16)
        self._exact_bytes(proc)

    def test_frame_count_enters_after_frame_events(self):
        # P=2：协商项恒加 5；帧 i 处理前加 F+5（F 为此前帧数）
        cfg = config([port("p1"), port("p2")])
        # [link, frame, frame]：2 + 5 + 5 + 6 = 18
        events = [
            link(0, "p1"),
            frame(10, "p1", "00:00:00:00:00:01"),
            frame(11, "p1", "00:00:00:00:00:01"),
        ]
        proc, _ = run_cli(cfg, events, 1000000, 1000000, 1000000, 1000000, 18)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        proc, _ = run_cli(cfg, events, 1000000, 1000000, 1000000, 1000000, 17)
        self._exact_bytes(proc)
        # 同为三事件，顺序 [frame, frame, link]：2 + 5 + 6 + 7 = 20
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            frame(1, "p1", "00:00:00:00:00:01"),
            link(2, "p1"),
        ]
        proc, _ = run_cli(cfg, events, 1000000, 1000000, 1000000, 1000000, 20)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        proc, _ = run_cli(cfg, events, 1000000, 1000000, 1000000, 1000000, 19)
        self._exact_bytes(proc)

    def test_first_exceed_stops_without_output(self):
        # 第二个事件即超上限：无正式仿真、stdout 全空
        cfg = config([port("p1"), port("p2")])
        events = [link(0, "p1"), link(1, "p1"),
                  frame(2, "p1", "00:00:00:00:00:01")]
        # 2 + 5 = 7 合法，第 2 项再加 5 -> 12 超限
        proc, _ = run_cli(cfg, events, 1000000, 1000000, 1000000, 1000000, 11)
        self._exact_bytes(proc)

    def test_semantic_failure_precedes_work_limit(self):
        # 语义非法（未知 mode）即使工作量上限极小，仍报 invalid_input/4
        cfg = config([dict(port("p1"), mode="nope"), port("p2")])
        proc, _ = run_cli(cfg, [link(0, "p1")], 1000000, 1000000,
                          1000000, 1000000, 1)
        self.assertEqual(proc.returncode, 4)
        self.assertEqual(proc.stdout, b"")
        self.assertIn(b"invalid_input", proc.stderr)

    def test_work_limit_precedes_output_limit(self):
        # 工作量与输出字节同时超限：先报工作量
        events = [link(0, "p1"), link(1, "p2")]
        proc, _ = run_cli(config(), events, 1000000, 1000000, 1000000, 1, 1)
        self._exact_bytes(proc)

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
                    [sys.executable, SWITCH, "link-forward", cfg, evt,
                     "1000000", "1000000", "1000000", "1000000", bad],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.assertEqual(proc.returncode, 2, bad)
                self.assertIn(b"usage", proc.stderr)
            # 任意长十进制（100 位 9）按数学整数接受
            proc = subprocess.run(
                [sys.executable, SWITCH, "link-forward", cfg, evt,
                 "1000000", "1000000", "1000000", "1000000", "9" * 100],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_default_fifth_limit_runs_unchanged(self):
        # 省略第五项时契约不变：正常事件序列成功
        events = [
            link(0, "p1"),
            link(0, "p2"),
            frame(10, "p1", "00:00:00:00:00:01"),
        ]
        proc, _ = run_cli(config(), events)
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
