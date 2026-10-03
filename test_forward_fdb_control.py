#!/usr/bin/env python3
"""forward-fdb-control 子命令回归：forward-capacity + 交错 flush 清理。

仅用标准库；通过 `python switch.py forward-fdb-control CONFIG EVENTS` 端到端
驱动。配置、双文件格式、资源参数、错误优先级与 JSON 约定均沿用
forward-capacity；事件流可交错 802.1Q 帧与 flush，每个事件前先按事件时钟
老化动态项。帧结果在 forward-capacity 五项前固定 kind="frame"；flush 删除
匹配的动态项（不删静态、不动计数与驱逐统计），输出 kind/t/removed，removed
按 vlan 数值、mac 字典序排列。
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
M1 = "00:00:00:00:00:01"
M2 = "00:00:00:00:00:02"
M3 = "00:00:00:00:00:03"
M4 = "00:00:00:00:00:04"
M9 = "00:00:00:00:00:09"


def port(name, pvid=1, allowed=None, untagged=None, mode="access", up=True):
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
        "up": up,
    }


def capacity(global_limit, vlans=None):
    doc = {"global": global_limit}
    doc["vlans"] = [] if vlans is None else vlans
    return doc


def cap_vlan(vlan, limit):
    return {"vlan": vlan, "limit": limit}


def config(
    ports=None, age=100, static=None, fdb_capacity=None
):
    if ports is None:
        ports = [port("p1"), port("p2"), port("p3")]
    if static is None:
        static = [{"vlan": 1, "mac": M9, "port": "p3"}]
    if fdb_capacity is None:
        fdb_capacity = capacity(100)
    return {
        "ports": ports,
        "age": age,
        "static": static,
        "fdb_capacity": fdb_capacity,
    }


def frame(t, p, src, dst=BCAST, vlan=None):
    return {"t": t, "port": p, "src": src, "dst": dst, "vlan": vlan}


def flush(t, vlan=None, p=None):
    return {"kind": "flush", "t": t, "vlan": vlan, "port": p}


def run_cli(argv):
    return subprocess.run(
        [sys.executable, SWITCH, *argv],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def run_case(config_doc, events, *limits, mode="forward-fdb-control"):
    with tempfile.TemporaryDirectory() as tmp:
        cfg = os.path.join(tmp, "config.json")
        data = os.path.join(tmp, "events.json")
        with open(cfg, "wb") as handle:
            handle.write(json.dumps(config_doc).encode("utf-8"))
        with open(data, "wb") as handle:
            handle.write(json.dumps(events).encode("utf-8"))
        proc = run_cli([mode, cfg, data, *[str(x) for x in limits]])
        missing = run_cli([mode, os.path.join(tmp, "nope.json"), data])
    return proc, missing


def run(config_doc, events, *limits):
    proc, missing = run_case(config_doc, events, *limits)
    assert proc.returncode == 0, (proc.returncode, proc.stderr.decode("utf-8"))
    assert missing.returncode == 3, missing.returncode
    assert missing.stdout == b""
    return json.loads(proc.stdout.decode("utf-8"))


def run_raw(config_doc, events, *limits, mode="forward-fdb-control"):
    proc, _ = run_case(config_doc, events, *limits, mode=mode)
    return proc


class OutputShapeTests(unittest.TestCase):
    def test_top_level_and_key_order(self):
        out = run(config(), [frame(0, "p1", M1, M9), flush(1)])
        self.assertEqual(
            list(out), ["results", "ports", "vlans", "fdb", "evictions"]
        )
        self.assertEqual(
            list(out["results"][0]),
            ["kind", "t", "action", "ports", "learned", "evicted"],
        )
        self.assertEqual(list(out["results"][1]), ["kind", "t", "removed"])
        self.assertEqual(out["results"][0]["kind"], "frame")
        self.assertEqual(out["results"][1]["kind"], "flush")
        self.assertEqual(
            list(out["fdb"][0]), ["vlan", "mac", "port", "source", "seen"]
        )

    def test_removed_entry_key_order(self):
        out = run(config(), [frame(0, "p1", M1), flush(1)])
        removed = out["results"][1]["removed"]
        self.assertEqual(len(removed), 1)
        self.assertEqual(list(removed[0]), ["vlan", "mac", "port", "seen"])

    def test_output_ends_with_single_newline(self):
        proc, _ = run_case(config(), [frame(0, "p1", M1), flush(1)])
        self.assertTrue(proc.stdout.endswith(b"\n"))
        self.assertFalse(proc.stdout.endswith(b"\n\n"))


class FrameSemanticsTests(unittest.TestCase):
    def test_pure_frames_match_forward_capacity_with_kind(self):
        cfg = config(
            ports=[
                port("p1", mode="trunk", allowed=[1, 2]),
                port("p2", mode="hybrid", allowed=[1, 2], untagged=[1]),
                port("p3"),
            ],
            static=[{"vlan": 2, "mac": M9, "port": "p2"}],
        )
        events = [
            frame(0, "p3", M3, M9, vlan=2),  # 拒绝
            frame(1, "p1", M1, M9, vlan=2),  # 静态目的单播
            frame(2, "p1", M1),              # 泛洪
        ]
        proc_cap = run_raw(cfg, events, mode="forward-capacity")
        proc_ctl = run_raw(cfg, events)
        self.assertEqual(proc_cap.returncode, 0)
        self.assertEqual(proc_ctl.returncode, 0)
        cap = json.loads(proc_cap.stdout.decode("utf-8"))
        ctl = json.loads(proc_ctl.stdout.decode("utf-8"))
        for key in ("ports", "vlans", "fdb", "evictions"):
            self.assertEqual(cap[key], ctl[key])
        self.assertEqual(len(ctl["results"]), len(cap["results"]))
        for cr, fr in zip(ctl["results"], cap["results"]):
            self.assertEqual(
                list(cr), ["kind", "t", "action", "ports",
                           "learned", "evicted"]
            )
            self.assertEqual(cr["kind"], "frame")
            for field, value in fr.items():
                self.assertEqual(cr[field], value)

    def test_capacity_eviction_under_control_unchanged(self):
        cfg = config(fdb_capacity=capacity(1))
        out = run(cfg, [frame(0, "p1", M1), frame(1, "p2", M2)])
        self.assertIsNone(out["results"][0]["evicted"])
        self.assertEqual(
            out["results"][1]["evicted"],
            {"vlan": 1, "mac": M1, "port": "p1", "seen": 0},
        )
        self.assertEqual(out["evictions"], [{"vlan": 1, "count": 1}])


class FlushSemanticsTests(unittest.TestCase):
    def test_wildcard_flush_removes_dynamic_keeps_static(self):
        out = run(config(), [frame(0, "p1", M1), frame(1, "p2", M2),
                             flush(2)])
        removed = out["results"][2]["removed"]
        self.assertEqual(
            removed,
            [
                {"vlan": 1, "mac": M1, "port": "p1", "seen": 0},
                {"vlan": 1, "mac": M2, "port": "p2", "seen": 1},
            ],
        )
        # 静态项保留，动态项清空
        self.assertEqual(
            out["fdb"],
            [{"vlan": 1, "mac": M9, "port": "p3",
              "source": "static", "seen": None}],
        )

    def test_removed_sorted_by_vlan_then_mac(self):
        ports = [
            port("p1", mode="trunk", allowed=[1, 2]),
            port("p2", mode="trunk", allowed=[1, 2]),
        ]
        cfg = config(ports=ports, static=[])
        events = [
            frame(0, "p1", M3, vlan=2),
            frame(1, "p2", M1, vlan=1),
            frame(2, "p1", M2, vlan=1),
            flush(3),
        ]
        out = run(cfg, events)
        removed = out["results"][3]["removed"]
        self.assertEqual(
            [(r["vlan"], r["mac"]) for r in removed],
            [(1, M1), (1, M2), (2, M3)],
        )

    def test_vlan_specific_flush(self):
        ports = [
            port("p1", mode="trunk", allowed=[1, 2]),
            port("p2", mode="trunk", allowed=[1, 2]),
        ]
        cfg = config(ports=ports, static=[])
        out = run(cfg, [frame(0, "p1", M1, vlan=1),
                        frame(1, "p2", M2, vlan=2),
                        flush(2, vlan=2)])
        removed = out["results"][2]["removed"]
        self.assertEqual(
            removed, [{"vlan": 2, "mac": M2, "port": "p2", "seen": 1}]
        )
        dyn = {(e["vlan"], e["mac"]) for e in out["fdb"]}
        self.assertEqual(dyn, {(1, M1)})

    def test_port_specific_flush(self):
        ports = [
            port("p1", mode="trunk", allowed=[1, 2]),
            port("p2", mode="trunk", allowed=[1, 2]),
        ]
        cfg = config(ports=ports, static=[])
        out = run(cfg, [frame(0, "p1", M1, vlan=1),
                        frame(1, "p2", M2, vlan=2),
                        flush(2, p="p2")])
        removed = out["results"][2]["removed"]
        self.assertEqual(
            removed, [{"vlan": 2, "mac": M2, "port": "p2", "seen": 1}]
        )
        dyn = {(e["vlan"], e["mac"]) for e in out["fdb"]}
        self.assertEqual(dyn, {(1, M1)})

    def test_vlan_and_port_flush_both_must_match(self):
        ports = [
            port("p1", mode="trunk", allowed=[1, 2]),
            port("p2", mode="trunk", allowed=[1, 2]),
        ]
        cfg = config(ports=ports, static=[])
        # p1 学 vlan1 与 vlan2；flush(vlan=2, port=p1) 只删 (2,M2)
        events = [
            frame(0, "p1", M1, vlan=1),
            frame(1, "p1", M2, vlan=2),
            flush(2, vlan=2, p="p1"),
        ]
        out = run(cfg, events)
        removed = out["results"][2]["removed"]
        self.assertEqual([(r["vlan"], r["mac"]) for r in removed], [(2, M2)])
        # vlan 与 port 不匹配任一动态项 → 空
        out = run(cfg, [frame(0, "p1", M1, vlan=1),
                        flush(1, vlan=2, p="p1")])
        self.assertEqual(out["results"][1]["removed"], [])

    def test_no_match_flush_empty(self):
        out = run(config(), [flush(0)])
        self.assertEqual(out["results"][0]["removed"], [])
        # 静态项不被通配 flush 删除
        self.assertEqual(len(out["fdb"]), 1)

    def test_flush_does_not_touch_counters_or_evictions(self):
        cfg = config()
        events = [frame(0, "p1", M1, M9), flush(1), flush(2, vlan=2)]
        out = run(cfg, events)
        # 第一帧目的静态 M9@p3 单播：p1.rx=1、p3.tx=1；两次 flush 不产生
        # 任何额外端口计数，p2 全零、无 drop
        by_name = {p["name"]: p for p in out["ports"]}
        self.assertEqual(by_name["p1"], {"name": "p1", "rx": 1,
                                         "tx": 0, "drop": 0})
        self.assertEqual(by_name["p2"], {"name": "p2", "rx": 0,
                                         "tx": 0, "drop": 0})
        self.assertEqual(by_name["p3"], {"name": "p3", "rx": 0,
                                         "tx": 1, "drop": 0})
        self.assertEqual(out["vlans"], [{"vlan": 1, "rx": 1,
                                         "tx": 1, "drop": 0}])
        self.assertEqual(out["evictions"], [])

    def test_flush_frees_capacity(self):
        cfg = config(fdb_capacity=capacity(1))
        # flush 在第二帧前清空，第二帧学习不触发驱逐
        out = run(cfg, [frame(0, "p1", M1), flush(1),
                        frame(2, "p2", M2)])
        self.assertTrue(all(r.get("evicted") is None for r in out["results"]))
        self.assertEqual(out["evictions"], [])
        dyn = [(e["mac"]) for e in out["fdb"] if e["source"] == "dynamic"]
        self.assertEqual(dyn, [M2])


class AgingAndOrderingTests(unittest.TestCase):
    def test_aging_before_flush(self):
        cfg = config(age=10)
        # flush@t=10：M1(seen=0) 先老化（10-0>=10），removed 为空
        out = run(cfg, [frame(0, "p1", M1), flush(10)])
        self.assertEqual(out["results"][1]["removed"], [])
        dyn = [e for e in out["fdb"] if e["source"] == "dynamic"]
        self.assertEqual(dyn, [])
        # flush@t=9：尚未老化，removed 含 M1
        out = run(cfg, [frame(0, "p1", M1), flush(9)])
        self.assertEqual(len(out["results"][1]["removed"]), 1)

    def test_aging_before_frame_still_applies(self):
        cfg = config(age=10, fdb_capacity=capacity(1))
        out = run(cfg, [frame(0, "p1", M1), frame(10, "p2", M2)])
        self.assertTrue(out["results"][1]["learned"])
        self.assertIsNone(out["results"][1]["evicted"])

    def test_same_timestamp_array_order(self):
        # 同一 t：先帧学习 M1，再同刻 flush 能删到 M1
        out = run(config(), [frame(5, "p1", M1), flush(5)])
        self.assertEqual(len(out["results"][1]["removed"]), 1)
        # 先 flush（空）再帧（学习），flush 无删除
        out = run(config(), [flush(5), frame(5, "p1", M1)])
        self.assertEqual(out["results"][0]["removed"], [])
        dyn = [e for e in out["fdb"] if e["source"] == "dynamic"]
        self.assertEqual(len(dyn), 1)

    def test_flush_then_frame_learns_again_refresh(self):
        # 删除后同 MAC 再学习为新建，seen 推进到新时刻
        out = run(config(), [frame(0, "p1", M1), flush(1),
                             frame(5, "p2", M1)])
        dyn = [e for e in out["fdb"] if e["source"] == "dynamic"]
        self.assertEqual(
            dyn, [{"vlan": 1, "mac": M1, "port": "p2",
                   "source": "dynamic", "seen": 5}]
        )


class ValidationTests(unittest.TestCase):
    def assert_invalid(self, config_doc=None, events=None):
        proc = run_raw(
            config() if config_doc is None else config_doc,
            [] if events is None else events,
        )
        self.assertEqual(proc.returncode, 4, proc.stderr)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b'{"error":"invalid_input"}\n')

    def test_config_shape_same_as_forward_capacity(self):
        bad = config()
        del bad["fdb_capacity"]
        self.assert_invalid(bad)
        bad = config()
        bad["extra"] = 1
        self.assert_invalid(bad)
        self.assert_invalid(config(fdb_capacity=capacity(-1)))

    def test_unknown_kind(self):
        for kind in ("frame", "learn", "FLUSH", "", 1):
            self.assert_invalid(
                events=[{"kind": kind, "t": 0, "vlan": None, "port": None}]
            )

    def test_flush_missing_or_extra_fields(self):
        base = {"kind": "flush", "t": 0, "vlan": None, "port": None}
        for drop in ("kind", "t", "vlan", "port"):
            doc = dict(base)
            del doc[drop]
            self.assert_invalid(events=[doc])
        doc = dict(base)
        doc["extra"] = 1
        self.assert_invalid(events=[doc])

    def test_flush_bad_t_and_regression(self):
        self.assert_invalid(events=[{"kind": "flush", "t": -1,
                                     "vlan": None, "port": None}])
        self.assert_invalid(events=[{"kind": "flush", "t": True,
                                     "vlan": None, "port": None}])
        # 跨事件类型时间倒退
        self.assert_invalid(events=[flush(5), frame(4, "p1", M1)])
        self.assert_invalid(events=[frame(5, "p1", M1), flush(4)])

    def test_flush_bad_vlan(self):
        for vlan in (0, 4095, -1, True, "1", 1.0):
            self.assert_invalid(events=[flush(0, vlan=vlan)])

    def test_flush_unknown_port(self):
        self.assert_invalid(events=[flush(0, p="nope")])
        self.assert_invalid(events=[flush(0, p=4)])

    def test_flush_vlan_port_individually_valid(self):
        # null 通配合法；合法 VLAN 与已配置端口均合法
        out = run(config(), [flush(0), flush(0, vlan=4094),
                             flush(0, p="p1")])
        self.assertEqual([r["removed"] for r in out["results"]],
                         [[], [], []])

    def test_frame_still_validated(self):
        self.assert_invalid(events=[frame(0, "nope", M1)])
        self.assert_invalid(events=[frame(0, "p1", BCAST)])
        self.assert_invalid(events=[frame(0, "p1", M1, vlan=0)])
        self.assert_invalid(events=[{"t": 0, "port": "p1", "src": M1,
                                     "dst": BCAST, "vlan": None,
                                     "kind": "frame"}])

    def test_events_must_be_list(self):
        proc = run_raw(config(), {"kind": "flush", "t": 0,
                                  "vlan": None, "port": None})
        self.assertEqual(proc.returncode, 4)

    def test_duplicate_json_key_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = os.path.join(tmp, "c.json")
            evt = os.path.join(tmp, "e.json")
            with open(cfg, "wb") as handle:
                handle.write(json.dumps(config()).encode("utf-8"))
            with open(evt, "wb") as handle:
                handle.write(
                    b'[{"kind":"flush","t":0,"t":1,"vlan":null,'
                    b'"port":null}]'
                )
            proc = run_cli(["forward-fdb-control", cfg, evt])
        self.assertEqual(proc.returncode, 4)
        self.assertEqual(proc.stdout, b"")


class ResourceAndErrorTests(unittest.TestCase):
    def test_usage(self):
        proc = run_cli(["forward-fdb-control"])
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, b"")
        with tempfile.TemporaryDirectory() as tmp:
            cfg = os.path.join(tmp, "c.json")
            data = os.path.join(tmp, "d.json")
            with open(cfg, "wb") as handle:
                handle.write(b"{}")
            with open(data, "wb") as handle:
                handle.write(b"[]")
            base = ["forward-fdb-control", cfg, data]
            # 仅允许 0、2、4、5 项上限
            for extra in (("1024",), ("1", "2", "3"),
                          ("1", "2", "3", "4", "5", "6")):
                proc = run_cli(base + list(extra))
                self.assertEqual(proc.returncode, 2, extra)
            # 上限须匹配 [1-9][0-9]*
            proc = run_cli(base + ["0", "1024"])
            self.assertEqual(proc.returncode, 2)

    def test_file_not_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = os.path.join(tmp, "d.json")
            with open(data, "wb") as handle:
                handle.write(b"[]")
            proc = run_cli(["forward-fdb-control",
                            os.path.join(tmp, "nope.json"), data])
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b'{"error":"file_not_found"}\n')

    def test_config_data_item_limits(self):
        cfg = config()
        events = [flush(i) for i in range(4)]
        proc = run_raw(cfg, events, 10, 100000)
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(proc.stderr, b'{"error":"config_limit"}\n')
        proc = run_raw(cfg, events, 100000, 5)
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(proc.stderr, b'{"error":"data_limit"}\n')
        proc = run_raw(cfg, events, 100000, 100000, 3, 100000)
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(proc.stderr, b'{"error":"item_limit"}\n')
        # 等于 item 上限合法
        proc = run_raw(cfg, events, 100000, 100000, 4, 100000)
        self.assertEqual(proc.returncode, 0)

    def test_output_limit(self):
        proc = run_raw(config(), [frame(0, "p1", M1, M9)],
                       100000, 100000, 100, 10)
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b'{"error":"output_limit"}\n')

    def test_work_limit_counts_every_event(self):
        # 3 端口 width=4；1 条静态项 → 首个事件成本 K+P+1 = 1+3+1 = 5
        proc = run_raw(config(), [flush(0)],
                       100000, 100000, 100, 100000, 4)
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(
            proc.stderr, b'{"error":"fdb_control_work_limit"}\n'
        )
        # 等于上限合法
        proc = run_raw(config(), [flush(0)],
                       100000, 100000, 100, 100000, 5)
        self.assertEqual(proc.returncode, 0)

    def test_work_limit_frame_then_flush_boundary(self):
        # frame@0 学 M1：成本 5，K 变为 2；flush@1 成本 2+4=6，累计 11
        events = [frame(0, "p1", M1), flush(1)]
        proc = run_raw(config(), events,
                       100000, 100000, 100, 100000, 10)
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(
            proc.stderr, b'{"error":"fdb_control_work_limit"}\n'
        )
        proc = run_raw(config(), events,
                       100000, 100000, 100, 100000, 11)
        self.assertEqual(proc.returncode, 0)

    def test_work_limit_flush_cost_uses_pre_aging_k(self):
        # age=10：flush@10 处理前 M1 尚未老化，K=2（含静态）成本 6；
        # 虽 removed 为空（M1 先老化），计费仍按老化前 K
        cfg = config(age=10)
        events = [frame(0, "p1", M1), flush(10)]
        proc = run_raw(cfg, events,
                       100000, 100000, 100, 100000, 10)
        self.assertEqual(proc.returncode, 5)
        proc = run_raw(cfg, events,
                       100000, 100000, 100, 100000, 11)
        self.assertEqual(proc.returncode, 0)
        doc = json.loads(proc.stdout.decode("utf-8"))
        self.assertEqual(doc["results"][1]["removed"], [])

    def test_flush_reduces_following_cost(self):
        # frame@0 学 M1（成本5，K=2），flush@1 清空动态（成本6，累计11，
        # K 回到1），frame@2 成本 1+4=5 → 累计 16；15 失败 16 成功
        events = [frame(0, "p1", M1), flush(1), frame(2, "p2", M2)]
        proc = run_raw(config(), events,
                       100000, 100000, 100, 100000, 15)
        self.assertEqual(proc.returncode, 5)
        proc = run_raw(config(), events,
                       100000, 100000, 100, 100000, 16)
        self.assertEqual(proc.returncode, 0)

    def test_exit_5_has_empty_stdout(self):
        for args in (
            run_raw(config(), [flush(0)], 100000, 100000, 100, 100000, 1),
            run_raw(config(), [frame(0, "p1", M1)], 10),
            run_raw(config(), [frame(0, "p1", M1)], 100000, 1),
        ):
            self.assertEqual(args.stdout, b"")

    def test_deterministic_byte_identical(self):
        events = [frame(0, "p1", M1), flush(1), frame(2, "p2", M2),
                  flush(3, vlan=1)]
        a = run_raw(config(fdb_capacity=capacity(1)), events)
        b = run_raw(config(fdb_capacity=capacity(1)), events)
        self.assertEqual(a.returncode, 0)
        self.assertEqual(a.stdout, b.stdout)


class OldEntryUnchangedTests(unittest.TestCase):
    def test_forward_capacity_rejects_flush_event(self):
        # 旧入口不识别 flush 形状 → invalid_input
        proc = run_raw(config(), [flush(0)], mode="forward-capacity")
        self.assertEqual(proc.returncode, 4)
        self.assertEqual(proc.stdout, b"")

    def test_forward_static_rejects_capacity_key(self):
        proc = run_raw(config(), [], mode="forward-static")
        self.assertEqual(proc.returncode, 4)
        self.assertEqual(proc.stdout, b"")

    def test_forward_capacity_pure_frames_unchanged(self):
        cfg = config(fdb_capacity=capacity(1))
        frames = [frame(0, "p1", M1), frame(1, "p2", M2, M9)]
        proc = run_raw(cfg, frames, mode="forward-capacity")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        doc = json.loads(proc.stdout.decode("utf-8"))
        self.assertEqual(
            list(doc), ["results", "ports", "vlans", "fdb", "evictions"]
        )
        self.assertEqual(
            list(doc["results"][0]), ["t", "action", "ports",
                                      "learned", "evicted"]
        )


if __name__ == "__main__":
    unittest.main()
