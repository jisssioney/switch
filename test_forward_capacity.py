#!/usr/bin/env python3
"""forward-capacity 子命令回归：forward-static + 动态 FDB 容量约束。

仅用标准库；通过 `python switch.py forward-capacity CONFIG DATA` 端到端
驱动。双文件格式、资源参数、错误优先级与 JSON 约定均沿用 forward-static；
静态项不占动态容量且永不被容量处理删除，逐帧先老化再处理源地址，每帧
固定输出 learned/evicted，汇总新增按 VLAN 排序的 evictions。
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
M5 = "00:00:00:00:00:05"
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


def run_cli(argv):
    return subprocess.run(
        [sys.executable, SWITCH, *argv],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def run_case(config_doc, frames, *limits, mode="forward-capacity"):
    with tempfile.TemporaryDirectory() as tmp:
        cfg = os.path.join(tmp, "config.json")
        data = os.path.join(tmp, "frames.json")
        with open(cfg, "wb") as handle:
            handle.write(json.dumps(config_doc).encode("utf-8"))
        with open(data, "wb") as handle:
            handle.write(json.dumps(frames).encode("utf-8"))
        proc = run_cli([mode, cfg, data, *[str(x) for x in limits]])
        missing = run_cli([mode, os.path.join(tmp, "nope.json"), data])
    return proc, missing


def run(config_doc, frames, *limits):
    proc, missing = run_case(config_doc, frames, *limits)
    assert proc.returncode == 0, (proc.returncode, proc.stderr.decode("utf-8"))
    assert missing.returncode == 3, missing.returncode
    assert missing.stdout == b""
    return json.loads(proc.stdout.decode("utf-8"))


def run_raw(config_doc, frames, *limits, mode="forward-capacity"):
    proc, _ = run_case(config_doc, frames, *limits, mode=mode)
    return proc


class CapacityOutputTests(unittest.TestCase):
    def test_top_level_and_entry_key_order(self):
        out = run(config(), [frame(0, "p1", M1, M9)])
        self.assertEqual(
            list(out), ["results", "ports", "vlans", "fdb", "evictions"]
        )
        self.assertEqual(
            list(out["results"][0]),
            ["t", "action", "ports", "learned", "evicted"],
        )
        self.assertEqual(
            list(out["fdb"][0]), ["vlan", "mac", "port", "source", "seen"]
        )

    def test_eviction_entry_key_order(self):
        out = run(config(fdb_capacity=capacity(0)), [])  # 无驱逐对照
        self.assertEqual(out["evictions"], [])
        cfg = config(fdb_capacity=capacity(1))
        out = run(cfg, [frame(0, "p1", M1), frame(1, "p1", M2)])
        evicted = out["results"][1]["evicted"]
        self.assertEqual(list(evicted), ["vlan", "mac", "port", "seen"])

    def test_learn_new_refresh_migrate_flags(self):
        frames = [
            frame(0, "p1", M1),          # 新建
            frame(1, "p1", M1, M2),      # 刷新（同口）
            frame(2, "p2", M1),          # 迁移
        ]
        out = run(config(), frames)
        self.assertEqual([r["learned"] for r in out["results"]],
                         [True, True, True])
        self.assertTrue(all(r["evicted"] is None for r in out["results"]))
        # 迁移后只有 1 条动态项
        dyn = [e for e in out["fdb"] if e["source"] == "dynamic"]
        self.assertEqual(
            dyn,
            [{"vlan": 1, "mac": M1, "port": "p2",
              "source": "dynamic", "seen": 2}],
        )

    def test_not_learned_cases(self):
        ports = [port("p1"), port("p2"), port("p3", up=False)]
        # down 口入帧：不学习
        out = run(config(ports=ports), [frame(0, "p3", M1)])
        self.assertFalse(out["results"][0]["learned"])
        # VLAN 准入拒绝：access 口收带标签帧
        out = run(config(), [frame(0, "p1", M1, vlan=2)])
        r = out["results"][0]
        self.assertEqual((r["action"], r["learned"], r["evicted"]),
                         ("drop", False, None))
        # 静态源端口不符：丢弃且不学习
        out = run(config(), [frame(0, "p2", M9, M1)])
        r = out["results"][0]
        self.assertEqual((r["action"], r["learned"], r["evicted"]),
                         ("drop", False, None))
        # 静态源同口：继续转发但 learned=False、表不动
        out = run(config(), [frame(0, "p3", M9, M1)])
        r = out["results"][0]
        self.assertEqual((r["action"], r["learned"]), ("flood", False))
        self.assertEqual(
            out["fdb"],
            [{"vlan": 1, "mac": M9, "port": "p3",
              "source": "static", "seen": None}],
        )


class EvictionTests(unittest.TestCase):
    def test_global_capacity_evicts_oldest(self):
        cfg = config(fdb_capacity=capacity(2))
        frames = [
            frame(0, "p1", M1),
            frame(1, "p2", M2),
            frame(2, "p3", M3),  # 全局满 → 驱逐 seen 最小 M1
        ]
        out = run(cfg, frames)
        self.assertEqual(
            out["results"][2]["evicted"],
            {"vlan": 1, "mac": M1, "port": "p1", "seen": 0},
        )
        dyn = {(e["vlan"], e["mac"]): e for e in out["fdb"]
               if e["source"] == "dynamic"}
        self.assertEqual(set(dyn), {(1, M2), (1, M3)})
        self.assertEqual(out["evictions"], [{"vlan": 1, "count": 1}])

    def test_refresh_updates_last_seen_for_eviction(self):
        cfg = config(fdb_capacity=capacity(2))
        frames = [
            frame(0, "p1", M1),
            frame(1, "p2", M2),
            frame(2, "p1", M1, BCAST),  # 刷新 M1 → seen=2
            frame(3, "p3", M3),         # 最旧为 M2(seen=1)
        ]
        out = run(cfg, frames)
        self.assertEqual(
            out["results"][3]["evicted"]["mac"], M2
        )

    def test_global_eviction_tie_breaks_by_vlan_then_mac(self):
        # global=1；M1 在 vlan2 与 M2 在 vlan1 同刻已占两项不可能：先填满
        # 两 VLAN（各 1，共 2）需要 global≥2；用 global=2，第三项同刻 t=2
        # 进入 vlan1，全局满，同 seen=2 时按 VLAN 数值选 vlan1 的 M2
        ports = [
            port("p1", mode="trunk", allowed=[1, 2]),
            port("p2", mode="trunk", allowed=[1, 2]),
        ]
        cfg = config(
            ports=ports, static=[], fdb_capacity=capacity(2)
        )
        frames = [
            frame(2, "p1", M1, vlan=2),
            frame(2, "p2", M2, vlan=1),
            frame(2, "p1", M3, vlan=1),
        ]
        out = run(cfg, frames)
        self.assertEqual(
            out["results"][2]["evicted"],
            {"vlan": 1, "mac": M2, "port": "p2", "seen": 2},
        )
        # 同 VLAN 同 seen：按 MAC 字典序
        cfg = config(ports=ports, static=[], fdb_capacity=capacity(2))
        frames = [
            frame(2, "p1", M2, vlan=1),
            frame(2, "p2", M3, vlan=1),
            frame(2, "p1", M1, vlan=1),
        ]
        out = run(cfg, frames)
        self.assertEqual(out["results"][2]["evicted"]["mac"], M2)

    def test_vlan_override_evicts_within_vlan_first(self):
        ports = [
            port("p1", mode="trunk", allowed=[1, 2]),
            port("p2", mode="trunk", allowed=[1, 2]),
        ]
        # global=10，vlan2 自身上限 1：vlan2 满时只驱逐 vlan2，不动 vlan1
        cfg = config(
            ports=ports, static=[],
            fdb_capacity=capacity(10, [cap_vlan(2, 1)]),
        )
        frames = [
            frame(0, "p1", M1, vlan=1),
            frame(1, "p1", M2, vlan=2),
            frame(2, "p2", M3, vlan=2),  # vlan2 满 → 驱逐 M2
        ]
        out = run(cfg, frames)
        self.assertEqual(
            out["results"][2]["evicted"],
            {"vlan": 2, "mac": M2, "port": "p1", "seen": 1},
        )
        dyn = sorted((e["vlan"], e["mac"]) for e in out["fdb"])
        self.assertEqual(dyn, [(1, M1), (2, M3)])
        self.assertEqual(out["evictions"], [{"vlan": 2, "count": 1}])

    def test_uncovered_vlan_only_bound_by_global(self):
        ports = [
            port("p1", mode="trunk", allowed=[1, 2]),
            port("p2", mode="trunk", allowed=[1, 2]),
        ]
        # vlan2 有覆盖上限 1；vlan1 无覆盖，只受 global=1 约束
        cfg = config(
            ports=ports, static=[],
            fdb_capacity=capacity(1, [cap_vlan(2, 1)]),
        )
        frames = [
            frame(0, "p1", M1, vlan=2),
            frame(1, "p2", M2, vlan=1),  # 全局满 → 全局驱逐 (2,M1)
            frame(2, "p1", M3, vlan=1),  # vlan1 已占 1 达全局值 → VLAN 驱逐
        ]
        out = run(cfg, frames)
        self.assertEqual(
            out["results"][1]["evicted"],
            {"vlan": 2, "mac": M1, "port": "p1", "seen": 0},
        )
        self.assertEqual(
            out["results"][2]["evicted"],
            {"vlan": 1, "mac": M2, "port": "p2", "seen": 1},
        )

    def test_global_eviction_may_evict_covered_vlan(self):
        # 覆盖项只在“该 VLAN 已满”时优先；全局驱逐从全部动态项选择，
        # 可驱逐有覆盖项的 VLAN
        ports = [
            port("p1", mode="trunk", allowed=[1, 2]),
            port("p2", mode="trunk", allowed=[1, 2]),
        ]
        cfg = config(
            ports=ports, static=[],
            fdb_capacity=capacity(2, [cap_vlan(2, 1)]),
        )
        frames = [
            frame(0, "p1", M1, vlan=2),
            frame(1, "p2", M2, vlan=1),
            frame(2, "p1", M3, vlan=1),  # 全局满 → 最旧为 (2,M1,seen0)
        ]
        out = run(cfg, frames)
        self.assertEqual(
            out["results"][2]["evicted"],
            {"vlan": 2, "mac": M1, "port": "p1", "seen": 0},
        )

    def test_static_entries_do_not_consume_or_get_evicted(self):
        # 1 条静态项 + global=1：首个新动态项即可学习（静态不占容量），
        # 第二个新动态项驱逐的是动态项，静态项永不被删
        cfg = config(fdb_capacity=capacity(1))
        frames = [
            frame(0, "p1", M1, M9),
            frame(1, "p2", M2, M9),
        ]
        out = run(cfg, frames)
        self.assertEqual(out["results"][1]["evicted"]["mac"], M1)
        self.assertEqual(
            [e for e in out["fdb"] if e["source"] == "static"],
            [{"vlan": 1, "mac": M9, "port": "p3",
              "source": "static", "seen": None}],
        )
        self.assertEqual(len([e for e in out["fdb"]
                              if e["source"] == "dynamic"]), 1)

    def test_zero_limits_forward_without_learning_or_eviction(self):
        ports = [
            port("p1", mode="trunk", allowed=[1, 2]),
            port("p2", mode="trunk", allowed=[1, 2]),
        ]
        cfg = config(
            ports=ports, static=[],
            fdb_capacity=capacity(5, [cap_vlan(2, 0)]),
        )
        frames = [
            frame(0, "p1", M1, vlan=2),  # vlan2 上限 0：不学不驱
            frame(1, "p2", M2, vlan=2),  # 同样不学；未命中仍泛洪
        ]
        out = run(cfg, frames)
        self.assertEqual([r["action"] for r in out["results"]],
                         ["flood", "flood"])
        self.assertEqual([r["learned"] for r in out["results"]],
                         [False, False])
        self.assertTrue(all(r["evicted"] is None for r in out["results"]))
        self.assertEqual(out["fdb"], [])
        self.assertEqual(out["evictions"], [])
        # global=0：任何 VLAN 都不学
        cfg = config(ports=ports, static=[], fdb_capacity=capacity(0))
        out = run(cfg, [frame(0, "p1", M1, vlan=1)])
        r = out["results"][0]
        self.assertEqual((r["action"], r["learned"], r["evicted"]),
                         ("flood", False, None))
        self.assertEqual(out["fdb"], [])

    def test_aging_frees_capacity_before_learning(self):
        cfg = config(age=10, fdb_capacity=capacity(1))
        frames = [
            frame(0, "p1", M1),
            frame(10, "p2", M2),  # 10-0>=10：M1 先老化，容量空出
        ]
        out = run(cfg, frames)
        self.assertTrue(out["results"][1]["learned"])
        self.assertIsNone(out["results"][1]["evicted"])
        dyn = [(e["mac"], e["seen"]) for e in out["fdb"]
               if e["source"] == "dynamic"]
        self.assertEqual(dyn, [(M2, 10)])

    def test_eviction_counts_sorted_by_vlan(self):
        ports = [
            port("p1", mode="trunk", allowed=[1, 2]),
            port("p2", mode="trunk", allowed=[1, 2]),
        ]
        cfg = config(
            ports=ports, static=[], fdb_capacity=capacity(1)
        )
        frames = [
            frame(0, "p1", M1, vlan=2),
            frame(1, "p1", M2, vlan=1),  # 驱逐 (2,M1)
            frame(2, "p2", M3, vlan=2),  # 驱逐 (1,M2)
            frame(3, "p1", M4, vlan=2),  # 驱逐 (2,M3)
        ]
        out = run(cfg, frames)
        self.assertEqual(
            out["evictions"],
            [{"vlan": 1, "count": 1}, {"vlan": 2, "count": 2}],
        )

    def test_forwarding_behavior_unchanged_under_capacity(self):
        # 容量足够大时，单播/泛洪/标签加剥与 forward-static 完全一致
        ports = [
            port("p1", mode="trunk", allowed=[1, 2]),
            port("p2", mode="hybrid", allowed=[1, 2], untagged=[1]),
            port("p3"),
        ]
        static = [{"vlan": 2, "mac": M9, "port": "p2"}]
        cfg = config(ports=ports, static=static,
                     fdb_capacity=capacity(100))
        frames = [
            frame(0, "p3", M3, M9, vlan=2),  # 拒绝
            frame(1, "p1", M1, M9, vlan=2),  # 静态目的单播带标签
            frame(2, "p1", M1),              # 泛洪
        ]
        out = run(cfg, frames)
        self.assertEqual(out["results"][0],
                         {"t": 0, "action": "drop", "ports": [],
                          "learned": False, "evicted": None})
        self.assertEqual(
            out["results"][1],
            {"t": 1, "action": "unicast",
             "ports": [{"name": "p2", "vlan": 2}],
             "learned": True, "evicted": None},
        )
        self.assertEqual(out["results"][2]["action"], "flood")


class CapacityValidationTests(unittest.TestCase):
    def assert_invalid(self, config_doc=None, frames=None):
        proc = run_raw(
            config() if config_doc is None else config_doc,
            [] if frames is None else frames,
        )
        self.assertEqual(proc.returncode, 4, proc.stderr)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b'{"error":"invalid_input"}\n')

    def test_config_keys_exact(self):
        bad = config()
        del bad["fdb_capacity"]
        self.assert_invalid(bad)  # 缺键时按 forward-static 形状也不接受
        bad = config()
        bad["extra"] = 1
        self.assert_invalid(bad)

    def test_capacity_object_shape(self):
        bad = config(fdb_capacity=[])
        self.assert_invalid(bad)
        bad = config(fdb_capacity={"global": 1})
        self.assert_invalid(bad)
        bad = config(fdb_capacity={"global": 1, "vlans": [], "x": 0})
        self.assert_invalid(bad)

    def test_global_non_negative_integer(self):
        for value in (-1, True, "1", 1.0, None, [0]):
            self.assert_invalid(config(fdb_capacity=capacity(value)))
        # 0 与大整数合法（global=0 且无静态项时 fdb 恒空）
        out = run(config(static=[], fdb_capacity=capacity(0)), [])
        self.assertEqual(out["fdb"], [])

    def test_vlans_must_be_list_of_entries(self):
        bad = config(fdb_capacity=capacity(1, {}))
        self.assert_invalid(bad)
        bad = config(fdb_capacity=capacity(1, [{"vlan": 1}]))
        self.assert_invalid(bad)
        bad = config(fdb_capacity=capacity(1, [{"vlan": 1, "limit": 0, "x": 1}]))
        self.assert_invalid(bad)
        bad = config(fdb_capacity=capacity(1, [[1, 0]]))
        self.assert_invalid(bad)

    def test_vlan_override_values(self):
        for vlan in (0, 4095, -1, True, "1", 1.0, None):
            self.assert_invalid(
                config(fdb_capacity=capacity(1, [cap_vlan(vlan, 1)]))
            )
        for limit in (-1, True, "1", 1.0, None):
            self.assert_invalid(
                config(fdb_capacity=capacity(1, [cap_vlan(1, limit)]))
            )

    def test_vlan_overrides_strictly_increasing(self):
        bad = config(fdb_capacity=capacity(
            10, [cap_vlan(2, 1), cap_vlan(2, 2)]
        ))
        self.assert_invalid(bad)
        bad = config(fdb_capacity=capacity(
            10, [cap_vlan(3, 1), cap_vlan(2, 1)]
        ))
        self.assert_invalid(bad)

    def test_static_and_frames_validated_like_forward_static(self):
        bad = config(static=[{"vlan": 1, "mac": M9, "port": "nope"}])
        self.assert_invalid(bad)
        self.assert_invalid(config(), [frame(-1, "p1", M1)])
        self.assert_invalid(config(), [frame(0, "nope", M1)])
        self.assert_invalid(config(), [frame(0, "p1", BCAST)])


class ResourceAndErrorTests(unittest.TestCase):
    def test_usage(self):
        proc = run_cli(["forward-capacity"])
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, b"")
        with tempfile.TemporaryDirectory() as tmp:
            cfg = os.path.join(tmp, "c.json")
            data = os.path.join(tmp, "d.json")
            open(cfg, "wb").write(b"{}")
            open(data, "wb").write(b"[]")
            # 仅允许 0、2、4、5 项上限
            proc = run_cli(["forward-capacity", cfg, data, "1024"])
            self.assertEqual(proc.returncode, 2)
            proc = run_cli(["forward-capacity", cfg, data,
                            "1024", "1024", "100", "1000", "100", "1"])
            self.assertEqual(proc.returncode, 2)
            # 上限须匹配 [1-9][0-9]*
            proc = run_cli(["forward-capacity", cfg, data, "0", "1024"])
            self.assertEqual(proc.returncode, 2)

    def test_file_not_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = os.path.join(tmp, "d.json")
            open(data, "wb").write(b"[]")
            proc = run_cli(["forward-capacity",
                            os.path.join(tmp, "nope.json"), data])
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b'{"error":"file_not_found"}\n')

    def test_output_limit(self):
        proc = run_raw(config(), [frame(0, "p1", M1, M9)],
                       100000, 100000, 100, 10)
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b'{"error":"output_limit"}\n')

    def test_work_limit_pre_aging_counts_all_entries(self):
        # 3 端口 width=4；1 条静态项 → 首帧成本 K+P+1 = 1+3+1 = 5
        frames = [frame(0, "p1", M1, M9)]
        proc = run_raw(config(), frames, 100000, 100000, 100, 100000, 4)
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(
            proc.stderr, b'{"error":"fdb_capacity_work_limit"}\n'
        )
        # 等于上限合法
        proc = run_raw(config(), frames, 100000, 100000, 100, 100000, 5)
        self.assertEqual(proc.returncode, 0)
        # global=0 时动态表恒空：第二帧 K 仍只含 1 条静态项 → 累计 10
        frames = [frame(0, "p1", M1, M9), frame(1, "p2", M2, M9)]
        cfg = config(fdb_capacity=capacity(0))
        proc = run_raw(cfg, frames, 100000, 100000, 100, 100000, 10)
        self.assertEqual(proc.returncode, 0)
        proc = run_raw(cfg, frames, 100000, 100000, 100, 100000, 9)
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(
            proc.stderr, b'{"error":"fdb_capacity_work_limit"}\n'
        )

    def test_deterministic_byte_identical(self):
        cfg = config(fdb_capacity=capacity(1))
        frames = [frame(0, "p1", M1), frame(1, "p2", M2, M9),
                  frame(2, "p3", M3)]
        a = run_raw(cfg, frames)
        b = run_raw(cfg, frames)
        self.assertEqual(a.returncode, 0)
        self.assertEqual(a.stdout, b.stdout)


class RecordReplayTests(unittest.TestCase):
    def _write(self, tmp, name, doc):
        path = os.path.join(tmp, name)
        with open(path, "wb") as handle:
            handle.write(json.dumps(doc).encode("utf-8"))
        return path

    def test_record_replay_recognizes_mode_and_rebuilds(self):
        ports = [
            port("p1", mode="trunk", allowed=[1, 2]),
            port("p2", mode="trunk", allowed=[1, 2]),
            port("p3", mode="trunk", allowed=[1, 2]),
        ]
        cfg = config(
            ports=ports,
            fdb_capacity=capacity(2, [cap_vlan(2, 1)]),
        )
        frames = [
            frame(0, "p1", M1, vlan=1),
            frame(1, "p1", M4, vlan=2),
            frame(2, "p2", M2, M9, vlan=1),
            frame(3, "p1", M5, vlan=2),
            frame(4, "p1", M3, vlan=1),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = self._write(tmp, "config.json", cfg)
            evt_path = self._write(tmp, "events.json", frames)
            log_path = os.path.join(tmp, "out.log")
            direct = run_cli(
                ["forward-capacity", cfg_path, evt_path]
            )
            self.assertEqual(direct.returncode, 0, direct.stderr)
            rec = run_cli(
                ["record", cfg_path, evt_path, log_path]
            )
            self.assertEqual(rec.returncode, 0, rec.stderr)
            # record stdout 与直接入口逐字节一致
            self.assertEqual(rec.stdout, direct.stdout)
            rep = run_cli(["replay", log_path])
            self.assertEqual(rep.returncode, 0, rep.stderr)
            # replay 重建结果逐字节一致
            self.assertEqual(rep.stdout, direct.stdout)
            log = json.loads(open(log_path, "rb").read().decode("utf-8"))
            # 新字段出现在记录输出中
            rec3 = log["records"][3]["output"]
            self.assertEqual(
                list(rec3), ["t", "action", "ports", "learned", "evicted"]
            )
            self.assertEqual(rec3["evicted"]["vlan"], 2)
            self.assertTrue(rec3["learned"])
            # 每帧恒 applied、version 恒 0
            self.assertTrue(all(r["applied"] for r in log["records"]))
            self.assertTrue(all(r["version"] == 0 for r in log["records"]))
            # replay 重算的 LOG 必须与原文件逐字节一致（再 replay 一次）
            log_bytes = open(log_path, "rb").read()
            rep2 = run_cli(["replay", log_path])
            self.assertEqual(rep2.stdout, direct.stdout)
            self.assertEqual(open(log_path, "rb").read(), log_bytes)

    def test_record_invalid_capacity_is_invalid_input(self):
        cfg = config(fdb_capacity=capacity(-1))
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = self._write(tmp, "config.json", cfg)
            evt_path = self._write(tmp, "events.json", [])
            log_path = os.path.join(tmp, "out.log")
            rec = run_cli(["record", cfg_path, evt_path, log_path])
            self.assertEqual(rec.returncode, 4)
            self.assertEqual(rec.stderr, b'{"error":"invalid_input"}\n')
            self.assertFalse(os.path.exists(log_path))


class OldEntryUnchangedTests(unittest.TestCase):
    """旧入口保持不变：forward/forward-static 不识别 fdb_capacity。"""

    def test_forward_static_rejects_capacity_key(self):
        proc = run_raw(config(), [], mode="forward-static")
        self.assertEqual(proc.returncode, 4)
        self.assertEqual(proc.stdout, b"")

    def test_forward_static_output_unchanged_shape(self):
        cfg = {
            "ports": [port("p1"), port("p2"), port("p3")],
            "age": 100,
            "static": [{"vlan": 1, "mac": M9, "port": "p3"}],
        }
        frames = [frame(0, "p1", M1, M9)]
        proc, _ = run_case(cfg, frames, mode="forward-static")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        doc = json.loads(proc.stdout.decode("utf-8"))
        self.assertEqual(list(doc), ["results", "ports", "vlans", "fdb"])
        self.assertEqual(
            list(doc["results"][0]), ["t", "action", "ports"]
        )


if __name__ == "__main__":
    unittest.main()
