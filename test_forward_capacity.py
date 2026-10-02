#!/usr/bin/env python3
"""forward-capacity 子命令回归：forward-static 转发语义 + 动态 FDB 容量。

仅用标准库；通过 `python switch.py forward-capacity CONFIG DATA` 端到端
驱动。双文件格式、资源上限与错误契约沿用 forward-static；新增
fdb_capacity（global 非负整数，vlans 为按 VLAN 严格递增的可选上限）。
静态项不占动态容量且不被驱逐；VLAN 覆盖优先于全局，零上限不学习也不
驱逐但仍转发。
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


def config(
    ports=None,
    age=100,
    static=None,
    cap_global=100,
    cap_vlans=None,
):
    if ports is None:
        ports = [port("p1"), port("p2"), port("p3")]
    return {
        "ports": ports,
        "age": age,
        "static": [] if static is None else static,
        "fdb_capacity": {
            "global": cap_global,
            "vlans": [] if cap_vlans is None else cap_vlans,
        },
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


def run_raw(config_doc, frames, *limits):
    proc, _ = run_case(config_doc, frames, *limits)
    return proc


class CapacityForwardTests(unittest.TestCase):
    def test_top_level_and_entry_key_order(self):
        out = run(config(cap_global=1), [frame(0, "p1", M1), frame(1, "p2", M2)])
        self.assertEqual(
            list(out), ["results", "ports", "vlans", "fdb", "evictions"]
        )
        self.assertEqual(
            list(out["results"][0]),
            ["t", "action", "ports", "learned", "evicted"],
        )
        self.assertEqual(list(out["evictions"][0]), ["vlan", "count"])
        self.assertEqual(
            list(out["results"][1]["evicted"]),
            ["vlan", "mac", "port", "seen"],
        )

    def test_new_learn_without_eviction_sets_learned(self):
        out = run(config(cap_global=2), [frame(0, "p1", M1)])
        self.assertEqual(out["results"][0]["learned"], True)
        self.assertIsNone(out["results"][0]["evicted"])

    def test_global_capacity_evicts_oldest_seen(self):
        frames = [
            frame(0, "p1", M1),
            frame(1, "p2", M2),
            frame(2, "p3", M3),
        ]
        out = run(config(cap_global=2), frames)
        self.assertEqual(
            out["results"][2]["evicted"],
            {"vlan": 1, "mac": M1, "port": "p1", "seen": 0},
        )
        self.assertEqual(
            [(e["mac"], e["port"]) for e in out["fdb"]],
            [(M2, "p2"), (M3, "p3")],
        )
        self.assertEqual(out["evictions"], [{"vlan": 1, "count": 1}])

    def test_global_tie_breaks_by_vlan_then_mac(self):
        ports = [port("p%d" % i, mode="trunk", allowed=[1, 2])
                 for i in range(1, 5)]
        frames = [
            frame(0, "p1", M2, vlan=2),
            frame(0, "p2", M1, vlan=1),
            frame(0, "p3", M3, vlan=1),
        ]
        out = run(config(ports=ports, cap_global=2), frames)
        # seen 相同：VLAN 数值小者优先，同 VLAN 内 MAC 字典序
        self.assertEqual(
            out["results"][2]["evicted"],
            {"vlan": 1, "mac": M1, "port": "p2", "seen": 0},
        )

    def test_vlan_override_evicts_within_vlan_only(self):
        ports = [port("p%d" % i, mode="trunk", allowed=[1, 2])
                 for i in range(1, 5)]
        cap_vlans = [{"vlan": 1, "limit": 2}]
        frames = [
            frame(0, "p1", M9, vlan=2),
            frame(0, "p2", M1, vlan=1),
            frame(5, "p3", M2, vlan=1),
            frame(6, "p4", M3, vlan=1),
        ]
        out = run(config(ports=ports, cap_global=100, cap_vlans=cap_vlans),
                  frames)
        # 即便 (2,M9) 全局更旧，VLAN 满时只在该 VLAN 内驱逐
        self.assertEqual(
            out["results"][3]["evicted"],
            {"vlan": 1, "mac": M1, "port": "p2", "seen": 0},
        )
        self.assertEqual(
            sorted((e["vlan"], e["mac"]) for e in out["fdb"]),
            [(1, M2), (1, M3), (2, M9)],
        )

    def test_vlan_not_full_falls_through_to_global(self):
        ports = [port("p%d" % i, mode="trunk", allowed=[1, 2])
                 for i in range(1, 5)]
        cap_vlans = [{"vlan": 1, "limit": 5}]
        frames = [
            frame(0, "p1", M1, vlan=1),
            frame(1, "p2", M2, vlan=2),
            frame(2, "p3", M3, vlan=1),
        ]
        out = run(config(ports=ports, cap_global=2, cap_vlans=cap_vlans),
                  frames)
        self.assertEqual(
            out["results"][2]["evicted"],
            {"vlan": 1, "mac": M1, "port": "p1", "seen": 0},
        )

    def test_zero_vlan_override_neither_learns_nor_evicts(self):
        ports = [port("p1"), port("p2")]
        frames = [frame(0, "p1", M1), frame(1, "p1", M2)]
        out = run(
            config(cap_global=3, cap_vlans=[{"vlan": 1, "limit": 0}]),
            frames,
        )
        for item in out["results"]:
            self.assertFalse(item["learned"])
            self.assertIsNone(item["evicted"])
            self.assertEqual(item["action"], "flood")
        self.assertEqual(out["fdb"], [])
        self.assertEqual(out["evictions"], [])

    def test_zero_global_neither_learns_nor_evicts(self):
        frames = [frame(0, "p1", M1), frame(1, "p2", M2)]
        out = run(config(cap_global=0), frames)
        for item in out["results"]:
            self.assertFalse(item["learned"])
            self.assertIsNone(item["evicted"])
            self.assertEqual(item["action"], "flood")
        self.assertEqual(out["fdb"], [])

    def test_refresh_and_migration_never_evict(self):
        frames = [
            frame(0, "p1", M1),
            frame(1, "p1", M1),       # 刷新
            frame(2, "p2", M1),       # 迁移
            frame(3, "p3", M2),       # 新学习 -> 驱逐
        ]
        out = run(config(cap_global=1), frames)
        for item in out["results"][:3]:
            self.assertTrue(item["learned"])
            self.assertIsNone(item["evicted"])
        self.assertEqual(
            out["results"][3]["evicted"],
            {"vlan": 1, "mac": M1, "port": "p2", "seen": 2},
        )
        self.assertEqual(
            [(e["mac"], e["port"], e["seen"]) for e in out["fdb"]],
            [(M2, "p3", 3)],
        )

    def test_aging_frees_capacity_without_eviction(self):
        frames = [frame(0, "p1", M1), frame(10, "p2", M2)]
        out = run(config(age=10, cap_global=1), frames)
        self.assertIsNone(out["results"][1]["evicted"])
        self.assertEqual([e["mac"] for e in out["fdb"]], [M2])

    def test_static_entries_ignore_capacity_and_forward_as_before(self):
        static = [{"vlan": 1, "mac": M9, "port": "p3"}]
        # global=0：动态不可学习，但静态目的仍单播
        out = run(config(static=static, cap_global=0), [frame(0, "p1", M1, M9)])
        self.assertEqual(out["results"][0]["action"], "unicast")
        self.assertFalse(out["results"][0]["learned"])
        self.assertEqual(
            out["fdb"],
            [{"vlan": 1, "mac": M9, "port": "p3",
              "source": "static", "seen": None}],
        )
        # 静态源出现在别的端口：丢弃，容量逻辑不触碰静态项
        out = run(config(static=static, cap_global=1), [frame(0, "p2", M9, M1)])
        self.assertEqual(out["results"][0]["action"], "drop")
        self.assertEqual(len(out["fdb"]), 1)

    def test_down_port_and_rejected_frame_not_learned(self):
        ports = [port("p1"), port("p2", up=False)]
        out = run(config(ports=ports, cap_global=1), [frame(0, "p2", M2)])
        self.assertFalse(out["results"][0]["learned"])
        self.assertEqual(out["fdb"], [])
        out = run(config(cap_global=1), [frame(0, "p1", M1, vlan=2)])
        self.assertEqual(out["results"][0]["action"], "drop")
        self.assertFalse(out["results"][0]["learned"])

    def test_evictions_aggregated_per_vlan_sorted(self):
        ports = [port("p%d" % i, mode="trunk", allowed=[1, 2])
                 for i in range(1, 5)]
        frames = [
            frame(0, "p1", M1, vlan=2),
            frame(1, "p2", M2, vlan=1),
            frame(2, "p3", M3, vlan=2),  # 驱逐 (2,M1)
            frame(3, "p4", M1, vlan=1),  # 驱逐 (1,M2)
        ]
        out = run(config(ports=ports, cap_global=1), frames)
        self.assertEqual(
            out["evictions"],
            [{"vlan": 1, "count": 1}, {"vlan": 2, "count": 2}],
        )

    def test_deterministic_byte_identical(self):
        frames = [frame(0, "p1", M1), frame(1, "p2", M2), frame(2, "p3", M3)]
        a = run_raw(config(cap_global=1), frames)
        b = run_raw(config(cap_global=1), frames)
        self.assertEqual(a.returncode, 0)
        self.assertEqual(a.stdout, b.stdout)


class CapacityValidationTests(unittest.TestCase):
    def assert_invalid(self, config_doc):
        proc = run_raw(config_doc, [])
        self.assertEqual(proc.returncode, 4, proc.stderr)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b'{"error":"invalid_input"}\n')

    def test_config_keys_exact(self):
        bad = config()
        del bad["fdb_capacity"]
        self.assert_invalid(bad)
        bad = config()
        bad["extra"] = 1
        self.assert_invalid(bad)

    def test_capacity_shape(self):
        bad = config()
        bad["fdb_capacity"] = []
        self.assert_invalid(bad)
        bad = config()
        bad["fdb_capacity"] = {"global": 1}
        self.assert_invalid(bad)
        bad = config()
        bad["fdb_capacity"] = {"global": 1, "vlans": [], "x": 0}
        self.assert_invalid(bad)

    def test_global_non_negative_integer(self):
        for value in (-1, True, "1", 1.0, None):
            self.assert_invalid(config(cap_global=value))

    def test_vlan_override_entries(self):
        for bad_vlans in (
            {},
            [{"vlan": 1}],
            [{"vlan": 1, "limit": 0, "x": 1}],
            [{"vlan": 0, "limit": 1}],
            [{"vlan": 4095, "limit": 1}],
            [{"vlan": 1, "limit": -1}],
            [{"vlan": 1, "limit": True}],
            [{"vlan": 2, "limit": 1}, {"vlan": 1, "limit": 1}],
            [{"vlan": 1, "limit": 1}, {"vlan": 1, "limit": 2}],
        ):
            self.assert_invalid(config(cap_vlans=bad_vlans))

    def test_static_and_ports_validated_like_forward_static(self):
        bad = config()
        bad["age"] = 0
        self.assert_invalid(bad)
        self.assert_invalid(
            config(static=[{"vlan": 2, "mac": M9, "port": "p3"}])
        )
        self.assert_invalid(config(static=[{"vlan": 1, "mac": M9,
                                           "port": "nope"}]))


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
            for argv in (
                ["forward-capacity", cfg, data, "1024"],
                ["forward-capacity", cfg, data, "1024", "1024", "100",
                 "1000", "100", "1"],
                ["forward-capacity", cfg, data, "0", "1024"],
            ):
                self.assertEqual(run_cli(argv).returncode, 2)

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
        proc = run_raw(config(), [frame(0, "p1", M1)],
                       100000, 100000, 100, 10)
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b'{"error":"output_limit"}\n')

    def test_work_limit_counts_all_entries(self):
        # 3 端口 width=4；1 条静态项 -> 首帧成本 1+3+1=5
        static = [{"vlan": 1, "mac": M9, "port": "p3"}]
        frames = [frame(0, "p1", M1, M9)]
        proc = run_raw(config(static=static), frames,
                       100000, 100000, 100, 100000, 4)
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(
            proc.stderr, b'{"error":"fdb_capacity_work_limit"}\n'
        )
        proc = run_raw(config(static=static), frames,
                       100000, 100000, 100, 100000, 5)
        self.assertEqual(proc.returncode, 0)

    def test_eviction_changes_no_cost_beyond_entry_count(self):
        # global=1：逐帧处理前计费，首帧 K=0 成本 4，次帧老化前 K=1
        # 成本 5（学习驱逐不增项数），累计 9
        frames = [frame(0, "p1", M1), frame(1, "p2", M2)]
        proc = run_raw(config(cap_global=1), frames,
                       100000, 100000, 100, 100000, 9)
        self.assertEqual(proc.returncode, 0)
        proc = run_raw(config(cap_global=1), frames,
                       100000, 100000, 100, 100000, 8)
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(
            proc.stderr, b'{"error":"fdb_capacity_work_limit"}\n'
        )


class RecordReplayTests(unittest.TestCase):
    def _write(self, tmp, config_doc, frames):
        cfg = os.path.join(tmp, "config.json")
        data = os.path.join(tmp, "frames.json")
        open(cfg, "wb").write(json.dumps(config_doc).encode("utf-8"))
        open(data, "wb").write(json.dumps(frames).encode("utf-8"))
        return cfg, data

    def test_record_replay_byte_identical(self):
        ports = [port("p%d" % i, mode="trunk", allowed=[1, 2])
                 for i in range(1, 4)]
        config_doc = config(
            ports=ports,
            static=[{"vlan": 1, "mac": M9, "port": "p3"}],
            cap_global=2,
            cap_vlans=[{"vlan": 1, "limit": 1}],
        )
        frames = [
            frame(0, "p1", M1, vlan=1),
            frame(1, "p2", M2, vlan=2),
            frame(2, "p3", M3, vlan=1),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            cfg, data = self._write(tmp, config_doc, frames)
            direct = run_cli(["forward-capacity", cfg, data])
            log1 = os.path.join(tmp, "a.log")
            log2 = os.path.join(tmp, "b.log")
            rec = run_cli(["record", cfg, data, log1])
            self.assertEqual(rec.returncode, 0, rec.stderr)
            self.assertEqual(rec.stdout, direct.stdout)
            rep = run_cli(["replay", log1])
            self.assertEqual(rep.returncode, 0, rep.stderr)
            self.assertEqual(rep.stdout, direct.stdout)
            # 重建 LOG 与首次产物逐字节一致
            run_cli(["record", cfg, data, log2])
            self.assertEqual(
                open(log1, "rb").read(), open(log2, "rb").read()
            )
            log = json.loads(open(log1, "rb").read().decode("utf-8"))
            self.assertEqual(
                list(log), ["schema", "config", "records", "sha256"]
            )
            for record in log["records"]:
                self.assertEqual(record["version"], 0)
                self.assertTrue(record["applied"])
                self.assertEqual(
                    list(record["output"]),
                    ["t", "action", "ports", "learned", "evicted"],
                )
            self.assertEqual(
                log["records"][2]["output"]["evicted"]["mac"], M1
            )

    def test_record_replay_work_limit(self):
        frames = [frame(0, "p1", M1)]
        with tempfile.TemporaryDirectory() as tmp:
            cfg, data = self._write(tmp, config(static=[
                {"vlan": 1, "mac": M9, "port": "p3"}]), frames)
            log_path = os.path.join(tmp, "out.log")
            proc = run_cli(
                ["record", cfg, data, log_path,
                 "100000", "16777216", "1048576", "16777216",
                 "16777216", "4"]
            )
            self.assertEqual(proc.returncode, 5)
            self.assertEqual(
                proc.stderr, b'{"error":"record_work_limit"}\n'
            )
            self.assertFalse(os.path.exists(log_path))


if __name__ == "__main__":
    unittest.main()
