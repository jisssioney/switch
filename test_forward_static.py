#!/usr/bin/env python3
"""forward-static 子命令回归：新式 802.1Q 转发 + 预置静态 FDB 项。

仅用标准库；通过 `python switch.py forward-static CONFIG DATA` 端到端驱动。
签名、资源上限、错误契约与 JSON 约定均沿用新式 forward；静态项不老化、
不刷新、不迁移，源命中静态项且端口不同则丢弃且不学习。
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


def config(ports=None, age=100, static=None):
    if ports is None:
        ports = [port("p1"), port("p2"), port("p3")]
    if static is None:
        static = [{"vlan": 1, "mac": M9, "port": "p3"}]
    return {"ports": ports, "age": age, "static": static}


def frame(t, p, src, dst=BCAST, vlan=None):
    return {"t": t, "port": p, "src": src, "dst": dst, "vlan": vlan}


def run_cli(argv):
    return subprocess.run(
        [sys.executable, SWITCH, *argv],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def run_case(config_doc, frames, *limits, mode="forward-static"):
    with tempfile.TemporaryDirectory() as tmp:
        cfg = os.path.join(tmp, "config.json")
        data = os.path.join(tmp, "frames.json")
        with open(cfg, "wb") as handle:
            handle.write(json.dumps(config_doc).encode("utf-8"))
        with open(data, "wb") as handle:
            handle.write(json.dumps(frames).encode("utf-8"))
        proc = run_cli(
            [mode, cfg, data, *[str(x) for x in limits]]
        )
        missing = run_cli(
            [mode, os.path.join(tmp, "nope.json"), data]
        )
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


class StaticForwardTests(unittest.TestCase):
    def test_top_level_and_entry_key_order(self):
        out = run(config(), [frame(0, "p1", M1, M9)])
        self.assertEqual(list(out), ["results", "ports", "vlans", "fdb"])
        self.assertEqual(
            list(out["fdb"][0]), ["vlan", "mac", "port", "source", "seen"]
        )

    def test_static_dst_unicast_without_learning(self):
        # 目的命中静态项：未学习源前即按单播转发
        out = run(config(), [frame(0, "p1", M1, M9)])
        self.assertEqual(
            out["results"],
            [{"t": 0, "action": "unicast",
              "ports": [{"name": "p3", "vlan": None}]}],
        )

    def test_static_entry_never_ages(self):
        # age=100，t=500 时静态项仍生效
        out = run(config(age=100), [frame(500, "p1", M1, M9)])
        self.assertEqual(out["results"][0]["action"], "unicast")
        self.assertEqual(
            out["fdb"],
            [
                {"vlan": 1, "mac": M1, "port": "p1",
                 "source": "dynamic", "seen": 500},
                {"vlan": 1, "mac": M9, "port": "p3",
                 "source": "static", "seen": None},
            ],
        )

    def test_dynamic_entry_ages_but_static_stays(self):
        frames = [
            frame(0, "p2", M2),      # 动态学习 M2@p2
            frame(150, "p1", M1, M2),  # M2 已老化（150-0>=100）→ 泛洪
            frame(150, "p1", M1, M9),  # 静态项不老化 → 单播
        ]
        out = run(config(age=100), frames)
        self.assertEqual(out["results"][1]["action"], "flood")
        self.assertEqual(out["results"][2]["action"], "unicast")
        self.assertEqual(
            out["fdb"],
            [
                {"vlan": 1, "mac": M1, "port": "p1",
                 "source": "dynamic", "seen": 150},
                {"vlan": 1, "mac": M9, "port": "p3",
                 "source": "static", "seen": None},
            ],
        )

    def test_static_src_other_port_dropped_and_not_learned(self):
        # 静态源出现在别的端口：丢弃、不学习、不迁移
        frames = [
            frame(0, "p2", M9, M1),   # 静态源端口不符 → 丢弃
            frame(1, "p1", M1, M9),   # 静态项仍指向 p3 → 单播
        ]
        out = run(config(), frames)
        self.assertEqual(out["results"][0],
                         {"t": 0, "action": "drop", "ports": []})
        self.assertEqual(out["results"][1]["action"], "unicast")
        self.assertEqual(
            out["fdb"],
            [
                {"vlan": 1, "mac": M1, "port": "p1",
                 "source": "dynamic", "seen": 1},
                {"vlan": 1, "mac": M9, "port": "p3",
                 "source": "static", "seen": None},
            ],
        )
        # 丢弃计入端口与 VLAN 统计
        p2 = next(p for p in out["ports"] if p["name"] == "p2")
        self.assertEqual((p2["rx"], p2["drop"]), (1, 1))
        self.assertEqual(out["vlans"][0]["drop"], 1)

    def test_static_src_same_port_continues_without_touch(self):
        # 静态源在同口：继续转发但不改表（seen 恒为 null）
        frames = [
            frame(0, "p3", M9, M1),   # 同口广播 → 泛洪，表不变
            frame(1, "p3", M9, M1),
        ]
        out = run(config(), frames)
        self.assertEqual(out["results"][0]["action"], "flood")
        self.assertEqual(
            out["fdb"],
            [{"vlan": 1, "mac": M9, "port": "p3",
              "source": "static", "seen": None}],
        )

    def test_dynamic_learning_does_not_override_static(self):
        # 同一 (vlan, mac) 的动态学习永不可发生：静态命中优先拦截
        frames = [frame(0, "p1", M9, M2)]
        out = run(config(), frames)
        self.assertEqual(out["results"][0]["action"], "drop")
        self.assertEqual(
            out["fdb"],
            [{"vlan": 1, "mac": M9, "port": "p3",
              "source": "static", "seen": None}],
        )

    def test_dynamic_learning_and_migration_unchanged(self):
        # 非静态源照旧动态学习与迁移
        frames = [
            frame(0, "p1", M1),
            frame(1, "p2", M1),       # 迁移到 p2
            frame(2, "p3", M3, M1),   # 单播到 p2
        ]
        out = run(config(), frames)
        self.assertEqual(
            out["results"][2],
            {"t": 2, "action": "unicast",
             "ports": [{"name": "p2", "vlan": None}]},
        )
        self.assertEqual(
            out["fdb"][0],
            {"vlan": 1, "mac": M1, "port": "p2",
             "source": "dynamic", "seen": 1},
        )

    def test_static_dst_egress_down_drops_not_floods(self):
        ports = [port("p1"), port("p2"), port("p3", up=False)]
        out = run(config(ports=ports), [frame(0, "p1", M1, M9)])
        self.assertEqual(out["results"][0],
                         {"t": 0, "action": "drop", "ports": []})

    def test_static_dst_same_port_drops(self):
        # 静态目的与入端口相同：丢弃（不泛洪）
        out = run(config(), [frame(0, "p3", M1, M9)])
        self.assertEqual(out["results"][0]["action"], "drop")

    def test_broadcast_and_miss_flood_unchanged(self):
        frames = [
            frame(0, "p1", M1),        # 广播 → 泛洪
            frame(1, "p1", M1, M2),    # 未命中 → 泛洪
        ]
        out = run(config(), frames)
        self.assertEqual(
            out["results"][0]["ports"],
            [{"name": "p2", "vlan": None}, {"name": "p3", "vlan": None}],
        )
        self.assertEqual(out["results"][1]["action"], "flood")

    def test_vlan_admission_and_tagging_unchanged(self):
        ports = [
            port("p1", mode="trunk", pvid=1, allowed=[1, 2]),
            port("p2", mode="hybrid", pvid=1, allowed=[1, 2], untagged=[1]),
            port("p3"),
        ]
        static = [{"vlan": 2, "mac": M9, "port": "p2"}]
        frames = [
            # access 口收到带标签帧 → 拒绝，不学习、不计 VLAN
            frame(0, "p3", M3, M9, vlan=2),
            # trunk 收 vlan 2 → 静态命中单播到 hybrid p2（带标签）
            frame(1, "p1", M1, M9, vlan=2),
        ]
        out = run(config(ports=ports, static=static), frames)
        self.assertEqual(out["results"][0],
                         {"t": 0, "action": "drop", "ports": []})
        self.assertEqual(
            out["results"][1],
            {"t": 1, "action": "unicast",
             "ports": [{"name": "p2", "vlan": 2}]},
        )
        v2 = next(v for v in out["vlans"] if v["vlan"] == 2)
        self.assertEqual((v2["rx"], v2["tx"]), (1, 1))

    def test_fdb_sorted_by_vlan_then_mac(self):
        ports = [
            port("p1", mode="trunk", pvid=1, allowed=[1, 2, 3]),
            port("p2", mode="trunk", pvid=1, allowed=[1, 2, 3]),
        ]
        static = [
            {"vlan": 3, "mac": M2, "port": "p2"},
            {"vlan": 1, "mac": M3, "port": "p2"},
            {"vlan": 1, "mac": M1, "port": "p1"},
        ]
        frames = [frame(0, "p1", M2, vlan=2)]  # 动态学习 (2, M2)
        out = run(config(ports=ports, static=static, age=100), frames)
        self.assertEqual(
            [(e["vlan"], e["mac"]) for e in out["fdb"]],
            [(1, M1), (1, M3), (2, M2), (3, M2)],
        )
        self.assertEqual(
            [e["source"] for e in out["fdb"]],
            ["static", "static", "dynamic", "static"],
        )

    def test_empty_static_and_empty_frames(self):
        out = run(config(static=[]), [])
        self.assertEqual(
            out,
            {"results": [], "ports": [
                {"name": n, "rx": 0, "tx": 0, "drop": 0}
                for n in ("p1", "p2", "p3")
            ], "vlans": [{"vlan": 1, "rx": 0, "tx": 0, "drop": 0}],
             "fdb": []},
        )

    def test_deterministic_byte_identical(self):
        frames = [frame(0, "p1", M1, M9), frame(1, "p2", M9, M1)]
        a = run_raw(config(), frames)
        b = run_raw(config(), frames)
        self.assertEqual(a.returncode, 0)
        self.assertEqual(a.stdout, b.stdout)


class StaticValidationTests(unittest.TestCase):
    def assert_invalid(self, config_doc=None, frames=None):
        proc = run_raw(
            config() if config_doc is None else config_doc,
            [] if frames is None else frames,
        )
        self.assertEqual(proc.returncode, 4, proc.stderr)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b'{"error":"invalid_input"}\n')

    def test_config_keys_must_be_exactly_ports_age_static(self):
        bad = config()
        del bad["static"]
        self.assert_invalid(bad)
        bad = config()
        bad["extra"] = 1
        self.assert_invalid(bad)

    def test_static_must_be_list(self):
        bad = config()
        bad["static"] = {}
        self.assert_invalid(bad)

    def test_static_entry_keys_exact(self):
        bad = config(static=[{"vlan": 1, "mac": M9, "port": "p3", "x": 1}])
        self.assert_invalid(bad)
        bad = config(static=[{"vlan": 1, "mac": M9}])
        self.assert_invalid(bad)
        bad = config(static=[["vlan", 1]])
        self.assert_invalid(bad)

    def test_static_vlan_range_and_type(self):
        for vlan in (0, 4095, -1, True, "1", 1.0, None):
            self.assert_invalid(
                config(static=[{"vlan": vlan, "mac": M9, "port": "p3"}])
            )
        # 边界 1 与 4094 合法（端口须放行对应 VLAN）
        trunk = port("p3", mode="trunk", pvid=1, allowed=[1, 4094])
        ports = [port("p1"), port("p2"), trunk]
        for vlan in (1, 4094):
            out = run(config(
                ports=ports,
                static=[{"vlan": vlan, "mac": M9, "port": "p3"}],
            ), [])
            self.assertEqual(out["fdb"][0]["vlan"], vlan)

    def test_static_mac_lowercase_nonzero_unicast(self):
        for mac in (
            "00:00:00:00:00:00",          # 全零
            "01:00:00:00:00:00",          # 组播位
            BCAST,                        # 广播
            "AA:00:00:00:00:00",          # 大写
            "0:00:00:00:00:00",           # 非规范
            "",
            9,
            None,
        ):
            self.assert_invalid(
                config(static=[{"vlan": 1, "mac": mac, "port": "p3"}])
            )

    def test_static_port_must_exist(self):
        self.assert_invalid(
            config(static=[{"vlan": 1, "mac": M9, "port": "nope"}])
        )
        self.assert_invalid(
            config(static=[{"vlan": 1, "mac": M9, "port": 3}])
        )

    def test_static_port_must_allow_vlan(self):
        # p3 为 access pvid=1，不允许 vlan 2
        self.assert_invalid(
            config(static=[{"vlan": 2, "mac": M9, "port": "p3"}])
        )

    def test_static_vlan_mac_pairs_distinct(self):
        dup = [
            {"vlan": 1, "mac": M9, "port": "p3"},
            {"vlan": 1, "mac": M9, "port": "p1"},
        ]
        self.assert_invalid(config(static=dup))
        # 同 mac 不同 vlan 合法
        ok = [
            {"vlan": 1, "mac": M9, "port": "p3"},
            {"vlan": 2, "mac": M9, "port": "p3"},
        ]
        ports = [port("p1"), port("p2"),
                 port("p3", mode="trunk", pvid=1, allowed=[1, 2])]
        out = run(config(ports=ports, static=ok), [])
        self.assertEqual(len(out["fdb"]), 2)

    def test_frames_validated_like_forward(self):
        self.assert_invalid(config(), [frame(-1, "p1", M1)])
        self.assert_invalid(config(), [frame(1, "p1", M1), frame(0, "p1", M1)])
        self.assert_invalid(config(), [frame(0, "nope", M1)])
        self.assert_invalid(config(), [frame(0, "p1", BCAST)])
        self.assert_invalid(config(), [frame(0, "p1", M1, vlan=0)])
        self.assert_invalid(config(), [{"t": 0, "port": "p1", "src": M1,
                                        "dst": M2}])  # 缺 vlan 键

    def test_ports_and_age_validated_like_forward(self):
        bad = config()
        bad["age"] = 0
        self.assert_invalid(bad)
        bad = config()
        bad["age"] = True
        self.assert_invalid(bad)
        bad = config(ports=[])
        self.assert_invalid(bad)
        bad = config(ports=[port("p1"), port("p1")])
        self.assert_invalid(bad)


class ResourceAndErrorTests(unittest.TestCase):
    def test_usage(self):
        proc = run_cli(["forward-static"])
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, b"")
        with tempfile.TemporaryDirectory() as tmp:
            cfg = os.path.join(tmp, "c.json")
            data = os.path.join(tmp, "d.json")
            open(cfg, "wb").write(b"{}")
            open(data, "wb").write(b"[]")
            # 仅允许 0、2、4、5 项上限（同 forward）
            proc = run_cli(["forward-static", cfg, data, "1024"])
            self.assertEqual(proc.returncode, 2)
            proc = run_cli(["forward-static", cfg, data,
                            "1024", "1024", "100", "1000", "100", "1"])
            self.assertEqual(proc.returncode, 2)
            # 上限须匹配 [1-9][0-9]*
            proc = run_cli(["forward-static", cfg, data,
                            "0", "1024"])
            self.assertEqual(proc.returncode, 2)

    def test_file_not_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = os.path.join(tmp, "d.json")
            open(data, "wb").write(b"[]")
            proc = run_cli(["forward-static",
                            os.path.join(tmp, "nope.json"), data])
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b'{"error":"file_not_found"}\n')

    def test_config_and_data_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = os.path.join(tmp, "c.json")
            data = os.path.join(tmp, "d.json")
            open(cfg, "wb").write(json.dumps(config()).encode("utf-8"))
            open(data, "wb").write(b"[]")
            proc = run_cli(["forward-static", cfg, data, "10", "1024"])
            self.assertEqual(proc.returncode, 5)
            self.assertEqual(proc.stderr, b'{"error":"config_limit"}\n')
            proc = run_cli(["forward-static", cfg, data, "100000", "1"])
            self.assertEqual(proc.returncode, 5)
            self.assertEqual(proc.stderr, b'{"error":"data_limit"}\n')
            self.assertEqual(proc.stdout, b"")

    def test_item_limit(self):
        frames = [frame(i, "p1", M1) for i in range(3)]
        proc = run_raw(config(), frames, 100000, 100000, 2, 100000)
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b'{"error":"item_limit"}\n')

    def test_output_limit(self):
        proc = run_raw(config(), [frame(0, "p1", M1, M9)],
                       100000, 100000, 100, 10)
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b'{"error":"output_limit"}\n')

    def test_work_limit_counts_static_entries(self):
        # 3 端口 width=4；1 条静态项 → 首帧成本 K+P+1 = 1+3+1 = 5
        frames = [frame(0, "p1", M1, M9)]
        proc = run_raw(config(), frames, 100000, 100000, 100, 100000, 4)
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b'{"error":"forward_work_limit"}\n')
        # 等于上限合法
        proc = run_raw(config(), frames, 100000, 100000, 100, 100000, 5)
        self.assertEqual(proc.returncode, 0)
        # 无静态项时首帧成本为 4（对照：K 含全部表项）
        proc = run_raw(config(static=[]), frames,
                       100000, 100000, 100, 100000, 4)
        self.assertEqual(proc.returncode, 0)


class OldEntryUnchangedTests(unittest.TestCase):
    """旧入口逐字节不变：forward 新旧式行为不受 forward-static 影响。"""

    def test_forward_v1_unchanged(self):
        cfg = {
            "ports": [
                {"name": "p1", "vlan": 1, "up": True},
                {"name": "p2", "vlan": 1, "up": True},
            ],
            "age": 100,
        }
        frames = [{"t": 0, "port": "p1", "src": M1, "dst": M2}]
        out = run_case(cfg, frames, mode="forward")[0]
        self.assertEqual(out.returncode, 0)
        doc = json.loads(out.stdout.decode("utf-8"))
        self.assertEqual(list(doc), ["results", "ports", "vlans"])
        self.assertNotIn("fdb", doc)

    def test_forward_v2_unchanged(self):
        cfg = {"ports": [port("p1"), port("p2")], "age": 100}
        frames = [frame(0, "p1", M1, M9)]
        out = run_case(cfg, frames, mode="forward")[0]
        self.assertEqual(out.returncode, 0)
        doc = json.loads(out.stdout.decode("utf-8"))
        self.assertEqual(list(doc), ["results", "ports", "vlans"])
        self.assertNotIn("fdb", doc)
        # 未命中 → 泛洪
        self.assertEqual(doc["results"][0]["action"], "flood")

    def test_forward_rejects_static_key(self):
        # static 键不属于新式 forward 配置：旧入口按非法输入处理
        proc = run_case(config(), [], mode="forward")[0]
        self.assertEqual(proc.returncode, 4)
        self.assertEqual(proc.stdout, b"")


if __name__ == "__main__":
    unittest.main()
