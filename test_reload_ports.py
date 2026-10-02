#!/usr/bin/env python3
"""reload/reload-rollback 的端口 VLAN 属性热加载与状态迁移回归。

覆盖：现有端口 mode/pvid/allowed/untagged 开放热变更，名称/顺序/up 不可
变；ports 按固定次序列入 changes，before/after 为完整端口数组与规范键
序；未标记帧归属与出站标签立即采用新值；FDB 项仅在逻辑口（物理口或
LAG）仍允许该 VLAN 时保留；动态 MAC 安全绑定按新 allowed 清理后再校验
新 static 归属、端口上限与全局唯一性；已入队副本出端口不再允许其 VLAN
时丢弃并计入端口与 VLAN 既有 drop 计数，合法副本保留帧号/队列/标签与
调度位置；rollback 按 LIFO 恢复且不复活已清除项；迁移阶段按检查项计费；
record/replay 逐字节一致。
"""

import copy
import json
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SWITCH = os.path.join(HERE, "switch.py")

sys.path.insert(0, HERE)

from test_reload import base_config, run_cli  # noqa: E402
from test_record import record, replay  # noqa: E402


def vport(name, mode="access", pvid=1, allowed=None, untagged=None, up=True):
    if allowed is None:
        allowed = [pvid]
    if untagged is None:
        untagged = [] if mode == "trunk" else [pvid]
    return {
        "name": name,
        "mode": mode,
        "pvid": pvid,
        "allowed": list(allowed),
        "untagged": list(untagged),
        "up": up,
    }


def tframe(t, port, src, dst="ff:ff:ff:ff:ff:ff", vlan=None, prio=0):
    return {
        "t": t,
        "port": port,
        "src": src,
        "dst": dst,
        "vlan": vlan,
        "ethertype": 0x0800,
        "priority": prio,
    }


def service(t, port, count):
    return {"t": t, "port": port, "count": count}


def reload_cfg(t, config):
    return {"t": t, "config": config}


def rollback(t):
    return {"t": t, "rollback": True}


def run(events, config=None, mode="reload-rollback", extra=()):
    config = config if config is not None else base_config()
    code, out, err = run_cli(config, events, mode=mode, extra=list(extra))
    assert code == 0, (code, err.decode("utf-8"))
    return json.loads(out.decode("utf-8"))


def run_invalid(events, config=None, mode="reload-rollback", extra=()):
    config = config if config is not None else base_config()
    code, out, err = run_cli(config, events, mode=mode, extra=list(extra))
    assert code == 4, (code, out, err)
    assert out == b"", out
    assert err == b'{"error":"invalid_input"}\n', err


def run_work_limit(events, config=None, mode="reload-rollback", extra=()):
    config = config if config is not None else base_config()
    code, out, err = run_cli(config, events, mode=mode, extra=list(extra))
    assert code == 5, (code, out, err)
    assert out == b"", out
    assert err == b'{"error":"reload_work_limit"}\n', err


def other_ports_vlan2(config):
    """p2/p3/p4/p5 改为 access vlan2，p1 保持 vlan1（p4/p5 同 LAG 共享）。"""
    new = copy.deepcopy(config)
    for i in (1, 2, 3, 4):
        name = new["ports"][i]["name"]
        new["ports"][i] = vport(name, pvid=2)
    return new


def set_ports(config, *ports):
    new = copy.deepcopy(config)
    by_index = {p["name"]: i for i, p in enumerate(new["ports"])}
    for port in ports:
        new["ports"][by_index[port["name"]]] = copy.deepcopy(port)
    return new


class PortsChangesTest(unittest.TestCase):
    def test_ports_listed_in_fixed_order_with_full_arrays(self):
        config = base_config()
        new = set_ports(config, vport("p1", "trunk", 1, [1, 2]))
        new["age"] = 50
        result = run([reload_cfg(0, new)], config=config)
        record = result["results"][0]
        self.assertEqual(record["action"], "reload")
        # 固定次序：age、ports、storm、mirror、acl、qos、security
        self.assertEqual(
            [c["key"] for c in record["changes"]], ["age", "ports"]
        )
        ports_change = record["changes"][1]
        self.assertEqual(list(ports_change), ["key", "before", "after"])
        # before/after 均为完整端口数组，对象键按 Unicode 码点升序
        for side in ("before", "after"):
            self.assertEqual(len(ports_change[side]), 5)
            self.assertEqual(
                [p["name"] for p in ports_change[side]],
                ["p1", "p2", "p3", "p4", "p5"],
            )
            for port in ports_change[side]:
                self.assertEqual(
                    list(port),
                    ["allowed", "mode", "name", "pvid", "untagged", "up"],
                )
        self.assertEqual(
            ports_change["after"][0],
            {
                "allowed": [1, 2],
                "mode": "trunk",
                "name": "p1",
                "pvid": 1,
                "untagged": [],
                "up": True,
            },
        )
        # 末态 config 为规范化新配置
        self.assertEqual(result["config"]["age"], 50)
        self.assertEqual(result["config"]["ports"][0]["mode"], "trunk")

    def test_no_actual_change_not_listed(self):
        config = base_config()
        new = copy.deepcopy(config)  # 端口身份与 VLAN 属性全等
        result = run([reload_cfg(0, new)], config=config)
        self.assertEqual(result["results"][0]["changes"], [])

    def test_changes_order_with_other_sections(self):
        config = base_config()
        new = set_ports(config, vport("p1", "trunk", 1, [1, 2]))
        new["storm"]["window"] = 20
        new["age"] = 5
        result = run([reload_cfg(0, new)], config=config)
        self.assertEqual(
            [c["key"] for c in result["results"][0]["changes"]],
            ["age", "ports", "storm"],
        )

    def test_reload_entry_also_takes_ports(self):
        config = base_config()
        new = set_ports(config, vport("p1", "trunk", 1, [1, 2]))
        result = run([reload_cfg(0, new)], config=config, mode="reload")
        self.assertEqual(
            [c["key"] for c in result["results"][0]["changes"]], ["ports"]
        )


class PortsIdentityTest(unittest.TestCase):
    def _reject(self, new):
        run_invalid([reload_cfg(0, new)])

    def test_up_immutable(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["ports"][0]["up"] = False
        self._reject(new)

    def test_name_immutable(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["ports"][0]["name"] = "p9"
        self._reject(new)

    def test_order_immutable(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["ports"][0], new["ports"][1] = new["ports"][1], new["ports"][0]
        self._reject(new)

    def test_port_add_remove_immutable(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["ports"].pop()  # security 仍覆盖五口；端口数量变化本身拒绝
        self._reject(new)

    def test_lag_members_must_keep_shared_vlan_config(self):
        config = base_config()
        new = set_ports(config, vport("p4", "trunk", 1, [1, 2]))
        # p5 仍为 access vlan1：LAG 成员 VLAN 配置不一致，整批无效
        self._reject(new)

    def test_bad_new_port_config_rejected(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["ports"][0]["pvid"] = 9999  # 非合法 VLAN
        self._reject(new)


class VlanImmediateEffectTest(unittest.TestCase):
    def test_untagged_classification_and_egress_tags_immediate(self):
        # p1/p2/p4/p5 为 trunk vlan1,2（untagged 空），p3 为 access vlan2
        config = base_config()
        new = set_ports(
            config,
            vport("p1", "trunk", 1, [1, 2]),
            vport("p2", "trunk", 1, [1, 2]),
            vport("p3", "access", 2),
            vport("p4", "trunk", 1, [1, 2]),
            vport("p5", "trunk", 1, [1, 2]),
        )
        events = [
            reload_cfg(0, new),
            # p3 未标记帧现归属 vlan2：泛洪到 p2、p4（LAG 选一个成员），
            # p3 access 出站无标签，p2/p4 trunk 出站带 vlan2 标签
            tframe(1, "p3", "00:00:00:00:00:0d"),
            # p1 带 vlan1 标签：仅 p2/p4 允许 vlan1，p3 不收
            tframe(2, "p1", "00:00:00:00:00:0e", vlan=1),
        ]
        result = run(events, config=config)
        flood_v2 = result["results"][1]
        self.assertEqual(flood_v2["action"], "flood")
        tags = {p["name"]: p["vlan"] for p in flood_v2["ports"]}
        self.assertIn("p2", tags)
        self.assertEqual(tags.get("p2"), 2)  # trunk 出站打标
        lag_port = "p4" if "p4" in tags else "p5"
        self.assertEqual(tags[lag_port], 2)
        self.assertNotIn("p3", tags)  # 不回送入口
        flood_v1 = result["results"][2]
        names_v1 = {p["name"]: p["vlan"] for p in flood_v1["ports"]}
        self.assertNotIn("p3", names_v1)  # access vlan2 不收 vlan1
        self.assertEqual(names_v1.get("p2"), 1)

    def test_tagged_admission_tracks_mode_change(self):
        # p1 由 access 改 hybrid（allowed/pvid/untagged 不变）：标签帧立即
        # 由拒绝变为准入
        config = base_config()
        new = set_ports(config, vport("p1", "hybrid", 1, [1], [1]))
        events = [
            tframe(0, "p1", "00:00:00:00:00:01", vlan=1),  # access 拒绝
            reload_cfg(1, new),
            tframe(2, "p1", "00:00:00:00:00:02", vlan=1),  # hybrid 准入
        ]
        result = run(events, config=config)
        self.assertEqual(result["results"][0]["action"], "drop")
        self.assertEqual(result["results"][2]["action"], "flood")


class FdbMigrationTest(unittest.TestCase):
    def test_fdb_entry_dropped_when_port_no_longer_allows_vlan(self):
        config = base_config()
        # p2 与 LAG 成员 p4/p5 移到 vlan2；p3 保持 vlan1 作为可达出口
        new = set_ports(
            config,
            vport("p2", "access", 2),
            vport("p4", "access", 2),
            vport("p5", "access", 2),
        )
        events = [
            # 从 LAG 成员 p4 学习：FDB 项 (1, 0a) 逻辑口为 L1
            tframe(0, "p4", "00:00:00:00:00:0a"),
            reload_cfg(1, new),
            # p1 vlan1 单播查 0a：L1 已不允许 vlan1，表项删除 -> 泛洪到 p3
            tframe(2, "p1", "00:00:00:00:00:0b", dst="00:00:00:00:00:0a"),
        ]
        result = run(events, config=config)
        self.assertEqual(result["results"][2]["action"], "flood")
        self.assertEqual(
            [p["name"] for p in result["results"][2]["ports"]], ["p3"]
        )

    def test_fdb_entry_retained_when_port_still_allows_vlan(self):
        config = base_config()
        events = [
            tframe(0, "p1", "00:00:00:00:00:0a"),  # 学在 p1（vlan1）
            reload_cfg(1, other_ports_vlan2(config)),  # p1 保持 vlan1
            # p2 改 vlan2 后无法从 vlan2 查 vlan1；回滚后单播仍直达 p1
            rollback(2),
            tframe(3, "p2", "00:00:00:00:00:0b", dst="00:00:00:00:00:0a"),
        ]
        result = run(events, config=config)
        self.assertEqual(result["results"][3]["action"], "unicast")
        self.assertEqual(
            [p["name"] for p in result["results"][3]["ports"]], ["p1"]
        )


class DynamicBindingMigrationTest(unittest.TestCase):
    def config(self):
        config = base_config()
        # p1 为 trunk vlan1,2；放宽安全上限
        config = set_ports(config, vport("p1", "trunk", 1, [1, 2]))
        for entry in config["security"]:
            entry["limit"] = 10
        return config

    def test_bindings_cleaned_then_limit_checked_invalid(self):
        config = self.config()
        config["security"][0]["limit"] = 3
        new = set_ports(config, vport("p1", "trunk", 1, [1]))
        new["security"][0]["limit"] = 1  # 清理 vlan2 后仍有 2 个 vlan1
        events = [
            tframe(0, "p1", "00:00:00:00:00:0a", vlan=1),
            tframe(1, "p1", "00:00:00:00:00:0b", vlan=1),
            tframe(2, "p1", "00:00:00:00:00:0c", vlan=2),
            reload_cfg(3, new),
        ]
        run_invalid(events, config=config)

    def test_cleaned_binding_freeing_static_slot_is_legal(self):
        # vlan2 动态绑定被清理后，同一 MAC 的 vlan1 静态绑定不再冲突
        config = self.config()
        new = set_ports(config, vport("p1", "trunk", 1, [1]))
        new["security"][0]["static"] = [
            {"mac": "00:00:00:00:00:0c", "vlan": 1}
        ]
        events = [
            tframe(0, "p1", "00:00:00:00:00:0a", vlan=1),
            tframe(1, "p1", "00:00:00:00:00:0b", vlan=1),
            tframe(2, "p1", "00:00:00:00:00:0c", vlan=2),
            reload_cfg(3, new),
            # (1, 0c) 为 p1 静态：放行且不违例
            tframe(4, "p1", "00:00:00:00:00:0c", vlan=1),
        ]
        result = run(events, config=config)
        learned = {
            (x["vlan"], x["mac"])
            for x in result["security"][0]["learned"]
        }
        self.assertEqual(
            learned,
            {
                (1, "00:00:00:00:00:0a"),
                (1, "00:00:00:00:00:0b"),
            },
        )
        self.assertEqual(result["security"][0]["violations"], 0)

    def test_remaining_dynamic_binding_in_new_static_invalid(self):
        config = self.config()
        new = set_ports(config, vport("p1", "trunk", 1, [1]))
        new["security"][0]["static"] = [
            {"mac": "00:00:00:00:00:0a", "vlan": 1}
        ]
        events = [
            tframe(0, "p1", "00:00:00:00:00:0a", vlan=1),
            tframe(1, "p1", "00:00:00:00:00:0c", vlan=2),
            reload_cfg(2, new),  # (1,0a) 仍动态存在且入新 static
        ]
        run_invalid(events, config=config)

    def test_new_static_globally_duplicate_invalid(self):
        config = self.config()
        new = set_ports(config, vport("p1", "trunk", 1, [1]))
        new["security"][0]["static"] = [
            {"mac": "00:00:00:00:00:0a", "vlan": 1}
        ]
        new["security"][1]["static"] = [
            {"mac": "00:00:00:00:00:0a", "vlan": 1}
        ]
        run_invalid([reload_cfg(0, new)], config=config)

    def test_failed_reload_commits_no_state(self):
        config = self.config()
        config["security"][0]["limit"] = 3
        new = set_ports(config, vport("p1", "trunk", 1, [1]))
        new["security"][0]["limit"] = 0
        events = [
            tframe(0, "p1", "00:00:00:00:00:0a", vlan=1),
            tframe(1, "p1", "00:00:00:00:00:0c", vlan=2),
            reload_cfg(2, new),  # 整批无效：stdout 空、无部分输出
        ]
        run_invalid(events, config=config)


class QueueMigrationTest(unittest.TestCase):
    def test_illegal_queued_copies_dropped_legal_ones_keep_place(self):
        # 初始 vlan1 广播从 p1 入队 p2/p3/p4（LAG 选一个成员）
        config = base_config()
        new = set_ports(config, vport("p3", "access", 2))  # 仅 p3 移到 vlan2
        events = [
            tframe(0, "p1", "00:00:00:00:00:01"),
            reload_cfg(1, new),
            service(2, "p2", 1),   # 合法副本：帧号 0 发出
            service(3, "p4", 1),   # LAG 口的合法副本：帧号 0 发出
            service(4, "p3", 5),   # vlan1 副本已丢弃：无帧可发
        ]
        result = run(events, config=config)
        self.assertEqual(result["results"][2]["frames"], [0])
        self.assertEqual(result["results"][3]["frames"], [0])
        self.assertEqual(result["results"][4]["frames"], [])
        ports = {p["name"]: p for p in result["ports"]}
        vlans = {v["vlan"]: v for v in result["vlans"]}
        # 丢弃计入 p3 与 vlan1 的既有 drop 计数各一
        self.assertEqual(ports["p3"]["drop"], 1)
        self.assertEqual(vlans[1]["drop"], 1)
        # p2 的副本被服务为 tx（p2 兼镜像口，tx 另含镜像副本）
        self.assertGreaterEqual(ports["p2"]["tx"], 1)

    def test_drops_happen_at_reload_not_at_service(self):
        config = base_config()
        new = set_ports(config, vport("p3", "access", 2))
        result = run(
            [tframe(0, "p1", "00:00:00:00:00:01"), reload_cfg(1, new)],
            config=config,
        )
        ports = {p["name"]: p for p in result["ports"]}
        vlans = {v["vlan"]: v for v in result["vlans"]}
        self.assertEqual(ports["p3"]["drop"], 1)
        self.assertEqual(vlans[1]["drop"], 1)


class RollbackMigrationTest(unittest.TestCase):
    def test_rollback_restores_ports_lifo(self):
        config = base_config()
        new = other_ports_vlan2(config)
        result = run(
            [reload_cfg(0, new), rollback(1)], config=config
        )
        actions = [r["action"] for r in result["results"]]
        self.assertEqual(actions, ["reload", "rollback"])
        record = result["results"][1]
        self.assertEqual(
            [c["key"] for c in record["changes"]], ["ports"]
        )
        self.assertEqual(record["changes"][0]["before"][0]["pvid"], 1)
        self.assertEqual(record["changes"][0]["after"][0]["pvid"], 1)
        self.assertEqual(record["changes"][0]["after"][1]["pvid"], 1)
        self.assertEqual(result["config"]["ports"][2]["pvid"], 1)

    def test_rollback_does_not_revive_dropped_copies_or_bindings(self):
        config = base_config()
        new = other_ports_vlan2(config)
        events = [
            tframe(0, "p1", "00:00:00:00:00:01"),  # 副本入队 p2/p3/p4
            reload_cfg(1, new),                     # vlan1 副本被丢弃
            rollback(2),                           # 恢复 vlan1，不复活副本
            service(3, "p3", 5),                   # 队列空
        ]
        result = run(events, config=config)
        self.assertEqual(result["results"][3]["frames"], [])
        ports = {p["name"]: p for p in result["ports"]}
        # 丢弃仅发生一次（reload 时），rollback 不重复计数
        self.assertEqual(ports["p3"]["drop"], 1)

    def test_chained_reload_rollback_migration(self):
        config = base_config()
        v2 = other_ports_vlan2(config)
        events = [
            tframe(0, "p1", "00:00:00:00:00:0a"),
            reload_cfg(1, v2),          # p1 仍 vlan1：表项保留
            rollback(2),                # 恢复
            tframe(
                3, "p2", "00:00:00:00:00:0b", dst="00:00:00:00:00:0a"
            ),                           # vlan1 单播直达 p1
        ]
        result = run(events, config=config)
        self.assertEqual(result["results"][3]["action"], "unicast")


class PortsReloadWorkTest(unittest.TestCase):
    LIMITS_OK = ["1048576", "16777216", "100000", "16777216"]

    def test_migration_charge_boundary(self):
        # 无流量：初始 B+L+2U=1；重载 X+D+P+A+T+H+1=0+0+5+1+0+0+1=7；
        # 迁移实际有端口变化：P + 0 FDB + 0 绑定 + 0 副本 = 5；合计 13
        config = base_config()
        new = set_ports(config, vport("p1", "trunk", 1, [1, 2]))
        events = [reload_cfg(0, new)]
        ok = run(events, config=config, extra=self.LIMITS_OK + ["13"])
        self.assertTrue(ok["results"])
        run_work_limit(events, config=config, extra=self.LIMITS_OK + ["12"])

    def test_no_port_vlan_change_no_migration_charge(self):
        # 仅改 age：既有计费不变（迁移阶段零检查）
        config = base_config()
        new = copy.deepcopy(config)
        new["age"] = 50
        events = [reload_cfg(0, new)]
        # 初始 1 + 重载 7 = 8
        run(events, config=config, extra=self.LIMITS_OK + ["8"])
        run_work_limit(events, config=config, extra=self.LIMITS_OK + ["7"])

    def test_migration_charge_counts_runtime_items(self):
        # 一帧后：FDB 1 项、动态绑定 1、速率时间记录 1、p2/p3/p4 三个排队
        # 副本。帧计 X+3P+M+R+D+S+1=19；重载点 X=2、D=1、H=1，基础
        # X+D+P+A+T+1+H=11；迁移 P+FDB+绑定+副本=5+1+1+3=10；
        # 初始 1，累计 1+19+11+10=41
        config = base_config()
        new = set_ports(config, vport("p3", "access", 2))
        events = [
            tframe(0, "p1", "00:00:00:00:00:01"),
            reload_cfg(1, new),
        ]
        run(events, config=config, extra=self.LIMITS_OK + ["41"])
        run_work_limit(events, config=config, extra=self.LIMITS_OK + ["40"])

    def test_semantic_error_precedes_work_limit(self):
        # 帧后累计 20（等于 20 合法）；reload 为清理后仍超新 limit 的非法批，
        # 语义冲突在计费累加前抛 invalid_input，即使该事件总工作量必超上限
        config = base_config()
        config = set_ports(config, vport("p1", "trunk", 1, [1, 2]))
        new = set_ports(config, vport("p1", "trunk", 1, [1]))
        new["security"][0]["limit"] = 0
        events = [
            tframe(0, "p1", "00:00:00:00:00:0a", vlan=1),
            tframe(1, "p1", "00:00:00:00:00:0c", vlan=2),
            reload_cfg(2, new),
        ]
        code, out, err = run_cli(
            config, events, mode="reload-rollback",
            extra=self.LIMITS_OK + ["20"],
        )
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')


class PortsReloadRecordReplayTest(unittest.TestCase):
    def test_record_replay_byte_identical(self):
        config = base_config()
        v2 = other_ports_vlan2(config)
        trunk_p1 = set_ports(v2, vport("p1", "trunk", 1, [1, 2]))
        events = [
            tframe(0, "p1", "00:00:00:00:00:01"),
            reload_cfg(1, v2),
            tframe(2, "p3", "00:00:00:00:00:02"),
            reload_cfg(3, trunk_p1),
            rollback(4),
            service(5, "p2", 1),
        ]
        out, log = record(config, events)
        code, replayed, err = replay(log)
        self.assertEqual(code, 0, err)
        self.assertEqual(replayed, out)
        # LOG 内 ports 变更记录键序规范
        doc = json.loads(log)
        for idx in (1, 3):
            keys = [c["key"] for c in doc["records"][idx]["output"]["changes"]]
            self.assertIn("ports", keys)
            for change in doc["records"][idx]["output"]["changes"]:
                if change["key"] == "ports":
                    for side in ("before", "after"):
                        for port in change[side]:
                            self.assertEqual(
                                list(port),
                                [
                                    "allowed", "mode", "name", "pvid",
                                    "untagged", "up",
                                ],
                            )


if __name__ == "__main__":
    unittest.main()
