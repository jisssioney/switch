#!/usr/bin/env python3
"""reload/reload-rollback 端口 VLAN 属性热变更回归。

覆盖 mode/pvid/allowed/untagged 热变更：changes 固定次序（ports 位于
age 之后、storm 之前）、完整端口数组的规范键序、未标记帧归属与出站
标签即时生效、FDB/动态绑定/队列副本的确定迁移、迁移后 security
再校验、rollback LIFO 同一迁移且不复活动态项、非法变更与工作量计费。
仅用标准库；端到端驱动两个既有子命令。
"""

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SWITCH = os.path.join(HERE, "switch.py")

sys.path.insert(0, HERE)
import switch  # noqa: E402

from test_reload import base_config, frame, run_cli  # noqa: E402

LIMITS_OK = ["1048576", "16777216", "100000", "16777216"]


def hybrid_port(name, pvid=1, allowed=(1, 2), untagged=(1,), up=True):
    return {
        "name": name,
        "mode": "hybrid",
        "pvid": pvid,
        "allowed": list(allowed),
        "untagged": list(untagged),
        "up": up,
    }


def hybrid_config():
    """p1/p2/p3 hybrid 允许 vlan1/2，vlan1 去标签；p4/p5 仍 access 且
    与 LAG 成员一致（LAG 校验要求成员 VLAN 配置相同）。"""
    config = base_config()
    config["ports"] = [
        hybrid_port("p1"),
        hybrid_port("p2"),
        hybrid_port("p3"),
        {
            "name": "p4", "mode": "access", "pvid": 1,
            "allowed": [1], "untagged": [1], "up": True,
        },
        {
            "name": "p5", "mode": "access", "pvid": 1,
            "allowed": [1], "untagged": [1], "up": True,
        },
    ]
    return config


def tagged_frame(t, port, src, dst="ff:ff:ff:ff:ff:ff", vlan=1, priority=0):
    return {
        "t": t, "port": port, "src": src, "dst": dst,
        "vlan": vlan, "ethertype": 0x0800, "priority": priority,
    }


def service(t, port, count):
    return {"t": t, "port": port, "count": count}


def run(config, events, mode="reload", extra=()):
    code, out, err = run_cli(config, events, mode=mode, extra=extra)
    assert code == 0, (code, err.decode("utf-8"))
    return json.loads(out.decode("utf-8"))


def run_invalid(config, events, mode="reload"):
    code, out, err = run_cli(config, events, mode=mode)
    assert code == 4, (code, out)
    assert out == b"", out
    assert err == b'{"error":"invalid_input"}\n', err


class PortsChangeTest(unittest.TestCase):
    def test_ports_change_ordering_and_canonical_arrays(self):
        config = hybrid_config()
        new = copy.deepcopy(config)
        new["age"] = 50
        new["ports"][0]["untagged"] = []
        new["storm"]["hold"] = 20
        events = [{"t": 0, "config": new}]
        result = run(config, events)
        changes = result["results"][0]["changes"]
        # 固定次序：age、ports、storm、mirror、acl、qos、security
        self.assertEqual(
            [c["key"] for c in changes], ["age", "ports", "storm"]
        )
        ports_change = changes[1]
        self.assertEqual(list(ports_change), ["key", "before", "after"])
        self.assertEqual(len(ports_change["before"]), 5)
        self.assertEqual(len(ports_change["after"]), 5)
        # before/after 为完整端口数组，端口对象规范键序
        for port in ports_change["before"] + ports_change["after"]:
            self.assertEqual(
                list(port),
                ["allowed", "mode", "name", "pvid", "untagged", "up"],
            )
        self.assertEqual(ports_change["before"][0]["untagged"], [1])
        self.assertEqual(ports_change["after"][0]["untagged"], [])
        # 其余未变端口逐字节保留
        self.assertEqual(
            ports_change["before"][1:], ports_change["after"][1:]
        )
        # 末态 config 规范化
        self.assertEqual(result["config"]["ports"][0]["untagged"], [])

    def test_untagged_only_change_no_fdb_migration(self):
        # 只改 untagged：allowed 不变，FDB/动态项与队列副本全部保留
        config = hybrid_config()
        new = copy.deepcopy(config)
        new["ports"][2]["untagged"] = []  # p3 vlan1 出站改为带标签
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "config": new},
            tagged_frame(
                2, "p3", "00:00:00:00:00:09", dst="00:00:00:00:00:01"
            ),
        ]
        result = run(config, events)
        # FDB 保留：vlan1 单播直达 p1
        record = result["results"][2]
        self.assertEqual(record["action"], "unicast")
        self.assertEqual(record["ports"][0]["name"], "p1")
        # p3 的 untagged 不影响入帧；下一帧从 p3 泛洪的副本在本配置下
        # 以新出站标签发出（p2 untagged 仍 [1] -> None；p1 -> None）
        sec = {s["port"]: s for s in result["security"]}
        self.assertEqual(
            sec["p1"]["learned"],
            [{"vlan": 1, "mac": "00:00:00:00:00:01"}],
        )

    def test_pvid_and_egress_tag_effective_immediately(self):
        config = hybrid_config()
        new = copy.deepcopy(config)
        # p1：pvid 改为 2，vlan2 去标签，vlan1 改带标签
        new["ports"][0]["pvid"] = 2
        new["ports"][0]["untagged"] = [2]
        events = [
            {"t": 0, "config": new},
            # p1 未标记帧立即归属 vlan2：泛洪副本 vlan2，p2 仍 untagged
            # [1]，故 vlan2 在 p2 带标签
            frame(1, "p1", "00:00:00:00:00:01"),
        ]
        result = run(config, events)
        record = result["results"][1]
        self.assertEqual(record["action"], "flood")
        tags = {p["name"]: p["vlan"] for p in record["ports"]}
        self.assertNotIn("p1", tags)  # 入端口不回送
        self.assertEqual(tags["p2"], 2)
        self.assertEqual(tags["p3"], 2)
        # pvid 2 决定未标记帧学习在 vlan2
        sec = {s["port"]: s for s in result["security"]}
        self.assertEqual(
            sec["p1"]["learned"],
            [{"vlan": 2, "mac": "00:00:00:00:00:01"}],
        )

    def test_ingress_admission_uses_new_mode_immediately(self):
        config = hybrid_config()
        new = copy.deepcopy(config)
        new["ports"][0]["mode"] = "access"
        new["ports"][0]["allowed"] = [1]
        new["ports"][0]["untagged"] = [1]
        events = [
            {"t": 0, "config": new},
            tagged_frame(1, "p1", "00:00:00:00:00:01", vlan=2),
        ]
        result = run(config, events)
        # access 口立即拒绝带标签帧
        self.assertEqual(result["results"][1]["action"], "drop")

    def test_same_timestamp_subsequent_events_see_new_config(self):
        config = hybrid_config()
        new = copy.deepcopy(config)
        new["ports"][0]["pvid"] = 2
        new["ports"][0]["allowed"] = [1, 2]
        new["ports"][0]["untagged"] = [2]
        # 同一 t：reload 后按输入顺序，未标记帧立即归属新 pvid=2
        events = [
            {"t": 5, "config": new},
            frame(5, "p1", "00:00:00:00:00:01"),
        ]
        result = run(config, events)
        sec = {s["port"]: s for s in result["security"]}
        self.assertEqual(
            sec["p1"]["learned"],
            [{"vlan": 2, "mac": "00:00:00:00:00:01"}],
        )

    def test_allowed_change_prunes_fdb_and_refloods(self):
        config = hybrid_config()
        new = copy.deepcopy(config)
        new["ports"][0]["allowed"] = [2]
        new["ports"][0]["pvid"] = 2
        new["ports"][0]["untagged"] = [2]
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),  # FDB (1,..01)->p1
            {"t": 1, "config": new},
            # p1 不再允许 vlan1：FDB 项删除，单播查找未命中 -> 泛洪
            tagged_frame(
                2, "p3", "00:00:00:00:00:09", dst="00:00:00:00:00:01"
            ),
        ]
        result = run(config, events)
        self.assertEqual(result["results"][2]["action"], "flood")
        names = {p["name"] for p in result["results"][2]["ports"]}
        self.assertNotIn("p1", names)  # p1 不在 vlan1 泛洪集合

    def test_dynamic_binding_cleaned_when_vlan_removed(self):
        config = hybrid_config()
        new = copy.deepcopy(config)
        new["ports"][0]["allowed"] = [2]
        new["ports"][0]["pvid"] = 2
        new["ports"][0]["untagged"] = [2]
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),  # 动态绑定 (1,..01)->p1
            {"t": 1, "config": new},
            # 旧绑定已清除：同 MAC 自 p2 入 vlan1 可重新绑定，不违例
            tagged_frame(2, "p2", "00:00:00:00:00:01"),
        ]
        result = run(config, events)
        sec = {s["port"]: s for s in result["security"]}
        self.assertEqual(sec["p1"]["learned"], [])
        self.assertEqual(
            sec["p2"]["learned"],
            [{"vlan": 1, "mac": "00:00:00:00:00:01"}],
        )
        self.assertEqual(sec["p2"]["violations"], 0)

    def test_surviving_binding_conflicts_new_static_invalid(self):
        # p1 仍允许 vlan1：旧动态绑定保留，与新静态（归属 p2）冲突
        config = hybrid_config()
        new = copy.deepcopy(config)
        new["ports"][0]["untagged"] = []
        new["security"][1]["static"] = [
            {"mac": "00:00:00:00:00:01", "vlan": 1}
        ]
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "config": new},
        ]
        run_invalid(config, events)

    def test_cleaned_binding_allows_new_static(self):
        # p1 移除 vlan1：绑定被清理，同静态不再冲突
        config = hybrid_config()
        new = copy.deepcopy(config)
        new["ports"][0]["allowed"] = [2]
        new["ports"][0]["pvid"] = 2
        new["ports"][0]["untagged"] = [2]
        new["security"][1]["static"] = [
            {"mac": "00:00:00:00:00:01", "vlan": 1}
        ]
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "config": new},
        ]
        result = run(config, events)
        sec = {s["port"]: s for s in result["security"]}
        self.assertEqual(sec["p1"]["learned"], [])

    def test_queued_copy_dropped_with_existing_counters(self):
        config = hybrid_config()
        new = copy.deepcopy(config)
        # p2 移除 vlan1：p2 上排队的 vlan1 副本迁移时丢弃
        new["ports"][1]["allowed"] = [2]
        new["ports"][1]["pvid"] = 2
        new["ports"][1]["untagged"] = [2]
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),  # 泛洪副本入 p2/p3 队列
            {"t": 1, "config": new},
            service(2, "p3", 4),
        ]
        result = run(config, events)
        ports = {p["name"]: p for p in result["ports"]}
        self.assertEqual(ports["p2"]["drop"], 1)  # 迁移时丢弃一副本
        vlans = {v["vlan"]: v for v in result["vlans"]}
        self.assertEqual(vlans[1]["drop"], 1)
        # p3 合法副本保留并被服务（帧号 0）
        self.assertEqual(result["results"][2]["frames"], [0])

    def test_surviving_copy_keeps_tag_queue_id_position(self):
        config = hybrid_config()
        # 多优先级帧：priority 0 -> q0（map[0]=0），priority 3 -> q3
        new = copy.deepcopy(config)
        new["ports"][1]["untagged"] = []  # 仅出站标签语义变化，allowed 不变
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),  # q0, 帧 0
            tagged_frame(
                1, "p1", "00:00:00:00:00:02", priority=3
            ),  # q3, 帧 1
            {"t": 2, "config": new},
            service(3, "p2", 4),
        ]
        result = run(config, events)
        served = result["results"][3]
        # WRR 初始 q=3：先出帧 1（q3），再出帧 0（q0）；队列与帧号保留
        self.assertEqual(served["frames"], [1, 0])
        # 出站标签按入队时冻结值：配置变更不追溯，vlan1 仍输出 None
        self.assertEqual(served["mirrors"], [])

    def test_untagged_frozen_on_queued_copy(self):
        # allowed 不变、仅 untagged 变化：已排队副本保留原出站标签 None
        config = hybrid_config()
        new = copy.deepcopy(config)
        new["ports"][2]["untagged"] = []  # p3 vlan1 出站改带标签
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),  # 副本在 p3 冻结 vlan=None
            {"t": 1, "config": new},
            service(2, "p3", 1),
        ]
        result = run(config, events)
        # 出站结果不回显标签（service 仅 frames/mirrors），drop=0 即保留
        self.assertEqual(result["results"][2]["frames"], [0])
        ports = {p["name"]: p for p in result["ports"]}
        self.assertEqual(ports["p3"]["drop"], 0)

    def test_fdb_lag_entry_kept_if_any_member_allows_vlan(self):
        config = hybrid_config()
        # p4/p5 同属 LAG L1 且同为 access vlan1；让 p4 改 hybrid 加 vlan2
        # 会破坏 LAG 一致性校验，故改为两成员同时加入 vlan2
        new = copy.deepcopy(config)
        for index in (3, 4):
            new["ports"][index]["mode"] = "hybrid"
            new["ports"][index]["allowed"] = [1, 2]
            new["ports"][index]["untagged"] = [1]
        # 向 L1 学入一项：自 p4 的未标记帧按 pvid 归属 vlan1，学习口 L1
        events_learn = [
            frame(0, "p4", "00:00:00:00:00:aa"),
        ]
        events = events_learn + [
            {"t": 1, "config": new},
            # vlan1 项保留（两成员仍允许 vlan1）：单播命中 L1
            tagged_frame(
                2, "p1", "00:00:00:00:00:09", dst="00:00:00:00:00:aa"
            ),
        ]
        result = run(config, events)
        self.assertEqual(result["results"][2]["action"], "unicast")
        out = {p["name"] for p in result["results"][2]["ports"]}
        self.assertTrue(out <= {"p4", "p5"}, out)

    def test_stp_violation_and_shutdown_counts_unchanged(self):
        config = hybrid_config()
        config["security"][0]["limit"] = 1
        config["security"][0]["action"] = "shutdown"
        new = copy.deepcopy(config)
        new["ports"][0]["untagged"] = []
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            frame(0, "p1", "00:00:00:00:00:02"),  # 违例 -> shutdown
            {"t": 1, "config": new},
            frame(2, "p1", "00:00:00:00:00:03"),
        ]
        result = run(config, events)
        sec = {s["port"]: s for s in result["security"]}
        self.assertTrue(sec["p1"]["shutdown"])
        self.assertEqual(sec["p1"]["violations"], 1)
        self.assertEqual(result["results"][3]["action"], "drop")


class PortsImmutableTest(unittest.TestCase):
    def _check(self, mutate):
        config = hybrid_config()
        new = copy.deepcopy(config)
        if mutate == "name":
            new["ports"][0]["name"] = "q1"
        elif mutate == "up":
            new["ports"][0]["up"] = False
        elif mutate == "reorder":
            new["ports"][0], new["ports"][1] = (
                new["ports"][1], new["ports"][0]
            )
        elif mutate == "count-add":
            new["ports"].append(
                hybrid_port("p6", allowed=(1,), untagged=(1,))
            )
            new["security"].append(
                {"port": "p6", "limit": 2, "action": "drop", "static": []}
            )
        elif mutate == "count-drop":
            new["ports"] = new["ports"][1:]
            new["security"] = new["security"][1:]
        run_invalid(config, [{"t": 0, "config": new}])

    def test_name_up_order_count_immutable(self):
        for mutate in ("name", "up", "reorder", "count-add", "count-drop"):
            with self.subTest(mutate=mutate):
                self._check(mutate)

    def test_bad_vlan_values_still_validated(self):
        config = hybrid_config()
        new = copy.deepcopy(config)
        new["ports"][0]["allowed"] = [1, 9999]  # 非法 VLAN
        run_invalid(config, [{"t": 0, "config": new}])

    def test_lag_member_vlan_consistency_validated(self):
        # 仅 p4 热改为 hybrid：LAG 成员 VLAN 配置不再一致，整批无效
        config = hybrid_config()
        new = copy.deepcopy(config)
        new["ports"][3]["mode"] = "hybrid"
        new["ports"][3]["allowed"] = [1, 2]
        new["ports"][3]["untagged"] = [1]
        run_invalid(config, [{"t": 0, "config": new}])

    def test_ports_change_then_semantic_conflict_no_partial_output(self):
        config = hybrid_config()
        new = copy.deepcopy(config)
        new["ports"][0]["untagged"] = []
        new["security"][0]["limit"] = 0
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "config": new},  # 迁移后动态 1 > 新 limit 0
        ]
        run_invalid(config, events)


class PortsRollbackTest(unittest.TestCase):
    def test_rollback_restores_port_attrs_lifo(self):
        config = hybrid_config()
        new = copy.deepcopy(config)
        new["ports"][0]["pvid"] = 2
        new["ports"][0]["allowed"] = [1, 2]
        new["ports"][0]["untagged"] = [2]
        events = [
            {"t": 0, "config": new},
            {"t": 1, "rollback": True},
        ]
        result = run(config, events, mode="reload-rollback")
        changes = result["results"][1]["changes"]
        self.assertEqual([c["key"] for c in changes], ["ports"])
        self.assertEqual(changes[0]["before"][0]["pvid"], 2)
        self.assertEqual(changes[0]["after"][0]["pvid"], 1)
        self.assertEqual(result["config"]["ports"][0]["pvid"], 1)

    def test_rollback_migrates_again_without_revival(self):
        config = hybrid_config()
        new = copy.deepcopy(config)
        new["ports"][0]["allowed"] = [2]
        new["ports"][0]["pvid"] = 2
        new["ports"][0]["untagged"] = [2]
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),  # FDB/绑定 vlan1
            {"t": 1, "config": new},  # 清除 FDB/绑定；p2 副本入队后丢弃
            {"t": 2, "rollback": True},  # 恢复 vlan1，动态项不复活
            tagged_frame(
                3, "p3", "00:00:00:00:00:09", dst="00:00:00:00:00:01"
            ),
        ]
        result = run(config, events, mode="reload-rollback")
        # 回滚不复活 FDB：单播未命中 -> 泛洪
        self.assertEqual(result["results"][3]["action"], "flood")
        sec = {s["port"]: s for s in result["security"]}
        self.assertEqual(sec["p1"]["learned"], [])

    def test_rollback_conflict_invalid_whole_batch(self):
        # 放宽 allowed 后在 vlan2 形成绑定，rollback 恢复仅 vlan1 不冲突；
        # 改为 reload 移除 vlan2 且新静态占用清理后仍保留的 vlan1 绑定
        config = hybrid_config()
        new = copy.deepcopy(config)
        new["ports"][0]["untagged"] = []
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "config": new},
            {"t": 2, "rollback": True},  # 恢复 untagged [1]：无冲突
        ]
        result = run(config, events, mode="reload-rollback")
        self.assertEqual(result["results"][2]["action"], "rollback")
        # reload 放宽 limit 后绑定增多，rollback 恢复低 limit：迁移后保留
        # 的动态项仍超限，整批无效
        low = copy.deepcopy(config)
        low["security"][0]["limit"] = 1
        high = copy.deepcopy(low)
        high["security"][0]["limit"] = 3
        events3 = [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "config": high},
            frame(2, "p1", "00:00:00:00:00:02"),
            {"t": 3, "rollback": True},  # limit 恢复 1 < 动态 2
        ]
        code, out, err = run_cli(low, events3, mode="reload-rollback")
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')

    def test_rollback_queue_copy_dropped_and_not_revived(self):
        config = hybrid_config()
        new = copy.deepcopy(config)
        new["ports"][1]["allowed"] = [2]
        new["ports"][1]["pvid"] = 2
        new["ports"][1]["untagged"] = [2]
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),  # 副本入 p2/p3
            {"t": 1, "config": new},  # p2 vlan1 副本丢弃
            {"t": 2, "rollback": True},  # p2 恢复 vlan1 但副本不复活
            service(3, "p2", 2),  # 队列空
        ]
        result = run(config, events, mode="reload-rollback")
        ports = {p["name"]: p for p in result["ports"]}
        self.assertEqual(ports["p2"]["drop"], 1)
        self.assertEqual(result["results"][3]["frames"], [])
        # p3 副本仍在
        served = run(
            config,
            events[:3] + [service(3, "p3", 2)],
            mode="reload-rollback",
        )
        self.assertEqual(served["results"][3]["frames"], [0])


class PortsWorkTest(unittest.TestCase):
    """MAX_RELOAD_WORK：迁移阶段每检查一端口/FDB/绑定/副本各加一单位。"""

    def _threshold(self, config, events):
        (
            bridges, links, delay, bridge, ports, age, storm, lags, mirror,
            acl, qos, security,
        ) = switch.validate_security_config(config)
        link_ids = {link["id"] for link in links}
        evs, _ = switch.validate_reload_events(
            events, ports, link_ids, lags, config, allow_rollback=True
        )
        args = (
            bridges, links, delay, bridge, ports, age, storm, lags, acl,
            qos, security,
        )
        lo, hi = 0, 10 ** 6
        while lo < hi:
            mid = (lo + hi) // 2
            try:
                switch.reload_work(*args, evs, mid)
                hi = mid
            except switch.ReloadWorkLimit:
                lo = mid + 1
        return lo

    def test_untagged_change_no_migration_charge(self):
        config = hybrid_config()
        new = copy.deepcopy(config)
        new["ports"][0]["untagged"] = []
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            frame(0, "p1", "00:00:00:00:00:02"),
            {"t": 1, "config": new},
        ]
        age_only = copy.deepcopy(config)
        age_only["age"] = 50
        events_age = [
            frame(0, "p1", "00:00:00:00:00:01"),
            frame(0, "p1", "00:00:00:00:00:02"),
            {"t": 1, "config": age_only},
        ]
        self.assertEqual(
            self._threshold(config, events),
            self._threshold(config, events_age),
        )

    def test_empty_state_migration_charge_is_p_per_event(self):
        # 空状态：迁移仅检查 P 个端口；reload 与 rollback 各 +P=5
        config = hybrid_config()
        new = copy.deepcopy(config)
        new["ports"][0]["allowed"] = [2]
        new["ports"][0]["pvid"] = 2
        new["ports"][0]["untagged"] = [2]
        events = [{"t": 0, "config": new}, {"t": 1, "rollback": True}]
        # 非迁移基线（仅 age）总计 15；两次迁移各 +5 -> 25
        self.assertEqual(self._threshold(config, events), 25)

    def test_migration_charge_p_plus_f_plus_d_plus_n(self):
        config = hybrid_config()
        new = copy.deepcopy(config)
        new["ports"][0]["allowed"] = [2]
        new["ports"][0]["pvid"] = 2
        new["ports"][0]["untagged"] = [2]
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            frame(0, "p1", "00:00:00:00:00:02"),
            {"t": 1, "config": new},
        ]
        # 非迁移同形场景总计 57；迁移点 P5+F2+D2+N6=15 -> 72
        self.assertEqual(self._threshold(config, events), 72)

    def test_cli_equal_legal_first_exceed(self):
        config = hybrid_config()
        new = copy.deepcopy(config)
        new["ports"][0]["allowed"] = [2]
        new["ports"][0]["pvid"] = 2
        new["ports"][0]["untagged"] = [2]
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            frame(0, "p1", "00:00:00:00:00:02"),
            {"t": 1, "config": new},
            {"t": 2, "rollback": True},
        ]
        total = self._threshold(config, events)
        code, out, err = run_cli(
            config, events, mode="reload-rollback",
            extra=LIMITS_OK + [str(total)],
        )
        self.assertEqual(code, 0, err)
        code, out, err = run_cli(
            config, events, mode="reload-rollback",
            extra=LIMITS_OK + [str(total - 1)],
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"reload_work_limit"}\n')

    def test_semantic_error_precedes_work_limit(self):
        config = hybrid_config()
        new = copy.deepcopy(config)
        new["ports"][0]["untagged"] = []
        new["security"][1]["static"] = [
            {"mac": "00:00:00:00:00:01", "vlan": 1}
        ]
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "config": new},
        ]
        code, out, err = run_cli(
            config, events, extra=LIMITS_OK + ["1"]
        )
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')


class PortsRecordReplayTest(unittest.TestCase):
    """record/replay 对端口 VLAN 热变更逐字节可重放。"""

    def test_record_replay_byte_identical(self):
        config = hybrid_config()
        new = copy.deepcopy(config)
        new["ports"][0]["pvid"] = 2
        new["ports"][0]["allowed"] = [1, 2]
        new["ports"][0]["untagged"] = [2]
        new["ports"][1]["allowed"] = [2]
        new["ports"][1]["pvid"] = 2
        new["ports"][1]["untagged"] = [2]
        restored = copy.deepcopy(new)
        restored["ports"][1] = copy.deepcopy(config["ports"][1])
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "config": new},
            tagged_frame(2, "p3", "00:00:00:00:00:02"),
            {"t": 3, "config": restored},
            {"t": 4, "rollback": True},
            service(5, "p3", 4),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            cfg = os.path.join(tmp, "config.json")
            evt = os.path.join(tmp, "events.json")
            log_path = os.path.join(tmp, "reload.log")
            with open(cfg, "wb") as handle:
                handle.write(json.dumps(config).encode("utf-8"))
            with open(evt, "wb") as handle:
                handle.write(json.dumps(events).encode("utf-8"))
            rec = subprocess.run(
                [sys.executable, SWITCH, "record", cfg, evt, log_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(rec.returncode, 0, rec.stderr)
            rep = subprocess.run(
                [sys.executable, SWITCH, "replay", log_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(rep.returncode, 0, rep.stderr)
            self.assertEqual(rep.stdout, rec.stdout)


if __name__ == "__main__":
    unittest.main()
