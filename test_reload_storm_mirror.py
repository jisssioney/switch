#!/usr/bin/env python3
"""reload/reload-rollback 把 storm 与 mirror 纳入可变范围的回归。

覆盖：
- changes 按 age、storm、mirror、acl、qos、security 顺序输出，before/after
  为规范化 JSON；非法 storm/mirror、未知端口、源目标约束均 invalid_input；
- storm 的 window/limits/move_limit/hold 自下一帧参与判定；缩短窗口暂存
  记录，回滚到较长窗口后恢复影响，自然过期不复活；阈值低于现存计数可
  重载，记录过期前对应帧按新阈值丢弃；重载与回滚不解除已有封锁；
- mirror 的 sources/target/direction 自下一帧决定镜像副本，不追溯已
  入队帧（egress 决定冻结于入队时），同一时间戳后续事件使用新配置；
- 回滚只恢复栈顶配置；record/replay 与 reload-rollback 逐字节一致。

仅用标准库；端到端驱动 `python switch.py reload[-rollback]`。
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

from test_reload import base_config, run_cli  # noqa: E402
from test_record import record  # noqa: E402


def bcast(t, port="p1", src=None):
    src = src or "00:00:00:00:00:%02x" % (t + 1)
    return {
        "t": t, "port": port, "src": src, "dst": "ff:ff:ff:ff:ff:ff",
        "vlan": None, "ethertype": 0x0800, "priority": 0,
    }


def service(t, port, count):
    return {"t": t, "port": port, "count": count}


def storm_config(window=10, broadcast=2, move_limit=100, hold=10):
    config = base_config()
    config["storm"] = {
        "window": window,
        "limits": {"broadcast": broadcast, "multicast": 100,
                   "unknown": 100},
        "move_limit": move_limit,
        "hold": hold,
    }
    for entry in config["security"]:
        entry["limit"] = 100
    return config


def run(events, config, mode="reload-rollback"):
    code, out, err = run_cli(config, events, mode=mode)
    assert code == 0, (code, err.decode())
    return json.loads(out.decode())


def run_invalid(events, config, mode="reload-rollback"):
    code, out, err = run_cli(config, events, mode=mode)
    assert code == 4, (code, out)
    assert out == b"", out
    assert err == b'{"error":"invalid_input"}\n', err


class StormChangesTest(unittest.TestCase):
    def test_storm_change_listed_canonical(self):
        config = storm_config()
        new = copy.deepcopy(config)
        new["storm"]["hold"] = 20
        result = run([{"t": 0, "config": new}], config)
        change = result["results"][0]["changes"][0]
        self.assertEqual(
            list(result["results"][0]["changes"]),
            [{
                "key": "storm",
                "before": {"hold": 10,
                           "limits": {"broadcast": 2, "multicast": 100,
                                      "unknown": 100},
                           "move_limit": 100, "window": 10},
                "after": {"hold": 20,
                          "limits": {"broadcast": 2, "multicast": 100,
                                     "unknown": 100},
                          "move_limit": 100, "window": 10},
            }],
        )
        self.assertEqual(list(change["before"]),
                         ["hold", "limits", "move_limit", "window"])
        self.assertEqual(result["config"]["storm"]["hold"], 20)

    def test_changes_full_order(self):
        config = storm_config()
        new = copy.deepcopy(config)
        new["age"] = 50
        new["storm"]["hold"] = 20
        new["mirror"]["direction"] = "ingress"
        new["acl"] = [{
            "src": None, "dst": "ff:ff:ff:ff:ff:ff", "vlan": None,
            "ethertype": None, "priority": None, "action": "drop",
            "to_vlan": None,
        }]
        new["qos"]["cap"] = 500
        new["security"][0]["limit"] = 5
        result = run([{"t": 0, "config": new}], config)
        self.assertEqual(
            [c["key"] for c in result["results"][0]["changes"]],
            ["age", "storm", "mirror", "acl", "qos", "security"],
        )

    def test_bad_storm_rejected(self):
        config = storm_config()
        for mut in (
            lambda c: c["storm"].__setitem__("window", 0),
            lambda c: c["storm"]["limits"].__setitem__("broadcast", 0),
            lambda c: c["storm"].__setitem__("move_limit", -1),
            lambda c: c["storm"].__setitem__("hold", True),
        ):
            new = copy.deepcopy(config)
            mut(new)
            with self.subTest():
                run_invalid([{"t": 0, "config": new}], config)

    def test_threshold_lower_than_count_allowed_then_drops(self):
        config = storm_config(broadcast=2)
        new = copy.deepcopy(config)
        new["storm"]["limits"]["broadcast"] = 1
        events = [
            bcast(0), bcast(1), {"t": 2, "config": new}, bcast(3), bcast(4),
        ]
        actions = [r["action"] for r in run(events, config)["results"]]
        self.assertEqual(
            actions, ["flood", "flood", "reload", "drop", "drop"]
        )
        # 记录过期后按新阈值：一帧放行、下一帧丢弃
        events = [
            bcast(0), bcast(1), {"t": 2, "config": new},
            bcast(12), bcast(13),
        ]
        actions = [r["action"] for r in run(events, config)["results"]]
        self.assertEqual(actions[3:], ["flood", "drop"])

    def test_window_shorten_and_rollback_restores_records(self):
        config = storm_config(window=10, broadcast=2)
        short = copy.deepcopy(config)
        short["storm"]["window"] = 3
        events = [
            bcast(0), bcast(1), bcast(2),          # 第 3 帧达阈值被丢
            {"t": 3, "config": short},
            bcast(4),                               # 短窗口内旧记录无关
            {"t": 5, "rollback": True},             # 恢复 window=10
            bcast(6),                               # 保留记录重新计入
        ]
        actions = [r["action"] for r in
                   run(events, config)["results"]]
        self.assertEqual(
            actions,
            ["flood", "flood", "drop", "reload", "flood", "rollback",
             "drop"],
        )

    def test_naturally_expired_records_do_not_revive(self):
        config = storm_config(window=10, broadcast=2)
        short = copy.deepcopy(config)
        short["storm"]["window"] = 3
        events = [
            bcast(0), bcast(1), bcast(2),
            {"t": 3, "config": short},
            bcast(20),
            {"t": 21, "rollback": True},
            bcast(22), bcast(23),
        ]
        actions = [r["action"] for r in
                   run(events, config)["results"]]
        # window=10 也覆盖不到 t0..2：t22 首帧放行，t23 第二帧达新阈值丢
        self.assertEqual(actions[6:], ["flood", "drop"])

    def test_new_limit_applies_same_timestamp_next_event(self):
        config = storm_config(broadcast=2)
        new = copy.deepcopy(config)
        new["storm"]["limits"]["broadcast"] = 1
        events = [bcast(0), bcast(1), {"t": 2, "config": new}, bcast(2)]
        actions = [r["action"] for r in
                   run(events, config, mode="reload")["results"]]
        self.assertEqual(actions[-1], "drop")

    def test_hold_change_accepted_and_state_retained(self):
        # hold 只作用于 MAC 迁移封锁；reload 改 hold 本身合法，风暴时间
        # 记录与封锁集合在热加载时原样保留（计数不因 reload 清零）
        config = storm_config(move_limit=50, hold=10)
        new = copy.deepcopy(config)
        new["storm"]["hold"] = 100
        events = [
            bcast(0), bcast(1),
            {"t": 2, "config": new},
            bcast(3),                         # 已有记录继续参与判定
        ]
        result = run(events, config, mode="reload")
        self.assertEqual(result["results"][2]["action"], "reload")
        # 三帧广播累计计数不因 reload 重置：threshold=2 下第 3 帧仍丢弃
        self.assertEqual(result["results"][3]["action"], "drop")


class MirrorChangesTest(unittest.TestCase):
    def config(self):
        config = base_config()
        config["mirror"] = {
            "sources": ["p1", "p3"], "target": "p2", "direction": "both",
        }
        for entry in config["security"]:
            entry["limit"] = 100
        return config

    def test_mirror_change_listed(self):
        config = self.config()
        new = copy.deepcopy(config)
        new["mirror"]["direction"] = "ingress"
        result = run([{"t": 0, "config": new}], config)
        self.assertEqual(
            [c["key"] for c in result["results"][0]["changes"]], ["mirror"]
        )
        self.assertEqual(result["config"]["mirror"]["direction"], "ingress")

    def test_bad_mirror_rejected(self):
        config = self.config()
        cases = []
        new = copy.deepcopy(config)
        new["mirror"]["target"] = "nope"
        cases.append(new)
        new = copy.deepcopy(config)
        new["mirror"]["target"] = "p1"  # target 不得在 sources
        cases.append(new)
        new = copy.deepcopy(config)
        new["mirror"]["target"] = "p4"  # target 不得为 LAG 成员
        cases.append(new)
        new = copy.deepcopy(config)
        new["mirror"]["sources"] = ["nope"]
        cases.append(new)
        new = copy.deepcopy(config)
        new["mirror"]["direction"] = "sideways"
        cases.append(new)
        new = copy.deepcopy(config)
        new["mirror"]["sources"] = []
        cases.append(new)
        for bad in cases:
            with self.subTest(target=bad["mirror"].get("target")):
                run_invalid([{"t": 0, "config": bad}], config)

    def test_egress_decision_frozen_at_enqueue_target(self):
        config = self.config()
        new = copy.deepcopy(config)
        new["mirror"]["target"] = "p3"
        new["mirror"]["sources"] = ["p1"]
        events = [
            bcast(0, "p1"),                # 帧入 p3 队，egress 决定冻结为 p2
            {"t": 1, "config": new},
            service(2, "p3", 10),          # 已入队帧的副本仍发 p2
            bcast(3, "p1"),                # 下一帧入站副本发新 target p3
        ]
        results = run(events, config)["results"]
        self.assertEqual([m["name"] for m in results[2]["mirrors"]], ["p2"])
        self.assertEqual([m["name"] for m in results[3]["mirrors"]], ["p3"])

    def test_egress_decision_frozen_direction_and_source(self):
        config = self.config()
        new = copy.deepcopy(config)
        new["mirror"]["direction"] = "ingress"
        events = [
            bcast(0, "p1"),
            {"t": 1, "config": new},
            service(2, "p3", 10),          # 旧帧 egress 副本仍产生
            bcast(3, "p1"),                # 新帧仅 ingress
            service(4, "p3", 10),          # 新帧无 egress 副本
        ]
        results = run(events, config)["results"]
        self.assertEqual(
            [m["direction"] for m in results[2]["mirrors"]], ["egress"]
        )
        self.assertEqual(
            [m["direction"] for m in results[3]["mirrors"]], ["ingress"]
        )
        self.assertEqual(results[4]["mirrors"], [])

        new = copy.deepcopy(config)
        new["mirror"]["sources"] = ["p1"]
        events = [
            bcast(0, "p1"),
            {"t": 1, "config": new},
            service(2, "p3", 10),          # 冻结时 p3 仍为 source：有副本
            bcast(3, "p1"),
            service(4, "p3", 10),          # 新帧出口 p3 已非 source：无副本
        ]
        results = run(events, config)["results"]
        self.assertEqual(
            [m["source"] for m in results[2]["mirrors"]], ["p3"]
        )
        self.assertEqual(results[4]["mirrors"], [])

    def test_rollback_restores_mirror(self):
        config = self.config()
        new = copy.deepcopy(config)
        new["mirror"]["direction"] = "ingress"
        events = [
            {"t": 0, "config": new},
            {"t": 1, "rollback": True},
            bcast(2, "p1"),
            service(3, "p3", 10),
        ]
        results = run(events, config)["results"]
        self.assertEqual(
            [c["key"] for c in results[1]["changes"]], ["mirror"]
        )
        # 恢复 both：p3 出口帧产生 egress 副本
        self.assertEqual(
            [m["direction"] for m in results[3]["mirrors"]], ["egress"]
        )

    def test_same_timestamp_later_event_uses_new_mirror(self):
        config = self.config()
        new = copy.deepcopy(config)
        new["mirror"]["direction"] = "ingress"
        events = [{"t": 1, "config": new}, bcast(1, "p1")]
        results = run(events, config, mode="reload")["results"]
        self.assertEqual(
            [m["direction"] for m in results[1]["mirrors"]], ["ingress"]
        )


class RollbackStackTest(unittest.TestCase):
    def test_rollback_restores_storm_stack_top(self):
        config = storm_config(window=10)
        first = copy.deepcopy(config)
        first["storm"]["window"] = 3
        second = copy.deepcopy(first)
        second["storm"]["window"] = 2
        events = [
            {"t": 0, "config": first},
            {"t": 1, "config": second},
            {"t": 2, "rollback": True},   # 回到 window=3
            {"t": 3, "rollback": True},   # 回到 window=10
        ]
        result = run(events, config)
        self.assertEqual(result["config"]["storm"]["window"], 10)
        self.assertEqual(
            [c["after"]["window"] for c in result["results"][2]["changes"]],
            [3],
        )
        self.assertEqual(
            [c["after"]["window"] for c in result["results"][3]["changes"]],
            [10],
        )

    def test_empty_stack_invalid(self):
        run_invalid([{"t": 0, "rollback": True}], storm_config())


class RecordReplayTest(unittest.TestCase):
    def test_record_matches_reload_rollback_byte_for_byte(self):
        config = storm_config(window=10, broadcast=2)
        config["mirror"] = {
            "sources": ["p1", "p3"], "target": "p2", "direction": "both",
        }
        storm_new = copy.deepcopy(config)
        storm_new["storm"]["window"] = 3
        storm_new["storm"]["limits"]["broadcast"] = 1
        mirror_new = copy.deepcopy(storm_new)
        mirror_new["mirror"]["direction"] = "ingress"
        events = [
            bcast(0), bcast(1),
            {"t": 2, "config": storm_new},
            bcast(4),
            {"t": 5, "config": mirror_new},
            service(6, "p3", 5),
            {"t": 8, "rollback": True},
            bcast(9),
            {"t": 10, "rollback": True},
            service(11, "p3", 5),
        ]
        out, log = record(config, events)
        code, rel_out, err = run_cli(config, events, mode="reload-rollback")
        self.assertEqual(code, 0, err)
        self.assertEqual(out, rel_out)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "in.log")
            with open(path, "wb") as handle:
                handle.write(log)
            proc = subprocess.run(
                [sys.executable, SWITCH, "replay", path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, out)
        # 重复执行逐字节一致
        out2, log2 = record(config, events)
        self.assertEqual(out2, out)
        self.assertEqual(log2, log)


if __name__ == "__main__":
    unittest.main()
