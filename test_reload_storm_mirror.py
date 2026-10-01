#!/usr/bin/env python3
"""reload/reload-rollback 的 storm 与 mirror 热加载回归。

覆盖：storm/mirror 列入可变项，changes 按 age、storm、mirror、acl、qos、
security 顺序，before/after 为规范化 JSON；非法 storm/mirror、引用不
存在端口、镜像源目标约束、改动不可变项、空栈回滚均 invalid_input/4
且 stdout 空。storm 的 window/三类 limits/move_limit/hold 自下一帧
参与判定；缩短窗口暂无关记录保留，重新取较长窗口（含回滚）后恢复影响；
阈值低于现存计数可重载，后续帧在记录过期前按新阈值丢弃；重载不解除
既有状态。mirror 的 sources/target/direction 自下一帧决定副本，不
追溯已处理或已入队帧（出口镜像在入队时冻结）。每次重载/回滚计费再
加 H（当时保留的风暴时间记录与封锁项总数）。record/replay 逐字节一致。
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
import switch  # noqa: E402

from test_reload import base_config, frame, run_cli  # noqa: E402
from test_record import record, replay  # noqa: E402


SRC = "00:00:00:00:00:01"


def service(t, port, count=10):
    return {"t": t, "port": port, "count": count}


def run(events, config=None, mode="reload-rollback"):
    config = config if config is not None else base_config()
    code, out, err = run_cli(config, events, mode=mode)
    assert code == 0, (code, err.decode("utf-8"))
    return json.loads(out.decode("utf-8"))


def run_invalid(events, config=None, mode="reload-rollback"):
    config = config if config is not None else base_config()
    code, out, err = run_cli(config, events, mode=mode)
    assert code == 4, (code, out, err)
    assert out == b"", out
    assert err == b'{"error":"invalid_input"}\n', err


def with_storm(config, **fields):
    new = copy.deepcopy(config)
    new["storm"].update(fields)
    return new


def with_mirror(config, **fields):
    new = copy.deepcopy(config)
    new["mirror"].update(fields)
    return new


class ChangesOrderTest(unittest.TestCase):
    def test_storm_mirror_in_changes_order(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["age"] = 50
        new["storm"]["hold"] = 20
        new["mirror"]["direction"] = "ingress"
        new["acl"][0]["action"] = "drop"
        new["qos"]["cap"] = 500
        new["security"][0]["limit"] = 9
        result = run([{"t": 0, "config": new}], config)
        keys = [c["key"] for c in result["results"][0]["changes"]]
        self.assertEqual(
            keys, ["age", "storm", "mirror", "acl", "qos", "security"]
        )

    def test_canonical_before_after(self):
        config = base_config()
        new = with_storm(config, hold=20)
        result = run([{"t": 0, "config": new}], config)
        change = result["results"][0]["changes"][0]
        self.assertEqual(change["key"], "storm")
        self.assertEqual(list(change), ["key", "before", "after"])
        self.assertEqual(
            list(change["before"]),
            ["hold", "limits", "move_limit", "window"],
        )
        self.assertEqual(
            list(change["before"]["limits"]),
            ["broadcast", "multicast", "unknown"],
        )
        self.assertEqual(change["before"]["hold"], 10)
        self.assertEqual(change["after"]["hold"], 20)

    def test_plain_reload_accepts_storm_mirror(self):
        config = base_config()
        new = with_mirror(with_storm(config, window=20), direction="ingress")
        result = run([{"t": 0, "config": new}], config, mode="reload")
        self.assertEqual(
            [c["key"] for c in result["results"][0]["changes"]],
            ["storm", "mirror"],
        )

    def test_immutable_still_rejected(self):
        config = base_config()
        for field, value in (
            ("delay", 2),
            ("bridge", "b9"),
        ):
            new = copy.deepcopy(config)
            new[field] = value
            run_invalid([{"t": 0, "config": new}], config)
        new = copy.deepcopy(config)
        new["lags"][0]["name"] = "L9"  # lags 嵌套改动亦拒绝
        run_invalid([{"t": 0, "config": new}], config)


class InvalidConfigTest(unittest.TestCase):
    def test_bad_storm(self):
        for fields in (
            {"window": 0},
            {"move_limit": -1},
            {"hold": 0},
        ):
            new = with_storm(base_config(), **fields)
            run_invalid([{"t": 0, "config": new}])
        bad_limits = copy.deepcopy(base_config())
        bad_limits["storm"]["limits"] = {
            "broadcast": 0, "multicast": 5, "unknown": 5
        }
        run_invalid([{"t": 0, "config": bad_limits}])

    def test_bad_mirror_ports_and_constraints(self):
        config = base_config()
        new = with_mirror(config, target="px")  # 不存在的目标口
        run_invalid([{"t": 0, "config": new}])
        new = with_mirror(config, sources=["px"])  # 不存在的源口
        run_invalid([{"t": 0, "config": new}])
        new = with_mirror(config, target="p4")  # 目标口为 LAG 成员
        run_invalid([{"t": 0, "config": new}])
        new = with_mirror(config, sources=["p2"])  # target 落入 sources
        run_invalid([{"t": 0, "config": new}])
        new = with_mirror(config, direction="sideways")  # 非法方向
        run_invalid([{"t": 0, "config": new}])

    def test_empty_stack_rollback(self):
        run_invalid([{"t": 0, "rollback": True}])


class StormReloadTest(unittest.TestCase):
    def test_threshold_below_count_is_legal_and_drops_next_frames(self):
        config = base_config()
        low = with_storm(
            config,
            limits={"broadcast": 2, "multicast": 100, "unknown": 100},
        )
        events = [
            frame(0, "p1", SRC),
            frame(1, "p1", SRC),
            frame(2, "p1", SRC),
            {"t": 3, "config": low},
            frame(4, "p1", SRC),  # window=10 内已有 3 条 ≥ 新阈值 2：丢弃
        ]
        result = run(events, config)
        self.assertEqual(
            [r["action"] for r in result["results"]],
            ["flood", "flood", "flood", "reload", "drop"],
        )

    def test_records_expire_under_new_threshold(self):
        config = base_config()
        low = with_storm(
            config,
            limits={"broadcast": 2, "multicast": 100, "unknown": 100},
        )
        # t=0,1,2 的记录在 window=10 下分别于 t=10,11,12 过期；t=13 放行
        events = [
            frame(0, "p1", SRC),
            frame(1, "p1", SRC),
            frame(2, "p1", SRC),
            {"t": 3, "config": low},
            frame(4, "p1", SRC),
            frame(13, "p1", SRC),
        ]
        result = run(events, config)
        self.assertEqual(result["results"][5]["action"], "flood")

    def test_shrink_window_then_long_window_recovers_influence(self):
        # 初始 window=100、阈值 100：三条放行并保留；切到 window=1 后
        # 下一帧当前窗口记录为 0 而放行（记录未清除）；再切回
        # window=100、阈值 2 时，四条保留记录仍在窗口内 → 丢弃
        config = base_config()
        short = with_storm(config, window=1)
        long_low = with_storm(
            config,
            window=100,
            limits={"broadcast": 2, "multicast": 2, "unknown": 2},
        )
        events = [
            frame(0, "p1", SRC),
            frame(1, "p1", SRC),
            frame(2, "p1", SRC),
            {"t": 3, "config": short},
            frame(4, "p1", SRC),      # 短窗口：暂无关记录不计，放行
            {"t": 5, "config": long_low},
            frame(6, "p1", SRC),      # 长窗口恢复影响：4 条 ≥ 2，丢弃
        ]
        result = run(events, config)
        actions = [r["action"] for r in result["results"]]
        self.assertEqual(actions[4], "flood")
        self.assertEqual(actions[6], "drop")

    def test_rollback_restores_window_and_retained_records(self):
        config = base_config()
        low = with_storm(
            config,
            limits={"broadcast": 2, "multicast": 100, "unknown": 100},
        )
        short_low = with_storm(low, window=1)
        # window=100 阈值 100 三放行；reload 到 window=1 阈值 2：下一帧
        # 当前窗口无记录放行；rollback 回 window=100 阈值 100：保留记录
        # 仍在窗口内（阈值高，放行），验证记录未随短窗口被清除
        events = [
            frame(0, "p1", SRC),
            frame(1, "p1", SRC),
            frame(2, "p1", SRC),
            {"t": 3, "config": short_low},
            frame(4, "p1", SRC),
            {"t": 5, "rollback": True},
            frame(6, "p1", SRC),
        ]
        result = run(events, config)
        actions = [r["action"] for r in result["results"]]
        self.assertEqual(actions[4], "flood")
        self.assertEqual(actions[5], "rollback")
        self.assertEqual(actions[6], "flood")
        rollback_change = result["results"][5]["changes"]
        self.assertTrue(any(c["key"] == "storm" for c in rollback_change))

    def test_window_params_apply_from_next_frame_same_timestamp(self):
        config = base_config()
        low = with_storm(
            config,
            limits={"broadcast": 1, "multicast": 100, "unknown": 100},
        )
        # 首帧阈值 100 放行；同 t 重载后下一帧（同时间戳）按阈值 1 丢弃
        events = [
            frame(5, "p1", SRC),
            {"t": 5, "config": low},
            frame(5, "p1", SRC),
        ]
        result = run(events, config)
        self.assertEqual(
            [r["action"] for r in result["results"]],
            ["flood", "reload", "drop"],
        )


class MirrorReloadTest(unittest.TestCase):
    def test_ingress_target_from_next_frame(self):
        config = base_config()  # sources=[p1] target=p2 direction=both
        new = with_mirror(config, target="p3", direction="ingress")
        events = [
            frame(0, "p1", SRC),
            {"t": 1, "config": new},
            frame(2, "p1", "00:00:00:00:00:09"),
        ]
        result = run(events, config)
        self.assertEqual(result["results"][0]["mirrors"][0]["name"], "p2")
        self.assertEqual(result["results"][2]["mirrors"][0]["name"], "p3")

    def test_egress_mirror_frozen_at_enqueue(self):
        # 帧自 p3 入（初始非 source），泛洪在 source 口 p1 入队，入队时
        # 冻结出口镜像到 p2；随后 reload 移除 p1 源并改为 ingress，服务
        # p1 时已入队帧仍产出到 p2 的出口副本（不追溯）
        config = base_config()
        new = with_mirror(config, sources=["p3"], direction="ingress")
        events = [
            frame(0, "p3", "00:00:00:00:00:aa"),
            {"t": 1, "config": new},
            frame(2, "p3", "00:00:00:00:00:bb"),
            service(3, "p1"),
        ]
        result = run(events, config)
        self.assertEqual(result["results"][0]["mirrors"], [])
        self.assertEqual(
            [m["name"] for m in result["results"][2]["mirrors"]], ["p2"]
        )
        egress = [
            m for m in result["results"][3]["mirrors"]
            if m["direction"] == "egress"
        ]
        self.assertEqual([m["name"] for m in egress], ["p2"])

    def test_sources_removal_not_retroactive_to_new_frames(self):
        config = base_config()
        new = with_mirror(config, sources=["p3"], direction="egress")
        events = [
            frame(0, "p1", SRC),
            {"t": 1, "config": new},
            frame(2, "p1", "00:00:00:00:00:09"),  # p1 不再是源：无入口副本
        ]
        result = run(events, config)
        self.assertEqual(result["results"][2]["mirrors"], [])


def _exact_work(config, events):
    """reload_work 的最小合法上限（即精确工作量），二分求得。"""
    parsed = switch.validate_security_config(config)
    (
        bridges, links, delay, bridge, ports, age, storm, lags, _mirror,
        acl, qos, security,
    ) = parsed
    link_ids = {link["id"] for link in links}
    reload_events, _ = switch.validate_reload_events(
        events, ports, link_ids, lags, config, allow_rollback=True
    )
    args = (bridges, links, delay, bridge, ports, age, storm, lags, acl,
            qos, security, reload_events)

    def over(limit):
        try:
            switch.reload_work(*args, limit)
            return False
        except switch.ReloadWorkLimit:
            return True

    lo, hi = 0, 1
    while over(hi):
        hi *= 2
    while lo < hi:
        mid = (lo + hi) // 2
        if over(mid):
            lo = mid + 1
        else:
            hi = mid
    return lo


class HBillingTest(unittest.TestCase):
    LIMITS_OK = ["1048576", "16777216", "100000", "16777216"]

    def test_h_adds_retained_storm_records(self):
        config = base_config()
        age_only = copy.deepcopy(config)
        age_only["age"] = 50
        storm_change = with_storm(config, hold=20)
        # 仅 age 变化与仅 storm 变化，A/T/P 等项相同；差额即 H（重载点
        # 保留的风暴速率记录数）
        pre = [frame(t, "p1", SRC) for t in range(6)]
        w_age = _exact_work(config, pre + [{"t": 6, "config": age_only}])
        w_storm = _exact_work(config, pre + [{"t": 6, "config": storm_change}])
        self.assertEqual(w_storm - w_age, 0)  # H 与变更键无关，两者相同
        # 与无任何前置帧相比，H 随保留记录数增长
        w_empty = _exact_work(config, [{"t": 6, "config": age_only}])
        self.assertGreater(w_age, w_empty)

    def test_equal_limit_legal_first_exceed(self):
        config = base_config()
        events = [
            frame(0, "p1", SRC),
            {"t": 1, "config": with_storm(config, window=20)},
            {"t": 2, "rollback": True},
        ]
        exact = _exact_work(config, events)
        ok = run_cli(
            config, events, mode="reload-rollback",
            extra=self.LIMITS_OK + [str(exact)],
        )
        self.assertEqual(ok[0], 0)
        bad = run_cli(
            config, events, mode="reload-rollback",
            extra=self.LIMITS_OK + [str(exact - 1)],
        )
        self.assertEqual(bad[0], 5)
        self.assertEqual(bad[1], b"")
        self.assertEqual(bad[2], b'{"error":"reload_work_limit"}\n')


class RecordReplayStormMirrorTest(unittest.TestCase):
    def test_record_replay_roundtrip_byte_identical(self):
        config = base_config()
        first = with_storm(config, window=20, hold=5)
        second = with_mirror(
            first, sources=["p1", "p3"], direction="egress"
        )
        events = [
            {"t": 0, "config": first},
            {"t": 1, "config": second},
            {"t": 2, "rollback": True},
            frame(3, "p1", "00:00:00:00:00:01"),
            frame(4, "p3", "00:00:00:00:00:02"),
        ]
        out, log = record(config, events)
        doc = json.loads(log.decode("utf-8"))
        self.assertEqual(list(doc), ["schema", "config", "records", "sha256"])
        code, replayed, err = replay(log)
        self.assertEqual(code, 0, err)
        self.assertEqual(replayed, out)  # replay 与 record stdout 逐字节一致


if __name__ == "__main__":
    unittest.main()
