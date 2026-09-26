#!/usr/bin/env python3
"""reload/reload-rollback 的 qos 热加载与回滚回归。

覆盖：qos 列入可变项与差异序；取配置后出口四队列按 tail/weighted 边界
校验（等于合法、超出 invalid_input/4、stdout 空且原子）；已排队帧保留
帧号/VLAN/队列号，不重分类、不丢弃、不改计数；新 map/cap/drop 自下一
帧生效；qos 变化时各端口 WRR 重置为 q=3,rem=weights[3]，否则保留；
rollback 按 LIFO 恢复 qos；qos 变化分支工作量另计 N+5；record/replay
同步且 LOG 结构不变。
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
from test_record import record, replay  # noqa: E402


def uframe(t, prio, src="00:00:00:00:00:01", dst="00:00:00:00:00:fe",
           vlan=None):
    return {
        "t": t,
        "port": "p1",
        "src": src,
        "dst": dst,
        "vlan": vlan,
        "ethertype": 0x0800,
        "priority": prio,
    }


def service(t, port, count):
    return {"t": t, "port": port, "count": count}


def run(events, config=None, mode="reload-rollback"):
    config = config if config is not None else base_config()
    code, out, err = run_cli(config, events, mode=mode)
    assert code == 0, (code, err.decode("utf-8"))
    return json.loads(out.decode("utf-8"))


def run_invalid(events, config=None, mode="reload-rollback"):
    config = config if config is not None else base_config()
    code, out, err = run_cli(config, events, mode=mode)
    assert code == 4, (code, out)
    assert out == b"", out
    assert err == b'{"error":"invalid_input"}\n', err


def qos_config(weights=(1, 1, 1, 1), cap=1000, mode="wrr", drop="tail",
               qos_map=(0, 1, 2, 3, 0, 1, 2, 3)):
    config = base_config()
    config["qos"] = {
        "map": list(qos_map),
        "cap": cap,
        "mode": mode,
        "weights": list(weights),
        "drop": drop,
    }
    # 放宽端口安全上界，避免多源泛洪被安全模块在入口丢弃
    for entry in config["security"]:
        entry["limit"] = 100
    return config


def with_qos(config, **changes):
    new = copy.deepcopy(config)
    new["qos"].update(changes)
    return new


class QosChangesTest(unittest.TestCase):
    def test_qos_listed_in_changes_order(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["age"] = 50
        new["qos"]["cap"] = 500
        new["security"][0]["limit"] = 5
        result = run([frame(0, "p1", "00:00:00:00:00:01"),
                      {"t": 1, "config": new}])
        record = result["results"][1]
        self.assertEqual(list(record), ["t", "action", "changes"])
        self.assertEqual(
            [c["key"] for c in record["changes"]],
            ["age", "qos", "security"],
        )
        for change in record["changes"]:
            self.assertEqual(list(change), ["key", "before", "after"])
        qos_change = record["changes"][1]
        self.assertEqual(qos_change["before"]["cap"], 1000)
        self.assertEqual(qos_change["after"]["cap"], 500)
        # before/after qos 对象键按码点升序规范化
        self.assertEqual(
            list(qos_change["after"]),
            ["cap", "drop", "map", "mode", "weights"],
        )
        # 末态 config 为规范化的新配置
        self.assertEqual(result["config"]["qos"]["cap"], 500)
        self.assertEqual(list(result["config"]), sorted(result["config"]))

    def test_no_qos_change_not_listed(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["age"] = 50
        result = run([{"t": 0, "config": new}])
        self.assertEqual(
            [c["key"] for c in result["results"][0]["changes"]], ["age"]
        )

    def test_plain_reload_entry_also_takes_qos(self):
        config = base_config()
        new = with_qos(config, cap=500)
        result = run([{"t": 0, "config": new}], mode="reload")
        self.assertEqual(result["results"][0]["changes"][0]["key"], "qos")
        self.assertEqual(result["config"]["qos"]["cap"], 500)

    def test_immutable_keys_still_rejected(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["qos"]["cap"] = 500
        new["delay"] = 2
        run_invalid([{"t": 0, "config": new}])


class TailQueueCheckTest(unittest.TestCase):
    def test_total_equal_cap_legal(self):
        # 一条广播泛洪到 p2、p3 与一个 LAG 成员，共 3 帧/口外副本；
        # cap=3 时每口恰 3 帧，合法
        config = qos_config(cap=1000)
        new = with_qos(config, cap=3)
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            frame(1, "p1", "00:00:00:00:00:02"),
            frame(2, "p1", "00:00:00:00:00:03"),
            {"t": 3, "config": new},
        ]
        result = run(events, config)
        self.assertEqual(result["results"][3]["action"], "reload")

    def test_total_over_cap_invalid(self):
        config = qos_config(cap=1000)
        new = with_qos(config, cap=2)  # 每口 3 帧 > 2
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            frame(1, "p1", "00:00:00:00:00:02"),
            frame(2, "p1", "00:00:00:00:00:03"),
            {"t": 3, "config": new},
        ]
        run_invalid(events, config)

    def test_empty_queues_always_fit(self):
        config = qos_config(cap=1000)
        new = with_qos(config, cap=1)
        result = run([{"t": 0, "config": new}], config)
        self.assertEqual(result["config"]["qos"]["cap"], 1)


class WeightedQueueCheckTest(unittest.TestCase):
    def test_queue_equal_quota_legal(self):
        # weights=[1,1,1,1] cap=4：每队列配额 ceil(4/4)=1
        config = qos_config(cap=1000, drop="tail")
        new = with_qos(config, cap=4, drop="weighted")
        events = [
            uframe(0, 3, src="00:00:00:00:00:01"),
            {"t": 1, "config": new},
            service(2, "p2", 10),
        ]
        result = run(events, config)
        self.assertEqual(result["results"][2]["frames"], [0])

    def test_queue_over_quota_invalid(self):
        config = qos_config(cap=1000, drop="tail")
        new = with_qos(config, cap=4, drop="weighted")  # q3 配额 1，实排队 2
        events = [
            uframe(0, 3, src="00:00:00:00:00:01"),
            uframe(1, 3, src="00:00:00:00:00:02"),
            {"t": 2, "config": new},
        ]
        run_invalid(events, config)

    def test_weighted_to_tail_total_invalid(self):
        # weighted cap=8、等权：每队列配额 2；逐优先级各入一帧后每口四队列
        # 各持 1（共 4）；切到 tail cap=3 时总数 4 > 3，整批无效
        config = qos_config(cap=8, drop="weighted")
        events_in = [
            uframe(0, 0, src="00:00:00:00:00:01"),
            uframe(1, 1, src="00:00:00:00:00:02"),
            uframe(2, 2, src="00:00:00:00:00:03"),
            uframe(3, 3, src="00:00:00:00:00:04"),
        ]
        # 先在 weighted 下每口排满 4 帧（各队列 1），再 tail cap=3
        new = with_qos(config, cap=3, drop="tail")
        run_invalid(events_in + [{"t": 4, "config": new}], config)

    def test_weighted_to_tail_total_equal_legal(self):
        # 同样 4 帧，tail cap=4 时总数恰等于上限：合法
        config = qos_config(cap=8, drop="weighted")
        events_in = [
            uframe(0, 0, src="00:00:00:00:00:01"),
            uframe(1, 1, src="00:00:00:00:00:02"),
            uframe(2, 2, src="00:00:00:00:00:03"),
            uframe(3, 3, src="00:00:00:00:00:04"),
        ]
        new = with_qos(config, cap=4, drop="tail")
        result = run(events_in + [{"t": 4, "config": new}], config)
        self.assertEqual(result["results"][4]["action"], "reload")


class QueuedFramePreservationTest(unittest.TestCase):
    def test_map_change_keeps_queue_and_apply_next_frame(self):
        # 初始 map 正常：prio0 入 q0；reload 把 prio0 改映到 q3，
        # 已排队的旧帧仍在 q0，下一帧按新 map 入 q3
        config = qos_config()
        new = with_qos(config, map=[3, 3, 3, 3, 3, 3, 3, 3])
        events = [
            uframe(0, 0, src="00:00:00:00:00:01"),  # id0 -> q0
            {"t": 1, "config": new},
            uframe(2, 0, src="00:00:00:00:00:02"),  # id1 -> q3（新 map）
            service(3, "p2", 10),
        ]
        result = run(events, config)
        # q3 优先于 q0：先服务 id1，再服务 id0；旧帧未被重分类
        self.assertEqual(result["results"][3]["frames"], [1, 0])

    def test_frames_not_dropped_or_recounted(self):
        config = qos_config()
        new = with_qos(config, weights=[4, 1, 1, 1])
        events = [
            uframe(0, 3, src="00:00:00:00:00:01"),
            uframe(1, 3, src="00:00:00:00:00:02"),
            {"t": 2, "config": new},
            service(3, "p2", 10),
        ]
        result = run(events, config)
        self.assertEqual(result["results"][3]["frames"], [0, 1])
        stats = {p["name"]: p for p in result["ports"]}
        # reload 不丢已排队帧：p2/p3 均无出口丢弃（p2 的 tx 另含其镜像副本）
        self.assertEqual(stats["p2"]["drop"], 0)
        self.assertEqual(stats["p3"]["drop"], 0)

    def test_fid_and_queue_content_preserved(self):
        # 已排队帧的帧号与出口标记随队列保留：reload 改 qos 后服务仍发出
        config = qos_config(weights=(1, 1, 1, 1))
        new = with_qos(config, weights=[1, 1, 1, 9])
        events = [
            uframe(0, 3, src="00:00:00:00:00:01"),
            {"t": 1, "config": new},
            service(2, "p2", 10),
        ]
        result = run(events, config)
        self.assertEqual(result["results"][2]["frames"], [0])
        out = result["results"][0]["ports"]
        self.assertIn({"name": "p2", "vlan": None}, out)


class NewCapDropEffectiveTest(unittest.TestCase):
    def test_smaller_cap_admits_next_frame(self):
        # cap=2 排满两口各 2 帧（合法），下一帧按新 cap 被拒计 drop，
        # 旧帧保留且可服务
        config = qos_config(cap=1000)
        new = with_qos(config, cap=2)
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            frame(1, "p1", "00:00:00:00:00:02"),
            {"t": 2, "config": new},  # 每口恰 2 帧：合法
            frame(3, "p1", "00:00:00:00:00:03"),  # 新 cap 下被各口拒绝
            service(4, "p2", 10),
        ]
        result = run(events, config)
        stats = {p["name"]: p for p in result["ports"]}
        self.assertEqual(result["results"][4]["frames"], [0, 1])
        self.assertGreaterEqual(stats["p2"]["drop"], 1)


class WrrResetTest(unittest.TestCase):
    def _events(self, after):
        # 帧事件占帧号（service 不占）：t0->id0、t3->id1、t4->id2
        return [
            uframe(0, 3),
            service(1, "p2", 2),          # 发空 q3 后游标推进到 q2
            {"t": 2, "config": after},
            uframe(3, 3),
            uframe(4, 2),
            service(5, "p2", 10),
        ]

    def test_qos_change_resets_cursor(self):
        config = qos_config(weights=(1, 1, 1, 4))
        new = with_qos(config, weights=[1, 1, 1, 9])  # qos 变化
        result = run(self._events(new), config)
        # 重置 q=3：先发 q3 的 id1，再 q2 的 id2
        self.assertEqual(result["results"][5]["frames"], [1, 2])

    def test_non_qos_change_keeps_cursor(self):
        config = qos_config(weights=(1, 1, 1, 4))
        new = copy.deepcopy(config)
        new["age"] = 50
        result = run(self._events(new), config)
        # 游标留在 q2：先发 id2，绕回再发 id1
        self.assertEqual(result["results"][5]["frames"], [2, 1])

    def test_drop_change_resets_cursor(self):
        config = qos_config(weights=(1, 1, 1, 4))
        new = with_qos(config, drop="weighted")  # 仅 drop 变化也算 qos 变化
        result = run(self._events(new), config)
        self.assertEqual(result["results"][5]["frames"], [1, 2])


class RollbackQosTest(unittest.TestCase):
    def test_rollback_restores_qos_lifo(self):
        config = qos_config()
        first = with_qos(config, weights=[2, 1, 1, 1])
        second = with_qos(first, cap=500)
        events = [
            {"t": 0, "config": first},
            {"t": 1, "config": second},
            {"t": 2, "rollback": True},   # 恢复 first
            {"t": 3, "rollback": True},   # 恢复初始
        ]
        result = run(events, config)
        self.assertEqual(
            [r["action"] for r in result["results"]],
            ["reload", "reload", "rollback", "rollback"],
        )
        self.assertEqual(result["results"][2]["changes"][0]["key"], "qos")
        self.assertEqual(result["results"][2]["changes"][0]["after"]["cap"],
                         1000)
        self.assertEqual(result["config"]["qos"]["cap"], 1000)
        self.assertEqual(result["config"]["qos"]["weights"], [1, 1, 1, 1])

    def test_rollback_queue_check_uses_restored_qos(self):
        # reload 放宽 weighted 配额入队后，rollback 恢复低 cap：整批无效
        config = qos_config(cap=1, drop="tail")
        high = with_qos(config, cap=1000)
        events = [
            {"t": 0, "config": high},
            frame(1, "p1", "00:00:00:00:00:01"),
            frame(2, "p1", "00:00:00:00:00:02"),  # 每口 2 帧
            {"t": 3, "rollback": True},           # 恢复 cap=1：2>1 整批无效
        ]
        run_invalid(events, config)


def _exact_work(config, events):
    """二求 reload_work 的最小合法上限（即精确工作量）。"""
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


class QosWorkLimitTest(unittest.TestCase):
    LIMITS_OK = ["1048576", "16777216", "100000", "16777216"]

    def _events(self, reload_config):
        config = base_config()
        return config, [
            frame(0, "p1", "00:00:00:00:00:01"),
            frame(1, "p1", "00:00:00:00:00:02"),
            {"t": 2, "config": reload_config},
            frame(3, "p1", "00:00:00:00:00:09"),
        ]

    def test_qos_change_extra_n_plus_5(self):
        config = base_config()
        # 两广播帧泛洪 p2、p3 与一个 LAG 成员：N=2*3=6
        age_cfg = copy.deepcopy(config)
        age_cfg["age"] = 50
        qos_cfg = with_qos(config, weights=[2, 1, 1, 1])
        age_events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            frame(1, "p1", "00:00:00:00:00:02"),
            {"t": 2, "config": age_cfg},
        ]
        qos_events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            frame(1, "p1", "00:00:00:00:00:02"),
            {"t": 2, "config": qos_cfg},
        ]
        w_age = _exact_work(config, age_events)
        w_qos = _exact_work(config, qos_events)
        self.assertEqual(w_qos - w_age, 6 + 5)

    def test_equal_legal_first_exceed_exit5(self):
        config = base_config()
        qos_cfg = with_qos(config, weights=[2, 1, 1, 1])
        _, events = self._events(qos_cfg)
        exact = _exact_work(config, events)
        ok = run_cli(
            config, events, mode="reload-rollback",
            extra=self.LIMITS_OK + [str(exact)],
        )
        self.assertEqual(ok[0], 0)
        self.assertEqual(ok[2], b"")
        bad = run_cli(
            config, events, mode="reload-rollback",
            extra=self.LIMITS_OK + [str(exact - 1)],
        )
        self.assertEqual(bad[0], 5)
        self.assertEqual(bad[1], b"")
        self.assertEqual(bad[2], b'{"error":"reload_work_limit"}\n')

    def test_rollback_qos_change_billed_same_branch(self):
        config = base_config()
        new = with_qos(config, weights=[2, 1, 1, 1])
        events = [
            {"t": 0, "config": new},
            frame(1, "p1", "00:00:00:00:00:01"),
            frame(2, "p1", "00:00:00:00:00:02"),
            {"t": 3, "rollback": True},  # qos 恢复即变化，亦计 N+5
        ]
        exact = _exact_work(config, events)
        code, out, err = run_cli(
            config, events, mode="reload-rollback",
            extra=self.LIMITS_OK + [str(exact)],
        )
        self.assertEqual(code, 0, err)
        code, out, err = run_cli(
            config, events, mode="reload-rollback",
            extra=self.LIMITS_OK + [str(exact - 1)],
        )
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"reload_work_limit"}\n')

    def test_semantic_error_precedes_work_limit(self):
        config = qos_config(cap=1000)
        bad = with_qos(config, cap=1)
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            frame(1, "p1", "00:00:00:00:00:02"),
            {"t": 2, "config": bad},
        ]
        code, out, err = run_cli(
            config, events, mode="reload-rollback",
            extra=self.LIMITS_OK + ["1"],
        )
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')


class RecordReplayQosTest(unittest.TestCase):
    def test_record_replay_qos_reload_roundtrip(self):
        config = base_config()
        new = with_qos(config, cap=500, weights=[2, 1, 1, 1])
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "config": new},
            {"t": 2, "rollback": True},
            service(3, "p2", 10),
        ]
        out, log = record(config, events)
        # LOG 结构不变：schema,config,records,sha256
        doc = json.loads(log.decode("utf-8"))
        self.assertEqual(list(doc), ["schema", "config", "records", "sha256"])
        # 两条 reload/rollback 记录 version 递增
        self.assertEqual(
            [rec["version"] for rec in doc["records"][1:3]], [1, 2]
        )
        code, replayed, err = replay(log)
        self.assertEqual(code, 0, err)
        self.assertEqual(replayed, out)  # replay 与 record stdout 逐字节一致

    def test_failed_qos_reload_writes_no_log(self):
        config = base_config()
        bad = with_qos(config, cap=1)
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            frame(1, "p1", "00:00:00:00:00:02"),
            {"t": 2, "config": bad},
        ]
        files = {
            "config.json": json.dumps(config).encode("utf-8"),
            "events.json": json.dumps(events).encode("utf-8"),
        }
        with tempfile.TemporaryDirectory() as tmp:
            paths = {}
            for name, content in files.items():
                path = os.path.join(tmp, name)
                with open(path, "wb") as handle:
                    handle.write(content)
                paths[name] = path
            log_path = os.path.join(tmp, "out.log")
            proc = subprocess.run(
                [sys.executable, SWITCH, "record", paths["config.json"],
                 paths["events.json"], log_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(proc.returncode, 4)
            self.assertEqual(proc.stdout, b"")
            self.assertFalse(os.path.exists(log_path))


if __name__ == "__main__":
    unittest.main()
