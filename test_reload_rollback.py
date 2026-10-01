#!/usr/bin/env python3
"""reload-rollback 子命令回归：配置栈回滚、main(argv) 与 link-state 上限。

仅用标准库；通过 `python switch.py reload-rollback CONFIG EVENTS`
端到端驱动，另直接调用 switch.main 验证首项分派。
"""

import copy
import io
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


def run(events, config=None, extra=()):
    config = config if config is not None else base_config()
    code, out, err = run_cli(config, events, mode="reload-rollback", extra=extra)
    assert code == 0, (code, err.decode("utf-8"))
    return json.loads(out.decode("utf-8"))


def run_invalid(events, config=None):
    config = config if config is not None else base_config()
    code, out, err = run_cli(config, events, mode="reload-rollback")
    assert code == 4, (code, out)
    assert out == b"", out
    assert err == b'{"error":"invalid_input"}\n', err


class RollbackResultTest(unittest.TestCase):
    def test_rollback_restores_and_result_shape(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["age"] = 50
        new["security"][0]["limit"] = 5
        events = [
            {"t": 0, "config": new},
            {"t": 1, "rollback": True},
        ]
        result = run(events)
        self.assertEqual(
            list(result), ["results", "ports", "vlans", "security", "config"]
        )
        record = result["results"][1]
        # 键序 t,action,changes；action 为 rollback
        self.assertEqual(list(record), ["t", "action", "changes"])
        self.assertEqual(record["t"], 1)
        self.assertEqual(record["action"], "rollback")
        # changes 按 age、acl、security 序仅列变化项；项键序 key,before,after
        self.assertEqual(
            [c["key"] for c in record["changes"]], ["age", "security"]
        )
        for change in record["changes"]:
            self.assertEqual(list(change), ["key", "before", "after"])
        self.assertEqual(record["changes"][0]["before"], 50)
        self.assertEqual(record["changes"][0]["after"], 100)
        # 末态 config 为恢复后的配置
        self.assertEqual(result["config"]["age"], 100)
        self.assertEqual(result["config"]["security"][0]["limit"], 2)

    def test_rollback_chain_restores_in_reverse(self):
        config = base_config()
        first = copy.deepcopy(config)
        first["age"] = 50
        second = copy.deepcopy(config)
        second["age"] = 30
        events = [
            {"t": 0, "config": first},
            {"t": 1, "config": second},
            {"t": 2, "rollback": True},
            {"t": 3, "rollback": True},
        ]
        result = run(events)
        self.assertEqual(
            [r["action"] for r in result["results"]],
            ["reload", "reload", "rollback", "rollback"],
        )
        self.assertEqual(
            result["results"][2]["changes"],
            [{"key": "age", "before": 30, "after": 50}],
        )
        self.assertEqual(
            result["results"][3]["changes"],
            [{"key": "age", "before": 50, "after": 100}],
        )
        self.assertEqual(result["config"]["age"], 100)

    def test_reload_after_rollback_pushes_again(self):
        # 空栈后 reload 仍可压栈
        config = base_config()
        first = copy.deepcopy(config)
        first["age"] = 50
        second = copy.deepcopy(config)
        second["age"] = 30
        events = [
            {"t": 0, "config": first},
            {"t": 1, "rollback": True},
            {"t": 2, "config": second},
            {"t": 3, "rollback": True},
        ]
        result = run(events)
        self.assertEqual(result["config"]["age"], 100)
        self.assertEqual(
            result["results"][3]["changes"],
            [{"key": "age", "before": 30, "after": 100}],
        )

    def test_rollback_no_change_gives_empty_changes(self):
        config = base_config()
        events = [
            {"t": 0, "config": copy.deepcopy(config)},
            {"t": 1, "rollback": True},
        ]
        result = run(events)
        self.assertEqual(
            result["results"][1],
            {"t": 1, "action": "rollback", "changes": []},
        )

    def test_rollback_restores_acl_effective_next_event(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["acl"] = [
            {
                "src": None,
                "dst": "ff:ff:ff:ff:ff:ff",
                "vlan": None,
                "ethertype": None,
                "priority": None,
                "action": "drop",
                "to_vlan": None,
            }
        ]
        events = [
            {"t": 0, "config": new},
            frame(1, "p1", "00:00:00:00:00:01"),  # drop acl 生效
            {"t": 2, "rollback": True},
            frame(3, "p1", "00:00:00:00:00:02"),  # 恢复 allow：泛洪
        ]
        result = run(events)
        self.assertEqual(result["results"][1]["action"], "drop")
        self.assertEqual(result["results"][3]["action"], "flood")

    def test_rollback_preserves_runtime_state_and_stats(self):
        # 回滚只恢复配置：动态绑定、shutdown 与计数保留
        config = base_config()
        config["security"][0]["limit"] = 1
        config["security"][0]["action"] = "shutdown"
        new = copy.deepcopy(config)
        new["age"] = 7
        new["security"][0]["action"] = "drop"
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            frame(1, "p1", "00:00:00:00:00:02"),  # 违例 -> p1 永久禁用
            {"t": 2, "config": new},
            {"t": 3, "rollback": True},  # 恢复 shutdown 配置，状态保留
            frame(4, "p1", "00:00:00:00:00:03"),
        ]
        result = run(events, config=config)
        sec = {s["port"]: s for s in result["security"]}
        self.assertTrue(sec["p1"]["shutdown"])
        self.assertEqual(sec["p1"]["violations"], 1)
        self.assertEqual(sec["p1"]["learned"], [])
        self.assertEqual(result["results"][4]["action"], "drop")

    def test_rollback_restores_age_for_aging(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["age"] = 3
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "config": new},
            {"t": 2, "rollback": True},  # age 恢复 100
            frame(5, "p2", "00:00:00:00:00:09", dst="00:00:00:00:00:01"),
        ]
        result = run(events)
        # age=100：t=5 时 (1, 00:..:01) 未老化，单播直达 p1
        self.assertEqual(result["results"][3]["action"], "unicast")
        self.assertEqual(
            [p["name"] for p in result["results"][3]["ports"]], ["p1"]
        )


class RollbackInvalidTest(unittest.TestCase):
    def test_empty_stack(self):
        run_invalid([{"t": 0, "rollback": True}])

    def test_stack_exhausted(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["age"] = 50
        events = [
            {"t": 0, "config": new},
            {"t": 1, "rollback": True},
            {"t": 2, "rollback": True},
        ]
        run_invalid(events)

    def test_rollback_must_be_true(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["age"] = 50
        for bad in (False, 1, 0, "true", None):
            with self.subTest(rollback=bad):
                run_invalid(
                    [{"t": 0, "config": new}, {"t": 1, "rollback": bad}]
                )

    def test_bad_rollback_t(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["age"] = 50
        for bad_t in (True, -1, 1.5, "0"):
            with self.subTest(t=bad_t):
                run_invalid(
                    [{"t": 0, "config": new}, {"t": bad_t, "rollback": True}]
                )

    def test_t_not_monotonic_across_rollback(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["age"] = 50
        events = [
            {"t": 5, "config": new},
            {"t": 4, "rollback": True},
        ]
        run_invalid(events)

    def test_rollback_event_extra_key(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["age"] = 50
        run_invalid(
            [
                {"t": 0, "config": new},
                {"t": 1, "rollback": True, "x": 1},
            ]
        )

    def test_dynamic_count_exceeds_restored_limit(self):
        config = base_config()
        low = copy.deepcopy(config)
        low["security"][0]["limit"] = 1
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            frame(1, "p1", "00:00:00:00:00:02"),
            {"t": 2, "config": low},  # 无效：动态 2 > 新 limit 1
            {"t": 3, "config": copy.deepcopy(config)},
            {"t": 4, "rollback": True},
        ]
        run_invalid(events)

    def test_rollback_restored_limit_conflict(self):
        # reload 放宽 limit 后绑定增多，rollback 恢复低 limit：整批无效
        config = base_config()
        config["security"][0]["limit"] = 1
        high = copy.deepcopy(config)
        high["security"][0]["limit"] = 3
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "config": high},
            frame(2, "p1", "00:00:00:00:00:02"),
            {"t": 3, "rollback": True},  # 恢复 limit 1 < 动态 2
        ]
        run_invalid(events, config=config)

    def test_rollback_restored_static_conflict(self):
        # reload 移除静态后该 mac 动态绑定，rollback 恢复静态：整批无效
        config = base_config()
        config["security"][1]["static"] = [
            {"mac": "00:00:00:00:00:aa", "vlan": 1}
        ]
        new = copy.deepcopy(config)
        new["age"] = 50
        new["security"][1]["static"] = []
        events = [
            {"t": 0, "config": new},
            frame(1, "p1", "00:00:00:00:00:aa"),
            {"t": 2, "rollback": True},
        ]
        run_invalid(events, config=config)

    def test_failed_batch_no_partial_output(self):
        # 整批无状态：前面事件已处理也不产生任何 stdout
        config = base_config()
        new = copy.deepcopy(config)
        new["age"] = 50
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "config": new},
            {"t": 2, "rollback": True},
            {"t": 3, "rollback": True},  # 空栈
        ]
        run_invalid(events)

    def test_rollback_event_rejected_by_reload(self):
        # 旧入口不接受 rollback 事件
        config = base_config()
        new = copy.deepcopy(config)
        new["age"] = 50
        code, out, err = run_cli(
            config,
            [{"t": 0, "config": new}, {"t": 1, "rollback": True}],
            mode="reload",
        )
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')


class RollbackContractTest(unittest.TestCase):
    """调用、资源与错误契约同 reload；旧入口逐字节不变。"""

    def test_plain_events_match_reload(self):
        config = base_config()
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "config": copy.deepcopy(config)},
            frame(2, "p1", "00:00:00:00:00:02"),
        ]
        old = run_cli(config, events, mode="reload")
        new = run_cli(config, events, mode="reload-rollback")
        self.assertEqual(old[0], 0)
        self.assertEqual(new, old)  # 无 rollback 事件时逐字节一致

    def test_usage_error(self):
        proc = subprocess.run(
            [sys.executable, SWITCH, "reload-rollback"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b'{"error":"usage"}\n')

    def test_file_not_found(self):
        proc = subprocess.run(
            [sys.executable, SWITCH, "reload-rollback", "nope", "nope2"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b'{"error":"file_not_found"}\n')

    def test_usage_bad_count_or_token(self):
        config = base_config()
        events = [{"t": 0, "config": copy.deepcopy(config)}]
        for extra in (
            ["1"],
            ["1", "2", "3"],
            ["1", "2", "3", "4", "5", "6"],
            ["0", "1"],
            ["1", "2", "3", "4", "0"],
            ["1", "2", "3", "4", "10x"],
        ):
            with self.subTest(extra=extra):
                code, out, err = run_cli(
                    config, events, mode="reload-rollback", extra=extra
                )
                self.assertEqual(code, 2)
                self.assertEqual(out, b"")
                self.assertEqual(err, b'{"error":"usage"}\n')


class RollbackWorkLimitTest(unittest.TestCase):
    """MAX_RELOAD_WORK 沿用原公式；rollback 按 reload 分支计费。"""

    LIMITS_OK = ["1048576", "16777216", "100000", "16777216"]

    def events(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["age"] = 50
        return config, [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "config": new},
            {"t": 2, "rollback": True},
            frame(3, "p1", "00:00:00:00:00:02"),
        ]

    def test_equal_legal_first_exceed_exit5(self):
        # 工作量：初始 B+L+2U=1；帧 19；重载 X+D+P+A+T+H+1
        # =2+1+5+1+0+1+1=11（H=1：首帧留下一条风暴记录，重载与回滚点
        # 均仍在保留窗口内）；回滚同式 11（A/T 取恢复配置）；末帧 22；
        # 累计 64
        config, events = self.events()
        code, out, err = run_cli(
            config, events, mode="reload-rollback",
            extra=self.LIMITS_OK + ["64"],
        )
        self.assertEqual(code, 0)
        self.assertEqual(err, b"")
        code, out, err = run_cli(
            config, events, mode="reload-rollback",
            extra=self.LIMITS_OK + ["63"],
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"reload_work_limit"}\n')

    def test_explicit_limits_byte_identical(self):
        config, events = self.events()
        base = run_cli(config, events, mode="reload-rollback")
        self.assertEqual(base[0], 0)
        for extra in (
            self.LIMITS_OK[:2],
            self.LIMITS_OK,
            self.LIMITS_OK + ["10000000"],
            self.LIMITS_OK + ["9" * 40],
        ):
            with self.subTest(extra=extra):
                code, out, err = run_cli(
                    config, events, mode="reload-rollback", extra=extra
                )
                self.assertEqual((code, out, err), (0, base[1], b""))

    def test_semantic_error_precedes_work_limit(self):
        config = base_config()
        events = [{"t": 0, "rollback": True}]  # 空栈
        code, out, err = run_cli(
            config, events, mode="reload-rollback",
            extra=self.LIMITS_OK + ["1"],
        )
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')


class MainArgvTest(unittest.TestCase):
    """main(argv)：首项为已知子命令时不丢弃，否则仅丢脚本名。"""

    def call_main(self, argv):
        class BinOut:
            def __init__(self):
                self.buffer = io.BytesIO()

        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = BinOut(), BinOut()
        try:
            code = switch.main(argv)
            return (
                code,
                sys.stdout.buffer.getvalue(),
                sys.stderr.buffer.getvalue(),
            )
        finally:
            sys.stdout, sys.stderr = old_out, old_err

    def test_first_item_subcommand_not_dropped(self):
        config = base_config()
        events = [frame(0, "p1", "00:00:00:00:00:01")]
        with tempfile.TemporaryDirectory() as tmp:
            cfg = os.path.join(tmp, "config.json")
            evt = os.path.join(tmp, "events.json")
            with open(cfg, "wb") as handle:
                handle.write(json.dumps(config).encode("utf-8"))
            with open(evt, "wb") as handle:
                handle.write(json.dumps(events).encode("utf-8"))
            for mode in ("reload", "reload-rollback"):
                with self.subTest(mode=mode):
                    with_name = self.call_main(
                        ["switch.py", mode, cfg, evt]
                    )
                    without_name = self.call_main([mode, cfg, evt])
                    self.assertEqual(with_name[0], 0)
                    self.assertEqual(without_name, with_name)

    def test_unknown_first_item_treated_as_script_name(self):
        code, out, err = self.call_main(["anything-else"])
        self.assertEqual(code, 2)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"usage"}\n')


class LinkStateLimitTest(unittest.TestCase):
    """link-state：无显式上限传默认 10000000，显式五项顺序不变。"""

    CONFIG = {
        "ports": [
            {"name": "p1", "rates": [100, 1000], "modes": ["half", "full"]}
        ],
        "delay": 5,
    }
    EVENTS = [
        {
            "t": 0,
            "port": "p1",
            "admin": True,
            "peer": True,
            "rates": [1000],
            "modes": ["full"],
        }
    ]

    def run_link_state(self, extra=()):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = os.path.join(tmp, "config.json")
            evt = os.path.join(tmp, "events.json")
            with open(cfg, "wb") as handle:
                handle.write(json.dumps(self.CONFIG).encode("utf-8"))
            with open(evt, "wb") as handle:
                handle.write(json.dumps(self.EVENTS).encode("utf-8"))
            proc = subprocess.run(
                [sys.executable, SWITCH, "link-state", cfg, evt] + list(extra),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        return proc.returncode, proc.stdout, proc.stderr

    def test_default_limit_matches_explicit(self):
        default = self.run_link_state()
        self.assertEqual(default[0], 0)
        explicit = self.run_link_state(
            ["1048576", "16777216", "100000", "16777216", "10000000"]
        )
        self.assertEqual(explicit, default)

    def test_explicit_five_order(self):
        # 五项顺序：MAX_CONFIG_BYTES MAX_DATA_BYTES MAX_ITEMS
        # MAX_OUTPUT_BYTES MAX_LINK_WORK；末项传 1（工作量 1）合法
        ok = self.run_link_state(
            ["1048576", "16777216", "100000", "16777216", "1"]
        )
        self.assertEqual(ok[0], 0)
        tight_config = self.run_link_state(
            ["1", "16777216", "100000", "16777216", "10000000"]
        )
        self.assertEqual(tight_config[0], 5)
        self.assertEqual(tight_config[2], b'{"error":"config_limit"}\n')
        tight_data = self.run_link_state(
            ["1048576", "1", "100000", "16777216", "10000000"]
        )
        self.assertEqual(tight_data[0], 5)
        self.assertEqual(tight_data[2], b'{"error":"data_limit"}\n')
        tight_output = self.run_link_state(
            ["1048576", "16777216", "100000", "1", "10000000"]
        )
        self.assertEqual(tight_output[0], 5)
        self.assertEqual(tight_output[2], b'{"error":"output_limit"}\n')


if __name__ == "__main__":
    unittest.main()
