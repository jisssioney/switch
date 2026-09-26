#!/usr/bin/env python3
"""reload-rollback 子命令回归：配置栈回滚、差异与末态快照。

仅用标准库；通过 `python switch.py reload-rollback CONFIG EVENTS`
端到端驱动，并直接调用 main(argv) 验证首项分派修复。
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


def make_port(name, pvid=1):
    return {
        "name": name,
        "mode": "access",
        "pvid": pvid,
        "allowed": [pvid],
        "untagged": [pvid],
        "up": True,
    }


def base_config():
    ports = [make_port(name) for name in ("p1", "p2", "p3", "p4", "p5")]
    return {
        "bridges": ["b1"],
        "links": [],
        "delay": 1,
        "bridge": "b1",
        "ports": ports,
        "age": 100,
        "storm": {
            "window": 10,
            "limits": {"broadcast": 100, "multicast": 100, "unknown": 100},
            "move_limit": 100,
            "hold": 10,
        },
        "lags": [{"name": "L1", "members": ["p4", "p5"], "hash": ["src"]}],
        "mirror": {"sources": ["p1"], "target": "p2", "direction": "both"},
        "acl": [
            {
                "src": None,
                "dst": None,
                "vlan": None,
                "ethertype": None,
                "priority": None,
                "action": "allow",
                "to_vlan": None,
            }
        ],
        "qos": {
            "map": [0, 1, 2, 3, 0, 1, 2, 3],
            "cap": 1000,
            "mode": "wrr",
            "weights": [1, 1, 1, 1],
            "drop": "tail",
        },
        "security": [
            {"port": "p1", "limit": 2, "action": "drop", "static": []},
            {"port": "p2", "limit": 2, "action": "drop", "static": []},
            {"port": "p3", "limit": 2, "action": "drop", "static": []},
            {"port": "p4", "limit": 2, "action": "drop", "static": []},
            {"port": "p5", "limit": 2, "action": "drop", "static": []},
        ],
    }


def frame(t, port, src, dst="ff:ff:ff:ff:ff:ff"):
    return {
        "t": t,
        "port": port,
        "src": src,
        "dst": dst,
        "vlan": None,
        "ethertype": 0x0800,
        "priority": 0,
    }


def run_cli(config, events, mode="reload-rollback", extra=()):
    """返回 (returncode, stdout_bytes, stderr_bytes)。"""
    with tempfile.TemporaryDirectory() as tmp:
        cfg = os.path.join(tmp, "config.json")
        evt = os.path.join(tmp, "events.json")
        with open(cfg, "wb") as handle:
            handle.write(json.dumps(config).encode("utf-8"))
        with open(evt, "wb") as handle:
            handle.write(json.dumps(events).encode("utf-8"))
        proc = subprocess.run(
            [sys.executable, SWITCH, mode, cfg, evt] + list(extra),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    return proc.returncode, proc.stdout, proc.stderr


def run(config, events, mode="reload-rollback"):
    code, out, err = run_cli(config, events, mode)
    assert code == 0, (code, err.decode("utf-8"))
    return json.loads(out.decode("utf-8"))


def run_invalid(config, events, mode="reload-rollback"):
    code, out, err = run_cli(config, events, mode)
    assert code == 4, (code, out, err)
    assert out == b"", out
    assert err == b'{"error":"invalid_input"}\n', err


class RollbackResultTest(unittest.TestCase):
    def test_rollback_restores_config(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["age"] = 50
        events = [
            {"t": 0, "config": new},
            {"t": 1, "rollback": True},
        ]
        result = run(config, events)
        self.assertEqual(
            list(result), ["results", "ports", "vlans", "security", "config"]
        )
        record = result["results"][1]
        # 结果键序 t,action,changes；action 为 rollback
        self.assertEqual(list(record), ["t", "action", "changes"])
        self.assertEqual(record["t"], 1)
        self.assertEqual(record["action"], "rollback")
        # changes 按 age、acl、security 序仅列变化项，项键序 key,before,after
        self.assertEqual(
            record["changes"],
            [{"key": "age", "before": 50, "after": 100}],
        )
        # 末态 config 为恢复后的全部当前配置
        self.assertEqual(list(result["config"]), sorted(result["config"]))
        self.assertEqual(result["config"]["age"], 100)

    def test_rollback_no_change(self):
        config = base_config()
        events = [
            {"t": 0, "config": copy.deepcopy(config)},
            {"t": 1, "rollback": True},
        ]
        result = run(config, events)
        self.assertEqual(
            result["results"][1],
            {"t": 1, "action": "rollback", "changes": []},
        )

    def test_stack_lifo_and_repush(self):
        config = base_config()
        first = copy.deepcopy(config)
        first["age"] = 10
        second = copy.deepcopy(config)
        second["age"] = 20
        third = copy.deepcopy(config)
        third["age"] = 30
        events = [
            {"t": 0, "config": first},
            {"t": 1, "config": second},
            {"t": 2, "rollback": True},  # 恢复 first
            {"t": 3, "rollback": True},  # 恢复原始
            {"t": 4, "config": third},   # 回滚后 reload 仍可压栈
            {"t": 5, "rollback": True},  # 恢复原始
        ]
        result = run(config, events)
        ages = [
            record["changes"][0]["after"] if record["changes"] else None
            for record in result["results"]
        ]
        self.assertEqual(ages, [10, 20, 10, 100, 30, 100])
        self.assertEqual(
            [record["action"] for record in result["results"]],
            ["reload", "reload", "rollback", "rollback", "reload", "rollback"],
        )
        self.assertEqual(result["config"]["age"], 100)

    def test_rollback_effective_next_event(self):
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
            frame(1, "p1", "00:00:00:00:00:01"),  # 新 acl：广播 drop
            {"t": 2, "rollback": True},
            frame(3, "p1", "00:00:00:00:00:02"),  # 恢复旧 acl：泛洪
        ]
        result = run(config, events)
        self.assertEqual(result["results"][1]["action"], "drop")
        self.assertEqual(result["results"][3]["action"], "flood")
        self.assertEqual(result["config"]["acl"], config["acl"])

    def test_runtime_state_preserved(self):
        # 回滚只恢复配置：动态绑定、违例计数与 FDB 均保留
        config = base_config()
        new = copy.deepcopy(config)
        new["age"] = 9
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),  # 绑定到 p1
            frame(1, "p2", "00:00:00:00:00:01"),  # 已绑定 p1 -> p2 违例
            {"t": 2, "config": new},
            {"t": 3, "rollback": True},
            frame(4, "p1", "00:00:00:00:00:01"),  # 重复源不增数
        ]
        result = run(config, events)
        sec = {s["port"]: s for s in result["security"]}
        self.assertEqual(
            sec["p1"]["learned"], [{"vlan": 1, "mac": "00:00:00:00:00:01"}]
        )
        self.assertEqual(sec["p1"]["violations"], 0)
        self.assertEqual(sec["p2"]["violations"], 1)
        self.assertEqual(result["config"]["age"], 100)

    def test_plain_events_match_reload(self):
        config = base_config()
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "config": copy.deepcopy(config)},
            frame(2, "p1", "00:00:00:00:00:02"),
        ]
        old = run(config, events, mode="reload")
        new = run(config, events)
        self.assertEqual(new, old)  # 无 rollback 事件时逐字节一致


class RollbackInvalidTest(unittest.TestCase):
    def test_empty_stack(self):
        config = base_config()
        run_invalid(config, [{"t": 0, "rollback": True}])

    def test_stack_exhausted(self):
        config = base_config()
        events = [
            {"t": 0, "config": copy.deepcopy(config)},
            {"t": 1, "rollback": True},
            {"t": 2, "rollback": True},
        ]
        run_invalid(config, events)

    def test_rollback_must_be_true(self):
        config = base_config()
        events = [{"t": 0, "config": copy.deepcopy(config)}]
        for bad in (False, 1, 0, "true", None):
            with self.subTest(rollback=bad):
                run_invalid(config, events + [{"t": 1, "rollback": bad}])

    def test_bad_t(self):
        config = base_config()
        events = [{"t": 0, "config": copy.deepcopy(config)}]
        for bad_t in (True, -1, 1.5, "0"):
            with self.subTest(t=bad_t):
                run_invalid(config, events + [{"t": bad_t, "rollback": True}])

    def test_t_not_monotonic(self):
        config = base_config()
        events = [
            {"t": 5, "config": copy.deepcopy(config)},
            {"t": 4, "rollback": True},
        ]
        run_invalid(config, events)

    def test_rollback_event_extra_key(self):
        config = base_config()
        events = [
            {"t": 0, "config": copy.deepcopy(config)},
            {"t": 1, "rollback": True, "x": 1},
        ]
        run_invalid(config, events)

    def test_old_reload_entry_rejects_rollback(self):
        # 旧入口逐字节不变：reload 不接受 rollback 事件
        config = base_config()
        events = [
            {"t": 0, "config": copy.deepcopy(config)},
            {"t": 1, "rollback": True},
        ]
        run_invalid(config, events, mode="reload")

    def test_dynamic_count_exceeds_restored_limit(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["security"][0]["limit"] = 5
        events = [
            {"t": 0, "config": new},
            frame(1, "p1", "00:00:00:00:00:01"),
            frame(2, "p1", "00:00:00:00:00:02"),
            frame(3, "p1", "00:00:00:00:00:03"),  # 新 limit=5 下绑定 3 个
            {"t": 4, "rollback": True},  # 恢复 limit=2：3 > 2 整批无效
        ]
        run_invalid(config, events)

    def test_dynamic_binding_in_restored_static(self):
        config = base_config()
        config["security"][1]["static"] = [
            {"mac": "00:00:00:00:00:01", "vlan": 1}
        ]
        new = copy.deepcopy(config)
        new["security"][1]["static"] = []
        events = [
            {"t": 0, "config": new},
            frame(1, "p1", "00:00:00:00:00:01"),  # 动态绑定 (1, ..:01)
            {"t": 2, "rollback": True},  # 恢复后 (1, ..:01) 进入 static
        ]
        run_invalid(config, events)

    def test_failed_batch_no_partial_output(self):
        # 整批无状态：前面事件已处理也不产生任何 stdout
        config = base_config()
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "rollback": True},
        ]
        run_invalid(config, events)


class RollbackUsageTest(unittest.TestCase):
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


class RollbackWorkLimitTest(unittest.TestCase):
    """rollback 按 reload 分支计费，A/T 取恢复配置的 ACL/静态绑定数。"""

    LIMITS_OK = ["1048576", "16777216", "100000", "16777216"]

    def events(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["age"] = 50
        return config, [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "config": new},
            {"t": 2, "rollback": True},
        ]

    def test_equal_legal_first_exceed_exit5(self):
        # 工作量：初始 B+L+2U=1；帧 X+3P+M+R+D+S+1=0+15+2+1+0+0+1=19；
        # 重载 X+D+P+A+T+1=2+1+5+1+0+1=10；回滚同式=2+1+5+1+0+1=10；累计 40
        config, events = self.events()
        code, out, err = run_cli(
            config, events, extra=self.LIMITS_OK + ["40"]
        )
        self.assertEqual(code, 0)
        self.assertEqual(err, b"")
        code, out, err = run_cli(
            config, events, extra=self.LIMITS_OK + ["39"]
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"reload_work_limit"}\n')

    def test_rollback_bill_uses_restored_acl_and_static(self):
        # 恢复配置含 2 条 ACL 与 1 条静态绑定：A=2、T=1
        config = base_config()
        config["acl"] = config["acl"] + [
            {
                "src": "00:00:00:00:00:09",
                "dst": None,
                "vlan": None,
                "ethertype": None,
                "priority": None,
                "action": "drop",
                "to_vlan": None,
            }
        ]
        config["security"][1]["static"] = [
            {"mac": "00:00:00:00:00:aa", "vlan": 1}
        ]
        new = copy.deepcopy(config)
        new["acl"] = new["acl"][:1]
        new["security"][1]["static"] = []
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "config": new},
            {"t": 2, "rollback": True},
        ]
        # 初始 1；帧 0+15+2+2+0+0+1=20；重载 X+D+P+A+T+1=2+1+5+1+0+1=10；
        # 回滚 X+D+P+A+T+1=2+1+5+2+1+1=12；累计 43
        code, out, err = run_cli(
            config, events, extra=self.LIMITS_OK + ["43"]
        )
        self.assertEqual(code, 0)
        self.assertEqual(err, b"")
        code, out, err = run_cli(
            config, events, extra=self.LIMITS_OK + ["42"]
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"reload_work_limit"}\n')

    def test_semantic_error_precedes_work_limit(self):
        config = base_config()
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "rollback": True},  # 空栈
        ]
        code, out, err = run_cli(
            config, events, extra=self.LIMITS_OK + ["1"]
        )
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')


class MainArgvTest(unittest.TestCase):
    """main(argv)：首项为已知子命令时不丢弃，否则仅丢脚本名。"""

    def call_main(self, argv):
        import io

        class FakeStdout:
            def __init__(self):
                self.buffer = io.BytesIO()

        out = FakeStdout()
        err = FakeStdout()
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out, err
        try:
            code = switch.main(argv)
        finally:
            sys.stdout, sys.stderr = old_out, old_err
        return code, out.buffer.getvalue(), err.buffer.getvalue()

    def write_inputs(self, tmp, config, events):
        cfg = os.path.join(tmp, "config.json")
        evt = os.path.join(tmp, "events.json")
        with open(cfg, "wb") as handle:
            handle.write(json.dumps(config).encode("utf-8"))
        with open(evt, "wb") as handle:
            handle.write(json.dumps(events).encode("utf-8"))
        return cfg, evt

    def test_subcommand_first_not_dropped(self):
        config = base_config()
        events = [{"t": 0, "config": copy.deepcopy(config)}]
        with tempfile.TemporaryDirectory() as tmp:
            cfg, evt = self.write_inputs(tmp, config, events)
            code, out, err = self.call_main(["reload-rollback", cfg, evt])
        self.assertEqual(code, 0)
        self.assertEqual(err, b"")
        self.assertEqual(json.loads(out.decode("utf-8"))["config"]["age"], 100)

    def test_script_name_dropped(self):
        config = base_config()
        events = [{"t": 0, "config": copy.deepcopy(config)}]
        with tempfile.TemporaryDirectory() as tmp:
            cfg, evt = self.write_inputs(tmp, config, events)
            code, out, err = self.call_main(
                ["switch.py", "reload-rollback", cfg, evt]
            )
        self.assertEqual(code, 0)
        self.assertEqual(err, b"")

    def test_link_state_default_work_limit(self):
        # link-state 无显式上限传默认 10000000
        config = {
            "ports": [
                {"name": "p1", "rates": [10, 100], "modes": ["half", "full"]},
                {"name": "p2", "rates": [1000], "modes": ["full"]},
            ],
            "delay": 1,
        }
        events = []
        with tempfile.TemporaryDirectory() as tmp:
            cfg, evt = self.write_inputs(tmp, config, events)
            code, out, err = self.call_main(["link-state", cfg, evt])
            self.assertEqual(code, 0, err)
            self.assertEqual(err, b"")
            # 显式五项顺序不变
            code2, out2, err2 = self.call_main(
                ["link-state", cfg, evt,
                 "1048576", "16777216", "100000", "16777216", "10000000"]
            )
            self.assertEqual((code2, out2, err2), (0, out, b""))


if __name__ == "__main__":
    unittest.main()
