#!/usr/bin/env python3
"""reload 子命令回归：port-security 配置热加载、差异与末态快照。

仅用标准库；通过 `python switch.py reload CONFIG EVENTS` 端到端驱动。
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
    # p1 入、p2 镜像口、p3 普通口；p4/p5 为 LAG 成员（target 不得为成员）
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


def run_cli(config, events, mode="reload"):
    """返回 (returncode, stdout_bytes, stderr_bytes)。"""
    with tempfile.TemporaryDirectory() as tmp:
        cfg = os.path.join(tmp, "config.json")
        evt = os.path.join(tmp, "events.json")
        with open(cfg, "wb") as handle:
            handle.write(json.dumps(config).encode("utf-8"))
        with open(evt, "wb") as handle:
            handle.write(json.dumps(events).encode("utf-8"))
        proc = subprocess.run(
            [sys.executable, SWITCH, mode, cfg, evt],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    return proc.returncode, proc.stdout, proc.stderr


def run(config, events, mode="reload"):
    code, out, err = run_cli(config, events, mode)
    assert code == 0, (code, err.decode("utf-8"))
    return json.loads(out.decode("utf-8"))


def run_invalid(config, events):
    code, out, err = run_cli(config, events)
    assert code == 4, (code, out)
    assert out == b"", out
    assert err == b'{"error":"invalid_input"}\n', err


class ReloadResultTest(unittest.TestCase):
    def test_changes_record_and_final_config(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["age"] = 50
        new["security"][0]["limit"] = 5
        new["security"][1]["static"] = [{"mac": "00:00:00:00:00:aa", "vlan": 1}]
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            frame(1, "p1", "00:00:00:00:00:02"),
            {"t": 2, "config": new},
            frame(3, "p1", "00:00:00:00:00:03"),
            frame(4, "p1", "00:00:00:00:00:04"),
            frame(5, "p1", "00:00:00:00:00:05"),  # 旧 limit=2 早违例；新 limit=5 放行
        ]
        result = run(config, events)
        self.assertEqual(
            list(result), ["results", "ports", "vlans", "security", "config"]
        )
        record = result["results"][2]
        self.assertEqual(list(record), ["t", "action", "changes"])
        self.assertEqual(record["t"], 2)
        self.assertEqual(record["action"], "reload")
        # acl 未变不列；项键序 key,before,after；age/acl/security 序
        self.assertEqual([c["key"] for c in record["changes"]], ["age", "security"])
        for change in record["changes"]:
            self.assertEqual(list(change), ["key", "before", "after"])
        self.assertEqual(record["changes"][0]["before"], 100)
        self.assertEqual(record["changes"][0]["after"], 50)
        # before/after 各层对象键按码点升序
        before_sec = record["changes"][1]["before"][0]
        self.assertEqual(list(before_sec), ["action", "limit", "port", "static"])
        # 新 limit 自下一事件生效：五个动态源全部绑定
        sec = {s["port"]: s for s in result["security"]}
        self.assertEqual(len(sec["p1"]["learned"]), 5)
        self.assertEqual(sec["p1"]["violations"], 0)
        # 末态 config 为全部当前配置，键按码点升序
        self.assertEqual(list(result["config"]), sorted(result["config"]))
        self.assertEqual(result["config"]["age"], 50)
        self.assertEqual(result["config"]["security"][0]["limit"], 5)

    def test_no_change_reload(self):
        config = base_config()
        result = run(config, [{"t": 3, "config": copy.deepcopy(config)}])
        self.assertEqual(
            result["results"], [{"t": 3, "action": "reload", "changes": []}]
        )
        self.assertEqual(result["config"]["age"], 100)

    def test_chained_reload_and_acl_effective_next_event(self):
        config = base_config()
        first = copy.deepcopy(config)
        first["age"] = 10
        second = copy.deepcopy(first)
        second["acl"] = [
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
            {"t": 0, "config": first},
            {"t": 1, "config": second},
            frame(2, "p1", "00:00:00:00:00:01"),
        ]
        result = run(config, events)
        self.assertEqual(
            result["results"][0]["changes"],
            [{"key": "age", "before": 100, "after": 10}],
        )
        self.assertEqual(result["results"][1]["changes"][0]["key"], "acl")
        # 新 acl 自下一事件生效：广播帧被 drop
        self.assertEqual(result["results"][2]["action"], "drop")
        self.assertEqual(result["config"]["age"], 10)
        self.assertEqual(result["config"]["acl"], second["acl"])

    def test_new_age_ages_fdb(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["age"] = 3
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            {"t": 1, "config": new},
            frame(5, "p2", "00:00:00:00:00:09", dst="00:00:00:00:00:01"),
        ]
        result = run(config, events)
        # 新 age=3：t=5 时 (1, 00:..:01) 已老化，未知单播按泛洪
        self.assertEqual(result["results"][2]["action"], "flood")

    def test_security_state_preserved(self):
        config = base_config()
        config["security"][0]["limit"] = 1
        config["security"][0]["action"] = "shutdown"
        new = copy.deepcopy(config)
        new["age"] = 7
        new["security"][0]["action"] = "drop"  # 不影响既有 shutdown
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            frame(1, "p1", "00:00:00:00:00:02"),  # 违例 -> p1 永久禁用
            {"t": 2, "config": new},
            frame(3, "p1", "00:00:00:00:00:03"),
        ]
        result = run(config, events)
        sec = {s["port"]: s for s in result["security"]}
        self.assertTrue(sec["p1"]["shutdown"])
        self.assertEqual(sec["p1"]["violations"], 1)
        self.assertEqual(sec["p1"]["learned"], [])
        self.assertEqual(result["results"][3]["action"], "drop")

    def test_dynamic_bindings_preserved(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["age"] = 9
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),  # 绑定到 p1
            {"t": 1, "config": new},
            frame(2, "p2", "00:00:00:00:00:01"),  # 已绑定 p1 -> p2 违例
            frame(3, "p1", "00:00:00:00:00:01"),  # 重复源不增数
        ]
        result = run(config, events)
        sec = {s["port"]: s for s in result["security"]}
        self.assertEqual(
            sec["p1"]["learned"], [{"vlan": 1, "mac": "00:00:00:00:00:01"}]
        )
        self.assertEqual(sec["p1"]["violations"], 0)
        self.assertEqual(sec["p2"]["violations"], 1)

    def test_plain_events_match_port_security(self):
        config = base_config()
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            frame(1, "p1", "00:00:00:00:00:02"),
            frame(2, "p1", "00:00:00:00:00:03"),
        ]
        old = run(config, events, mode="port-security")
        new = run(config, events)
        self.assertEqual(list(new), ["results", "ports", "vlans", "security", "config"])
        new.pop("config")
        self.assertEqual(new, old)  # 既有四键逐字节一致


class ReloadInvalidTest(unittest.TestCase):
    def test_immutable_top_level_changed(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["delay"] = 2
        run_invalid(config, [{"t": 0, "config": new}])

    def test_immutable_nested_changed(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["storm"]["hold"] = 11
        run_invalid(config, [{"t": 0, "config": new}])

    def test_dynamic_count_exceeds_new_limit(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["security"][0]["limit"] = 1
        events = [
            frame(0, "p1", "00:00:00:00:00:01"),
            frame(1, "p1", "00:00:00:00:00:02"),
            {"t": 2, "config": new},
        ]
        run_invalid(config, events)

    def test_dynamic_binding_in_new_static(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["security"][1]["static"] = [{"mac": "00:00:00:00:00:01", "vlan": 1}]
        events = [frame(0, "p1", "00:00:00:00:00:01"), {"t": 1, "config": new}]
        run_invalid(config, events)

    def test_t_not_monotonic_across_reload(self):
        config = base_config()
        events = [
            {"t": 5, "config": copy.deepcopy(config)},
            {"t": 4, "config": copy.deepcopy(config)},
        ]
        run_invalid(config, events)

    def test_bad_reload_t(self):
        config = base_config()
        for bad_t in (True, -1, 1.5, "0"):
            with self.subTest(t=bad_t):
                run_invalid(config, [{"t": bad_t, "config": copy.deepcopy(config)}])

    def test_incomplete_reload_config(self):
        config = base_config()
        new = copy.deepcopy(config)
        del new["qos"]
        run_invalid(config, [{"t": 0, "config": new}])

    def test_reload_event_extra_key(self):
        config = base_config()
        run_invalid(
            config, [{"t": 0, "config": copy.deepcopy(config), "x": 1}]
        )

    def test_new_static_not_globally_distinct(self):
        config = base_config()
        new = copy.deepcopy(config)
        new["security"][0]["static"] = [{"mac": "00:00:00:00:00:aa", "vlan": 1}]
        new["security"][1]["static"] = [{"mac": "00:00:00:00:00:aa", "vlan": 1}]
        run_invalid(config, [{"t": 0, "config": new}])

    def test_failed_reload_no_partial_output(self):
        # 整批无状态：前面事件已处理也不产生任何 stdout
        config = base_config()
        new = copy.deepcopy(config)
        new["security"][0]["limit"] = 0
        events = [frame(0, "p1", "00:00:00:00:00:01"), {"t": 1, "config": new}]
        run_invalid(config, events)


class ReloadUsageTest(unittest.TestCase):
    def test_usage_error(self):
        proc = subprocess.run(
            [sys.executable, SWITCH, "reload"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b'{"error":"usage"}\n')

    def test_file_not_found(self):
        proc = subprocess.run(
            [sys.executable, SWITCH, "reload", "nope", "nope2"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b'{"error":"file_not_found"}\n')


if __name__ == "__main__":
    unittest.main()
