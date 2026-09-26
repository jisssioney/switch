#!/usr/bin/env python3
"""config-diff 子命令回归：两份 port-security 配置的规范化深度比较。

仅用标准库；通过 `python switch.py config-diff OLD NEW` 端到端驱动。
比较忽略对象键序（对象递归，键按 Unicode 码点升序深度优先），数组整体
顺序敏感，标量按 JSON 类型与值比较，path 采用 RFC6901 JSON Pointer。
"""

import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

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


def allow_rule():
    return {
        "src": None,
        "dst": None,
        "vlan": None,
        "ethertype": None,
        "priority": None,
        "action": "allow",
        "to_vlan": None,
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
        "acl": [allow_rule()],
        "qos": {
            "map": [0, 1, 2, 3, 0, 1, 2, 3],
            "cap": 1000,
            "mode": "wrr",
            "weights": [1, 1, 1, 1],
            "drop": "tail",
        },
        "security": [
            {"port": p, "limit": 2, "action": "drop", "static": []}
            for p in ("p1", "p2", "p3", "p4", "p5")
        ],
    }


def _write(tmp, name, raw):
    path = os.path.join(tmp, name)
    with open(path, "wb") as handle:
        handle.write(raw)
    return path


def run_cli(old_raw, new_raw, args=()):
    """返回 (returncode, stdout_bytes, stderr_bytes)。"""
    with tempfile.TemporaryDirectory() as tmp:
        old_path = _write(tmp, "old.json", old_raw)
        new_path = _write(tmp, "new.json", new_raw)
        proc = subprocess.run(
            [sys.executable, SWITCH, "config-diff", old_path, new_path]
            + list(args),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    return proc.returncode, proc.stdout, proc.stderr


def run_diff(old, new):
    code, out, err = run_cli(
        json.dumps(old).encode("utf-8"), json.dumps(new).encode("utf-8")
    )
    assert code == 0, (code, err.decode("utf-8"))
    return json.loads(out.decode("utf-8")), out


class ConfigDiffEqualTest(unittest.TestCase):
    def test_identical_configs(self):
        config = base_config()
        result, raw = run_diff(config, copy.deepcopy(config))
        self.assertEqual(result, {"equal": True, "changes": []})
        self.assertEqual(raw, b'{"equal":true,"changes":[]}\n')

    def test_object_key_order_ignored_everywhere(self):
        old = base_config()
        new = copy.deepcopy(old)
        # 顶层与嵌套对象键序打乱，数组保序：仍视为完全相同
        new = {
            "security": old["security"],
            "qos": old["qos"],
            "acl": old["acl"],
            "mirror": old["mirror"],
            "lags": old["lags"],
            "storm": {
                "hold": 10,
                "move_limit": 100,
                "limits": {"unknown": 100, "multicast": 100,
                           "broadcast": 100},
                "window": 10,
            },
            "age": 100,
            "ports": old["ports"],
            "bridge": "b1",
            "delay": 1,
            "links": [],
            "bridges": ["b1"],
        }
        result, _ = run_diff(old, new)
        self.assertEqual(result, {"equal": True, "changes": []})


class ConfigDiffChangeTest(unittest.TestCase):
    def _paths(self, result):
        return [item["path"] for item in result["changes"]]

    def test_scalar_change_exact_bytes(self):
        old = base_config()
        new = copy.deepcopy(old)
        new["age"] = 50
        _, raw = run_diff(old, new)
        self.assertEqual(
            raw,
            b'{"equal":false,"changes":['
            b'{"path":"/age","before":100,"after":50}]}\n',
        )

    def test_nested_scalar_path(self):
        old = base_config()
        new = copy.deepcopy(old)
        new["storm"]["hold"] = 11
        result, _ = run_diff(old, new)
        self.assertEqual(
            result["changes"],
            [{"path": "/storm/hold", "before": 10, "after": 11}],
        )

    def test_array_compared_whole_and_order_sensitive(self):
        old = base_config()
        new = copy.deepcopy(old)
        # 仅交换 ports 数组前两个元素：整组数组不同，只出一项
        new["ports"] = [old["ports"][1], old["ports"][0]] + old["ports"][2:]
        result, _ = run_diff(old, new)
        self.assertEqual(self._paths(result), ["/ports"])
        item = result["changes"][0]
        self.assertEqual(item["before"], switch._canonical(old["ports"]))
        self.assertEqual(item["after"], switch._canonical(new["ports"]))
        self.assertNotEqual(item["before"], item["after"])

    def test_array_length_change_single_item(self):
        old = base_config()
        new = copy.deepcopy(old)
        new["acl"] = [allow_rule(), allow_rule()]
        result, _ = run_diff(old, new)
        self.assertEqual(self._paths(result), ["/acl"])
        self.assertEqual(len(result["changes"][0]["before"]), 1)
        self.assertEqual(len(result["changes"][0]["after"]), 2)

    def test_deep_array_path_inside_object(self):
        old = base_config()
        new = copy.deepcopy(old)
        new["qos"]["map"] = [3, 2, 1, 0, 3, 2, 1, 0]
        result, _ = run_diff(old, new)
        self.assertEqual(
            result["changes"],
            [
                {
                    "path": "/qos/map",
                    "before": [0, 1, 2, 3, 0, 1, 2, 3],
                    "after": [3, 2, 1, 0, 3, 2, 1, 0],
                }
            ],
        )

    def test_changes_depth_first_unicode_codepoint_order(self):
        old = base_config()
        new = copy.deepcopy(old)
        new["age"] = 50
        new["delay"] = 2
        new["storm"]["hold"] = 11
        # 根键码点序：age < delay < storm；storm 内部差异随 storm 整段输出
        result, _ = run_diff(old, new)
        self.assertEqual(self._paths(result), ["/age", "/delay", "/storm/hold"])

    def test_object_subtree_order_between_arrays(self):
        old = base_config()
        new = copy.deepcopy(old)
        new["age"] = 1
        new["security"][0]["limit"] = 9
        # 根键码点序 age < security：先标量后数组
        result, _ = run_diff(old, new)
        self.assertEqual(self._paths(result), ["/age", "/security"])
        item = result["changes"][1]
        self.assertEqual(item["before"][0]["limit"], 2)
        self.assertEqual(item["after"][0]["limit"], 9)

    def test_before_after_canonicalized(self):
        # 输入对象键序任意；before/after 仍按键序规范化输出
        old = {key: base_config()[key] for key in reversed(list(base_config()))}
        new = copy.deepcopy(old)
        new["age"] = 1
        result, raw = run_diff(old, new)
        item = result["changes"][0]
        self.assertEqual(item, {"path": "/age", "before": 100, "after": 1})
        # 项内键序恒为 path,before,after
        self.assertIn(b'"path":"/age","before":100,"after":1', raw)

    def test_special_characters_in_value_not_escaped(self):
        # RFC6901 只转义引用令牌（键）；字符串值中的 / 与 ~ 原样输出。
        # name 位于 lags 数组内，数组整体比较 -> 差异项 path 为 /lags
        old = base_config()
        new = copy.deepcopy(old)
        new["lags"][0]["name"] = "a/b~c"
        result, raw = run_diff(old, new)
        self.assertEqual(self._paths(result), ["/lags"])
        self.assertEqual(result["changes"][0]["before"][0]["name"], "L1")
        self.assertEqual(result["changes"][0]["after"][0]["name"], "a/b~c")
        self.assertIn(b'"name":"a/b~c"', raw)  # 值内 / ~ 不按 pointer 转义

    def test_unicode_value_emitted_raw_utf8(self):
        old = base_config()
        new = copy.deepcopy(old)
        new["lags"][0]["name"] = "L1口"
        _, raw = run_diff(old, new)
        self.assertIn('"name":"L1口"'.encode("utf-8"), raw)
        self.assertNotIn(b"\\u", raw)  # ensure_ascii=False


class JsonPointerEscapeTest(unittest.TestCase):
    def test_tilde_before_slash(self):
        # ~0 必须先于 ~1，避免二次转义歧义
        self.assertEqual(switch._json_pointer_token("a/b"), "a~1b")
        self.assertEqual(switch._json_pointer_token("a~b"), "a~0b")
        self.assertEqual(switch._json_pointer_token("~/"), "~0~1")
        self.assertEqual(switch._json_pointer_token("/~"), "~1~0")

    def test_diff_type_mismatch_is_whole_scalar_item(self):
        # 合法配置间不可达类型差异；直接核对比较契约（bool 不等于 int）
        changes = []
        switch._diff_collect({"k": 1}, {"k": True}, "", changes)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0], {"path": "/k", "before": 1, "after": True})

    def test_diff_path_escapes_special_object_key(self):
        # 合法配置键集固定为 ASCII，故键含 /、~ 的指针转义只能在此直接核对
        changes = []
        switch._diff_collect(
            {"a/b": {"~c": 1}}, {"a/b": {"~c": 2}}, "", changes
        )
        self.assertEqual(
            changes,
            [{"path": "/a~1b/~0c", "before": 1, "after": 2}],
        )

    def test_missing_object_key_items(self):
        changes = []
        switch._diff_collect({"a": 1, "b": 2}, {"a": 1}, "", changes)
        self.assertEqual(
            changes, [{"path": "/b", "before": 2, "after": None}]
        )
        changes = []
        switch._diff_collect({"a": 1}, {"a": 1, "c": [1]}, "", changes)
        self.assertEqual(
            changes, [{"path": "/c", "before": None, "after": [1]}]
        )


class ConfigDiffUsageTest(unittest.TestCase):
    def _run_raw(self, argv):
        return subprocess.run(
            [sys.executable, SWITCH] + argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_arg_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "a.json")
            with open(path, "wb") as handle:
                handle.write(b"{}")
            for argv in (
                ["config-diff"],
                ["config-diff", path],
                ["config-diff", path, path, "extra"],
            ):
                with self.subTest(argv=argv):
                    proc = self._run_raw(argv)
                    self.assertEqual(proc.returncode, 2)
                    self.assertEqual(proc.stdout, b"")
                    self.assertEqual(proc.stderr,
                                     b'{"error":"usage"}\n')

    def test_old_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            existing = _write(tmp, "new.json",
                              json.dumps(base_config()).encode())
            proc = self._run_raw(
                ["config-diff", os.path.join(tmp, "nope"), existing]
            )
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b'{"error":"file_not_found"}\n')

    def test_new_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            existing = _write(tmp, "old.json",
                              json.dumps(base_config()).encode())
            proc = self._run_raw(
                ["config-diff", existing, os.path.join(tmp, "nope")]
            )
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b'{"error":"file_not_found"}\n')


class ConfigDiffInvalidTest(unittest.TestCase):
    def _expect_invalid(self, old_raw, new_raw):
        code, out, err = run_cli(old_raw, new_raw)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')

    def test_old_invalid_json(self):
        self._expect_invalid(b"{", json.dumps(base_config()).encode())

    def test_new_invalid_json(self):
        self._expect_invalid(json.dumps(base_config()).encode(), b"[}")

    def test_non_utf8(self):
        self._expect_invalid(b"\xff\xfe", json.dumps(base_config()).encode())

    def test_duplicate_object_key(self):
        raw = b'{"age":1,"age":2}'
        self._expect_invalid(raw, json.dumps(base_config()).encode())

    def test_valid_json_wrong_type(self):
        self._expect_invalid(b"123", json.dumps(base_config()).encode())

    def test_old_not_security_contract(self):
        bad = base_config()
        del bad["qos"]
        self._expect_invalid(
            json.dumps(bad).encode(), json.dumps(base_config()).encode()
        )

    def test_new_not_security_contract(self):
        bad = copy.deepcopy(base_config())
        bad["security"][0]["limit"] = -1  # 合法 JSON，违反端口安全契约
        self._expect_invalid(
            json.dumps(base_config()).encode(), json.dumps(bad).encode()
        )

    def test_both_validated_even_if_identical_bytes(self):
        bad = b'{"age":1}'
        self._expect_invalid(bad, bad)


class ConfigDiffLimitTest(unittest.TestCase):
    LIMIT = 1024 * 1024

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.old = os.path.join(d, "old.json")
        self.new = os.path.join(d, "new.json")
        base = json.dumps(base_config(), separators=(",", ":")).encode()
        self.pad = self.LIMIT - len(base)
        with open(self.old, "wb") as handle:
            handle.write(base + b" " * self.pad)
        with open(self.new, "wb") as handle:
            handle.write(base + b" " * self.pad)

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self):
        proc = subprocess.run(
            [sys.executable, SWITCH, "config-diff", self.old, self.new],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return proc.returncode, proc.stdout, proc.stderr

    def test_exactly_limit_is_legal(self):
        self.assertEqual(os.path.getsize(self.old), self.LIMIT)
        code, out, err = self._run()
        self.assertEqual((code, err), (0, b""))
        self.assertEqual(out, b'{"equal":true,"changes":[]}\n')

    def test_old_one_byte_over(self):
        with open(self.old, "ab") as handle:
            handle.write(b" ")
        code, out, err = self._run()
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"input_limit"}\n')

    def test_new_one_byte_over(self):
        with open(self.new, "ab") as handle:
            handle.write(b"\n")
        code, out, err = self._run()
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"input_limit"}\n')

    def test_input_limit_precedes_invalid_json(self):
        # OLD 超限即停：即便内容不是合法 JSON 也报 input_limit
        with open(self.old, "wb") as handle:
            handle.write(b"{" + b" " * self.LIMIT)
        code, out, err = self._run()
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"input_limit"}\n')

    def test_output_limit_in_process(self):
        old = base_config()
        new = copy.deepcopy(old)
        new["age"] = 50
        with tempfile.TemporaryDirectory() as d:
            old_path = _write(d, "a", json.dumps(old).encode())
            new_path = _write(d, "b", json.dumps(new).encode())
            stdout = SimpleNamespace(buffer=io.BytesIO())
            stderr = SimpleNamespace(buffer=io.BytesIO())
            with mock.patch.object(sys, "stdout", stdout), \
                    mock.patch.object(sys, "stderr", stderr), \
                    mock.patch.object(
                        switch, "DEFAULT_MAX_OUTPUT_BYTES", 1
                    ):
                code = switch._cmd_config_diff(old_path, new_path)
        self.assertEqual(code, 5)
        self.assertEqual(stdout.buffer.getvalue(), b"")
        self.assertEqual(stderr.buffer.getvalue(),
                         b'{"error":"output_limit"}\n')


if __name__ == "__main__":
    unittest.main()
