#!/usr/bin/env python3
"""config-diff 子命令回归：两份 port-security 配置的规范化深比较。

仅用标准库；通过 `python switch.py config-diff OLD NEW` 端到端驱动，
另以白盒方式锁定 RFC6901 转义、差异遍历顺序与输出上限分支。
"""

import contextlib
import copy
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SWITCH = os.path.join(HERE, "switch.py")


def _load_switch():
    spec = importlib.util.spec_from_file_location("switch_under_test", SWITCH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


switch = _load_switch()


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
            {"port": p, "limit": 2, "action": "drop", "static": []}
            for p in ("p1", "p2", "p3", "p4", "p5")
        ],
    }


def scramble(value):
    """递归以逆键序重建对象；内容不变，仅键序变化。"""
    if isinstance(value, dict):
        return {k: scramble(value[k]) for k in reversed(list(value))}
    if isinstance(value, list):
        return [scramble(item) for item in value]
    return value


def run_cli(old, new, files=None):
    """files: {相对名: bytes}；old/new 为其中相对名，返回码与标准流。"""
    with tempfile.TemporaryDirectory() as tmp:
        paths = {}
        for name, content in (files or {}).items():
            path = os.path.join(tmp, name)
            with open(path, "wb") as handle:
                handle.write(content)
            paths[name] = path
        argv = [
            sys.executable,
            SWITCH,
            "config-diff",
            paths.get(old, os.path.join(tmp, old)),
            paths.get(new, os.path.join(tmp, new)),
        ]
        proc = subprocess.run(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
    return proc.returncode, proc.stdout, proc.stderr


def diff_configs(old, new, *, old_bytes=None, new_bytes=None):
    files = {
        "old.json": old_bytes
        if old_bytes is not None
        else json.dumps(old, ensure_ascii=False).encode("utf-8"),
        "new.json": new_bytes
        if new_bytes is not None
        else json.dumps(new, ensure_ascii=False).encode("utf-8"),
    }
    code, out, err = run_cli("old.json", "new.json", files)
    assert code == 0, (code, out, err)
    return out


def pad_to(raw, size):
    """在末个 '}' 前填充空白，使字节数恰为 size（须不小于原长）。"""
    return raw[:-1] + b" " * (size - len(raw)) + raw[-1:]


class ConfigDiffEqualTest(unittest.TestCase):
    def test_identical_configs(self):
        config = base_config()
        out = diff_configs(config, copy.deepcopy(config))
        self.assertEqual(out, b'{"equal":true,"changes":[]}\n')

    def test_key_order_ignored_recursively(self):
        config = base_config()
        out = diff_configs(config, scramble(config))
        self.assertEqual(out, b'{"equal":true,"changes":[]}\n')
        # 反向比较同样相等
        out = diff_configs(scramble(config), config)
        self.assertEqual(out, b'{"equal":true,"changes":[]}\n')

    def test_equal_false_when_scalar_differs(self):
        old = base_config()
        new = copy.deepcopy(old)
        new["age"] = 50
        doc = json.loads(diff_configs(old, new))
        self.assertFalse(doc["equal"])
        self.assertEqual(
            doc["changes"], [{"path": "/age", "before": 100, "after": 50}]
        )

    def test_nested_scalar_path(self):
        old = base_config()
        new = copy.deepcopy(old)
        new["storm"]["limits"]["broadcast"] = 99
        doc = json.loads(diff_configs(old, new))
        self.assertEqual(
            doc["changes"],
            [
                {
                    "path": "/storm/limits/broadcast",
                    "before": 100,
                    "after": 99,
                }
            ],
        )

    def test_changes_sorted_depth_first_by_codepoint(self):
        old = base_config()
        new = copy.deepcopy(old)
        new["delay"] = 2  # /delay
        new["age"] = 50  # /age（码点在 delay 前）
        new["storm"]["hold"] = 9  # /storm/hold
        doc = json.loads(diff_configs(old, new))
        self.assertEqual(
            [item["path"] for item in doc["changes"]],
            ["/age", "/delay", "/storm/hold"],
        )

    def test_array_compared_whole_and_order_sensitive(self):
        old = base_config()
        # qos.map 为标量数组：逐元素不同 -> 仅 /qos/map 一项，值为整个数组
        new = copy.deepcopy(old)
        new["qos"]["map"] = [0, 1, 2, 3, 0, 1, 2, 0]
        doc = json.loads(diff_configs(old, new))
        self.assertEqual(
            doc["changes"],
            [
                {
                    "path": "/qos/map",
                    "before": [0, 1, 2, 3, 0, 1, 2, 3],
                    "after": [0, 1, 2, 3, 0, 1, 2, 0],
                }
            ],
        )
        # 数组顺序敏感：仅交换两元素也算整组不同
        new2 = copy.deepcopy(old)
        new2["qos"]["weights"] = [1, 1, 1, 2]
        old2 = copy.deepcopy(old)
        old2["qos"]["weights"] = [2, 1, 1, 1]
        doc = json.loads(diff_configs(old2, new2))
        self.assertEqual(
            doc["changes"],
            [
                {
                    "path": "/qos/weights",
                    "before": [2, 1, 1, 1],
                    "after": [1, 1, 1, 2],
                }
            ],
        )

    def test_array_of_objects_emitted_whole(self):
        # security 元素变化不下钻到 /security/0/...，整体一项
        old = base_config()
        new = copy.deepcopy(old)
        new["security"][0]["limit"] = 1
        doc = json.loads(diff_configs(old, new))
        self.assertEqual(len(doc["changes"]), 1)
        change = doc["changes"][0]
        self.assertEqual(change["path"], "/security")
        self.assertEqual(change["before"], old["security"])
        self.assertEqual(change["after"], new["security"])

    def test_before_after_canonical_even_with_scrambled_input(self):
        old = scramble(base_config())  # 键序逆序
        new = copy.deepcopy(old)
        # 找到 p1 条目（dict 键序已乱）并改 limit，触发 /security 整组
        for entry in new["security"]:
            if entry["port"] == "p1":
                entry["limit"] = 1
        out = diff_configs(old, new)
        doc = json.loads(out)
        change = next(item for item in doc["changes"] if item["path"] == "/security")
        canon = json.dumps(
            change["before"],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        self.assertIn(('"before":' + canon).encode("utf-8"), out)
        # 每个 change 项键序恒为 path,before,after
        for item in doc["changes"]:
            self.assertEqual(list(item), ["path", "before", "after"])

    def test_direction_before_after_swapped(self):
        old = base_config()
        new = copy.deepcopy(old)
        new["age"] = 50
        forward = json.loads(diff_configs(old, new))["changes"][0]
        backward = json.loads(diff_configs(new, old))["changes"][0]
        self.assertEqual(forward["before"], backward["after"])
        self.assertEqual(forward["after"], backward["before"])
        self.assertEqual(forward["path"], backward["path"])


class ConfigDiffEncodingTest(unittest.TestCase):
    def test_compact_canonical_output_with_lf(self):
        old = base_config()
        new = copy.deepcopy(old)
        new["age"] = 50
        out = diff_configs(old, new)
        self.assertTrue(out.endswith(b"\n"))
        self.assertFalse(out.endswith(b"\n\n"))
        text = out.decode("utf-8")
        self.assertNotIn(", ", text)
        self.assertNotIn('": ', text)
        # 顶层键序 equal,changes
        self.assertLess(text.index('"equal"'), text.index('"changes"'))
        json.loads(text)

    def test_unicode_emitted_unescaped(self):
        old = base_config()
        uni = "端~口/1"
        for port in old["ports"]:
            if port["name"] == "p1":
                port["name"] = uni
        old["mirror"]["sources"] = [uni]
        for entry in old["security"]:
            if entry["port"] == "p1":
                entry["port"] = uni
        new = copy.deepcopy(old)
        for entry in new["security"]:
            if entry["port"] == uni:
                entry["limit"] = 9  # 触发含 Unicode 端口名的 /security 项
        out = diff_configs(old, new)
        self.assertIn(uni.encode("utf-8"), out)
        self.assertNotIn(b"\\u", out)


class ConfigDiffPrimitiveTest(unittest.TestCase):
    """白盒：RFC6901 转义、遍历顺序、键集合分叉与类型比较。"""

    def test_pointer_escaping(self):
        changes = switch._json_diff(
            {"a/b": {"m~n": 1}}, {"a/b": {"m~n": 2}}
        )
        self.assertEqual(
            changes,
            [{"path": "/a~1b/m~0n", "before": 1, "after": 2}],
        )

    def test_object_key_set_fork_emits_subtree_once(self):
        changes = switch._json_diff({"a": 1}, {"b": 1})
        self.assertEqual(
            changes, [{"path": "", "before": {"a": 1}, "after": {"b": 1}}]
        )

    def test_array_order_sensitive_whole_value(self):
        changes = switch._json_diff({"x": [1, 2]}, {"x": [2, 1]})
        self.assertEqual(
            changes, [{"path": "/x", "before": [1, 2], "after": [2, 1]}]
        )

    def test_bool_not_equal_to_int(self):
        changes = switch._json_diff(True, 1)
        self.assertEqual(
            changes, [{"path": "", "before": True, "after": 1}]
        )

    def test_null_typed(self):
        self.assertEqual(switch._json_diff(None, None), [])
        self.assertEqual(
            switch._json_diff(None, 0),
            [{"path": "", "before": None, "after": 0}],
        )

    def test_changes_traverse_sorted_keys(self):
        changes = switch._json_diff(
            {"b": [1], "a": [1]}, {"b": [2], "a": [2]}
        )
        self.assertEqual([item["path"] for item in changes], ["/a", "/b"])


class ConfigDiffUsageTest(unittest.TestCase):
    def _raw(self, *argv):
        proc = subprocess.run(
            [sys.executable, SWITCH, *argv],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return proc.returncode, proc.stdout, proc.stderr

    def test_wrong_arg_counts(self):
        for argv in (
            ("config-diff",),
            ("config-diff", "only-one"),
            ("config-diff", "a", "b", "extra"),
        ):
            with self.subTest(argv=argv):
                code, out, err = self._raw(*argv)
                self.assertEqual(code, 2)
                self.assertEqual(out, b"")
                self.assertEqual(err, b'{"error":"usage"}\n')

    def test_unknown_command_still_usage(self):
        code, out, err = self._raw("frobnicate", "a", "b")
        self.assertEqual(code, 2)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"usage"}\n')


class ConfigDiffFileTest(unittest.TestCase):
    def test_old_missing(self):
        files = {"new.json": json.dumps(base_config()).encode()}
        code, out, err = run_cli("missing.json", "new.json", files)
        self.assertEqual((code, out, err), (3, b"", b'{"error":"file_not_found"}\n'))

    def test_new_missing(self):
        files = {"old.json": json.dumps(base_config()).encode()}
        code, out, err = run_cli("old.json", "missing.json", files)
        self.assertEqual((code, out, err), (3, b"", b'{"error":"file_not_found"}\n'))

    def test_both_opened_before_reading(self):
        # OLD 超字节上限但 NEW 不存在：先开两文件 -> file_not_found(3)，
        # 不进入读取判定
        old = pad_to(json.dumps(base_config()).encode(), 1048576) + b" "
        files = {"old.json": old}
        code, out, err = run_cli("old.json", "nope.json", files)
        self.assertEqual((code, err), (3, b'{"error":"file_not_found"}\n'))
        self.assertEqual(out, b"")


class ConfigDiffInvalidTest(unittest.TestCase):
    def test_invalid_json(self):
        files = {"old.json": b"{", "new.json": json.dumps(base_config()).encode()}
        code, out, err = run_cli("old.json", "new.json", files)
        self.assertEqual((code, out, err), (4, b"", b'{"error":"invalid_input"}\n'))

    def test_non_utf8(self):
        files = {"old.json": b"\xff\xff", "new.json": json.dumps(base_config()).encode()}
        code, out, err = run_cli("old.json", "new.json", files)
        self.assertEqual((code, out, err), (4, b"", b'{"error":"invalid_input"}\n'))

    def test_semantically_bad_old(self):
        bad = base_config()
        bad["age"] = -1
        files = {
            "old.json": json.dumps(bad).encode(),
            "new.json": json.dumps(base_config()).encode(),
        }
        code, out, err = run_cli("old.json", "new.json", files)
        self.assertEqual((code, out, err), (4, b"", b'{"error":"invalid_input"}\n'))

    def test_semantically_bad_new(self):
        bad = base_config()
        del bad["qos"]
        files = {
            "old.json": json.dumps(base_config()).encode(),
            "new.json": json.dumps(bad).encode(),
        }
        code, out, err = run_cli("old.json", "new.json", files)
        self.assertEqual((code, out, err), (4, b"", b'{"error":"invalid_input"}\n'))


class ConfigDiffInputLimitTest(unittest.TestCase):
    def test_exactly_limit_is_legal(self):
        raw = pad_to(json.dumps(base_config()).encode(), 1048576)
        self.assertEqual(len(raw), 1048576)
        files = {"old.json": raw, "new.json": raw}
        code, out, err = run_cli("old.json", "new.json", files)
        self.assertEqual(code, 0, err)
        self.assertEqual(out, b'{"equal":true,"changes":[]}\n')

    def test_old_one_byte_over(self):
        over = pad_to(json.dumps(base_config()).encode(), 1048576) + b" "
        files = {
            "old.json": over,
            "new.json": json.dumps(base_config()).encode(),
        }
        code, out, err = run_cli("old.json", "new.json", files)
        self.assertEqual((code, out, err), (5, b"", b'{"error":"input_limit"}\n'))

    def test_new_one_byte_over(self):
        over = pad_to(json.dumps(base_config()).encode(), 1048576) + b" "
        files = {
            "old.json": json.dumps(base_config()).encode(),
            "new.json": over,
        }
        code, out, err = run_cli("old.json", "new.json", files)
        self.assertEqual((code, out, err), (5, b"", b'{"error":"input_limit"}\n'))

    def test_old_read_before_new(self):
        # OLD 超限时不再读取 NEW：NEW 即便非法也仍报 input_limit
        over = pad_to(json.dumps(base_config()).encode(), 1048576) + b" "
        files = {"old.json": over, "new.json": b"not json at all but long" * 4}
        code, out, err = run_cli("old.json", "new.json", files)
        self.assertEqual((code, out, err), (5, b"", b'{"error":"input_limit"}\n'))


class ConfigDiffOutputLimitTest(unittest.TestCase):
    """两份 ≤1MiB 的合法配置规范化后不可能超过 16MiB；白盒锁定分支。"""

    def test_output_limit_branch(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_path = os.path.join(tmp, "old.json")
            new_path = os.path.join(tmp, "new.json")
            with open(old_path, "wb") as handle:
                handle.write(json.dumps(base_config()).encode())
            with open(new_path, "wb") as handle:
                handle.write(json.dumps(base_config()).encode())
            original = switch.CONFIG_DIFF_MAX_OUTPUT
            err_buffer = io.BytesIO()
            fake_stderr = types.SimpleNamespace(buffer=err_buffer)
            try:
                switch.CONFIG_DIFF_MAX_OUTPUT = 1
                with contextlib.redirect_stderr(fake_stderr):
                    code = switch._cmd_config_diff(old_path, new_path)
            finally:
                switch.CONFIG_DIFF_MAX_OUTPUT = original
            self.assertEqual(code, 5)
            self.assertEqual(
                err_buffer.getvalue(), b'{"error":"output_limit"}\n'
            )


if __name__ == "__main__":
    unittest.main()
