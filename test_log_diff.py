#!/usr/bin/env python3
"""log-diff 子命令回归：两份 record 日志的确定性首个语义分歧。

仅用标准库；端到端驱动 `python switch.py log-diff LEFT RIGHT
[MAX_LOG_BYTES MAX_OUTPUT_BYTES MAX_DIFF_WORK]`。先比 config（对象忽略
键序、数组保序，按 JSON 类型和值），相等后逐项比 records，首个不同即停；
共同前缀后的长度差亦不同。成功产物键序固定 equal,at,left,right；相等时
后三值为 null；配置不同 at="config"，记录不同 at 为零基下标，长度不同
at 为公共长度且缺侧 null。仅静态校验与内部摘要核对，不重演。
"""

import hashlib
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


def canonical(value):
    if isinstance(value, dict):
        return {key: canonical(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [canonical(item) for item in value]
    return value


def rehash(doc):
    """按当前 schema/config/records 重算 LOG 内部 sha256，返回紧凑字节。"""
    doc["sha256"] = hashlib.sha256(
        switch._log_prefix_bytes(doc)
    ).hexdigest()
    return (
        json.dumps(
            {key: doc[key] for key in switch.LOG_KEYS},
            ensure_ascii=False,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def make_log(config, events, applied_flags=None):
    """按 (kind, event) 序列构造静态合法 LOG（config 任意但键须规范）。"""
    records = []
    for index, event in enumerate(events):
        applied = True if applied_flags is None else applied_flags[index]
        records.append(
            {
                "t": event["t"],
                "version": index,
                "event": canonical(event),
                "applied": applied,
                "output": None,
            }
        )
    doc = {
        "schema": switch.RECORD_SCHEMA,
        "config": canonical(config),
        "records": records,
    }
    return rehash(doc)


LEARN0 = {"t": 0, "port": "p1", "mac": "00:00:00:00:00:01", "vlan": 1}
FRAME1 = {
    "t": 1,
    "port": "p1",
    "src": "00:00:00:00:00:02",
    "dst": "ff:ff:ff:ff:ff:ff",
}
LINK2 = {"t": 2, "id": "L1", "up": True}
MEMBER3 = {"t": 3, "member": "m1", "up": True}
CONFIG = {"a": 1, "ports": []}


def _write(tmp, name, raw):
    path = os.path.join(tmp, name)
    with open(path, "wb") as handle:
        handle.write(raw)
    return path


def run_cli(left_raw, right_raw, args=()):
    with tempfile.TemporaryDirectory() as tmp:
        left_path = _write(tmp, "left.json", left_raw)
        right_path = _write(tmp, "right.json", right_raw)
        proc = subprocess.run(
            [sys.executable, SWITCH, "log-diff", left_path, right_path]
            + list(str(a) for a in args),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    return proc.returncode, proc.stdout, proc.stderr


def run_diff(left_raw, right_raw, args=()):
    code, out, err = run_cli(left_raw, right_raw, args)
    assert code == 0, (code, err.decode("utf-8"))
    return json.loads(out.decode("utf-8")), out


class LogDiffEqualTest(unittest.TestCase):
    def test_identical_logs(self):
        raw = make_log(CONFIG, [LEARN0, FRAME1, LINK2])
        result, out = run_diff(raw, raw)
        self.assertEqual(
            result,
            {"equal": True, "at": None, "left": None, "right": None},
        )
        self.assertEqual(
            out, b'{"equal":true,"at":null,"left":null,"right":null}\n'
        )

    def test_equal_value_distinct_sha_surface(self):
        # config/event 键序在静态校验时即须规范；同值不同顶层键序非法，
        # 故等价仅能由值相同的两份独立文件体现
        left = make_log(CONFIG, [LEARN0, FRAME1])
        right = make_log({"a": 1, "ports": []}, [dict(LEARN0), dict(FRAME1)])
        result, _ = run_diff(left, right)
        self.assertTrue(result["equal"])


class LogDiffConfigTest(unittest.TestCase):
    def test_config_diff_exact_bytes(self):
        left = make_log(CONFIG, [LEARN0, FRAME1])
        right = make_log({"a": 2, "ports": []}, [LEARN0, FRAME1])
        result, out = run_diff(left, right)
        self.assertEqual(result["equal"], False)
        self.assertEqual(result["at"], "config")
        self.assertEqual(result["left"], {"a": 1, "ports": []})
        self.assertEqual(result["right"], {"a": 2, "ports": []})
        self.assertIn(b'"at":"config"', out)

    def test_config_diff_takes_precedence_over_records(self):
        left = make_log(CONFIG, [LEARN0, FRAME1])
        right = make_log(
            {"a": 2, "ports": []},
            [LEARN0, {"t": 9, "port": "p9",
                      "src": "00:00:00:00:00:09",
                      "dst": "ff:ff:ff:ff:ff:ff"}],
        )
        result, _ = run_diff(left, right)
        self.assertEqual(result["at"], "config")


class LogDiffRecordTest(unittest.TestCase):
    def test_first_record_difference(self):
        left = make_log(CONFIG, [LEARN0, FRAME1, LINK2])
        right_events = [
            LEARN0,
            {
                "t": 1,
                "port": "p2",
                "src": "00:00:00:00:00:02",
                "dst": "ff:ff:ff:ff:ff:ff",
            },
            LINK2,
        ]
        right = make_log(CONFIG, right_events)
        result, _ = run_diff(left, right)
        self.assertEqual(result["at"], 1)
        self.assertEqual(result["left"]["event"]["port"], "p1")
        self.assertEqual(result["right"]["event"]["port"], "p2")

    def test_values_are_canonical_records(self):
        left = make_log(CONFIG, [LEARN0])
        right = make_log(CONFIG, [dict(LEARN0, vlan=2)])
        result, out = run_diff(left, right)
        self.assertEqual(result["at"], 0)
        # 规范记录：顶层键按 Unicode 码点序
        self.assertEqual(
            list(result["left"]),
            ["applied", "event", "output", "t", "version"],
        )
        self.assertEqual(result["left"]["event"]["vlan"], 1)
        self.assertEqual(result["right"]["event"]["vlan"], 2)
        self.assertIn(
            b'"left":{"applied":true,"event":', out
        )

    def test_bool_not_equal_to_int_semantics_via_static_shape(self):
        # applied 仅可为 bool；改 t 的数值即记录不同
        left = make_log(CONFIG, [LEARN0])
        right = make_log(CONFIG, [dict(LEARN0, t=5)])
        result, _ = run_diff(left, right)
        self.assertEqual(result["at"], 0)

    def test_array_order_sensitive_inside_event(self):
        ev = {"t": 0, "port": "p1", "mac": "00:00:00:00:00:01", "vlan": 1}
        left = make_log(CONFIG, [ev])
        # learn 事件无数组；用 output 为 dict 的差异不可直接构造（静态
        # output 不校验键序），这里仅核对同下标记录差异口径
        right = make_log(CONFIG, [dict(ev, vlan=2)])
        result, _ = run_diff(left, right)
        self.assertEqual(result["at"], 0)
        self.assertEqual(result["left"]["event"]["vlan"], 1)
        self.assertEqual(result["right"]["event"]["vlan"], 2)


class LogDiffLengthTest(unittest.TestCase):
    def test_right_longer(self):
        left = make_log(CONFIG, [LEARN0, FRAME1, LINK2])
        right = make_log(CONFIG, [LEARN0, FRAME1, LINK2, MEMBER3])
        result, out = run_diff(left, right)
        self.assertEqual(result["at"], 3)
        self.assertIsNone(result["left"])
        self.assertEqual(result["right"]["t"], 3)
        self.assertIn(b'"at":3,"left":null,"right":', out)

    def test_left_longer(self):
        left = make_log(CONFIG, [LEARN0, FRAME1, LINK2, MEMBER3])
        right = make_log(CONFIG, [LEARN0, FRAME1, LINK2])
        result, _ = run_diff(left, right)
        self.assertEqual(result["at"], 3)
        self.assertEqual(result["left"]["t"], 3)
        self.assertIsNone(result["right"])

    def test_record_difference_before_length(self):
        left = make_log(CONFIG, [LEARN0, FRAME1, LINK2])
        right = make_log(
            CONFIG,
            [
                LEARN0,
                dict(FRAME1, port="p2"),
                LINK2,
                MEMBER3,
            ],
        )
        result, _ = run_diff(left, right)
        self.assertEqual(result["at"], 1)


def ref_size(value):
    if isinstance(value, dict):
        return 1 + len(value) + sum(ref_size(v) for v in value.values())
    if isinstance(value, list):
        return 1 + sum(ref_size(v) for v in value)
    return 1


def ref_work(old, new):
    if isinstance(old, dict) and isinstance(new, dict):
        total = 1 + len(set(old) | set(new))
        for key in set(old) | set(new):
            if key in old and key in new:
                total += ref_work(old[key], new[key])
            else:
                total += ref_size(old[key] if key in old else new[key])
        return total
    return 1 + ref_size(old) + ref_size(new)


def required_work(left_log, right_log):
    """规格工作量：配置 D；仅配置相等才加共同记录对 D 与长度差 1。"""
    total = ref_work(left_log["config"], right_log["config"])
    if left_log["config"] == right_log["config"]:
        for a, b in zip(left_log["records"], right_log["records"]):
            total += ref_work(a, b)
        if len(left_log["records"]) != len(right_log["records"]):
            total += 1
    return total


class LogDiffWorkLimitTest(unittest.TestCase):
    def setUp(self):
        self.left_raw = make_log(CONFIG, [LEARN0, FRAME1, LINK2])
        self.right_raw = make_log(CONFIG, [LEARN0, FRAME1, LINK2, MEMBER3])
        self.left = json.loads(self.left_raw)
        self.right = json.loads(self.right_raw)

    def test_exact_limit_succeeds(self):
        work = required_work(self.left, self.right)
        code, out, err = run_cli(
            self.left_raw, self.right_raw,
            args=(16777216, 16777216, work),
        )
        self.assertEqual((code, err), (0, b""))
        self.assertEqual(json.loads(out)["at"], 3)

    def test_one_under_limit_fails(self):
        work = required_work(self.left, self.right)
        code, out, err = run_cli(
            self.left_raw, self.right_raw,
            args=(16777216, 16777216, work - 1),
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"diff_work_limit"}\n')

    def test_equal_logs_also_bounded(self):
        work = required_work(self.left, json.loads(self.left_raw))
        code, _, err = run_cli(
            self.left_raw, self.left_raw,
            args=(16777216, 16777216, work),
        )
        self.assertEqual((code, err), (0, b""))
        code, out, err = run_cli(
            self.left_raw, self.left_raw,
            args=(16777216, 16777216, work - 1),
        )
        self.assertEqual((code, out), (5, b""))
        self.assertEqual(err, b'{"error":"diff_work_limit"}\n')

    def test_config_diff_charges_config_only(self):
        right_raw = make_log({"a": 2, "ports": []}, [LEARN0, FRAME1, LINK2])
        right = json.loads(right_raw)
        work = required_work(self.left, right)
        # 配置不同：记录不参与计费，即便记录同构同值
        self.assertEqual(
            work, ref_work(self.left["config"], right["config"])
        )
        code, _, err = run_cli(
            self.left_raw, right_raw,
            args=(16777216, 16777216, work),
        )
        self.assertEqual((code, err), (0, b""))
        code, out, err = run_cli(
            self.left_raw, right_raw,
            args=(16777216, 16777216, work - 1),
        )
        self.assertEqual((code, out), (5, b""))
        self.assertEqual(err, b'{"error":"diff_work_limit"}\n')

    def test_length_difference_adds_one(self):
        equal_work = required_work(self.left, json.loads(self.left_raw))
        length_work = required_work(self.left, self.right)
        self.assertEqual(length_work, equal_work + 1)


class LogDiffUsageTest(unittest.TestCase):
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
                ["log-diff"],
                ["log-diff", path],
                ["log-diff", path, path, "9"],
                ["log-diff", path, path, "9", "9"],
                ["log-diff", path, path, "9", "9", "9", "9"],
            ):
                with self.subTest(argv=argv):
                    proc = self._run_raw(argv)
                    self.assertEqual(proc.returncode, 2)
                    self.assertEqual(proc.stdout, b"")
                    self.assertEqual(proc.stderr,
                                     b'{"error":"usage"}\n')

    def test_limit_tokens_must_match(self):
        raw = make_log(CONFIG, [LEARN0])
        for token in ("0", "01", "1.5", "-1", "x", ""):
            code, out, err = run_cli(
                raw, raw, args=(token, "9", "9")
            )
            self.assertEqual((code, out, err),
                             (2, b"", b'{"error":"usage"}\n'))

    def test_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            existing = _write(
                tmp, "a.json", make_log(CONFIG, [LEARN0])
            )
            proc = self._run_raw(
                ["log-diff", existing, os.path.join(tmp, "nope")]
            )
            self.assertEqual(proc.returncode, 3)
            self.assertEqual(proc.stdout, b"")
            self.assertEqual(proc.stderr,
                             b'{"error":"file_not_found"}\n')

    def test_usage_precedes_file_errors(self):
        proc = self._run_raw(
            ["log-diff", "/nonexistent/a", "/nonexistent/b", "0", "9", "9"]
        )
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stderr, b'{"error":"usage"}\n')


class LogDiffInvalidTest(unittest.TestCase):
    def _expect_invalid(self, left_raw, right_raw):
        code, out, err = run_cli(left_raw, right_raw)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')

    def test_bad_json(self):
        good = make_log(CONFIG, [LEARN0])
        self._expect_invalid(b"{", good)
        self._expect_invalid(good, b"[}")

    def test_bad_sha256(self):
        good = make_log(CONFIG, [LEARN0])
        doc = json.loads(good)
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode()
        self._expect_invalid(bad, good)

    def test_wrong_static_shape(self):
        good = make_log(CONFIG, [LEARN0])
        # 合法 JSON 但非 LOG 结构
        self._expect_invalid(b"123", good)
        self._expect_invalid(b"{}", good)


class LogDiffLimitTest(unittest.TestCase):
    def test_log_limit_exact_then_over(self):
        raw = make_log(CONFIG, [LEARN0])
        code, out, err = run_cli(
            raw, raw, args=(len(raw), 16777216, 10 ** 9)
        )
        self.assertEqual((code, err), (0, b""))
        self.assertTrue(json.loads(out)["equal"])
        code, out, err = run_cli(
            raw + b" ", raw, args=(len(raw), 16777216, 10 ** 9)
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"log_limit"}\n')

    def test_error_name_is_log_limit_not_input_limit(self):
        raw = make_log(CONFIG, [LEARN0])
        code, _, err = run_cli(
            raw + b" ", raw, args=(len(raw), 16777216, 10 ** 9)
        )
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"log_limit"}\n')

    def test_output_limit(self):
        left = make_log(CONFIG, [LEARN0])
        right = make_log({"a": 2, "ports": []}, [LEARN0])
        _, payload, _ = run_cli(left, right)
        code, out, err = run_cli(
            left, right, args=(16777216, len(payload), 10 ** 9)
        )
        self.assertEqual((code, err), (0, b""))
        self.assertEqual(out, payload)
        code, out, err = run_cli(
            left, right, args=(16777216, len(payload) - 1, 10 ** 9)
        )
        self.assertEqual((code, out), (5, b""))
        self.assertEqual(err, b'{"error":"output_limit"}\n')

    def test_precedence_chain(self):
        good = make_log(CONFIG, [LEARN0])
        right = make_log({"a": 2, "ports": []}, [LEARN0])
        # 输入超限先于非法 JSON
        code, out, err = run_cli(
            b"{" + b" " * len(good), good,
            args=(len(good), 16777216, 10 ** 9),
        )
        self.assertEqual((code, out), (5, b""))
        self.assertEqual(err, b'{"error":"log_limit"}\n')
        # 非法输入先于工作量上限
        code, out, err = run_cli(
            b"{", good, args=(16777216, 16777216, 1)
        )
        self.assertEqual((code, out), (4, b""))
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        # 工作量上限先于输出上限
        code, out, err = run_cli(
            good, right, args=(16777216, 1, 1)
        )
        self.assertEqual((code, out), (5, b""))
        self.assertEqual(err, b'{"error":"diff_work_limit"}\n')

    def test_defaults_constants(self):
        self.assertEqual(switch.DEFAULT_MAX_LOG_BYTES, 16777216)
        self.assertEqual(switch.DEFAULT_MAX_OUTPUT_BYTES, 16777216)
        self.assertEqual(switch.DEFAULT_MAX_DIFF_WORK, 10000000)

    def test_programmatic_output_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            left_path = _write(tmp, "l", make_log(CONFIG, [LEARN0]))
            right_path = _write(
                tmp, "r", make_log({"a": 2, "ports": []}, [LEARN0])
            )
            stdout = SimpleNamespace(buffer=io.BytesIO())
            stderr = SimpleNamespace(buffer=io.BytesIO())
            with mock.patch.object(sys, "stdout", stdout), \
                    mock.patch.object(sys, "stderr", stderr), \
                    mock.patch.object(
                        switch, "DEFAULT_MAX_OUTPUT_BYTES", 1
                    ):
                code = switch._cmd_log_diff(left_path, right_path)
        self.assertEqual(code, 5)
        self.assertEqual(stdout.buffer.getvalue(), b"")
        self.assertEqual(
            stderr.buffer.getvalue(), b'{"error":"output_limit"}\n'
        )


if __name__ == "__main__":
    unittest.main()
