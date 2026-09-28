#!/usr/bin/env python3
"""log-filter 子命令回归：静态过滤 LOG 记录，不重演、不推导。

仅用标准库；端到端驱动 `python switch.py log-filter LOG START END APPLIED
[MAX_LOG_BYTES MAX_OUTPUT_BYTES]`。成功产物键序固定为
schema,source_sha256,records,sha256，末项为前三键紧凑 UTF-8 加 LF 的
sha256；记录原样、原序保留（t 闭区间且 applied 匹配）。
"""

import copy
import hashlib
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
from test_record import base_config  # noqa: E402
from test_record import frame  # noqa: E402
from test_record import record  # noqa: E402


def log_doc(log_bytes):
    return json.loads(log_bytes.decode("utf-8"))


def rehash(doc):
    """按当前 schema/config/records 重算 LOG 内部 sha256，返回紧凑字节。"""
    doc["sha256"] = hashlib.sha256(
        switch._log_prefix_bytes(doc)
    ).hexdigest()
    return (
        json.dumps(
            {key: doc[key] for key in switch.LOG_KEYS},
            ensure_ascii=False, separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def mixed_log():
    """三记录日志，applied 形为 True/False/True（中段改为 false 并重算）。"""
    events = [
        frame(0, "p1", "00:00:00:00:00:01"),
        frame(1, "p2", "00:00:00:00:00:02"),
        frame(2, "p3", "00:00:00:00:00:03"),
    ]
    _, log_bytes = record(base_config(), events)
    doc = log_doc(log_bytes)
    doc["records"][1]["applied"] = False
    return rehash(doc)


def digest_of(doc):
    prefix = {
        "schema": doc["schema"],
        "source_sha256": doc["source_sha256"],
        "records": doc["records"],
    }
    raw = (
        json.dumps(prefix, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def run_filter(log_bytes, *args, extra_files=None):
    """写 in.log（可附 extra 文件），原样透传参数（含 *），回读 LOG。"""
    with tempfile.TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "in.log")
        with open(log_path, "wb") as handle:
            handle.write(log_bytes)
        for name, content in (extra_files or {}).items():
            with open(os.path.join(tmp, name), "wb") as handle:
                handle.write(content)
        proc = subprocess.run(
            [sys.executable, SWITCH, "log-filter", log_path, *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        with open(log_path, "rb") as handle:
            after = handle.read()
    return proc.returncode, proc.stdout, proc.stderr, after


class HappyPathTests(unittest.TestCase):
    def test_star_keeps_all_with_fixed_key_order_and_digest(self):
        log_bytes = mixed_log()
        code, out, err, after = run_filter(log_bytes, "*", "*", "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertTrue(out.endswith(b"\n"))
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(
            list(doc), ["schema", "source_sha256", "records", "sha256"]
        )
        source = log_doc(log_bytes)
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["source_sha256"], source["sha256"])
        self.assertEqual(doc["records"], source["records"])
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_closed_interval_is_inclusive_and_order_preserved(self):
        log_bytes = mixed_log()
        code, out, err, _ = run_filter(log_bytes, "1", "2", "*")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual([r["t"] for r in doc["records"]], [1, 2])
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_equal_bounds_single_record(self):
        log_bytes = mixed_log()
        code, out, err, _ = run_filter(log_bytes, "1", "1", "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(
            [r["t"] for r in json.loads(out.decode("utf-8"))["records"]],
            [1],
        )

    def test_zero_bound_legal(self):
        log_bytes = mixed_log()
        code, out, err, _ = run_filter(log_bytes, "0", "0", "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(
            [r["t"] for r in json.loads(out.decode("utf-8"))["records"]],
            [0],
        )

    def test_open_ended_start_and_end(self):
        log_bytes = mixed_log()
        code, out, err, _ = run_filter(log_bytes, "2", "*", "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(
            [r["t"] for r in json.loads(out.decode("utf-8"))["records"]], [2]
        )
        code, out, err, _ = run_filter(log_bytes, "*", "0", "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(
            [r["t"] for r in json.loads(out.decode("utf-8"))["records"]], [0]
        )

    def test_applied_true_false_filter(self):
        log_bytes = mixed_log()
        code, out, err, _ = run_filter(log_bytes, "*", "*", "false")
        self.assertEqual(code, 0, err)
        self.assertEqual(
            [r["t"] for r in json.loads(out.decode("utf-8"))["records"]], [1]
        )
        code, out, err, _ = run_filter(log_bytes, "*", "*", "true")
        self.assertEqual(code, 0, err)
        self.assertEqual(
            [r["t"] for r in json.loads(out.decode("utf-8"))["records"]],
            [0, 2],
        )

    def test_combined_interval_and_applied(self):
        log_bytes = mixed_log()
        code, out, err, _ = run_filter(log_bytes, "0", "1", "true")
        self.assertEqual(code, 0, err)
        self.assertEqual(
            [r["t"] for r in json.loads(out.decode("utf-8"))["records"]], [0]
        )

    def test_records_are_byte_identical_originals(self):
        log_bytes = mixed_log()
        code, out, err, _ = run_filter(log_bytes, "1", "1", "*")
        self.assertEqual(code, 0, err)
        kept = json.loads(out.decode("utf-8"))["records"][0]
        self.assertEqual(kept, log_doc(log_bytes)["records"][1])
        # 输出为紧凑 JSON，原样记录不重排字段
        self.assertIn(
            b'"t":1,"version":0,"event":',
            out,
        )

    def test_empty_result_still_valid_doc(self):
        log_bytes = mixed_log()
        code, out, err, _ = run_filter(log_bytes, "9", "9", "*")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["records"], [])
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_arbitrary_length_integer_bounds(self):
        log_bytes = mixed_log()
        huge = "9" * 60  # 远超 64 位，按数学整数比较
        code, out, err, _ = run_filter(log_bytes, "0", huge, "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(
            len(json.loads(out.decode("utf-8"))["records"]), 3
        )
        code, out, err, _ = run_filter(log_bytes, huge, huge, "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(
            json.loads(out.decode("utf-8"))["records"], []
        )

    def test_explicit_equal_limits_legal(self):
        log_bytes = mixed_log()
        size = len(log_bytes)
        code, out, err, after = run_filter(
            log_bytes, "*", "*", "*", str(size), str(size * 100)
        )
        self.assertEqual(code, 0, err)
        self.assertLessEqual(len(out), size * 100)


class UsageTests(unittest.TestCase):
    def test_arg_counts(self):
        log_bytes = mixed_log()
        # 4 个位置参数以下，或上限个数为 1 均非法
        self.assertEqual(run_filter(log_bytes)[0], 2)
        self.assertEqual(run_filter(log_bytes, "*")[0], 2)
        self.assertEqual(run_filter(log_bytes, "*", "*")[0], 2)
        self.assertEqual(
            run_filter(log_bytes, "*", "*", "*", "1")[0], 2
        )
        self.assertEqual(
            run_filter(log_bytes, "*", "*", "*", "1", "2", "3")[0], 2
        )

    def test_bad_bounds(self):
        log_bytes = mixed_log()
        for start, end in (
            ("x", "*"), ("", "*"), ("-1", "*"), ("01", "*"),
            ("1.0", "*"), ("*", "x"), ("*", "-0"), ("*", "+1"),
        ):
            self.assertEqual(
                run_filter(log_bytes, start, end, "*")[0],
                2,
                (start, end),
            )

    def test_start_greater_than_end(self):
        log_bytes = mixed_log()
        self.assertEqual(run_filter(log_bytes, "5", "3", "*")[0], 2)

    def test_bad_applied_token(self):
        log_bytes = mixed_log()
        for token in ("True", "TRUE", "yes", "1", "0", "false "):
            self.assertEqual(
                run_filter(log_bytes, "*", "*", token)[0], 2, token
            )

    def test_bad_limit_tokens(self):
        log_bytes = mixed_log()
        for lo, hi in (
            ("0", "16777216"),
            ("-1", "16777216"),
            ("01", "16777216"),
            ("abc", "16777216"),
            ("16777216", "0"),
        ):
            self.assertEqual(
                run_filter(log_bytes, "*", "*", "*", lo, hi)[0], 2, (lo, hi)
            )


class ErrorPrecedenceTests(unittest.TestCase):
    def test_file_not_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "nope.log")
            proc = subprocess.run(
                [sys.executable, SWITCH, "log-filter", missing, "*", "*", "*"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(proc.returncode, 3)
        self.assertIn(b"file_not_found", proc.stderr)
        self.assertEqual(proc.stdout, b"")

    def test_log_limit_before_invalid_input(self):
        # 超限截断的内容即便不是合法 JSON，也先报 log_limit
        log_bytes = mixed_log()
        size = len(log_bytes)
        code, out, err, after = run_filter(
            log_bytes, "*", "*", "*", str(size - 1), "16777216"
        )
        self.assertEqual(code, 5)
        self.assertIn(b"log_limit", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_invalid_input_shapes(self):
        good = mixed_log()
        # 错误内部 sha256
        doc = log_doc(good)
        bad_sha = copy.deepcopy(doc)
        bad_sha["sha256"] = "0" * 64
        cases = {
            "bad_sha.log": (
                json.dumps(bad_sha, separators=(",", ":")) + "\n"
            ).encode("utf-8"),
            "malformed.log": b"{not json\n",
        }
        # 缺记录键
        missing_key = copy.deepcopy(doc)
        del missing_key["records"][0]["version"]
        cases["missing_key.log"] = (
            json.dumps(missing_key, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        # applied 类型错误（int 而非 bool）
        wrong_type = copy.deepcopy(doc)
        wrong_type["records"][0]["applied"] = 1
        wrong_type["sha256"] = hashlib.sha256(
            switch._log_prefix_bytes(wrong_type)
        ).hexdigest()
        cases["wrong_type.log"] = (
            json.dumps(wrong_type, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        # 未知事件键形
        unknown = copy.deepcopy(doc)
        unknown["records"][0]["event"]["bogus"] = 1
        unknown["sha256"] = hashlib.sha256(
            switch._log_prefix_bytes(unknown)
        ).hexdigest()
        cases["unknown_event.log"] = (
            json.dumps(unknown, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        for name, content in cases.items():
            code, out, err, _ = _run_named(content, name)
            self.assertEqual(code, 4, name)
            self.assertIn(b"invalid_input", err, name)
            self.assertEqual(out, b"", name)

    def test_output_limit_after_validation(self):
        log_bytes = mixed_log()
        code, out, err, after = run_filter(
            log_bytes, "*", "*", "*", str(len(log_bytes)), "1"
        )
        self.assertEqual(code, 5)
        self.assertIn(b"output_limit", err)
        self.assertEqual(out, b"")
        # 失败不改 LOG
        self.assertEqual(after, log_bytes)


def _run_named(content, name):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, name)
        with open(path, "wb") as handle:
            handle.write(content)
        proc = subprocess.run(
            [sys.executable, SWITCH, "log-filter", path, "*", "*", "*"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    return proc.returncode, proc.stdout, proc.stderr, b""


if __name__ == "__main__":
    unittest.main()
