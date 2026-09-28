#!/usr/bin/env python3
"""log-page 子命令回归：按游标分页原样读取 LOG 记录，不重演、不推导。

仅用标准库；端到端驱动 `python switch.py log-page LOG CURSOR COUNT
[MAX_LOG_BYTES MAX_OUTPUT_BYTES]`。成功产物键序固定为
schema,source_sha256,records,next,sha256，末项为前四键紧凑 UTF-8 加 LF 的
sha256；CURSOR 为 *（从下标 0）或 <sha256>:<offset>，记录原样、原序保留，
有后续时 next 为 LOG.sha256:<下一下标>，否则 null。
"""

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

from test_record import base_config  # noqa: E402
from test_record import frame  # noqa: E402
from test_record import record  # noqa: E402


def log_doc(log_bytes):
    return json.loads(log_bytes.decode("utf-8"))


def paged_log(n):
    events = [
        frame(i, "p%d" % (i + 1), "00:00:00:00:00:%02x" % (i + 1))
        for i in range(n)
    ]
    _, log_bytes = record(base_config(), events)
    return log_bytes


def digest_of(doc):
    prefix = {
        "schema": doc["schema"],
        "source_sha256": doc["source_sha256"],
        "records": doc["records"],
        "next": doc["next"],
    }
    raw = (
        json.dumps(prefix, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def run_page(log_bytes, cursor, count, *limits):
    with tempfile.TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "in.log")
        with open(log_path, "wb") as handle:
            handle.write(log_bytes)
        proc = subprocess.run(
            [sys.executable, SWITCH, "log-page", log_path, cursor, count,
             *limits],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        with open(log_path, "rb") as handle:
            after = handle.read()
    return proc.returncode, proc.stdout, proc.stderr, after


class HappyPathTests(unittest.TestCase):
    def test_star_starts_at_zero_with_fixed_key_order_and_digest(self):
        log_bytes = paged_log(5)
        source = log_doc(log_bytes)["sha256"]
        code, out, err, _ = run_page(log_bytes, "*", "2")
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertTrue(out.endswith(b"\n"))
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(
            list(doc),
            ["schema", "source_sha256", "records", "next", "sha256"],
        )
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["source_sha256"], source)
        self.assertEqual([r["t"] for r in doc["records"]], [0, 1])
        self.assertEqual(doc["next"], source + ":2")
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_walk_all_pages_with_cursors(self):
        log_bytes = paged_log(5)
        source = log_doc(log_bytes)["sha256"]
        pages = []
        cursor = "*"
        while True:
            code, out, err, _ = run_page(log_bytes, cursor, "2")
            self.assertEqual(code, 0, err)
            doc = json.loads(out.decode("utf-8"))
            pages.extend(r["t"] for r in doc["records"])
            self.assertEqual(doc["sha256"], digest_of(doc))
            if doc["next"] is None:
                break
            self.assertEqual(
                doc["next"], source + ":" + str(len(pages))
            )
            cursor = doc["next"]
        self.assertEqual(pages, [0, 1, 2, 3, 4])

    def test_last_partial_page_next_null(self):
        log_bytes = paged_log(5)
        source = log_doc(log_bytes)["sha256"]
        code, out, err, _ = run_page(log_bytes, source + ":4", "2")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual([r["t"] for r in doc["records"]], [4])
        self.assertIsNone(doc["next"])
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_offset_equal_record_count_empty_page(self):
        log_bytes = paged_log(3)
        source = log_doc(log_bytes)["sha256"]
        code, out, err, _ = run_page(log_bytes, source + ":3", "10")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["records"], [])
        self.assertIsNone(doc["next"])

    def test_count_beyond_records_returns_rest(self):
        log_bytes = paged_log(3)
        code, out, err, _ = run_page(log_bytes, "*", "9" * 60)
        self.assertEqual(code, 0, err)
        self.assertEqual(
            [r["t"] for r in json.loads(out.decode("utf-8"))["records"]],
            [0, 1, 2],
        )

    def test_records_are_byte_identical_originals(self):
        log_bytes = paged_log(3)
        code, out, err, _ = run_page(log_bytes, "*", "1")
        self.assertEqual(code, 0, err)
        kept = json.loads(out.decode("utf-8"))["records"][0]
        self.assertEqual(kept, log_doc(log_bytes)["records"][0])
        self.assertIn(b'"t":0,"version":0,"event":', out)

    def test_offset_zero_cursor_equals_star_payload(self):
        log_bytes = paged_log(3)
        source = log_doc(log_bytes)["sha256"]
        _, star_out, _, _ = run_page(log_bytes, "*", "2")
        _, cur_out, _, _ = run_page(log_bytes, source + ":0", "2")
        self.assertEqual(cur_out, star_out)

    def test_explicit_equal_limits_legal(self):
        log_bytes = paged_log(3)
        size = len(log_bytes)
        code, out, err, after = run_page(
            log_bytes, "*", "2", str(size), str(size * 100)
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(after, log_bytes)
        self.assertLessEqual(len(out), size * 100)


class UsageTests(unittest.TestCase):
    def test_arg_counts(self):
        log_bytes = paged_log(3)
        # 不足 3 个位置参数；上限不成对（1 或 3 个）均非法
        runs = [
            [],
            ["*"],
            ["*", "2", "x"],
            ["*", "2", "16777216"],
            ["*", "2", "16777216", "16777216", "1"],
        ]
        for tokens in runs:
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "in.log")
                with open(path, "wb") as handle:
                    handle.write(log_bytes)
                proc = subprocess.run(
                    [sys.executable, SWITCH, "log-page", path, *tokens],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
            self.assertEqual(proc.returncode, 2, tokens)

    def test_bad_cursor_tokens(self):
        log_bytes = paged_log(3)
        source = log_doc(log_bytes)["sha256"]
        for cursor in (
            "",
            "x",
            "* ",
            source[:63],
            source + "x:0",
            "G" * 64 + ":0",
            source.upper() + ":0",
            source + ":",
            source + ":01",
            source + ":-0",
            source + ":+1",
            source + ":1.0",
            source + ":0:0",
        ):
            code, _, _, _ = run_page(log_bytes, cursor, "1")
            self.assertEqual(code, 2, cursor)

    def test_bad_count_tokens(self):
        log_bytes = paged_log(3)
        source = log_doc(log_bytes)["sha256"]
        for count in ("", "0", "-1", "01", "1.0", "1 ", "x", "1e3"):
            code, _, _, _ = run_page(log_bytes, source + ":0", count)
            self.assertEqual(code, 2, count)
            code, _, _, _ = run_page(log_bytes, "*", count)
            self.assertEqual(code, 2, count)

    def test_bad_limit_tokens(self):
        log_bytes = paged_log(3)
        for lo, hi in (
            ("0", "16777216"),
            ("-1", "16777216"),
            ("01", "16777216"),
            ("abc", "16777216"),
            ("16777216", "0"),
        ):
            code, _, _, _ = run_page(log_bytes, "*", "1", lo, hi)
            self.assertEqual(code, 2, (lo, hi))


class ErrorPrecedenceTests(unittest.TestCase):
    def test_file_not_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "nope.log")
            proc = subprocess.run(
                [sys.executable, SWITCH, "log-page", missing, "*", "1"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(proc.returncode, 3)
        self.assertIn(b"file_not_found", proc.stderr)
        self.assertEqual(proc.stdout, b"")

    def test_log_limit_before_invalid_input(self):
        log_bytes = paged_log(3)
        size = len(log_bytes)
        code, out, err, after = run_page(
            log_bytes, "*", "1", str(size - 1), "16777216"
        )
        self.assertEqual(code, 5)
        self.assertIn(b"log_limit", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_bad_internal_sha_invalid_input(self):
        log_bytes = paged_log(3)
        doc = log_doc(log_bytes)
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_page(bad, "*", "1")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_sha_mismatch_invalid_input(self):
        log_bytes = paged_log(3)
        code, out, err, _ = run_page(log_bytes, "0" * 64 + ":0", "1")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_offset_beyond_record_count_invalid_input(self):
        log_bytes = paged_log(3)
        source = log_doc(log_bytes)["sha256"]
        code, out, err, _ = run_page(log_bytes, source + ":4", "1")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_output_limit_after_validation(self):
        log_bytes = paged_log(3)
        code, out, err, after = run_page(
            log_bytes, "*", "1", str(len(log_bytes)), "1"
        )
        self.assertEqual(code, 5)
        self.assertIn(b"output_limit", err)
        self.assertEqual(out, b"")
        # 失败不改 LOG
        self.assertEqual(after, log_bytes)


if __name__ == "__main__":
    unittest.main()
