#!/usr/bin/env python3
"""log-page 子命令回归：静态分页读取 LOG 记录，不重演、不推导。

仅用标准库；端到端驱动 `python switch.py log-page LOG CURSOR COUNT
[MAX_LOG_BYTES MAX_OUTPUT_BYTES]`。成功产物键序固定为
schema,source_sha256,records,next,sha256，末项为前四键紧凑 UTF-8 加 LF
的 sha256；记录原样、原序按下标窗口取至多 COUNT 条；CURSOR 为 * 或
<sha256>:<offset>，next 指向返回末项的下一下标或 null。
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

PAGE_KEYS = ["schema", "source_sha256", "records", "next", "sha256"]


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


def three_frame_log():
    """三帧记录日志，t 依次为 0/1/2。"""
    events = [
        frame(0, "p1", "00:00:00:00:00:01"),
        frame(1, "p2", "00:00:00:00:00:02"),
        frame(2, "p3", "00:00:00:00:00:03"),
    ]
    _, log_bytes = record(base_config(), events)
    return log_bytes


def digest_of(doc):
    prefix = {key: doc[key] for key in PAGE_KEYS[:4]}
    raw = (
        json.dumps(prefix, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def run_page(log_bytes, *args, extra_files=None):
    """写 in.log（可附 extra 文件），原样透传参数，回读 LOG。"""
    with tempfile.TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "in.log")
        with open(log_path, "wb") as handle:
            handle.write(log_bytes)
        for name, content in (extra_files or {}).items():
            with open(os.path.join(tmp, name), "wb") as handle:
                handle.write(content)
        proc = subprocess.run(
            [sys.executable, SWITCH, "log-page", log_path, *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        with open(log_path, "rb") as handle:
            after = handle.read()
    return proc.returncode, proc.stdout, proc.stderr, after


class HappyPathTests(unittest.TestCase):
    def test_star_key_order_and_digest(self):
        log_bytes = three_frame_log()
        code, out, err, _ = run_page(log_bytes, "*", "10")
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertTrue(out.endswith(b"\n"))
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(list(doc), PAGE_KEYS)
        source = log_doc(log_bytes)
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["source_sha256"], source["sha256"])
        self.assertEqual(doc["records"], source["records"])
        # 一次取尽，无后续
        self.assertIsNone(doc["next"])
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_star_starts_at_zero(self):
        log_bytes = three_frame_log()
        code, out, err, _ = run_page(log_bytes, "*", "2")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual([r["t"] for r in doc["records"]], [0, 1])
        source_sha = log_doc(log_bytes)["sha256"]
        self.assertEqual(doc["next"], source_sha + ":2")
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_walk_all_pages_with_returned_cursors(self):
        log_bytes = three_frame_log()
        seen = []
        cursor = "*"
        pages = 0
        while True:
            code, out, err, _ = run_page(log_bytes, cursor, "1")
            self.assertEqual(code, 0, err)
            doc = json.loads(out.decode("utf-8"))
            pages += 1
            seen.extend(r["t"] for r in doc["records"])
            cursor = doc["next"]
            if cursor is None:
                break
        self.assertEqual(pages, 3)
        self.assertEqual(seen, [0, 1, 2])

    def test_cursor_offset_middle(self):
        log_bytes = three_frame_log()
        source_sha = log_doc(log_bytes)["sha256"]
        code, out, err, _ = run_page(log_bytes, source_sha + ":1", "10")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual([r["t"] for r in doc["records"]], [1, 2])
        self.assertIsNone(doc["next"])
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_cursor_offset_equal_length_returns_empty_with_null(self):
        log_bytes = three_frame_log()
        source_sha = log_doc(log_bytes)["sha256"]
        code, out, err, _ = run_page(log_bytes, source_sha + ":3", "10")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["records"], [])
        self.assertIsNone(doc["next"])
        self.assertEqual(doc["source_sha256"], source_sha)
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_cursor_zero_offset_equals_star(self):
        log_bytes = three_frame_log()
        source_sha = log_doc(log_bytes)["sha256"]
        code, out, err, _ = run_page(log_bytes, source_sha + ":0", "2")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual([r["t"] for r in doc["records"]], [0, 1])
        self.assertEqual(doc["next"], source_sha + ":2")

    def test_partial_page_when_fewer_than_count_remain(self):
        log_bytes = three_frame_log()
        source_sha = log_doc(log_bytes)["sha256"]
        code, out, err, _ = run_page(log_bytes, source_sha + ":2", "5")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual([r["t"] for r in doc["records"]], [2])
        self.assertIsNone(doc["next"])

    def test_records_are_byte_identical_originals(self):
        log_bytes = three_frame_log()
        code, out, err, _ = run_page(log_bytes, "*", "1")
        self.assertEqual(code, 0, err)
        kept = json.loads(out.decode("utf-8"))["records"][0]
        self.assertEqual(kept, log_doc(log_bytes)["records"][0])
        # 输出为紧凑 JSON，原样记录不重排字段
        self.assertIn(b'"t":0,"version":0,"event":', out)

    def test_empty_log(self):
        doc = {"schema": 1, "config": {}, "records": []}
        log_bytes = rehash(copy.deepcopy(doc))
        code, out, err, _ = run_page(log_bytes, "*", "10")
        self.assertEqual(code, 0, err)
        page = json.loads(out.decode("utf-8"))
        self.assertEqual(page["records"], [])
        self.assertIsNone(page["next"])
        self.assertEqual(page["sha256"], digest_of(page))
        source_sha = log_doc(log_bytes)["sha256"]
        # 空日志仅允许 offset 0
        code, out, err, _ = run_page(log_bytes, source_sha + ":0", "1")
        self.assertEqual(code, 0, err)

    def test_arbitrary_length_count(self):
        log_bytes = three_frame_log()
        huge = "9" * 60  # 远超 64 位，按数学整数处理
        code, out, err, _ = run_page(log_bytes, "*", huge)
        self.assertEqual(code, 0, err)
        self.assertEqual(
            len(json.loads(out.decode("utf-8"))["records"]), 3
        )

    def test_arbitrary_length_offset(self):
        log_bytes = three_frame_log()
        source_sha = log_doc(log_bytes)["sha256"]
        huge = "9" * 60
        # offset 超大（大于记录数）按 invalid_input
        code, out, err, _ = run_page(log_bytes, source_sha + ":" + huge, "1")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)

    def test_explicit_equal_limits_legal(self):
        log_bytes = three_frame_log()
        size = len(log_bytes)
        code, out, err, after = run_page(
            log_bytes, "*", "10", str(size), str(size * 100)
        )
        self.assertEqual(code, 0, err)
        self.assertLessEqual(len(out), size * 100)


class UsageTests(unittest.TestCase):
    def test_arg_counts(self):
        log_bytes = three_frame_log()
        # 少于 LOG/CURSOR/COUNT 三项，或上限个数为 1 均非法
        self.assertEqual(run_page(log_bytes)[0], 2)
        self.assertEqual(run_page(log_bytes, "*")[0], 2)
        self.assertEqual(run_page(log_bytes, "*", "1", "2")[0], 2)
        self.assertEqual(
            run_page(log_bytes, "*", "1", "16777216", "16777216", "1")[0], 2
        )
        # 无上限合法
        self.assertEqual(run_page(log_bytes, "*", "1")[0], 0)

    def test_bad_count(self):
        log_bytes = three_frame_log()
        for count in ("0", "-1", "01", "1.0", "x", "", "+1", "1 "):
            self.assertEqual(
                run_page(log_bytes, "*", count)[0], 2, count
            )

    def test_bad_cursor(self):
        log_bytes = three_frame_log()
        good_sha = log_doc(log_bytes)["sha256"]
        for cursor in (
            "",
            "x",
            "*x",
            good_sha,            # 缺 :offset
            good_sha + ":",      # 空 offset
            good_sha + ":01",    # offset 前导零
            good_sha + ":-1",    # 负 offset
            good_sha + ":1x",    # offset 非法字符
            "A" * 64 + ":0",     # 大写十六进制
            "g" * 64 + ":0",     # 非十六进制
            "0" * 63 + ":0",     # 63 位
            "0" * 65 + ":0",     # 65 位
            "*:" + good_sha,
        ):
            self.assertEqual(
                run_page(log_bytes, cursor, "1")[0], 2, cursor
            )

    def test_bad_limit_tokens(self):
        log_bytes = three_frame_log()
        for lo, hi in (
            ("0", "16777216"),
            ("-1", "16777216"),
            ("01", "16777216"),
            ("abc", "16777216"),
            ("16777216", "0"),
        ):
            self.assertEqual(
                run_page(log_bytes, "*", "1", lo, hi)[0], 2, (lo, hi)
            )


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
        # 超限截断的内容即便不是合法 JSON，也先报 log_limit
        log_bytes = three_frame_log()
        size = len(log_bytes)
        code, out, err, after = run_page(
            log_bytes, "*", "1", str(size - 1), "16777216"
        )
        self.assertEqual(code, 5)
        self.assertIn(b"log_limit", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_bad_internal_sha_is_invalid_input(self):
        good = three_frame_log()
        doc = log_doc(good)
        doc["sha256"] = "0" * 64
        content = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, after = _run_named(content, "bad_sha.log", "*", "1")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, content)

    def test_malformed_json_is_invalid_input(self):
        code, out, err, _ = _run_named(
            b"{not json\n", "malformed.log", "*", "1"
        )
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_sha_mismatch_is_invalid_input(self):
        log_bytes = three_frame_log()
        # 静态格式合法（64 位小写十六进制）但与 LOG.sha256 不符
        code, out, err, after = run_page(log_bytes, "0" * 64 + ":0", "1")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_cursor_offset_beyond_length_is_invalid_input(self):
        log_bytes = three_frame_log()
        source_sha = log_doc(log_bytes)["sha256"]
        code, out, err, after = run_page(
            log_bytes, source_sha + ":4", "1"
        )
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_output_limit_after_validation(self):
        log_bytes = three_frame_log()
        code, out, err, after = run_page(
            log_bytes, "*", "1", str(len(log_bytes)), "1"
        )
        self.assertEqual(code, 5)
        self.assertIn(b"output_limit", err)
        self.assertEqual(out, b"")
        # 失败不改 LOG
        self.assertEqual(after, log_bytes)

    def test_output_limit_equal_is_legal(self):
        log_bytes = three_frame_log()
        code, out, err, _ = run_page(
            log_bytes, "*", "3",
            str(len(log_bytes)), str(2 ** 31 - 1),
        )
        self.assertEqual(code, 0, err)
        # 缩小输出上限到恰为产物长度：等于上限合法
        code, out, err, _ = run_page(
            log_bytes, "*", "3",
            str(len(log_bytes)), str(len(out)),
        )
        self.assertEqual(code, 0, err)


def _run_named(content, name, *args):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, name)
        with open(path, "wb") as handle:
            handle.write(content)
        proc = subprocess.run(
            [sys.executable, SWITCH, "log-page", path, *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        with open(path, "rb") as handle:
            after = handle.read()
    return proc.returncode, proc.stdout, proc.stderr, after


if __name__ == "__main__":
    unittest.main()
