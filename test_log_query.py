#!/usr/bin/env python3
"""log-query 子命令回归：按游标分页静态查询 LOG 记录，不重演、不推导。

仅用标准库；端到端驱动 `python switch.py log-query LOG START END KIND
APPLIED CURSOR COUNT [MAX_LOG_BYTES MAX_OUTPUT_BYTES]`。START/END/APPLIED
沿用 log-filter，KIND 取 *|learn|frame|link|member|service|reload|rollback，
CURSOR/COUNT 沿用 log-page，但 offset 是原 LOG 的 records 下标。成功产物
键序固定为 schema,source_sha256,query,records,next,sha256；query 键序
start,end,kind,applied，输入 * 写 null；末项为前五键紧凑 UTF-8 加 LF 的
sha256；从 offset 起按时间闭区间、kind、applied 合取，原序原样取至多
COUNT 项，后续仍有匹配项时 next 为 LOG.sha256:<最后返回项的下一原始下标>，
否则 null。
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

from test_log_summary import all_kind_spec  # noqa: E402
from test_log_summary import synthetic_log  # noqa: E402
from test_record import base_config  # noqa: E402
from test_record import frame  # noqa: E402
from test_record import record  # noqa: E402

QUERY_KEYS = ["schema", "source_sha256", "query", "records", "next", "sha256"]
QUERY_INNER_KEYS = ["start", "end", "kind", "applied"]
# all_kind_spec 的 t 与 kind 对齐：0 learn,1 frame,2/3 link,4 member,
# 5 service,6 reload,7 rollback；第二条 link 与 rollback 未生效
APPLIED_FLAGS = [True, True, True, False, True, True, True, False]


def log_doc(log_bytes):
    return json.loads(log_bytes.decode("utf-8"))


def mixed_log():
    return synthetic_log(all_kind_spec(), APPLIED_FLAGS)


def frame_log(n):
    events = [
        frame(i, "p%d" % (i + 1), "00:00:00:00:00:%02x" % (i + 1))
        for i in range(n)
    ]
    _, log_bytes = record(base_config(), events)
    return log_bytes


def digest_of(doc):
    prefix = {key: doc[key] for key in QUERY_KEYS[:5]}
    raw = (
        json.dumps(prefix, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def run_query(log_bytes, *args):
    with tempfile.TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "in.log")
        with open(log_path, "wb") as handle:
            handle.write(log_bytes)
        proc = subprocess.run(
            [sys.executable, SWITCH, "log-query", log_path, *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        with open(log_path, "rb") as handle:
            after = handle.read()
    return proc.returncode, proc.stdout, proc.stderr, after


class HappyPathTests(unittest.TestCase):
    def test_star_query_key_order_nulls_and_digest(self):
        log_bytes = mixed_log()
        source = log_doc(log_bytes)["sha256"]
        code, out, err, after = run_query(
            log_bytes, "*", "*", "*", "*", "*", "8"
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertTrue(out.endswith(b"\n"))
        self.assertEqual(after, log_bytes)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(list(doc), QUERY_KEYS)
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["source_sha256"], source)
        self.assertEqual(list(doc["query"]), QUERY_INNER_KEYS)
        self.assertEqual(
            doc["query"],
            {"start": None, "end": None, "kind": None, "applied": None},
        )
        self.assertEqual([r["t"] for r in doc["records"]], list(range(8)))
        # 全量返回后无后续
        self.assertIsNone(doc["next"])
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_query_echo_uses_int_string_bool(self):
        log_bytes = mixed_log()
        code, out, err, _ = run_query(
            log_bytes, "1", "6", "link", "false", "*", "8"
        )
        self.assertEqual(code, 0, err)
        query = json.loads(out.decode("utf-8"))["query"]
        self.assertEqual(
            query,
            {"start": 1, "end": 6, "kind": "link", "applied": False},
        )
        self.assertIsInstance(query["start"], int)
        self.assertIsInstance(query["end"], int)
        self.assertNotIsInstance(query["start"], bool)

    def test_kind_conjunction_with_interval_and_applied(self):
        log_bytes = mixed_log()
        # 区间 [2,7] 内 link 且未生效：仅 t=3
        code, out, err, _ = run_query(
            log_bytes, "2", "7", "link", "false", "*", "8"
        )
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual([r["t"] for r in doc["records"]], [3])
        self.assertIsNone(doc["next"])
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_each_kind_bucket(self):
        log_bytes = mixed_log()
        expect = {
            "learn": [0],
            "frame": [1],
            "link": [2, 3],
            "member": [4],
            "service": [5],
            "reload": [6],
            "rollback": [7],
        }
        for kind, ts in expect.items():
            code, out, err, _ = run_query(
                log_bytes, "*", "*", kind, "*", "*", "8"
            )
            self.assertEqual(code, 0, (kind, err))
            self.assertEqual(
                [r["t"] for r in json.loads(out.decode("utf-8"))["records"]],
                ts,
                kind,
            )

    def test_closed_interval_is_inclusive(self):
        log_bytes = mixed_log()
        code, out, err, _ = run_query(
            log_bytes, "3", "5", "*", "*", "*", "8"
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(
            [r["t"] for r in json.loads(out.decode("utf-8"))["records"]],
            [3, 4, 5],
        )

    def test_walk_pages_offsets_are_original_indices(self):
        log_bytes = mixed_log()
        source = log_doc(log_bytes)["sha256"]
        # applied=true 命中原始下标 0,1,2,4,5,6；COUNT=2 跨非匹配下标 3
        pages = []
        cursor = "*"
        while True:
            code, out, err, _ = run_query(
                log_bytes, "*", "*", "*", "true", cursor, "2"
            )
            self.assertEqual(code, 0, err)
            doc = json.loads(out.decode("utf-8"))
            pages.append([r["t"] for r in doc["records"]])
            self.assertEqual(doc["sha256"], digest_of(doc))
            if doc["next"] is None:
                break
            # next 锚定最后返回项的下一原始下标（跨非匹配下标 3）
            cursor = doc["next"]
        self.assertEqual(pages, [[0, 1], [2, 4], [5, 6]])

    def test_next_skips_nonmatching_gap(self):
        log_bytes = mixed_log()
        source = log_doc(log_bytes)["sha256"]
        # applied=false：首个命中原始下标 3，其后下标 7 仍命中 → next=sha:4
        code, out, err, _ = run_query(
            log_bytes, "*", "*", "*", "false", "*", "1"
        )
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual([r["t"] for r in doc["records"]], [3])
        self.assertEqual(doc["next"], source + ":4")
        # 从 sha:4 续查得到 t=7，之后无匹配 → null
        code, out, err, _ = run_query(
            log_bytes, "*", "*", "*", "false", source + ":4", "1"
        )
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual([r["t"] for r in doc["records"]], [7])
        self.assertIsNone(doc["next"])

    def test_no_match_empty_records_next_null(self):
        log_bytes = mixed_log()
        code, out, err, _ = run_query(
            log_bytes, "9", "9", "*", "*", "*", "8"
        )
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["records"], [])
        self.assertIsNone(doc["next"])
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_kind_without_match_empty(self):
        log_bytes = frame_log(3)
        code, out, err, _ = run_query(
            log_bytes, "*", "*", "rollback", "*", "*", "8"
        )
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["records"], [])
        self.assertIsNone(doc["next"])

    def test_empty_log(self):
        log_bytes = frame_log(0)
        source = log_doc(log_bytes)["sha256"]
        code, out, err, _ = run_query(
            log_bytes, "*", "*", "*", "*", "*", "8"
        )
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["records"], [])
        self.assertIsNone(doc["next"])
        self.assertEqual(doc["source_sha256"], source)

    def test_offset_equal_record_count_empty_page(self):
        log_bytes = mixed_log()
        source = log_doc(log_bytes)["sha256"]
        code, out, err, _ = run_query(
            log_bytes, "*", "*", "*", "*", source + ":8", "8"
        )
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["records"], [])
        self.assertIsNone(doc["next"])

    def test_star_equals_zero_cursor_payload(self):
        log_bytes = mixed_log()
        source = log_doc(log_bytes)["sha256"]
        _, star_out, _, _ = run_query(
            log_bytes, "*", "*", "*", "*", "*", "3"
        )
        _, zero_out, _, _ = run_query(
            log_bytes, "*", "*", "*", "*", source + ":0", "3"
        )
        self.assertEqual(star_out, zero_out)

    def test_records_are_byte_identical_originals(self):
        log_bytes = mixed_log()
        source = log_doc(log_bytes)
        code, out, err, _ = run_query(
            log_bytes, "*", "*", "frame", "*", "*", "1"
        )
        self.assertEqual(code, 0, err)
        kept = json.loads(out.decode("utf-8"))["records"][0]
        self.assertEqual(kept, source["records"][1])
        # 紧凑 JSON 中原样记录不重排字段（synthetic 日志 version 同下标）
        self.assertIn(b'"t":1,"version":1,"event":', out)

    def test_arbitrary_length_integer_bounds_and_count(self):
        log_bytes = mixed_log()
        huge = "9" * 60
        code, out, err, _ = run_query(
            log_bytes, "0", huge, "*", "*", "*", huge
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(
            [r["t"] for r in json.loads(out.decode("utf-8"))["records"]],
            list(range(8)),
        )

    def test_explicit_equal_limits_legal(self):
        log_bytes = mixed_log()
        size = len(log_bytes)
        code, out, err, after = run_query(
            log_bytes, "*", "*", "*", "*", "*", "8",
            str(size), str(size * 100),
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(after, log_bytes)
        self.assertLessEqual(len(out), size * 100)


class UsageTests(unittest.TestCase):
    def test_arg_counts(self):
        log_bytes = mixed_log()
        # 必选 7 项（含 LOG）；上限仅可 0 或 2 个
        self.assertEqual(
            run_query(log_bytes, "*", "*", "*", "*", "*")[0], 2
        )
        self.assertEqual(
            run_query(
                log_bytes, "*", "*", "*", "*", "*", "8", "16777216"
            )[0],
            2,
        )
        self.assertEqual(
            run_query(
                log_bytes, "*", "*", "*", "*", "*", "8",
                "1", "2", "3",
            )[0],
            2,
        )

    def test_bad_bounds(self):
        log_bytes = mixed_log()
        for start, end in (
            ("x", "*"), ("", "*"), ("-1", "*"), ("01", "*"),
            ("1.0", "*"), ("*", "x"), ("*", "-0"), ("*", "+1"),
        ):
            code, _, _, _ = run_query(
                log_bytes, start, end, "*", "*", "*", "1"
            )
            self.assertEqual(code, 2, (start, end))

    def test_start_greater_than_end(self):
        log_bytes = mixed_log()
        code, _, _, _ = run_query(
            log_bytes, "5", "3", "*", "*", "*", "1"
        )
        self.assertEqual(code, 2)

    def test_bad_kind_token(self):
        log_bytes = mixed_log()
        for kind in ("", "learn ", "LEARN", "all", "learns", "link2"):
            code, out, _, _ = run_query(
                log_bytes, "*", "*", kind, "*", "*", "1"
            )
            self.assertEqual(code, 2, kind)
            self.assertEqual(out, b"")

    def test_bad_applied_token(self):
        log_bytes = mixed_log()
        for token in ("True", "TRUE", "yes", "1", "0", "false "):
            code, _, _, _ = run_query(
                log_bytes, "*", "*", "*", token, "*", "1"
            )
            self.assertEqual(code, 2, token)

    def test_bad_cursor_tokens(self):
        log_bytes = mixed_log()
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
            code, _, _, _ = run_query(
                log_bytes, "*", "*", "*", "*", cursor, "1"
            )
            self.assertEqual(code, 2, cursor)

    def test_bad_count_tokens(self):
        log_bytes = mixed_log()
        source = log_doc(log_bytes)["sha256"]
        for count in ("", "0", "-1", "01", "1.0", "1 ", "x", "1e3"):
            code, _, _, _ = run_query(
                log_bytes, "*", "*", "*", "*", source + ":0", count
            )
            self.assertEqual(code, 2, count)
            code, _, _, _ = run_query(
                log_bytes, "*", "*", "*", "*", "*", count
            )
            self.assertEqual(code, 2, count)

    def test_bad_limit_tokens(self):
        log_bytes = mixed_log()
        for lo, hi in (
            ("0", "16777216"),
            ("-1", "16777216"),
            ("01", "16777216"),
            ("abc", "16777216"),
            ("16777216", "0"),
        ):
            code, _, _, _ = run_query(
                log_bytes, "*", "*", "*", "*", "*", "1", lo, hi
            )
            self.assertEqual(code, 2, (lo, hi))


class ErrorPrecedenceTests(unittest.TestCase):
    def test_file_not_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "nope.log")
            proc = subprocess.run(
                [
                    sys.executable, SWITCH, "log-query", missing,
                    "*", "*", "*", "*", "*", "1",
                ],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(proc.returncode, 3)
        self.assertIn(b"file_not_found", proc.stderr)
        self.assertEqual(proc.stdout, b"")

    def test_log_limit_before_invalid_input(self):
        log_bytes = mixed_log()
        size = len(log_bytes)
        code, out, err, after = run_query(
            log_bytes, "*", "*", "*", "*", "*", "8",
            str(size - 1), "16777216",
        )
        self.assertEqual(code, 5)
        self.assertIn(b"log_limit", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_bad_internal_sha_invalid_input(self):
        log_bytes = mixed_log()
        doc = log_doc(log_bytes)
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, after = run_query(
            bad, "*", "*", "*", "*", "*", "1"
        )
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, bad)

    def test_cursor_sha_mismatch_invalid_input(self):
        log_bytes = mixed_log()
        code, out, err, _ = run_query(
            log_bytes, "*", "*", "*", "*", "0" * 64 + ":0", "1"
        )
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_offset_beyond_record_count_invalid_input(self):
        log_bytes = mixed_log()
        source = log_doc(log_bytes)["sha256"]
        code, out, err, _ = run_query(
            log_bytes, "*", "*", "*", "*", source + ":9", "1"
        )
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_output_limit_after_validation(self):
        log_bytes = mixed_log()
        code, out, err, after = run_query(
            log_bytes, "*", "*", "*", "*", "*", "8",
            str(len(log_bytes)), "1",
        )
        self.assertEqual(code, 5)
        self.assertIn(b"output_limit", err)
        self.assertEqual(out, b"")
        # 失败不改 LOG
        self.assertEqual(after, log_bytes)


if __name__ == "__main__":
    unittest.main()
