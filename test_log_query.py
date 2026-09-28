#!/usr/bin/env python3
"""log-query 子命令回归：从游标起按时间闭区间、kind、applied 合取扫描，
原序原样取至多 COUNT 项，不重演、不推导。

仅用标准库；端到端驱动 `python switch.py log-query LOG START END KIND
APPLIED CURSOR COUNT [MAX_LOG_BYTES MAX_OUTPUT_BYTES]`。START/END/APPLIED
沿用 log-filter，KIND 取 *|learn|frame|link|member|service|reload|rollback，
CURSOR/COUNT 沿用 log-page，但 CURSOR 的 offset 是原 LOG 的 records 下标。
成功产物键序固定为 schema,source_sha256,query,records,next,sha256，query
键序 start,end,kind,applied（输入 * 写 null，其余依次为整数、整数、字符串、
布尔），末项为前五键紧凑 UTF-8 加 LF 的 sha256；有后续匹配时 next 为
LOG.sha256:<最后返回项的下一原始下标>，否则 null。
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

import switch  # noqa: E402
from test_record import base_config  # noqa: E402
from test_record import frame  # noqa: E402
from test_record import record  # noqa: E402

QUERY_KEYS = ["schema", "source_sha256", "query", "records", "next", "sha256"]
QUERY_INNER_KEYS = ["start", "end", "kind", "applied"]
KINDS = [
    "learn", "frame", "link", "member", "service", "reload", "rollback",
]


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


def frame_log(n, applied_flags=None):
    """n 条 frame 记录的 LOG；applied_flags 给定时逐记录指定 applied。"""
    events = [
        frame(i, "p%d" % (i % 5 + 1), "00:00:00:00:00:%02x" % (i + 1))
        for i in range(n)
    ]
    _, log_bytes = record(base_config(), events)
    if applied_flags is not None:
        doc = log_doc(log_bytes)
        for rec, flag in zip(doc["records"], applied_flags):
            rec["applied"] = flag
        return rehash(doc)
    return log_bytes


def canonical(value):
    if isinstance(value, dict):
        return {key: canonical(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [canonical(item) for item in value]
    return value


def synthetic_log(spec, applied_flags=None):
    """按 (kind, event) 序列构造静态合法 LOG（config 为空对象），不重演。

    applied_flags 给定时逐记录指定 applied，否则全 True；output 恒 None。
    """
    records = []
    for index, (_kind, event) in enumerate(spec):
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
    doc = {"schema": 1, "config": {}, "records": records}
    return rehash(doc)


def all_kind_spec():
    return [
        ("learn", {"t": 0, "port": "p1", "mac": "00:00:00:00:00:01",
                   "vlan": 1}),
        ("frame", {"t": 1, "port": "p1",
                   "src": "00:00:00:00:00:02", "dst": "ff:ff:ff:ff:ff:ff"}),
        ("link", {"t": 2, "id": "L1", "up": True}),
        ("link", {"t": 3, "id": "L1", "up": True}),
        ("member", {"t": 4, "member": "m1", "up": True}),
        ("service", {"t": 5, "port": "p1", "count": 2}),
        ("reload", {"t": 6, "config": {}}),
        ("rollback", {"t": 7, "rollback": 1}),
    ]


def digest_of(doc):
    prefix = {key: doc[key] for key in QUERY_KEYS[:5]}
    raw = (
        json.dumps(prefix, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def run_query(log_bytes, *args):
    """写 in.log，原样透传参数（含 *），回读 LOG。"""
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
    def test_star_wildcards_key_order_digest_and_null_query(self):
        log_bytes = frame_log(5)
        source = log_doc(log_bytes)["sha256"]
        code, out, err, after = run_query(
            log_bytes, "*", "*", "*", "*", "*", "5"
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertTrue(out.endswith(b"\n"))
        self.assertEqual(after, log_bytes)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(list(doc), QUERY_KEYS)
        self.assertEqual(list(doc["query"]), QUERY_INNER_KEYS)
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["source_sha256"], source)
        self.assertEqual(
            doc["query"],
            {"start": None, "end": None, "kind": None, "applied": None},
        )
        self.assertEqual([r["t"] for r in doc["records"]], [0, 1, 2, 3, 4])
        self.assertIsNone(doc["next"])
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_query_value_types_for_explicit_tokens(self):
        log_bytes = frame_log(3)
        code, out, err, _ = run_query(
            log_bytes, "1", "2", "frame", "true", "*", "5"
        )
        self.assertEqual(code, 0, err)
        query = json.loads(out.decode("utf-8"))["query"]
        self.assertEqual(list(query), QUERY_INNER_KEYS)
        self.assertIsInstance(query["start"], int)
        self.assertIsInstance(query["end"], int)
        self.assertIsInstance(query["kind"], str)
        self.assertIsInstance(query["applied"], bool)
        self.assertEqual(
            query, {"start": 1, "end": 2, "kind": "frame", "applied": True}
        )

    def test_closed_interval_inclusive_and_order_preserved(self):
        log_bytes = frame_log(5)
        code, out, err, _ = run_query(
            log_bytes, "1", "3", "*", "*", "*", "9"
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(
            [r["t"] for r in json.loads(out.decode("utf-8"))["records"]],
            [1, 2, 3],
        )

    def test_equal_bounds_single_record(self):
        log_bytes = frame_log(5)
        code, out, err, _ = run_query(
            log_bytes, "2", "2", "*", "*", "*", "9"
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(
            [r["t"] for r in json.loads(out.decode("utf-8"))["records"]], [2]
        )

    def test_zero_bound_legal(self):
        log_bytes = frame_log(3)
        code, out, err, _ = run_query(
            log_bytes, "0", "0", "*", "*", "*", "9"
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(
            [r["t"] for r in json.loads(out.decode("utf-8"))["records"]], [0]
        )

    def test_open_ended_bounds(self):
        log_bytes = frame_log(3)
        code, out, err, _ = run_query(
            log_bytes, "2", "*", "*", "*", "*", "9"
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(
            [r["t"] for r in json.loads(out.decode("utf-8"))["records"]], [2]
        )
        code, out, err, _ = run_query(
            log_bytes, "*", "0", "*", "*", "*", "9"
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(
            [r["t"] for r in json.loads(out.decode("utf-8"))["records"]], [0]
        )

    def test_applied_true_false(self):
        log_bytes = frame_log(3, [True, False, True])
        code, out, err, _ = run_query(
            log_bytes, "*", "*", "*", "false", "*", "9"
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(
            [r["t"] for r in json.loads(out.decode("utf-8"))["records"]], [1]
        )
        code, out, err, _ = run_query(
            log_bytes, "*", "*", "*", "true", "*", "9"
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(
            [r["t"] for r in json.loads(out.decode("utf-8"))["records"]],
            [0, 2],
        )

    def test_each_kind_selected(self):
        log_bytes = synthetic_log(all_kind_spec())
        # kind -> 命中记录的 t 列表（link 在原 LOG 中出现两次）
        expected = {
            "learn": [0],
            "frame": [1],
            "link": [2, 3],
            "member": [4],
            "service": [5],
            "reload": [6],
            "rollback": [7],
        }
        for kind in KINDS:
            code, out, err, _ = run_query(
                log_bytes, "*", "*", kind, "*", "*", "9"
            )
            self.assertEqual(code, 0, err)
            ts = [r["t"] for r in json.loads(out.decode("utf-8"))["records"]]
            self.assertEqual(ts, expected[kind], kind)

    def test_kind_star_keeps_all_kinds(self):
        log_bytes = synthetic_log(all_kind_spec())
        code, out, err, _ = run_query(
            log_bytes, "*", "*", "*", "*", "*", "9"
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(
            [r["t"] for r in json.loads(out.decode("utf-8"))["records"]],
            list(range(8)),
        )

    def test_conjunction_of_interval_kind_applied(self):
        # 两条 link：t=2 applied、t=3 未生效；合取仅留 t=2
        log_bytes = synthetic_log(
            all_kind_spec(),
            applied_flags=[
                True, True, True, False, True, True, True, False
            ],
        )
        code, out, err, _ = run_query(
            log_bytes, "0", "2", "link", "true", "*", "9"
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(
            [r["t"] for r in json.loads(out.decode("utf-8"))["records"]], [2]
        )
        # kind=link applied=true 但区间排除 t=2 后无匹配
        code, out, err, _ = run_query(
            log_bytes, "3", "3", "link", "true", "*", "9"
        )
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["records"], [])
        self.assertIsNone(doc["next"])

    def test_records_are_byte_identical_originals(self):
        log_bytes = frame_log(3)
        code, out, err, _ = run_query(
            log_bytes, "1", "1", "*", "*", "*", "9"
        )
        self.assertEqual(code, 0, err)
        kept = json.loads(out.decode("utf-8"))["records"][0]
        self.assertEqual(kept, log_doc(log_bytes)["records"][1])
        self.assertIn(b'"t":1,"version":0,"event":', out)

    def test_empty_result_valid_doc_with_null_next(self):
        log_bytes = frame_log(3)
        code, out, err, _ = run_query(
            log_bytes, "9", "9", "*", "*", "*", "9"
        )
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["records"], [])
        self.assertIsNone(doc["next"])
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_arbitrary_length_integer_bounds(self):
        log_bytes = frame_log(3)
        huge = "9" * 60
        code, out, err, _ = run_query(
            log_bytes, "0", huge, "*", "*", "*", "9"
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(
            len(json.loads(out.decode("utf-8"))["records"]), 3
        )
        code, out, err, _ = run_query(
            log_bytes, huge, huge, "*", "*", "*", "9"
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out.decode("utf-8"))["records"], [])

    def test_count_limits_page_and_next_uses_original_indices(self):
        log_bytes = frame_log(5)
        source = log_doc(log_bytes)["sha256"]
        code, out, err, _ = run_query(
            log_bytes, "*", "*", "*", "*", "*", "2"
        )
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual([r["t"] for r in doc["records"]], [0, 1])
        self.assertEqual(doc["next"], source + ":2")

    def test_walk_all_pages(self):
        log_bytes = frame_log(5)
        source = log_doc(log_bytes)["sha256"]
        cursor = "*"
        walked = []
        while True:
            code, out, err, _ = run_query(
                log_bytes, "*", "*", "*", "*", cursor, "2"
            )
            self.assertEqual(code, 0, err)
            doc = json.loads(out.decode("utf-8"))
            self.assertEqual(doc["sha256"], digest_of(doc))
            walked.extend(r["t"] for r in doc["records"])
            if doc["next"] is None:
                break
            self.assertEqual(
                doc["next"], source + ":" + str(len(walked))
            )
            cursor = doc["next"]
        self.assertEqual(walked, [0, 1, 2, 3, 4])

    def test_last_partial_page_next_null(self):
        log_bytes = frame_log(5)
        source = log_doc(log_bytes)["sha256"]
        code, out, err, _ = run_query(
            log_bytes, "*", "*", "*", "*", source + ":4", "2"
        )
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual([r["t"] for r in doc["records"]], [4])
        self.assertIsNone(doc["next"])

    def test_offset_equal_record_count_empty(self):
        log_bytes = frame_log(3)
        source = log_doc(log_bytes)["sha256"]
        code, out, err, _ = run_query(
            log_bytes, "*", "*", "*", "*", source + ":3", "10"
        )
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["records"], [])
        self.assertIsNone(doc["next"])

    def test_star_equals_zero_offset_cursor_payload(self):
        log_bytes = frame_log(3)
        source = log_doc(log_bytes)["sha256"]
        _, star_out, _, _ = run_query(
            log_bytes, "*", "*", "*", "*", "*", "2"
        )
        _, cur_out, _, _ = run_query(
            log_bytes, "*", "*", "*", "*", source + ":0", "2"
        )
        self.assertEqual(cur_out, star_out)

    def test_scan_starts_at_cursor_offset(self):
        # 游标落在下标 2：即便区间从 0 起，也不返回下标 0、1
        log_bytes = frame_log(5)
        source = log_doc(log_bytes)["sha256"]
        code, out, err, _ = run_query(
            log_bytes, "0", "9", "*", "*", source + ":2", "9"
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(
            [r["t"] for r in json.loads(out.decode("utf-8"))["records"]],
            [2, 3, 4],
        )

    def test_next_skips_nonmatching_and_points_after_last_returned(self):
        # applied T,F,T,F,T,F；applied=true 每页 2 项：先得原下标 0、2，
        # 其后原下标 4 仍匹配，故 next 指最后返回项的下一原始下标 2+1=3
        # （不是下一匹配项下标 4）
        log_bytes = frame_log(6, [True, False, True, False, True, False])
        source = log_doc(log_bytes)["sha256"]
        code, out, err, _ = run_query(
            log_bytes, "*", "*", "*", "true", "*", "2"
        )
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual([r["t"] for r in doc["records"]], [0, 2])
        self.assertEqual(doc["next"], source + ":3")
        # 从下标 3 继续：仅原下标 4 匹配（不足 2 项），next 为 null
        code, out, err, _ = run_query(
            log_bytes, "*", "*", "*", "true", doc["next"], "2"
        )
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual([r["t"] for r in doc["records"]], [4])
        self.assertIsNone(doc["next"])

    def test_next_null_when_count_filled_exactly(self):
        # 全匹配恰好 3 项、COUNT=3：收满后无后续匹配，next 为 null
        log_bytes = frame_log(3)
        code, out, err, _ = run_query(
            log_bytes, "*", "*", "*", "*", "*", "3"
        )
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual([r["t"] for r in doc["records"]], [0, 1, 2])
        self.assertIsNone(doc["next"])

    def test_explicit_equal_limits_legal(self):
        log_bytes = frame_log(3)
        size = len(log_bytes)
        code, out, err, after = run_query(
            log_bytes, "*", "*", "*", "*", "*", "9",
            str(size), str(size * 100),
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(after, log_bytes)
        self.assertLessEqual(len(out), size * 100)


class UsageTests(unittest.TestCase):
    def test_arg_counts(self):
        log_bytes = frame_log(3)
        # LOG 后须恰有 6 个位置参数（START END KIND APPLIED CURSOR COUNT），
        # 上限仅可成对（再加 0 或 2 个）
        runs = [
            [],
            ["*"],
            ["*", "*", "*", "*"],
            # 5 个查询参数（缺 COUNT）非法
            ["*", "*", "*", "*", "*"],
            # 7 个 = 6 参数 + 1 个上限（不成对）非法
            ["*", "*", "*", "*", "*", "2", "1"],
            # 9 个 = 6 参数 + 3 个上限非法
            ["*", "*", "*", "*", "*", "2", "1", "2", "3"],
        ]
        for tokens in runs:
            code, _, _, _ = run_query(log_bytes, *tokens)
            self.assertEqual(code, 2, tokens)

    def test_bad_bounds(self):
        log_bytes = frame_log(3)
        for start, end in (
            ("x", "*"), ("", "*"), ("-1", "*"), ("01", "*"),
            ("1.0", "*"), ("*", "x"), ("*", "-0"), ("*", "+1"),
        ):
            code, _, _, _ = run_query(
                log_bytes, start, end, "*", "*", "*", "1"
            )
            self.assertEqual(code, 2, (start, end))

    def test_start_greater_than_end(self):
        log_bytes = frame_log(3)
        code, _, _, _ = run_query(
            log_bytes, "5", "3", "*", "*", "*", "1"
        )
        self.assertEqual(code, 2)

    def test_bad_kind(self):
        log_bytes = frame_log(3)
        for kind in (
            "", "Learn", "FRAME", "learn ", "unknown", "stp", "all",
        ):
            code, _, _, _ = run_query(
                log_bytes, "*", "*", kind, "*", "*", "1"
            )
            self.assertEqual(code, 2, kind)

    def test_bad_applied_token(self):
        log_bytes = frame_log(3)
        for token in ("True", "TRUE", "yes", "1", "0", "false "):
            code, _, _, _ = run_query(
                log_bytes, "*", "*", "*", token, "*", "1"
            )
            self.assertEqual(code, 2, token)

    def test_bad_cursor_tokens(self):
        log_bytes = frame_log(3)
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
        log_bytes = frame_log(3)
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
        log_bytes = frame_log(3)
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
        log_bytes = frame_log(3)
        size = len(log_bytes)
        code, out, err, after = run_query(
            log_bytes, "*", "*", "*", "*", "*", "1",
            str(size - 1), "16777216",
        )
        self.assertEqual(code, 5)
        self.assertIn(b"log_limit", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_bad_internal_sha_invalid_input(self):
        log_bytes = frame_log(3)
        doc = log_doc(log_bytes)
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_query(
            bad, "*", "*", "*", "*", "*", "1"
        )
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_sha_mismatch_invalid_input(self):
        log_bytes = frame_log(3)
        code, out, err, _ = run_query(
            log_bytes, "*", "*", "*", "*", "0" * 64 + ":0", "1"
        )
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_offset_beyond_record_count_invalid_input(self):
        log_bytes = frame_log(3)
        source = log_doc(log_bytes)["sha256"]
        code, out, err, _ = run_query(
            log_bytes, "*", "*", "*", "*", source + ":4", "1"
        )
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_output_limit_after_validation(self):
        log_bytes = frame_log(3)
        code, out, err, after = run_query(
            log_bytes, "*", "*", "*", "*", "*", "1",
            str(len(log_bytes)), "1",
        )
        self.assertEqual(code, 5)
        self.assertIn(b"output_limit", err)
        self.assertEqual(out, b"")
        # 失败不改 LOG
        self.assertEqual(after, log_bytes)


if __name__ == "__main__":
    unittest.main()
