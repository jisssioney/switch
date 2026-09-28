#!/usr/bin/env python3
"""log-summary 子命令回归：静态汇总 LOG 记录，不重演、不推导。

仅用标准库；端到端驱动 `python switch.py log-summary LOG
[MAX_LOG_BYTES MAX_OUTPUT_BYTES]`。成功产物键序固定为
schema,source_sha256,total,applied,kinds,sha256，末项为前五键紧凑
UTF-8 加 LF 的 sha256；kinds 按 learn,frame,link,member,service,reload,
rollback 固定序全列，各项键序 kind,total,applied，计数直接取记录字段。
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

SUMMARY_KEYS = [
    "schema", "source_sha256", "total", "applied", "kinds", "sha256",
]
KIND_ORDER = [
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


def frame_log():
    """三帧记录日志，applied 形为 True/False/True（中段改为 false 并重算）。"""
    events = [
        frame(0, "p1", "00:00:00:00:00:01"),
        frame(1, "p2", "00:00:00:00:00:02"),
        frame(2, "p3", "00:00:00:00:00:03"),
    ]
    _, log_bytes = record(base_config(), events)
    doc = log_doc(log_bytes)
    doc["records"][1]["applied"] = False
    return rehash(doc)


def canonical(value):
    if isinstance(value, dict):
        return {key: canonical(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [canonical(item) for item in value]
    return value


def synthetic_log(spec, applied_flags=None):
    """按 (kind, event) 序列构造静态合法 LOG（config 为空对象），不重演。

    applied_flags 给定时逐记录指定 applied，否则全 True；输出恒 None。
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
    prefix = {key: doc[key] for key in SUMMARY_KEYS[:5]}
    raw = (
        json.dumps(prefix, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def run_summary(log_bytes, *args, extra_files=None):
    """写 in.log（可附 extra 文件），原样透传参数，回读 LOG。"""
    with tempfile.TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "in.log")
        with open(log_path, "wb") as handle:
            handle.write(log_bytes)
        for name, content in (extra_files or {}).items():
            with open(os.path.join(tmp, name), "wb") as handle:
                handle.write(content)
        proc = subprocess.run(
            [sys.executable, SWITCH, "log-summary", log_path, *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        with open(log_path, "rb") as handle:
            after = handle.read()
    return proc.returncode, proc.stdout, proc.stderr, after


class HappyPathTests(unittest.TestCase):
    def test_key_order_and_digest_on_frame_log(self):
        log_bytes = frame_log()
        code, out, err, _ = run_summary(log_bytes)
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertTrue(out.endswith(b"\n"))
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(list(doc), SUMMARY_KEYS)
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_schema_and_source_sha256(self):
        log_bytes = frame_log()
        code, out, err, _ = run_summary(log_bytes)
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["source_sha256"], log_doc(log_bytes)["sha256"])

    def test_total_and_applied_counts(self):
        log_bytes = frame_log()  # True/False/True
        code, out, err, _ = run_summary(log_bytes)
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["total"], 3)
        self.assertEqual(doc["applied"], 2)

    def test_kinds_all_listed_in_fixed_order_with_item_key_order(self):
        code, out, err, _ = run_summary(frame_log())
        self.assertEqual(code, 0, err)
        kinds = json.loads(out.decode("utf-8"))["kinds"]
        self.assertEqual([item["kind"] for item in kinds], KIND_ORDER)
        for item in kinds:
            self.assertEqual(list(item), ["kind", "total", "applied"])

    def test_frame_kind_bucket_and_zero_fill(self):
        code, out, err, _ = run_summary(frame_log())
        self.assertEqual(code, 0, err)
        kinds = {
            item["kind"]: (item["total"], item["applied"])
            for item in json.loads(out.decode("utf-8"))["kinds"]
        }
        self.assertEqual(kinds["frame"], (3, 2))
        for kind in ("learn", "link", "member", "service", "reload",
                     "rollback"):
            self.assertEqual(kinds[kind], (0, 0), kind)

    def test_all_seven_kinds_bucketed(self):
        log_bytes = synthetic_log(
            all_kind_spec(),
            # 第二条 link(t=3) 与 rollback(t=7) 未生效
            applied_flags=[
                True, True, True, False, True, True, True, False
            ],
        )
        code, out, err, _ = run_summary(log_bytes)
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["total"], 8)
        self.assertEqual(doc["applied"], 6)
        kinds = {
            item["kind"]: (item["total"], item["applied"])
            for item in doc["kinds"]
        }
        self.assertEqual(kinds["learn"], (1, 1))
        self.assertEqual(kinds["frame"], (1, 1))
        self.assertEqual(kinds["link"], (2, 1))
        self.assertEqual(kinds["member"], (1, 1))
        self.assertEqual(kinds["service"], (1, 1))
        self.assertEqual(kinds["reload"], (1, 1))
        self.assertEqual(kinds["rollback"], (1, 0))
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_empty_records(self):
        log_bytes = synthetic_log([])
        code, out, err, _ = run_summary(log_bytes)
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["total"], 0)
        self.assertEqual(doc["applied"], 0)
        for item in doc["kinds"]:
            self.assertEqual((item["total"], item["applied"]), (0, 0))
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_counts_use_record_field_without_replay(self):
        # 即便 applied 形与语义不一致（静态合法即可），计数只认记录字段
        log_bytes = synthetic_log(
            all_kind_spec(), applied_flags=[False] * 8
        )
        code, out, err, _ = run_summary(log_bytes)
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["total"], 8)
        self.assertEqual(doc["applied"], 0)
        for item in doc["kinds"]:
            self.assertEqual(item["applied"], 0, item["kind"])
            self.assertGreaterEqual(item["total"], 0)

    def test_explicit_equal_limits_legal(self):
        log_bytes = frame_log()
        size = len(log_bytes)
        code, out, err, after = run_summary(
            log_bytes, str(size), str(size * 100)
        )
        self.assertEqual(code, 0, err)
        self.assertLessEqual(len(out), size * 100)


class UsageTests(unittest.TestCase):
    def test_arg_counts(self):
        log_bytes = frame_log()
        # 无上限为合法形式
        self.assertEqual(run_summary(log_bytes)[0], 0)
        self.assertEqual(
            run_summary(log_bytes, "16777216", "16777216")[0], 0
        )
        # 上限须成对：1 个或 3 个均非法
        self.assertEqual(run_summary(log_bytes, "16777216")[0], 2)
        self.assertEqual(
            run_summary(log_bytes, "16777216", "16777216", "1")[0], 2
        )

    def test_bad_limit_tokens(self):
        log_bytes = frame_log()
        for lo, hi in (
            ("0", "16777216"),
            ("-1", "16777216"),
            ("01", "16777216"),
            ("abc", "16777216"),
            ("16777216", "0"),
        ):
            self.assertEqual(
                run_summary(log_bytes, lo, hi)[0], 2, (lo, hi)
            )


class ErrorPrecedenceTests(unittest.TestCase):
    def test_file_not_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "nope.log")
            proc = subprocess.run(
                [sys.executable, SWITCH, "log-summary", missing],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(proc.returncode, 3)
        self.assertIn(b"file_not_found", proc.stderr)
        self.assertEqual(proc.stdout, b"")

    def test_log_limit_before_invalid_input(self):
        # 超限截断的内容即便不是合法 JSON，也先报 log_limit
        log_bytes = frame_log()
        size = len(log_bytes)
        code, out, err, after = run_summary(
            log_bytes, str(size - 1), "16777216"
        )
        self.assertEqual(code, 5)
        self.assertIn(b"log_limit", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_invalid_input_shapes(self):
        good = frame_log()
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
        cases["wrong_type.log"] = rehash(wrong_type)
        # 未知事件键形
        unknown = copy.deepcopy(doc)
        unknown["records"][0]["event"]["bogus"] = 1
        cases["unknown_event.log"] = rehash(unknown)
        for name, content in cases.items():
            code, out, err, after = _run_named(content, name)
            self.assertEqual(code, 4, name)
            self.assertIn(b"invalid_input", err, name)
            self.assertEqual(out, b"", name)
            self.assertEqual(after, content, name)

    def test_output_limit_after_validation(self):
        log_bytes = frame_log()
        code, out, err, after = run_summary(
            log_bytes, str(len(log_bytes)), "1"
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
            [sys.executable, SWITCH, "log-summary", path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        with open(path, "rb") as handle:
            after = handle.read()
    return proc.returncode, proc.stdout, proc.stderr, after


if __name__ == "__main__":
    unittest.main()
