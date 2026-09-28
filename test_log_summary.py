#!/usr/bin/env python3
"""log-summary 子命令回归：静态统计 LOG 记录，不重演、不推导。

仅用标准库；端到端驱动 `python switch.py log-summary LOG
[MAX_LOG_BYTES MAX_OUTPUT_BYTES]`。成功产物键序固定为
schema,source_sha256,total,applied,kinds,sha256，末项为前五键紧凑
非 ASCII 转义 UTF-8 加 LF 的 sha256；kinds 固定按
learn,frame,link,member,service,reload,rollback 全列七项。
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

KIND_ORDER = (
    "learn",
    "frame",
    "link",
    "member",
    "service",
    "reload",
    "rollback",
)
SUMMARY_KEYS = (
    "schema",
    "source_sha256",
    "total",
    "applied",
    "kinds",
    "sha256",
)


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


def event_learn(t):
    # 键须按 Unicode 码点升序：mac,port,t,vlan
    return {"mac": "00:00:00:00:00:01", "port": "p1", "t": t, "vlan": 1}


def event_frame(t, port="p1"):
    # 七键帧形：dst,ethertype,port,priority,src,t,vlan
    return {
        "dst": "ff:ff:ff:ff:ff:ff",
        "ethertype": 0x0800,
        "port": port,
        "priority": 0,
        "src": "00:00:00:00:00:02",
        "t": t,
        "vlan": None,
    }


def event_link(t):
    return {"id": "L1", "t": t, "up": True}


def event_member(t):
    return {"member": "p4", "t": t, "up": True}


def event_service(t):
    return {"count": 5, "port": "p1", "t": t}


def event_reload(t):
    return {"config": {}, "t": t}


def event_rollback(t):
    return {"rollback": 1, "t": t}


def make_log(spec):
    """spec 为 (event, applied) 序列；version/t 静态校验不重演，直接落值。"""
    records = [
        {
            "t": t,
            "version": 0,
            "event": event,
            "applied": applied,
            "output": None,
        }
        for t, (event, applied) in enumerate(spec)
    ]
    doc = {"schema": 1, "config": {"k": 1}, "records": records}
    return rehash(doc)


def all_kinds_log():
    """七类各一条：applied 形为 真,真,假,真,假,真,真（总 7、生效 5）。"""
    return make_log(
        [
            (event_learn(0), True),
            (event_frame(1), True),
            (event_link(2), False),
            (event_member(3), True),
            (event_service(4), False),
            (event_reload(5), True),
            (event_rollback(6), True),
        ]
    )


def recorded_frame_log():
    """真实 record 产出的三帧日志，中段改为 false 并重算。"""
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
        "total": doc["total"],
        "applied": doc["applied"],
        "kinds": doc["kinds"],
    }
    raw = (
        json.dumps(prefix, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def run_summary(log_bytes, *args):
    """写 in.log，原样透传参数，回读 LOG。"""
    with tempfile.TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "in.log")
        with open(log_path, "wb") as handle:
            handle.write(log_bytes)
        proc = subprocess.run(
            [sys.executable, SWITCH, "log-summary", log_path, *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        with open(log_path, "rb") as handle:
            after = handle.read()
    return proc.returncode, proc.stdout, proc.stderr, after


class HappyPathTests(unittest.TestCase):
    def test_key_order_schema_source_and_digest(self):
        log_bytes = recorded_frame_log()
        code, out, err, _ = run_summary(log_bytes)
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertTrue(out.endswith(b"\n"))
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(list(doc), list(SUMMARY_KEYS))
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["source_sha256"], log_doc(log_bytes)["sha256"])
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_totals_from_records_without_replay(self):
        log_bytes = recorded_frame_log()
        code, out, err, _ = run_summary(log_bytes)
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["total"], 3)
        self.assertEqual(doc["applied"], 2)
        frame_item = next(k for k in doc["kinds"] if k["kind"] == "frame")
        self.assertEqual(frame_item, {"kind": "frame", "total": 3, "applied": 2})

    def test_all_seven_kinds_listed_in_fixed_order(self):
        log_bytes = all_kinds_log()
        code, out, err, _ = run_summary(log_bytes)
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["total"], 7)
        self.assertEqual(doc["applied"], 5)
        kinds = doc["kinds"]
        self.assertEqual([k["kind"] for k in kinds], list(KIND_ORDER))
        for item in kinds:
            self.assertEqual(list(item), ["kind", "total", "applied"])
        expected = {
            "learn": (1, 1),
            "frame": (1, 1),
            "link": (1, 0),
            "member": (1, 1),
            "service": (1, 0),
            "reload": (1, 1),
            "rollback": (1, 1),
        }
        for item in kinds:
            self.assertEqual(
                (item["total"], item["applied"]), expected[item["kind"]]
            )
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_zero_kinds_still_all_listed(self):
        log_bytes = make_log([])
        code, out, err, _ = run_summary(log_bytes)
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["total"], 0)
        self.assertEqual(doc["applied"], 0)
        self.assertEqual([k["kind"] for k in doc["kinds"]], list(KIND_ORDER))
        self.assertTrue(all(k["total"] == 0 and k["applied"] == 0
                            for k in doc["kinds"]))
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_compact_non_ascii_escaped_payload(self):
        log_bytes = all_kinds_log()
        code, out, err, _ = run_summary(log_bytes)
        self.assertEqual(code, 0, err)
        # 紧凑分隔，kind 项键序固定
        self.assertIn(b'"kinds":[{"kind":"learn","total":1,"applied":1', out)
        self.assertFalse(out.endswith(b"\n\n"))

    def test_explicit_equal_limits_legal(self):
        log_bytes = all_kinds_log()
        size = len(log_bytes)
        code, out, err, _ = run_summary(
            log_bytes, str(size), str(size * 100)
        )
        self.assertEqual(code, 0, err)
        self.assertLessEqual(len(out), size * 100)


class UsageTests(unittest.TestCase):
    def test_arg_counts(self):
        log_bytes = all_kinds_log()
        self.assertEqual(run_summary(log_bytes, "1")[0], 2)
        self.assertEqual(run_summary(log_bytes, "1", "2", "3")[0], 2)

    def test_bad_limit_tokens(self):
        log_bytes = all_kinds_log()
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
        log_bytes = all_kinds_log()
        code, out, err, after = run_summary(
            log_bytes, str(len(log_bytes) - 1), "16777216"
        )
        self.assertEqual(code, 5)
        self.assertIn(b"log_limit", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_invalid_input_shapes(self):
        good = recorded_frame_log()
        doc = log_doc(good)
        bad_sha = copy.deepcopy(doc)
        bad_sha["sha256"] = "0" * 64
        cases = {
            "bad_sha.log": (
                json.dumps(bad_sha, separators=(",", ":")) + "\n"
            ).encode("utf-8"),
            "malformed.log": b"{not json\n",
        }
        missing_key = copy.deepcopy(doc)
        del missing_key["records"][0]["version"]
        cases["missing_key.log"] = (
            json.dumps(missing_key, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        wrong_type = copy.deepcopy(doc)
        wrong_type["records"][0]["applied"] = 1
        wrong_type["sha256"] = hashlib.sha256(
            switch._log_prefix_bytes(wrong_type)
        ).hexdigest()
        cases["wrong_type.log"] = (
            json.dumps(wrong_type, separators=(",", ":")) + "\n"
        ).encode("utf-8")
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
        log_bytes = all_kinds_log()
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
    return proc.returncode, proc.stdout, proc.stderr, b""


if __name__ == "__main__":
    unittest.main()
