#!/usr/bin/env python3
"""log-filter 子命令回归：按 t 闭区间与 applied 静态筛选 LOG。

契约要点：
- 仅静态校验 LOG（顶层与记录键序、字段类型、config/event 规范键序、event
  已知键形、内部 sha256），不校验配置语义、不重演事件、不推导任何字段；
- 原序保留 t∈[START,END] 且 applied 匹配的记录，记录原样（含
  version/output）；
- stdout 顶层键序 schema,source_sha256,records,sha256，紧凑 UTF-8 加 LF，
  末项为前三键同口径的 64 位小写 sha256；
- 错误顺序 usage(2)、file_not_found(3)、log_limit(5)、invalid_input(4)、
  output_limit(5)；等于上限合法；失败时 stdout 为空且 LOG 不改动。

仅用标准库；端到端驱动 `python switch.py log-filter ...`。
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

from test_record import linked_config  # noqa: E402
from test_record import record as record_log  # noqa: E402

DEFAULT_LIMIT = "16777216"


def run_filter(log_bytes, *args):
    """写 in.log 后端到端调用 log-filter；其余 token 原样传入并回读 LOG。"""
    with tempfile.TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "in.log")
        with open(log_path, "wb") as handle:
            handle.write(log_bytes)
        proc = subprocess.run(
            [sys.executable, SWITCH, "log-filter", log_path, *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        with open(log_path, "rb") as handle:
            after = handle.read()
    return proc.returncode, proc.stdout, proc.stderr, {"in.log": after}


def write_log(doc):
    """按 schema,config,records 紧凑加 LF 重算内部 sha256，返回 LOG 字节。"""
    prefix = {key: doc[key] for key in ("schema", "config", "records")}
    raw = (
        json.dumps(prefix, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    doc["sha256"] = hashlib.sha256(raw).hexdigest()
    return (
        json.dumps(doc, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def learn(t, applied, port="p1", mac="00:00:00:00:00:01"):
    return {
        "t": t,
        "version": 0,
        "event": {"mac": mac, "port": port, "t": t, "vlan": None},
        "applied": applied,
        "output": None,
    }


def static_log(records, config=None):
    return write_log(
        {"schema": 1, "config": config or {"age": 100}, "records": records}
    )


def filter_doc(log_bytes, *args):
    code, out, err, _ = run_filter(log_bytes, *args)
    assert code == 0, (code, err.decode())
    return json.loads(out.decode()), out


def output_digest(doc):
    prefix = {key: doc[key] for key in ("schema", "source_sha256", "records")}
    raw = (
        json.dumps(prefix, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest(), raw


class LogFilterHappyPathTests(unittest.TestCase):
    def setUp(self):
        # linked_config 的链路/成员事件幂等项 applied=False、状态改变项
        # applied=True，output 恒 null：t=1..7 真假交替
        events = [
            {"t": 1, "id": "L2", "up": True},
            {"t": 2, "id": "L2", "up": False},
            {"t": 3, "id": "L2", "up": False},
            {"t": 4, "id": "L2", "up": True},
            {"t": 5, "member": "p4", "up": True},
            {"t": 6, "member": "p4", "up": False},
            {"t": 7, "member": "p4", "up": False},
        ]
        _, self.log_bytes = record_log(linked_config(), events)
        self.source_doc = json.loads(self.log_bytes.decode())

    def _check(self, doc, raw, kept_ts):
        # 顶层四键：值/序固定，末项为前三键同口径摘要
        self.assertEqual(list(doc), ["schema", "source_sha256",
                                     "records", "sha256"])
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["source_sha256"], self.source_doc["sha256"])
        self.assertEqual([r["t"] for r in doc["records"]], kept_ts)
        digest, _ = output_digest(doc)
        self.assertEqual(doc["sha256"], digest)
        self.assertTrue(raw.endswith(b"\n"))

    def test_wildcards_keep_everything(self):
        doc, raw = filter_doc(self.log_bytes, "*", "*", "*")
        self._check(doc, raw, [1, 2, 3, 4, 5, 6, 7])
        # 记录原样：version/output 均不重算，与源 LOG 逐字段一致
        for kept, original in zip(doc["records"],
                                  self.source_doc["records"]):
            self.assertEqual(kept, original)

    def test_closed_interval_inclusive_both_ends(self):
        doc, raw = filter_doc(self.log_bytes, "3", "5", "*")
        self._check(doc, raw, [3, 4, 5])

    def test_one_sided_bounds(self):
        doc, raw = filter_doc(self.log_bytes, "6", "*", "*")
        self._check(doc, raw, [6, 7])
        doc, raw = filter_doc(self.log_bytes, "*", "2", "*")
        self._check(doc, raw, [1, 2])

    def test_filter_applied_true(self):
        doc, raw = filter_doc(self.log_bytes, "*", "*", "true")
        self._check(doc, raw, [2, 4, 6])

    def test_filter_applied_false(self):
        doc, raw = filter_doc(self.log_bytes, "*", "*", "false")
        self._check(doc, raw, [1, 3, 5, 7])

    def test_interval_and_applied_combined(self):
        doc, raw = filter_doc(self.log_bytes, "2", "6", "true")
        self._check(doc, raw, [2, 4, 6])
        doc, raw = filter_doc(self.log_bytes, "2", "6", "false")
        self._check(doc, raw, [3, 5])

    def test_single_point_interval(self):
        doc, raw = filter_doc(self.log_bytes, "4", "4", "*")
        self._check(doc, raw, [4])

    def test_no_match_is_empty_records(self):
        doc, raw = filter_doc(self.log_bytes, "8", "100", "*")
        self._check(doc, raw, [])
        doc, raw = filter_doc(self.log_bytes, "*", "*", "true")
        # 源摘要不随筛选结果变化
        self.assertEqual(doc["source_sha256"], self.source_doc["sha256"])

    def test_records_keep_original_order(self):
        # 源记录按 t 升序；筛选后保序而非重排
        log_bytes = static_log(
            [learn(0, True), learn(5, False), learn(6, True), learn(9, True)]
        )
        doc, raw = filter_doc(log_bytes, "*", "*", "true")
        self.assertEqual([r["t"] for r in doc["records"]], [0, 6, 9])

    def test_records_preserve_version_and_output_verbatim(self):
        # 不重演、不推导：即便 version 与 applied 看似不自洽也原样保留
        records = [
            {"t": 0, "version": 3,
             "event": {"mac": "00:00:00:00:00:01", "port": "p1",
                       "t": 0, "vlan": None},
             "applied": False, "output": {"x": 1}},
        ]
        log_bytes = static_log(records)
        doc, _ = filter_doc(log_bytes, "*", "*", "*")
        self.assertEqual(doc["records"][0], records[0])


class LogFilterDigestTests(unittest.TestCase):
    def test_sha_covers_first_three_keys_with_lf(self):
        log_bytes = static_log([learn(0, True), learn(1, False)])
        _, raw = filter_doc(log_bytes, "*", "*", "*")
        text = raw.decode("utf-8")
        doc = json.loads(text)
        _, prefix_raw = output_digest(doc)
        # 完整输出 = 前三键摘要输入 + 末键包装的等价字节：摘要可独立复算
        self.assertEqual(
            doc["sha256"], hashlib.sha256(prefix_raw).hexdigest()
        )
        # 摘要为 64 位小写十六进制
        self.assertRegex(doc["sha256"], r"^[0-9a-f]{64}$")

    def test_digest_changes_with_filter_result(self):
        log_bytes = static_log([learn(0, True), learn(1, False)])
        all_doc, _ = filter_doc(log_bytes, "*", "*", "*")
        true_doc, _ = filter_doc(log_bytes, "*", "*", "true")
        self.assertNotEqual(all_doc["sha256"], true_doc["sha256"])
        # 源摘要恒定
        self.assertEqual(
            all_doc["source_sha256"], true_doc["source_sha256"]
        )


class LogFilterUsageTests(unittest.TestCase):
    def setUp(self):
        self.log_bytes = static_log([learn(0, True)])

    def _usage(self, *args):
        code, out, err, logs = run_filter(self.log_bytes, *args)
        self.assertEqual((code, out, err),
                         (2, b"", b'{"error":"usage"}\n'), args)
        self.assertEqual(logs["in.log"], self.log_bytes)

    def test_arity(self):
        self._usage()
        self._usage("*", "*")
        self._usage("*")
        self._usage("*", "*", "*", "1")            # 单个上限不成对
        self._usage("*", "*", "*", "1", "2", "3")  # 三个上限

    def test_bounds_shape(self):
        self._usage("-1", "*", "*")
        self._usage("*", "-1", "*")
        self._usage("01", "*", "*")
        self._usage("00", "*", "*")
        self._usage("1x", "*", "*")
        self._usage("", "*", "*")
        self._usage("**", "*", "*")

    def test_start_greater_than_end(self):
        self._usage("5", "2", "*")
        self._usage("1", "0", "*")

    def test_star_compares_equal_to_anything(self):
        # 任一端为 * 均无 START<=END 约束，合法
        for bounds in (("100000", "*"), ("*", "0"), ("*", "*")):
            code, _, err, _ = run_filter(
                self.log_bytes, bounds[0], bounds[1], "*"
            )
            self.assertEqual(code, 0, err)

    def test_applied_values(self):
        self._usage("*", "*", "TRUE")
        self._usage("*", "*", "yes")
        self._usage("*", "*", "1")
        self._usage("*", "*", "")

    def test_limit_shape(self):
        self._usage("*", "*", "*", "0", DEFAULT_LIMIT)
        self._usage("*", "*", "*", DEFAULT_LIMIT, "0")
        self._usage("*", "*", "*", "-1", DEFAULT_LIMIT)
        self._usage("*", "*", "*", "1a", DEFAULT_LIMIT)
        self._usage("*", "*", "*", "01", DEFAULT_LIMIT)

    def test_unbounded_integers_accepted(self):
        big = "9" * 300
        code, _, err, _ = run_filter(
            self.log_bytes, big, big, "*", "1" + "0" * 200,
            "1" + "0" * 200
        )
        self.assertEqual(code, 0, err)

    def test_zero_bounds_accepted(self):
        log_bytes = static_log([learn(0, True), learn(1, False)])
        doc, _ = filter_doc(log_bytes, "0", "0", "*")
        self.assertEqual([r["t"] for r in doc["records"]], [0])


class LogFilterFileAndLimitTests(unittest.TestCase):
    def setUp(self):
        self.log_bytes = static_log(
            [learn(t, t % 2 == 0) for t in range(1200)]
        )
        self.assertGreater(len(self.log_bytes), 65536)  # 跨多块读取

    def test_chunked_read_over_65536(self):
        # 每块至多 65536 字节：大 LOG 须正常读全并筛选
        doc, _ = filter_doc(self.log_bytes, "100", "199", "true")
        self.assertEqual(len(doc["records"]), 50)

    def test_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run(
                [sys.executable, SWITCH, "log-filter",
                 os.path.join(tmp, "nope.log"), "*", "*", "*"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b'{"error":"file_not_found"}\n')

    def test_log_limit_exceeded(self):
        code, out, err, logs = run_filter(
            self.log_bytes, "*", "*", "*", "10", DEFAULT_LIMIT
        )
        self.assertEqual((code, out, err),
                         (5, b"", b'{"error":"log_limit"}\n'))
        self.assertEqual(logs["in.log"], self.log_bytes)

    def test_log_limit_equal_is_legal(self):
        size = len(self.log_bytes)
        code, out, err, _ = run_filter(
            self.log_bytes, "*", "*", "*", str(size), DEFAULT_LIMIT
        )
        self.assertEqual(code, 0, err)
        self.assertTrue(out.endswith(b"\n"))

    def test_output_limit_exceeded(self):
        code, out, err, logs = run_filter(
            self.log_bytes, "*", "*", "*", DEFAULT_LIMIT, "1"
        )
        self.assertEqual((code, out, err),
                         (5, b"", b'{"error":"output_limit"}\n'))
        self.assertEqual(logs["in.log"], self.log_bytes)

    def test_output_limit_equal_is_legal(self):
        # 空筛选结果最短；输出上界恰等字节数（含 LF）合法
        doc, raw = filter_doc(self.log_bytes, "999999", "*", "*")
        self.assertEqual(doc["records"], [])
        size = len(raw)
        code, out, err, _ = run_filter(
            self.log_bytes, "999999", "*", "*", DEFAULT_LIMIT, str(size)
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(out, raw)
        # 少 1 字节即超限
        code, out, err, _ = run_filter(
            self.log_bytes, "999999", "*", "*", DEFAULT_LIMIT,
            str(size - 1)
        )
        self.assertEqual((code, out, err),
                         (5, b"", b'{"error":"output_limit"}\n'))


class LogFilterStaticValidationTests(unittest.TestCase):
    def _invalid(self, log_bytes, *args):
        code, out, err, logs = run_filter(
            log_bytes, *(args or ("*", "*", "*"))
        )
        self.assertEqual((code, out, err),
                         (4, b"", b'{"error":"invalid_input"}\n'))
        self.assertEqual(logs["in.log"], log_bytes)

    def test_malformed_json(self):
        self._invalid(b"{not json\n")

    def test_not_an_object(self):
        self._invalid(b"[]\n")

    def test_wrong_top_level_keys(self):
        doc = {"schema": 1, "config": {"age": 1}, "records": []}
        # 缺 sha256
        complete = json.loads(write_log(copy.deepcopy(doc)).decode())
        del complete["sha256"]
        self._invalid(
            (json.dumps(complete, separators=(",", ":")) + "\n").encode()
        )
        # 多余顶层键
        parsed = json.loads(write_log(copy.deepcopy(doc)).decode())
        parsed["extra"] = 1
        self._invalid((json.dumps(parsed) + "\n").encode())

    def test_bad_record_key_order(self):
        good = json.loads(static_log([learn(0, True)]).decode())
        raw = (
            '{"schema":1,"config":{"age":100},'
            '"records":[{"applied":true,"event":'
            '{"mac":"00:00:00:00:00:01","port":"p1","t":0,"vlan":null},'
            '"output":null,"t":0,"version":0}]'
        )
        prefix = raw.encode()
        sha = hashlib.sha256(prefix + b"\n").hexdigest()
        bad = (raw + ',"sha256":"%s"}\n' % sha).encode()
        self._invalid(bad)

    def test_bad_field_types(self):
        good = {"schema": 1, "config": {"age": 100},
                "records": [learn(0, True)]}
        # applied 为 int 而非 bool
        doc = json.loads(json.dumps(good))
        doc["records"][0]["applied"] = 1
        self._invalid(write_log(doc))
        # t 为负
        doc = json.loads(json.dumps(good))
        doc["records"][0]["t"] = -1
        doc["records"][0]["event"]["t"] = -1
        self._invalid(write_log(doc))
        # schema 非 1
        doc = json.loads(json.dumps(good))
        doc["schema"] = 2
        self._invalid(write_log(doc))
        # output 非 null/object
        doc = json.loads(json.dumps(good))
        doc["records"][0]["output"] = []
        self._invalid(write_log(doc))

    def test_unknown_event_shape(self):
        records = [{
            "t": 0, "version": 0,
            "event": {"t": 0, "port": "p1", "weird": 1},
            "applied": True, "output": None,
        }]
        self._invalid(static_log(records))

    def test_non_canonical_event_key_order(self):
        # event 内键须按 Unicode 码点升序
        records = [{
            "t": 0, "version": 0,
            "event": {"vlan": None, "t": 0, "port": "p1",
                      "mac": "00:00:00:00:00:01"},
            "applied": True, "output": None,
        }]
        self._invalid(static_log(records))

    def test_internal_sha256_mismatch(self):
        log_bytes = static_log([learn(0, True), learn(1, False)])
        doc = json.loads(log_bytes.decode())
        doc["records"][0]["t"] = 99  # 改记录但不重算摘要
        self._invalid((json.dumps(doc) + "\n").encode())

    def test_semantically_odd_config_passes_static_check(self):
        # 不校验配置语义：结构为对象、键序规范即放行
        log_bytes = static_log(
            [learn(0, True)], config={"age": "whatever", "ports": [-1, {}]}
        )
        code, out, err, _ = run_filter(log_bytes, "*", "*", "*")
        self.assertEqual(code, 0, err)
        self.assertTrue(out)


class LogFilterPrecedenceTests(unittest.TestCase):
    def setUp(self):
        self.log_bytes = static_log([learn(0, True)])

    def test_usage_beats_file_not_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run(
                [sys.executable, SWITCH, "log-filter",
                 os.path.join(tmp, "nope.log"), "*", "*"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stderr, b'{"error":"usage"}\n')

    def test_file_not_found_beats_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run(
                [sys.executable, SWITCH, "log-filter",
                 os.path.join(tmp, "nope.log"), "*", "*", "*", "1", "1"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(proc.stderr, b'{"error":"file_not_found"}\n')

    def test_log_limit_beats_invalid_input(self):
        # 半截 JSON 配更小字节上界：读到上界即报 log_limit，不进入解析
        truncated = self.log_bytes[: len(self.log_bytes) // 2]
        code, out, err, _ = run_filter(
            truncated, "*", "*", "*", str(len(truncated) - 1),
            DEFAULT_LIMIT
        )
        self.assertEqual((code, out, err),
                         (5, b"", b'{"error":"log_limit"}\n'))

    def test_invalid_input_beats_output_limit(self):
        code, out, err, _ = run_filter(
            b"{bad", "*", "*", "*", DEFAULT_LIMIT, "1"
        )
        self.assertEqual((code, out, err),
                         (4, b"", b'{"error":"invalid_input"}\n'))

    def test_log_limit_beats_output_limit(self):
        big = static_log([learn(t, True) for t in range(1200)])
        code, out, err, _ = run_filter(
            big, "*", "*", "*", "10", "1"
        )
        self.assertEqual((code, out, err),
                         (5, b"", b'{"error":"log_limit"}\n'))


if __name__ == "__main__":
    unittest.main()
