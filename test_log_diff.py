#!/usr/bin/env python3
"""log-diff 子命令回归：两份 record 日志的确定性差异诊断。

仅用标准库；端到端驱动 `python switch.py log-diff LEFT RIGHT
[MAX_LOG_BYTES MAX_OUTPUT_BYTES MAX_DIFF_WORK]`。两文件先打开后按
LEFT、RIGHT 依 log-query 分块读取（各受首项限制，等于上限合法），
均须通过静态结构、规范化与内部 sha256 校验，不重演。按 JSON 类型和值
比较（对象忽略键序、数组保序）：先比 config，相等后逐项比 records，
首个不同即停，共同前缀后的长度差亦不同。stdout 键序固定
equal,at,left,right；工作量沿用 config-diff 的 S/D。
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

EQUAL_LINE = b'{"equal":true,"at":null,"left":null,"right":null}\n'


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


def log_doc(log_bytes):
    return json.loads(log_bytes.decode("utf-8"))


def frame_log(n, applied_flags=None):
    """n 条 frame 记录的真实 LOG；applied_flags 给定时逐记录指定 applied。"""
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


def synthetic_log(spec, config=None, outputs=None, applied_flags=None):
    """按 (kind, event) 序列构造静态合法 LOG（config 默认空对象），不重演。

    outputs/applied_flags 给定时逐记录指定 output/applied，否则 None/True。
    """
    records = []
    for index, (_kind, event) in enumerate(spec):
        applied = True if applied_flags is None else applied_flags[index]
        output = None if outputs is None else outputs[index]
        records.append(
            {
                "t": event["t"],
                "version": index,
                "event": canonical(event),
                "applied": applied,
                "output": output,
            }
        )
    doc = {"schema": 1, "config": {} if config is None else config,
           "records": records}
    return rehash(doc)


def learn_spec(t, port="p1", mac="00:00:00:00:00:01", vlan=1):
    return ("learn", {"t": t, "port": port, "mac": mac, "vlan": vlan})


def run_diff(left_raw, right_raw, args=()):
    """写两文件，原样透传参数（含上限），回读两文件内容。"""
    with tempfile.TemporaryDirectory() as tmp:
        left_path = os.path.join(tmp, "left.log")
        right_path = os.path.join(tmp, "right.log")
        with open(left_path, "wb") as handle:
            handle.write(left_raw)
        with open(right_path, "wb") as handle:
            handle.write(right_raw)
        proc = subprocess.run(
            [sys.executable, SWITCH, "log-diff", left_path, right_path]
            + list(args),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        with open(left_path, "rb") as handle:
            left_after = handle.read()
        with open(right_path, "rb") as handle:
            right_after = handle.read()
    return proc.returncode, proc.stdout, proc.stderr, left_after, right_after


def run_ok(left_raw, right_raw, args=()):
    code, out, err, _, _ = run_diff(left_raw, right_raw, args)
    assert code == 0, (code, err.decode("utf-8"))
    return json.loads(out.decode("utf-8")), out


def ref_size(value):
    """S 的独立参照实现：标量 1；数组 1+各元素 S；对象 1+键数+各值 S。"""
    if isinstance(value, dict):
        return 1 + len(value) + sum(ref_size(v) for v in value.values())
    if isinstance(value, list):
        return 1 + sum(ref_size(v) for v in value)
    return 1


def ref_work(old, new):
    """D 的独立参照实现：对象计 1+并集键数，共有键递归，单侧键计该侧 S；
    其余计 1+S(旧值)+S(新值)。"""
    if isinstance(old, dict) and isinstance(new, dict):
        total = 1 + len(set(old) | set(new))
        for key in set(old) | set(new):
            if key in old and key in new:
                total += ref_work(old[key], new[key])
            else:
                total += ref_size(old[key] if key in old else new[key])
        return total
    return 1 + ref_size(old) + ref_size(new)


class EqualTests(unittest.TestCase):
    def test_identical_real_logs_byte_exact(self):
        log_bytes = frame_log(5)
        result, raw = run_ok(log_bytes, log_bytes)
        self.assertEqual(result, {"equal": True, "at": None,
                                  "left": None, "right": None})
        self.assertEqual(raw, EQUAL_LINE)

    def test_distinct_bytes_same_semantics(self):
        # 同语义日志分别由两次 record 生成（逐字节一致是更强保证），
        # 再以不同 JSON 空白写入：比较只看语义
        log_bytes = frame_log(3)
        doc = log_doc(log_bytes)
        spaced = (
            json.dumps(
                {key: doc[key] for key in switch.LOG_KEYS},
                ensure_ascii=False, indent=2,
            ).encode("utf-8")
            + b"\n"
        )
        result, _ = run_ok(spaced, log_bytes)
        self.assertEqual(result["equal"], True)

    def test_output_object_key_order_ignored(self):
        # output 静态校验不要求键序；两侧同值不同键序仍判相等
        spec = [learn_spec(0)]
        left = synthetic_log(spec, outputs=[{"b": 1, "a": 2}])
        right = synthetic_log(spec, outputs=[{"a": 2, "b": 1}])
        result, _ = run_ok(left, right)
        self.assertEqual(result["equal"], True)


class ConfigDifferenceTests(unittest.TestCase):
    def _logs(self):
        spec = [learn_spec(0), learn_spec(1)]
        left = synthetic_log(spec, config=canonical({"a": 1, "c": 2}))
        right = synthetic_log(spec, config=canonical({"a": 9, "c": 2}))
        return left, right

    def test_config_diff_is_reported_before_records(self):
        left, right = self._logs()
        result, raw = run_ok(left, right)
        self.assertFalse(result["equal"])
        self.assertEqual(result["at"], "config")
        self.assertEqual(result["left"], {"a": 1, "c": 2})
        self.assertEqual(result["right"], {"a": 9, "c": 2})
        # 键序与 at 类型
        self.assertTrue(raw.startswith(b'{"equal":false,"at":"config",'))
        self.assertIn(b'"left":{"a":1,"c":2}', raw)
        self.assertIn(b'"right":{"a":9,"c":2}', raw)

    def test_config_diff_records_never_compared(self):
        # 配置不同时即使记录数不同也报 config
        left_doc = log_doc(self._logs()[0])
        right = self._logs()[1]
        left_doc["records"].append(left_doc["records"][0])
        left = rehash(left_doc)
        result, _ = run_ok(left, right)
        self.assertEqual(result["at"], "config")


class RecordDifferenceTests(unittest.TestCase):
    def test_first_differing_record_zero_based_index(self):
        left = frame_log(5)
        right_doc = log_doc(frame_log(5))
        right_doc["records"][2]["applied"] = False
        right = rehash(right_doc)
        result, raw = run_ok(left, right)
        self.assertEqual(result["equal"], False)
        self.assertEqual(result["at"], 2)
        left_doc = log_doc(left)
        self.assertEqual(
            result["left"], switch._canonical(left_doc["records"][2])
        )
        self.assertEqual(
            result["right"], switch._canonical(right_doc["records"][2])
        )
        self.assertTrue(result["left"]["applied"] is True)
        self.assertTrue(result["right"]["applied"] is False)
        self.assertIn(b'"at":2,"left":', raw)

    def test_stops_at_first_difference(self):
        left = frame_log(5)
        right_doc = log_doc(frame_log(5))
        right_doc["records"][1]["t"] = 4096
        right_doc["records"][3]["t"] = 8192  # 更靠后的差异不得出现
        right = rehash(right_doc)
        result, _ = run_ok(left, right)
        self.assertEqual(result["at"], 1)
        self.assertEqual(result["left"]["t"], 1)
        self.assertEqual(result["right"]["t"], 4096)

    def test_bool_distinguished_from_int_in_event(self):
        # 静态校验只看 event 键形；JSON 类型比较须区分 bool 与 int
        spec = [learn_spec(0)]
        left = synthetic_log(spec)
        right_doc = log_doc(synthetic_log(spec))
        right_doc["records"][0]["event"]["t"] = True
        right = rehash(right_doc)
        result, _ = run_ok(left, right)
        self.assertEqual(result["at"], 0)
        self.assertIs(result["right"]["event"]["t"], True)
        left_doc = log_doc(left)
        right2_doc = log_doc(synthetic_log(spec))
        right2_doc["records"][0]["event"]["t"] = 1
        right2 = rehash(right2_doc)
        result, _ = run_ok(right, right2)
        self.assertEqual(result["at"], 0)

    def test_records_canonicalized_in_output(self):
        # output 内键序打乱：两侧不同点须按规范化键序输出
        spec = [learn_spec(0)]
        left = synthetic_log(spec, outputs=[{"z": 1, "a": {"y": 2, "x": 3}}])
        right = synthetic_log(spec, outputs=[{"z": 2, "a": {"x": 3, "y": 2}}])
        result, raw = run_ok(left, right)
        self.assertEqual(result["at"], 0)
        self.assertEqual(
            result["left"]["output"], {"a": {"x": 3, "y": 2}, "z": 1}
        )
        self.assertIn(b'"output":{"a":{"x":3,"y":2},"z":1}', raw)

    def test_array_order_sensitive(self):
        spec_l = [learn_spec(0)]
        spec_r = [learn_spec(0)]
        # output 为数组时保序比较
        left = synthetic_log(spec_l, outputs=[{"q": [1, 2, 3]}])
        right = synthetic_log(spec_r, outputs=[{"q": [3, 2, 1]}])
        result, _ = run_ok(left, right)
        self.assertEqual(result["at"], 0)
        self.assertEqual(result["left"]["output"]["q"], [1, 2, 3])
        self.assertEqual(result["right"]["output"]["q"], [3, 2, 1])


class LengthDifferenceTests(unittest.TestCase):
    def test_right_longer(self):
        left = frame_log(2)
        right = frame_log(4)
        result, raw = run_ok(left, right)
        self.assertEqual(result["equal"], False)
        self.assertEqual(result["at"], 2)
        self.assertIsNone(result["left"])
        right_doc = log_doc(right)
        self.assertEqual(
            result["right"], switch._canonical(right_doc["records"][2])
        )
        self.assertIn(b'"at":2,"left":null,"right":', raw)

    def test_left_longer(self):
        left_doc = log_doc(frame_log(3))
        right = frame_log(1)
        result, _ = run_ok(rehash(left_doc), right)
        self.assertEqual(result["at"], 1)
        self.assertIsNone(result["right"])
        self.assertEqual(
            result["left"], switch._canonical(left_doc["records"][1])
        )

    def test_difference_before_length_wins(self):
        # 公共前缀内已有差异：报下标，不报长度
        left = frame_log(3)
        right_doc = log_doc(frame_log(5))
        right_doc["records"][0]["applied"] = False
        right = rehash(right_doc)
        result, _ = run_ok(left, right)
        self.assertEqual(result["at"], 0)


class WorkLimitTests(unittest.TestCase):
    BIG = ("9" * 30, "9" * 30)  # 日志/输出上限给极大值，只控工作量

    def test_equal_logs_work_boundary(self):
        log_bytes = frame_log(4)
        doc = log_doc(log_bytes)
        work = ref_work(canonical(doc["config"]), canonical(doc["config"]))
        work += sum(
            ref_work(switch._canonical(r), switch._canonical(r))
            for r in doc["records"]
        )
        code, out, err, _, _ = run_diff(
            log_bytes, log_bytes, self.BIG + (str(work),)
        )
        self.assertEqual((code, err), (0, b""))
        self.assertEqual(out, EQUAL_LINE)
        code, out, err, left_after, right_after = run_diff(
            log_bytes, log_bytes, self.BIG + (str(work - 1),)
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"diff_work_limit"}\n')
        self.assertEqual(left_after, log_bytes)
        self.assertEqual(right_after, log_bytes)

    def test_record_diff_work_boundary_byte_identical(self):
        left = frame_log(5)
        right_doc = log_doc(frame_log(5))
        right_doc["records"][2]["t"] = 777
        right = rehash(right_doc)
        left_doc = log_doc(left)
        left_cfg = switch._canonical(left_doc["config"])
        right_cfg = switch._canonical(right_doc["config"])
        work = ref_work(left_cfg, right_cfg)
        for i in range(3):  # 两条相等对 + 下标 2 的不同对
            work += ref_work(
                switch._canonical(left_doc["records"][i]),
                switch._canonical(right_doc["records"][i]),
            )
        code, default_out, err, _, _ = run_diff(left, right)
        self.assertEqual((code, err), (0, b""))
        code, out, err, _, _ = run_diff(
            left, right, self.BIG + (str(work),)
        )
        self.assertEqual((code, err), (0, b""))
        self.assertEqual(out, default_out)
        code, out, err, _, _ = run_diff(
            left, right, self.BIG + (str(work - 1),)
        )
        self.assertEqual((code, out, err),
                         (5, b"", b'{"error":"diff_work_limit"}\n'))

    def test_length_diff_adds_one(self):
        # 空记录对其一：config 为空对象，配置相等 D=1，长度差 +1，恰为 2
        left = synthetic_log([], config={})
        right = synthetic_log([learn_spec(0)])
        code, out, err, _, _ = run_diff(
            left, right, self.BIG + ("2",)
        )
        self.assertEqual((code, err), (0, b""))
        self.assertEqual(json.loads(out)["at"], 0)
        code, out, err, _, _ = run_diff(
            left, right, self.BIG + ("1",)
        )
        self.assertEqual((code, out, err),
                         (5, b"", b'{"error":"diff_work_limit"}\n'))

    def test_config_diff_never_charges_records(self):
        # 配置不同：记录再多也不计 D；config D = 1+1(并集键)+3(标量对)=5
        spec = [learn_spec(i) for i in range(30)]
        outputs = [{"pad": list(range(50))} for _ in spec]
        left = synthetic_log(spec, config={"a": 1}, outputs=copy.deepcopy(outputs))
        right = synthetic_log(spec, config={"a": 2}, outputs=copy.deepcopy(outputs))
        code, out, err, _, _ = run_diff(
            left, right, self.BIG + ("5",)
        )
        self.assertEqual((code, err), (0, b""))
        self.assertEqual(json.loads(out)["at"], "config")
        code, out, err, _, _ = run_diff(
            left, right, self.BIG + ("4",)
        )
        self.assertEqual((code, out, err),
                         (5, b"", b'{"error":"diff_work_limit"}\n'))

    def test_charging_stops_after_first_difference(self):
        # 下标 1 即不同：其后的巨型相等记录对不得计费
        spec = [learn_spec(0), learn_spec(1)]
        big = {"pad": list(range(3000))}
        left = synthetic_log(
            spec + [learn_spec(i) for i in range(2, 12)],
            outputs=[None, None] + [copy.deepcopy(big) for _ in range(10)],
        )
        right_doc = log_doc(left)
        right_doc["records"][1]["t"] = 4096
        right = rehash(right_doc)
        left_doc = log_doc(left)
        work = ref_work({}, {})
        work += ref_work(
            switch._canonical(left_doc["records"][0]),
            switch._canonical(right_doc["records"][0]),
        )
        work += ref_work(
            switch._canonical(left_doc["records"][1]),
            switch._canonical(right_doc["records"][1]),
        )
        code, default_out, err, _, _ = run_diff(left, right)
        self.assertEqual((code, err), (0, b""))
        code, out, err, _, _ = run_diff(
            left, right, self.BIG + (str(work),)
        )
        self.assertEqual((code, err), (0, b""))
        self.assertEqual(out, default_out)
        code, out, err, _, _ = run_diff(
            left, right, self.BIG + (str(work - 1),)
        )
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"diff_work_limit"}\n')

    def test_default_limit_is_ten_million(self):
        self.assertEqual(switch.DEFAULT_MAX_DIFF_WORK, 10000000)
        self.assertEqual(switch.DEFAULT_MAX_LOG_BYTES, 16777216)
        self.assertEqual(switch.DEFAULT_MAX_OUTPUT_BYTES, 16777216)


class InputLimitTests(unittest.TestCase):
    def test_exactly_limit_legal_then_over(self):
        log_bytes = frame_log(1)
        size = len(log_bytes)
        code, out, err, _, _ = run_diff(
            log_bytes, log_bytes, (str(size), "99999999", "99999999")
        )
        self.assertEqual((code, err), (0, b""))
        self.assertEqual(out, EQUAL_LINE)
        code, out, err, left_after, right_after = run_diff(
            log_bytes, log_bytes, (str(size - 1), "99999999", "99999999")
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"log_limit"}\n')
        self.assertEqual(left_after, log_bytes)
        self.assertEqual(right_after, log_bytes)

    def test_left_over_before_right(self):
        over = frame_log(4)
        ok = frame_log(1)
        code, out, err, _, _ = run_diff(
            over, ok, (str(len(ok)), "99999999", "99999999")
        )
        self.assertEqual((code, out, err),
                         (5, b"", b'{"error":"log_limit"}\n'))
        code, out, err, _, _ = run_diff(
            ok, over, (str(len(ok)), "99999999", "99999999")
        )
        self.assertEqual((code, out, err),
                         (5, b"", b'{"error":"log_limit"}\n'))

    def test_log_limit_precedes_invalid_input(self):
        # LEFT 超限即停：内容不是合法 JSON 也报 log_limit
        code, out, err, _, _ = run_diff(
            b"{" + b" " * 100, frame_log(1),
            ("10", "99999999", "99999999"),
        )
        self.assertEqual((code, out, err),
                         (5, b"", b'{"error":"log_limit"}\n'))
        # LEFT 恰在限内（1 字节 b"{"），RIGHT 超限：先读两文件，RIGHT 报超限
        code, out, err, _, _ = run_diff(
            b"{", frame_log(1), ("1", "99999999", "99999999")
        )
        self.assertEqual((code, out, err),
                         (5, b"", b'{"error":"log_limit"}\n'))

    def test_trailing_whitespace_counts_toward_limit(self):
        log_bytes = frame_log(1)
        padded = log_bytes + b"   "
        code, out, err, _, _ = run_diff(
            padded, log_bytes, (str(len(padded)), "99999999", "99999999")
        )
        self.assertEqual(code, 0)
        code, out, err, _, _ = run_diff(
            padded, log_bytes,
            (str(len(padded) - 1), "99999999", "99999999"),
        )
        self.assertEqual((code, out, err),
                         (5, b"", b'{"error":"log_limit"}\n'))


class OutputLimitTests(unittest.TestCase):
    def test_exactly_limit_then_over(self):
        left = frame_log(2)
        right_doc = log_doc(frame_log(2))
        right_doc["records"][0]["applied"] = False
        right = rehash(right_doc)
        _, payload, err, _, _ = run_diff(left, right)
        self.assertEqual(err, b"")
        code, out, err, _, _ = run_diff(
            left, right,
            ("99999999", str(len(payload)), "99999999"),
        )
        self.assertEqual((code, err), (0, b""))
        self.assertEqual(out, payload)
        code, out, err, _, _ = run_diff(
            left, right,
            ("99999999", str(len(payload) - 1), "99999999"),
        )
        self.assertEqual((code, out, err),
                         (5, b"", b'{"error":"output_limit"}\n'))

    def test_work_limit_precedes_output_limit(self):
        # 配置不同 D=5；工作量 4 先超限，不产生输出
        spec = [learn_spec(0)]
        left = synthetic_log(spec, config={"a": 1})
        right = synthetic_log(spec, config={"a": 2})
        code, out, err, _, _ = run_diff(
            left, right, ("99999999", "1", "4")
        )
        self.assertEqual((code, out, err),
                         (5, b"", b'{"error":"diff_work_limit"}\n'))


class InvalidInputTests(unittest.TestCase):
    def _expect_invalid(self, left_raw, right_raw):
        code, out, err, left_after, right_after = run_diff(left_raw, right_raw)
        self.assertEqual((code, out, err),
                         (4, b"", b'{"error":"invalid_input"}\n'))
        self.assertEqual(left_after, left_raw)
        self.assertEqual(right_after, right_raw)

    def test_bad_json(self):
        good = frame_log(1)
        self._expect_invalid(b"{", good)
        self._expect_invalid(good, b"[}")

    def test_bad_shape(self):
        good = frame_log(1)
        self._expect_invalid(b"123\n", good)
        self._expect_invalid(good, b"null\n")

    def test_bad_internal_sha(self):
        good = frame_log(1)
        doc = log_doc(good)
        doc["records"][0]["t"] = 4096  # 篡改后不重算 sha
        tampered = (
            json.dumps(
                {key: doc[key] for key in switch.LOG_KEYS},
                ensure_ascii=False, separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        self._expect_invalid(tampered, good)
        self._expect_invalid(good, tampered)

    def test_left_validated_before_right(self):
        code, out, err, _, _ = run_diff(b"{", b"[}")
        self.assertEqual((code, out, err),
                         (4, b"", b'{"error":"invalid_input"}\n'))

    def test_no_replay_semantically_bad_log_accepted(self):
        # 静态合法但事件时间序列语义荒谬的日志仍被接受：不重演
        spec = [learn_spec(99), learn_spec(0)]
        log_bytes = synthetic_log(spec)
        code, out, err, _, _ = run_diff(log_bytes, log_bytes)
        self.assertEqual((code, err), (0, b""))
        self.assertEqual(out, EQUAL_LINE)


class UsageAndFileTests(unittest.TestCase):
    def _run_raw(self, argv):
        return subprocess.run(
            [sys.executable, SWITCH] + argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_arg_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "a.log")
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

    def test_bad_limit_tokens_are_usage(self):
        log_bytes = frame_log(1)
        for token in ("0", "01", "1.5", "-1", "x", "", "1 "):
            with tempfile.TemporaryDirectory() as tmp:
                left = os.path.join(tmp, "l.log")
                right = os.path.join(tmp, "r.log")
                with open(left, "wb") as handle:
                    handle.write(log_bytes)
                with open(right, "wb") as handle:
                    handle.write(log_bytes)
                proc = self._run_raw(
                    ["log-diff", left, right, token, "9", "9"]
                )
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(proc.stderr,
                                 b'{"error":"usage"}\n')

    def test_missing_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            existing = os.path.join(tmp, "a.log")
            with open(existing, "wb") as handle:
                handle.write(frame_log(1))
            missing = os.path.join(tmp, "nope")
            proc = self._run_raw(["log-diff", missing, existing])
            self.assertEqual((proc.returncode, proc.stdout), (3, b""))
            self.assertEqual(proc.stderr,
                             b'{"error":"file_not_found"}\n')
            proc = self._run_raw(["log-diff", existing, missing])
            self.assertEqual(proc.returncode, 3)
            self.assertEqual(proc.stderr,
                             b'{"error":"file_not_found"}\n')

    def test_usage_precedes_file_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "nope")
            proc = self._run_raw(
                ["log-diff", missing, missing, "0", "9", "9"]
            )
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(proc.stderr, b'{"error":"usage"}\n')
            proc = self._run_raw(
                ["log-diff", missing, missing, "9", "9", "9"]
            )
            self.assertEqual(proc.returncode, 3)
            self.assertEqual(proc.stderr,
                             b'{"error":"file_not_found"}\n')

    def test_precedence_chain(self):
        # usage -> file_not_found -> log_limit -> invalid_input
        #   -> diff_work_limit -> output_limit
        good = frame_log(1)
        with tempfile.TemporaryDirectory() as tmp:
            left = os.path.join(tmp, "l.log")
            right = os.path.join(tmp, "r.log")
            # 左文件 1 字节恰在限内，右文件远超 1 字节 -> log_limit
            with open(left, "wb") as handle:
                handle.write(b"{")
            with open(right, "wb") as handle:
                handle.write(good)
            proc = self._run_raw(
                ["log-diff", left, right, "1", "1", "1"]
            )
            self.assertEqual((proc.returncode, proc.stdout), (5, b""))
            self.assertEqual(proc.stderr, b'{"error":"log_limit"}\n')
            # 两侧均 1 字节非法 JSON -> invalid_input
            with open(right, "wb") as handle:
                handle.write(b"{")
            proc = self._run_raw(
                ["log-diff", left, right, "1", "1", "1"]
            )
            self.assertEqual(proc.returncode, 4)
            self.assertEqual(proc.stderr,
                             b'{"error":"invalid_input"}\n')
            # 合法小日志、配置不同 D=5，工作量 4 -> diff_work_limit
            spec = [learn_spec(0)]
            l = synthetic_log(spec, config={"a": 1})
            r = synthetic_log(spec, config={"a": 2})
            with open(left, "wb") as handle:
                handle.write(l)
            with open(right, "wb") as handle:
                handle.write(r)
            proc = self._run_raw(
                ["log-diff", left, right, "99999999", "1", "4"]
            )
            self.assertEqual(proc.returncode, 5)
            self.assertEqual(proc.stderr,
                             b'{"error":"diff_work_limit"}\n')
            # 工作量充足但输出仅 1 字节 -> output_limit
            proc = self._run_raw(
                ["log-diff", left, right, "99999999", "1", "99999999"]
            )
            self.assertEqual(proc.returncode, 5)
            self.assertEqual(proc.stderr,
                             b'{"error":"output_limit"}\n')


if __name__ == "__main__":
    unittest.main()
