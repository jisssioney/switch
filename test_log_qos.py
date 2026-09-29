#!/usr/bin/env python3
"""log-qos 子命令回归：按游标重演 qos-check 模式 LOG 的前 offset 条事件
并给出出口队列。

仅用标准库；端到端驱动 `python switch.py log-qos LOG CURSOR [MAX_WORK]`。
参数、资源、CURSOR 及错误顺序完全沿用 log-security；成功产物键序固定为
schema,source_sha256,offset,ports,sha256，末项为前四键紧凑 UTF-8 加 LF
的 sha256；CURSOR 的 * 表示 records 长度（重演全部），否则
<sha256>:<offset>，offset=0 为初始空队列。ports 按配置序，项键序
name,queues,current,remaining；queues 依优先级 0..3 为四个 FIFO 帧号
整数数组，帧号按所有帧事件零基编号，坏帧占号但不入队；wrr 时 current
为 0..3 整数、remaining 为正整数（下次 service 续用的持久状态），sp 时
二者为 null。LOG 须通过摘要核对、qos-check 语义、全部记录核对与重建
日志逐字节一致，其他模式 invalid_input/4；重演前 offset 项按
qos-check 工作量公式计费，等于上限合法，首次超过 stderr 仅
{"error":"qos_work_limit"} 加 LF 并退出 5。
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

# 5000 位游标 offset/MAX_WORK 须按不限长十进制处理；测试自身解析产物时
# 同样需关闭 3.11+ 的 int↔str 位数上限
if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(0)

from test_log_fdb import fdb_config, mac, record  # noqa: E402
from test_qos import base_config, frame, service  # noqa: E402
from test_record_qos_check import (  # noqa: E402
    make_config,
    make_events,
)

QOS_KEYS = ["schema", "source_sha256", "offset", "ports", "sha256"]
PORT_KEYS = ["name", "queues", "current", "remaining"]
BCAST = "ff:ff:ff:ff:ff:ff"


def check_frame(t, port, dst=BCAST, length=100, fcs=True, alignment=True,
                priority=0, src="00:00:00:00:00:01", vlan=None):
    result = frame(t, port, dst, priority=priority, src=src, vlan=vlan)
    result.update({"length": length, "fcs": fcs, "alignment": alignment})
    return result


def qos_config(weights=(1, 1, 1, 1), mode="wrr"):
    result = json.loads(json.dumps(base_config(weights=list(weights),
                                               mode=mode)))
    result["max_frame"] = 1518
    return result


def qos_log(events, cfg=None):
    return record(cfg or make_config(), events)


def digest_of(doc):
    prefix = {
        "schema": doc["schema"],
        "source_sha256": doc["source_sha256"],
        "offset": doc["offset"],
        "ports": doc["ports"],
    }
    raw = (
        json.dumps(prefix, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def run_qos(log_bytes, cursor, *extra):
    with tempfile.TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "in.log")
        with open(log_path, "wb") as handle:
            handle.write(log_bytes)
        proc = subprocess.run(
            [sys.executable, SWITCH, "log-qos", log_path, cursor, *extra],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        with open(log_path, "rb") as handle:
            after = handle.read()
    return proc.returncode, proc.stdout, proc.stderr, after


def record_log(cfg, events):
    """record CONFIG EVENTS → (log 字节, LOG.sha256)。"""
    log_bytes = record(cfg, events)
    source = json.loads(log_bytes.decode("utf-8"))["sha256"]
    return log_bytes, source


def by_name(doc, name):
    return {entry["name"]: entry for entry in doc["ports"]}[name]


class HappyPathTests(unittest.TestCase):
    def test_star_is_records_length_with_fixed_key_order_and_digest(self):
        events = [
            check_frame(0, "p1", BCAST, src="00:00:00:00:00:01"),
            check_frame(1, "p1", BCAST, src="00:00:00:00:00:02"),
        ]
        log_bytes, source = record_log(qos_config(), events)
        code, out, err, after = run_qos(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertTrue(out.endswith(b"\n"))
        self.assertEqual(after, log_bytes)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(list(doc), QOS_KEYS)
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["source_sha256"], source)
        self.assertEqual(doc["offset"], 2)
        # 端口按配置序 p1..p6；初始 WRR 为 (3, weight3=1)
        self.assertEqual(
            [entry["name"] for entry in doc["ports"]],
            ["p1", "p2", "p3", "p4", "p5", "p6"],
        )
        for entry in doc["ports"]:
            self.assertEqual(list(entry), PORT_KEYS)
            self.assertEqual(len(entry["queues"]), 4)
            for queue in entry["queues"]:
                self.assertIsInstance(queue, list)
                self.assertTrue(all(isinstance(fid, int) for fid in queue))
            self.assertIn(entry["current"], (0, 1, 2, 3))
            self.assertIsInstance(entry["remaining"], int)
            self.assertGreater(entry["remaining"], 0)
        # 两广播帧 flood 入 p2/p3 的 0 号队；其余口空
        self.assertEqual(by_name(doc, "p2")["queues"], [[0, 1], [], [], []])
        self.assertEqual(by_name(doc, "p3")["queues"], [[0, 1], [], [], []])
        self.assertEqual(by_name(doc, "p1")["queues"], [[], [], [], []])
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_star_equals_sha_cursor_at_record_count(self):
        events = [check_frame(0, "p1", BCAST)]
        log_bytes, source = record_log(qos_config(), events)
        _, star_out, _, _ = run_qos(log_bytes, "*")
        code, cur_out, err, _ = run_qos(log_bytes, source + ":1")
        self.assertEqual(code, 0, err)
        self.assertEqual(cur_out, star_out)
        self.assertEqual(json.loads(cur_out.decode())["offset"], 1)

    def test_offset_zero_is_initial_empty_queues(self):
        events = [
            check_frame(0, "p1", BCAST),
            check_frame(1, "p1", BCAST, priority=3),
        ]
        log_bytes, source = record_log(qos_config(), events)
        code, out, err, _ = run_qos(log_bytes, source + ":0")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["offset"], 0)
        for entry in doc["ports"]:
            self.assertEqual(entry["queues"], [[], [], [], []])
            self.assertEqual(entry["current"], 3)
            self.assertEqual(entry["remaining"], 1)
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_queues_follow_priority_mapping_and_fifo_order(self):
        # qos_map 直接把 priority 映到队列号；三帧入 p2/p3 同口不同队
        events = [
            check_frame(0, "p1", BCAST, priority=3,
                        src="00:00:00:00:00:01"),
            check_frame(1, "p1", BCAST, priority=1,
                        src="00:00:00:00:00:02"),
            check_frame(2, "p1", BCAST, priority=3,
                        src="00:00:00:00:00:03"),
        ]
        log_bytes, source = record_log(qos_config(), events)
        code, out, err, _ = run_qos(log_bytes, source + ":3")
        self.assertEqual(code, 0, err)
        p2 = by_name(json.loads(out.decode()), "p2")
        self.assertEqual(p2["queues"], [[], [1], [], [0, 2]])

    def test_bad_frame_consumes_id_but_never_enqueues(self):
        # fid0 好帧、fid1 runt 坏帧、fid2 好帧：坏帧占号不入队
        events = [
            check_frame(0, "p1", BCAST, src="00:00:00:00:00:01"),
            check_frame(1, "p1", BCAST, length=10,
                        src="00:00:00:00:00:02"),
            check_frame(2, "p1", BCAST, src="00:00:00:00:00:03"),
        ]
        log_bytes, source = record_log(qos_config(), events)
        code, out, err, _ = run_qos(log_bytes, source + ":3")
        self.assertEqual(code, 0, err)
        p2 = by_name(json.loads(out.decode()), "p2")
        self.assertEqual(p2["queues"], [[0, 2], [], [], []])

    def test_service_removes_frames_and_advances_wrr_state(self):
        # 3 队两帧（fid0,1）、2 队一帧（fid2）；初始服务 3 队。权重全 1
        # 时每发一帧即推进：service 1 发 fid0 → (2,1)；service 1 发 fid2
        # → (1,1)，3 队仅剩 fid1
        events = [
            check_frame(0, "p1", BCAST, priority=3,
                        src="00:00:00:00:00:01"),
            check_frame(1, "p1", BCAST, priority=3,
                        src="00:00:00:00:00:02"),
            check_frame(2, "p1", BCAST, priority=2,
                        src="00:00:00:00:00:03"),
            service(3, "p2", 1),
            service(4, "p2", 1),
        ]
        log_bytes, source = record_log(qos_config(), events)
        expected = [
            (0, [[], [], [], []], 3),
            (1, [[], [], [], [0]], 3),
            (2, [[], [], [], [0, 1]], 3),
            (3, [[], [], [2], [0, 1]], 3),
            (4, [[], [], [2], [1]], 2),
            (5, [[], [], [], [1]], 1),
        ]
        for offset, queues, current in expected:
            code, out, err, _ = run_qos(log_bytes, source + ":%d" % offset)
            self.assertEqual(code, 0, (offset, err))
            p2 = by_name(json.loads(out.decode()), "p2")
            self.assertEqual(p2["queues"], queues, offset)
            self.assertEqual(p2["current"], current, offset)
            self.assertEqual(p2["remaining"], 1, offset)

    def test_wrr_remaining_quota_persists_across_service_calls(self):
        # 权重 [1, 2, 3, 4]：3 队权重 4。连续两帧服务后 rem=2，状态保留
        # 供下次 service 续用
        cfg = qos_config(weights=(1, 2, 3, 4))
        events = [
            check_frame(0, "p1", BCAST, priority=3,
                        src="00:00:00:00:00:01"),
            check_frame(1, "p1", BCAST, priority=3,
                        src="00:00:00:00:00:02"),
            check_frame(2, "p1", BCAST, priority=3,
                        src="00:00:00:00:00:03"),
            service(3, "p2", 2),
        ]
        log_bytes, source = record_log(cfg, events)
        code, out, err, _ = run_qos(log_bytes, source + ":4")
        self.assertEqual(code, 0, err)
        p2 = by_name(json.loads(out.decode()), "p2")
        self.assertEqual(p2["queues"], [[], [], [], [2]])
        self.assertEqual(p2["current"], 3)
        self.assertEqual(p2["remaining"], 2)

    def test_sp_mode_reports_null_current_and_remaining(self):
        cfg = qos_config(mode="sp")
        events = [
            check_frame(0, "p1", BCAST, priority=3,
                        src="00:00:00:00:00:01"),
            check_frame(1, "p1", BCAST, priority=1,
                        src="00:00:00:00:00:02"),
        ]
        log_bytes, source = record_log(cfg, events)
        code, out, err, _ = run_qos(log_bytes, source + ":2")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode())
        for entry in doc["ports"]:
            self.assertIsNone(entry["current"])
            self.assertIsNone(entry["remaining"])
        p2 = by_name(doc, "p2")
        self.assertEqual(p2["queues"], [[], [1], [], [0]])

    def test_empty_log_star_and_zero_identical(self):
        log_bytes = qos_log([])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for cursor in ("*", source + ":0"):
            code, out, err, _ = run_qos(log_bytes, cursor)
            self.assertEqual(code, 0, err)
            doc = json.loads(out.decode("utf-8"))
            self.assertEqual(doc["offset"], 0)
            for entry in doc["ports"]:
                self.assertEqual(entry["queues"], [[], [], [], []])

    def test_make_config_full_sequence_queues(self):
        # test_record_qos_check 的完整序列：t=7 断链后 p3 清队
        log_bytes, source = record_log(make_config(), make_events())
        code, out, err, _ = run_qos(log_bytes, "*")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["offset"], 7)
        # fid0 入 p2/p3；t=6 p2 服务发出；t=7 断链清空 p3
        self.assertEqual(by_name(doc, "p2")["queues"], [[], [], [], []])
        self.assertEqual(by_name(doc, "p3")["queues"], [[], [], [], []])
        self.assertEqual(doc["sha256"], digest_of(doc))


class UsageTests(unittest.TestCase):
    def test_arg_counts(self):
        log_bytes = qos_log(make_events()[:1])
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "in.log")
            with open(path, "wb") as handle:
                handle.write(log_bytes)
            # 缺 CURSOR；多余位置参数均 usage/2
            for tokens in ([], [path], [path, "*", "1", "2"]):
                proc = subprocess.run(
                    [sys.executable, SWITCH, "log-qos", *tokens],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                self.assertEqual(proc.returncode, 2, tokens)

    def test_bad_cursor_tokens(self):
        log_bytes = qos_log(make_events()[:1])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
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
            code, _, _, _ = run_qos(log_bytes, cursor)
            self.assertEqual(code, 2, cursor)

    def test_bad_max_work_tokens(self):
        log_bytes = qos_log(make_events()[:1])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for token in ("", "0", "-1", "01", "1.0", "1 ", "x", "1e3"):
            code, _, _, _ = run_qos(log_bytes, source + ":0", token)
            self.assertEqual(code, 2, token)
            code, _, _, _ = run_qos(log_bytes, "*", token)
            self.assertEqual(code, 2, token)

    def test_arbitrary_length_decimal_max_work_accepted(self):
        log_bytes = qos_log(make_events()[:1])
        code, _, err, _ = run_qos(log_bytes, "*", "9" * 60)
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_qos(log_bytes, "*", "9" * 5000)
        self.assertEqual(code, 0, err)

    def test_five_thousand_digit_cursor_offset_unbounded(self):
        # 5000 位 offset 按不限长十进制解析：超过记录数报 invalid_input/4，
        # 不得触发 int↔str 位数上限崩溃
        log_bytes = qos_log(make_events()[:1])
        code, out, err, after = run_qos(
            log_bytes, json.loads(log_bytes.decode())["sha256"]
            + ":" + "1" * 5000
        )
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)


class ErrorPrecedenceTests(unittest.TestCase):
    def test_file_not_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "nope.log")
            proc = subprocess.run(
                [sys.executable, SWITCH, "log-qos", missing, "*"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(proc.returncode, 3)
        self.assertIn(b"file_not_found", proc.stderr)
        self.assertEqual(proc.stdout, b"")

    def test_log_limit_before_invalid_input(self):
        # 固定输入上限 16777216；超限先于 JSON 解析（log_limit/5）
        oversized = b"{" + b" " * (16 * 1024 * 1024)
        code, out, err, after = run_qos(oversized, "*")
        self.assertEqual(code, 5)
        self.assertIn(b"log_limit", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, oversized)

    def test_bad_internal_sha_invalid_input(self):
        log_bytes = qos_log(make_events()[:1])
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_qos(bad, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_sha_mismatch_invalid_input(self):
        log_bytes = qos_log(make_events()[:1])
        code, out, err, _ = run_qos(log_bytes, "0" * 64 + ":0")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_offset_beyond_record_count_invalid_input(self):
        log_bytes = qos_log(make_events()[:1])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_qos(log_bytes, source + ":2")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_non_qos_check_modes_rejected(self):
        # fdb 模式 LOG：静态合法但非 qos-check 模式
        events = [{"t": 0, "port": "p1", "mac": mac(1), "vlan": 1}]
        log_bytes = record(fdb_config(), events)
        code, out, err, after = run_qos(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_qos_non_check_mode_rejected(self):
        # qos（无 max_frame）模式同样拒绝
        cfg = json.loads(json.dumps(qos_config()))
        del cfg["max_frame"]
        log_bytes = record(cfg, [frame(0, "p1", BCAST)])
        code, out, err, after = run_qos(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_tampered_records_fail_verification(self):
        # 幂等链路恒 applied=false；篡改为 true 并重算内部摘要 → 记录核对
        # 失败
        log_bytes = qos_log(make_events())
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["records"][0]["applied"] = True
        prefix = {
            "schema": doc["schema"],
            "config": doc["config"],
            "records": doc["records"],
        }
        doc["sha256"] = hashlib.sha256(
            (json.dumps(prefix, separators=(",", ":")) + "\n").encode("utf-8")
        ).hexdigest()
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, after = run_qos(bad, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, bad)

    def test_invalid_input_before_work_limit(self):
        # 摘要错与极小工作量上限同时成立：invalid_input/4 优先
        log_bytes = qos_log(make_events()[:1])
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_qos(bad, "*", "1")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")


class WorkLimitTests(unittest.TestCase):
    # make_config/make_events 计费（test_record_qos_check.QosCheckBillingTest）：
    # 初始 5；各项后累计 6、28、52、55、58、62、81
    CUMULATIVE = (5, 6, 28, 52, 55, 58, 62, 81)

    def test_work_counts_only_prefix_events(self):
        log_bytes, source = record_log(make_config(), make_events())
        for offset, total in enumerate(self.CUMULATIVE):
            code, _, err, _ = run_qos(
                log_bytes, source + ":%d" % offset, str(total)
            )
            self.assertEqual(code, 0, (offset, err))
            code, out, err, after = run_qos(
                log_bytes, source + ":%d" % offset, str(total - 1)
            )
            self.assertEqual(code, 5, offset)
            self.assertEqual(err, b'{"error":"qos_work_limit"}\n')
            self.assertEqual(out, b"")
            self.assertEqual(after, log_bytes)

    def test_frame_charge_uses_qos_check_formula(self):
        # base qos-check config（test_qos_check）：P=6、M=2、R=1，初始
        # C=1；首帧（坏帧同价）计 22，累计 23
        good = check_frame(0, "p1", BCAST, length=100)
        bad = check_frame(1, "p1", BCAST, length=10)
        log_bytes, source = record_log(qos_config(), [good, bad])
        code, _, err, _ = run_qos(log_bytes, source + ":1", "23")
        self.assertEqual(code, 0, err)
        code, out, err, after = run_qos(log_bytes, source + ":1", "22")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"qos_work_limit"}\n')
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_offset_zero_charges_initial_convergence_only(self):
        log_bytes, source = record_log(make_config(), make_events())
        # make_config：B=2、L=1、初始 U=1 → 初始 B+L+2U=5
        code, out, err, _ = run_qos(log_bytes, source + ":0", "5")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode())
        self.assertEqual(doc["offset"], 0)
        code, _, err, _ = run_qos(log_bytes, source + ":0", "4")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"qos_work_limit"}\n')

    def test_default_max_work_is_ten_million(self):
        code, _, err, _ = run_qos(qos_log([]), "*")
        self.assertEqual(code, 0, err)


if __name__ == "__main__":
    unittest.main()
