#!/usr/bin/env python3
"""log-mirror 子命令回归：按游标重演 mirror-check 模式 LOG 的前 offset 条
事件并累计镜像副本。

仅用标准库；端到端驱动 `python switch.py log-mirror LOG CURSOR [MAX_WORK]`。
参数、资源、CURSOR 及错误顺序完全沿用 log-qos；成功产物键序固定为
schema,source_sha256,offset,target,sources,sha256，末项为前五键紧凑非
ASCII 转义 UTF-8 加 LF 的 sha256；CURSOR 的 * 表示 records 长度（重演
全部），否则 <sha256>:<offset>，offset=0 为零副本。target 取配置镜像
目标；sources 按 mirror.sources 序，项键序 name,ingress,egress,total，
ingress/egress/total 为非负整数且 total=ingress+egress，累计前缀全部帧
结果 mirrors 项（入站按 source、出站按源出口）。LOG 须通过摘要核对、
mirror-check 语义、全部记录核对与重建日志逐字节一致，其他模式
invalid_input/4；重演前 offset 项按 mirror-check 工作量公式（与 mirror
同口径）计费，等于上限合法，首次超过 stderr 仅
{"error":"mirror_work_limit"} 加 LF 并退出 5。
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

from test_log_fdb import record  # noqa: E402
from test_record_mirror_check import (  # noqa: E402
    check_frame,
    link_event,
    make_config,
    member_event,
)

LOG_KEYS = ["schema", "source_sha256", "offset", "target", "sources",
            "sha256"]
SOURCE_KEYS = ["name", "ingress", "egress", "total"]
BCAST = "ff:ff:ff:ff:ff:ff"


def mirror_log(events, cfg=None):
    return record(cfg or make_config(), events)


def digest_of(doc):
    prefix = {
        "schema": doc["schema"],
        "source_sha256": doc["source_sha256"],
        "offset": doc["offset"],
        "target": doc["target"],
        "sources": doc["sources"],
    }
    raw = (
        json.dumps(prefix, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def run_mirror(log_bytes, cursor, *extra):
    with tempfile.TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "in.log")
        with open(log_path, "wb") as handle:
            handle.write(log_bytes)
        proc = subprocess.run(
            [sys.executable, SWITCH, "log-mirror", log_path, cursor, *extra],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        with open(log_path, "rb") as handle:
            after = handle.read()
    return proc.returncode, proc.stdout, proc.stderr, after


def events():
    # t=0 链路幂等；t=2 good 广播（flood 入 p2/p3，入站镜像 p1）；
    # t=3 runt 坏帧（无镜像）；t=4 成员幂等 up；t=5 成员实际下线；
    # t=7 链路实际断开
    return [
        link_event(0, "L2", True),
        check_frame(2, "p1"),
        check_frame(3, "p1", src="00:00:00:00:00:02", length=10),
        member_event(4, "p5", True),
        member_event(5, "p5", False),
        link_event(7, "L2", False),
    ]


class HappyPathTests(unittest.TestCase):
    def test_star_is_records_length_with_fixed_key_order_and_digest(self):
        log_bytes = mirror_log(events())
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_mirror(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertTrue(out.endswith(b"\n"))
        self.assertNotIn(b", ", out)
        self.assertNotIn(b": ", out)
        self.assertEqual(after, log_bytes)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(list(doc), LOG_KEYS)
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["source_sha256"], source)
        self.assertEqual(doc["offset"], 6)
        self.assertEqual(doc["target"], "p4")
        self.assertEqual(
            doc["sources"],
            [{"name": "p1", "ingress": 1, "egress": 0, "total": 1}],
        )
        for entry in doc["sources"]:
            self.assertEqual(list(entry), SOURCE_KEYS)
            self.assertIsInstance(entry["name"], str)
            for key in ("ingress", "egress", "total"):
                self.assertIsInstance(entry[key], int)
                self.assertGreaterEqual(entry[key], 0)
            self.assertEqual(
                entry["total"], entry["ingress"] + entry["egress"]
            )
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_star_equals_sha_cursor_at_record_count(self):
        log_bytes = mirror_log(events())
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        _, star_out, _, _ = run_mirror(log_bytes, "*")
        code, cur_out, err, _ = run_mirror(log_bytes, source + ":6")
        self.assertEqual(code, 0, err)
        self.assertEqual(cur_out, star_out)
        self.assertEqual(json.loads(cur_out.decode())["offset"], 6)

    def test_offset_zero_is_zero_copies(self):
        log_bytes = mirror_log(events())
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_mirror(log_bytes, source + ":0")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["offset"], 0)
        self.assertEqual(doc["target"], "p4")
        self.assertEqual(
            doc["sources"],
            [{"name": "p1", "ingress": 0, "egress": 0, "total": 0}],
        )
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_partial_offsets_count_only_prefix_mirrors(self):
        log_bytes = mirror_log(events())
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        # 仅 t=2 good 帧在 p1 产生 1 个入站副本（offset>=2 起出现）；
        # t=3 runt 无镜像；成员/链路事件不产生帧结果
        expected = [0, 0, 1, 1, 1, 1, 1]
        for offset in range(7):
            code, out, err, _ = run_mirror(
                log_bytes, source + ":%d" % offset
            )
            self.assertEqual(code, 0, (offset, err))
            doc = json.loads(out.decode("utf-8"))
            self.assertEqual(doc["offset"], offset)
            self.assertEqual(doc["sources"][0]["ingress"], expected[offset])
            self.assertEqual(doc["sources"][0]["egress"], 0)
            self.assertEqual(doc["sha256"], digest_of(doc))

    def test_sources_follow_config_order_with_ingress_and_egress(self):
        cfg = make_config()
        cfg["mirror"] = {
            "sources": ["p2", "p1"], "target": "p4", "direction": "both"
        }
        evs = [
            check_frame(10, "p1", src="00:00:00:00:00:01"),
            check_frame(11, "p2", src="00:00:00:00:00:02"),
        ]
        log_bytes = mirror_log(evs, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_mirror(log_bytes, "*")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual([s["name"] for s in doc["sources"]], ["p2", "p1"])
        # 帧入 p1：p1 入站 1，flood 出 p2 → p2 出站 1
        # 帧入 p2：p2 入站 1，flood 出 p1 → p1 出站 1
        self.assertEqual(
            doc["sources"],
            [
                {"name": "p2", "ingress": 1, "egress": 1, "total": 2},
                {"name": "p1", "ingress": 1, "egress": 1, "total": 2},
            ],
        )
        # 前缀仅第一条：p2 仅出站 1、p1 仅入站 1
        code, out, err, _ = run_mirror(log_bytes, source + ":1")
        self.assertEqual(code, 0, err)
        self.assertEqual(
            json.loads(out.decode("utf-8"))["sources"],
            [
                {"name": "p2", "ingress": 0, "egress": 1, "total": 1},
                {"name": "p1", "ingress": 1, "egress": 0, "total": 1},
            ],
        )

    def test_target_down_yields_zero_copies(self):
        cfg = make_config()
        for port in cfg["ports"]:
            if port["name"] == "p4":
                port["up"] = False
        log_bytes = mirror_log([check_frame(2, "p1")], cfg)
        code, out, err, _ = run_mirror(log_bytes, "*")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["target"], "p4")
        self.assertEqual(
            doc["sources"],
            [{"name": "p1", "ingress": 0, "egress": 0, "total": 0}],
        )

    def test_empty_log_star_and_zero_identical(self):
        log_bytes = mirror_log([])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        outputs = []
        for cursor in ("*", source + ":0"):
            code, out, err, _ = run_mirror(log_bytes, cursor)
            self.assertEqual(code, 0, err)
            doc = json.loads(out.decode("utf-8"))
            self.assertEqual(doc["offset"], 0)
            self.assertEqual(
                doc["sources"],
                [{"name": "p1", "ingress": 0, "egress": 0, "total": 0}],
            )
            outputs.append(out)
        self.assertEqual(outputs[0], outputs[1])


class UsageTests(unittest.TestCase):
    def test_arg_counts(self):
        log_bytes = mirror_log([check_frame(0, "p1")])
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "in.log")
            with open(path, "wb") as handle:
                handle.write(log_bytes)
            for tokens in ([], [path], [path, "*", "1", "2"]):
                proc = subprocess.run(
                    [sys.executable, SWITCH, "log-mirror", *tokens],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                self.assertEqual(proc.returncode, 2, tokens)

    def test_bad_cursor_tokens(self):
        log_bytes = mirror_log([check_frame(0, "p1")])
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
            code, _, _, _ = run_mirror(log_bytes, cursor)
            self.assertEqual(code, 2, cursor)

    def test_bad_max_work_tokens(self):
        log_bytes = mirror_log([check_frame(0, "p1")])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for token in ("", "0", "-1", "01", "1.0", "1 ", "x", "1e3"):
            code, _, _, _ = run_mirror(log_bytes, source + ":0", token)
            self.assertEqual(code, 2, token)
            code, _, _, _ = run_mirror(log_bytes, "*", token)
            self.assertEqual(code, 2, token)

    def test_arbitrary_length_decimal_max_work_accepted(self):
        log_bytes = mirror_log([check_frame(0, "p1")])
        code, _, err, _ = run_mirror(log_bytes, "*", "9" * 60)
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_mirror(log_bytes, "*", "9" * 5000)
        self.assertEqual(code, 0, err)

    def test_five_thousand_digit_cursor_offset_unbounded(self):
        log_bytes = mirror_log([check_frame(0, "p1")])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_mirror(
            log_bytes, source + ":" + "1" * 5000
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
                [sys.executable, SWITCH, "log-mirror", missing, "*"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(proc.returncode, 3)
        self.assertIn(b"file_not_found", proc.stderr)
        self.assertEqual(proc.stdout, b"")

    def test_log_limit_before_invalid_input(self):
        oversized = b"{" + b" " * (16 * 1024 * 1024)
        code, out, err, after = run_mirror(oversized, "*")
        self.assertEqual(code, 5)
        self.assertIn(b"log_limit", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, oversized)

    def test_bad_internal_sha_invalid_input(self):
        log_bytes = mirror_log([check_frame(0, "p1")])
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_mirror(bad, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_sha_mismatch_invalid_input(self):
        log_bytes = mirror_log([check_frame(0, "p1")])
        code, out, err, _ = run_mirror(log_bytes, "0" * 64 + ":0")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_offset_beyond_record_count_invalid_input(self):
        log_bytes = mirror_log([check_frame(0, "p1")])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_mirror(log_bytes, source + ":2")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_qos_check_mode_rejected(self):
        from test_qos_check import config, check_frame as qos_frame
        ev = [qos_frame(0, "p1", BCAST, src="00:00:00:00:00:01")]
        log_bytes = record(config(), ev)
        code, out, err, after = run_mirror(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_plain_mirror_mode_rejected(self):
        # mirror（无 max_frame）模式 LOG：静态合法但非 mirror-check 模式
        from test_record_mirror import make_config as mirror_config
        cfg = mirror_config()
        frame = {
            "t": 2, "port": "p2", "src": "00:00:00:00:00:01",
            "dst": BCAST, "vlan": None,
        }
        log_bytes = record(cfg, [frame])
        code, out, err, after = run_mirror(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_tampered_records_fail_verification(self):
        # 幂等链路 applied=false；篡改为 true 并重算内部摘要 → 记录核对失败
        log_bytes = mirror_log(events())
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
        code, out, err, after = run_mirror(bad, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, bad)

    def test_invalid_input_before_work_limit(self):
        log_bytes = mirror_log([check_frame(0, "p1")])
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_mirror(bad, "*", "1")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")


class WorkLimitTests(unittest.TestCase):
    # make_config：B=2、L=1、初始 U=1 → 初始 5；P=6、M=2。
    # t=0 幂等链路 X=0 计 1（累计 6）；t=2 good 帧 X=0 计 2P+M+1=15
    # （累计 21）；t=3 runt 帧 X=2 计 K+H+Q+15=17（累计 38）。
    def test_prefix_one_idempotent_link_boundary(self):
        log_bytes = mirror_log(events())
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_mirror(log_bytes, source + ":1", "6")
        self.assertEqual(code, 0, err)
        code, out, err, after = run_mirror(log_bytes, source + ":1", "5")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"mirror_work_limit"}\n')
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_frame_charge_uses_mirror_formula(self):
        log_bytes = mirror_log(events())
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        # offset=2：5+1+15=21；等于上限合法，20 首次超过
        code, _, err, _ = run_mirror(log_bytes, source + ":2", "21")
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_mirror(log_bytes, source + ":2", "20")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"mirror_work_limit"}\n')

    def test_runt_still_billed(self):
        log_bytes = mirror_log(events())
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        # offset=3：21+17=38；37 首次超过
        code, _, err, _ = run_mirror(log_bytes, source + ":3", "38")
        self.assertEqual(code, 0, err)
        code, out, err, _ = run_mirror(log_bytes, source + ":3", "37")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"mirror_work_limit"}\n')
        self.assertEqual(out, b"")

    def test_offset_zero_only_initial_convergence(self):
        log_bytes = mirror_log(events())
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_mirror(log_bytes, source + ":0", "5")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out.decode())["offset"], 0)
        code, out, err, _ = run_mirror(log_bytes, source + ":0", "4")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"mirror_work_limit"}\n')

    def test_default_max_work_is_ten_million(self):
        code, _, err, _ = run_mirror(mirror_log([]), "*")
        self.assertEqual(code, 0, err)


if __name__ == "__main__":
    unittest.main()
