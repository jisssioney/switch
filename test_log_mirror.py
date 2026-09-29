#!/usr/bin/env python3
"""log-mirror 子命令回归：按游标重演 mirror-check 模式 LOG 的前 offset 条
事件并累计镜像副本。

仅用标准库；端到端驱动 `python switch.py log-mirror LOG CURSOR [MAX_WORK]`。
参数、资源、CURSOR 及错误顺序完全沿用 log-qos；成功产物键序固定为
schema,source_sha256,offset,target,sources,sha256，末项为前五键紧凑非
ASCII 转义 UTF-8 加 LF 的 sha256；CURSOR 的 * 表示 records 长度（重演
全部），否则 <sha256>:<offset>，offset=0 为全零累计。target 取配置镜像
目标；sources 按 mirror.sources 序，项键序 name,ingress,egress,total，
后三项为非负整数且 total=ingress+egress，统计前缀结果中实际生成（target
可用）的入/出站副本；坏帧、VLAN 准入拒绝不生成副本。
LOG 须通过摘要核对、mirror-check 语义、全部记录核对与重建日志逐字节一致，
其他模式 invalid_input/4；重演前 offset 项按 mirror-check 工作量公式计费，
等于上限合法，首次超过 stderr 仅 {"error":"mirror_work_limit"} 加 LF 并
退出 5。
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

import switch as switch_mod  # noqa: E402
from test_log_fdb import record  # noqa: E402
from test_record_mirror_check import (  # noqa: E402
    make_config, check_frame, link_event, member_event,
)

MIRROR_KEYS = ["schema", "source_sha256", "offset", "target", "sources",
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


def simulate_sources(cfg, events):
    """直接调用 forward_mirror_check 求前 events 的镜像副本累计。"""
    cfg = json.loads(json.dumps(cfg))  # 防 forward 改写链路状态
    (
        bridges, links, delay, bridge, ports, age, storm, lags, mirror,
        max_frame,
    ) = switch_mod.validate_mirror_check_config(cfg)
    link_ids = {link["id"] for link in links}
    check_events = switch_mod.validate_lag_check_events(
        events, ports, link_ids, lags
    )
    result = switch_mod.forward_mirror_check(
        bridges, links, delay, bridge, ports, age, storm, lags, mirror,
        max_frame, check_events,
    )
    counts = {
        name: {"ingress": 0, "egress": 0} for name in mirror["sources"]
    }
    for item in result["results"]:
        for copy in item["mirrors"]:
            counts[copy["source"]][copy["direction"]] += 1
    sources = [
        {
            "name": name,
            "ingress": counts[name]["ingress"],
            "egress": counts[name]["egress"],
            "total": counts[name]["ingress"] + counts[name]["egress"],
        }
        for name in mirror["sources"]
    ]
    return mirror["target"], sources


def by_name(sources, name):
    return next(item for item in sources if item["name"] == name)


def two_good_frames():
    return [
        check_frame(0, "p1", src="00:00:00:00:00:01"),
        check_frame(1, "p1", src="00:00:00:00:00:02"),
    ]


class HappyPathTests(unittest.TestCase):
    def test_star_is_records_length_with_fixed_key_order_and_digest(self):
        log_bytes = mirror_log(two_good_frames())
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_mirror(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertTrue(out.endswith(b"\n"))
        self.assertNotIn(b", ", out)
        self.assertNotIn(b": ", out)
        self.assertEqual(after, log_bytes)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(list(doc), MIRROR_KEYS)
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["source_sha256"], source)
        self.assertEqual(doc["offset"], 2)
        self.assertEqual(doc["target"], "p4")
        self.assertEqual(
            [item["name"] for item in doc["sources"]], ["p1"]
        )
        for item in doc["sources"]:
            self.assertEqual(list(item), SOURCE_KEYS)
            self.assertIsInstance(item["name"], str)
            for key in ("ingress", "egress", "total"):
                self.assertIsInstance(item[key], int)
                self.assertGreaterEqual(item[key], 0)
            self.assertEqual(item["total"], item["ingress"] + item["egress"])
        # 两帧均由 p1 入站、target 可用：各计一次入站副本
        self.assertEqual(
            doc["sources"],
            [{"name": "p1", "ingress": 2, "egress": 0, "total": 2}],
        )
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_star_equals_sha_cursor_at_record_count(self):
        log_bytes = mirror_log(two_good_frames())
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        _, star_out, _, _ = run_mirror(log_bytes, "*")
        code, cur_out, err, _ = run_mirror(log_bytes, source + ":2")
        self.assertEqual(code, 0, err)
        self.assertEqual(cur_out, star_out)
        self.assertEqual(json.loads(cur_out.decode())["offset"], 2)

    def test_offset_zero_is_all_zero(self):
        log_bytes = mirror_log(two_good_frames())
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

    def test_partial_offset_accumulates_prefix_only(self):
        log_bytes = mirror_log(two_good_frames())
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        expected = [0, 1, 2]
        for offset in range(3):
            code, out, err, _ = run_mirror(
                log_bytes, source + ":%d" % offset
            )
            self.assertEqual(code, 0, (offset, err))
            doc = json.loads(out.decode("utf-8"))
            self.assertEqual(doc["offset"], offset)
            self.assertEqual(
                by_name(doc["sources"], "p1")["ingress"], expected[offset]
            )
            self.assertEqual(doc["sha256"], digest_of(doc))

    def test_ingress_and_egress_in_both_direction(self):
        cfg = make_config()
        # p1 入站命中入站镜像；广播泛洪出 p2（边缘口）命中出站镜像
        cfg["mirror"] = {
            "sources": ["p1", "p2"], "target": "p4", "direction": "both"
        }
        events = [check_frame(2, "p1")]
        log_bytes = mirror_log(events, cfg)
        code, out, err, _ = run_mirror(log_bytes, "*")
        self.assertEqual(code, 0, err)
        sources = json.loads(out.decode("utf-8"))["sources"]
        self.assertEqual(
            sources,
            [
                {"name": "p1", "ingress": 1, "egress": 0, "total": 1},
                {"name": "p2", "ingress": 0, "egress": 1, "total": 1},
            ],
        )

    def test_sources_follow_config_order(self):
        cfg = make_config()
        cfg["mirror"] = {
            "sources": ["p2", "p1"], "target": "p4", "direction": "both"
        }
        log_bytes = mirror_log([check_frame(2, "p1")], cfg)
        code, out, err, _ = run_mirror(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(
            [item["name"] for item in json.loads(out.decode())["sources"]],
            ["p2", "p1"],
        )

    def test_target_down_yields_no_copies(self):
        cfg = make_config()
        for port in cfg["ports"]:
            if port["name"] == "p4":
                port["up"] = False
        log_bytes = mirror_log(two_good_frames(), cfg)
        code, out, err, _ = run_mirror(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(
            json.loads(out.decode("utf-8"))["sources"],
            [{"name": "p1", "ingress": 0, "egress": 0, "total": 0}],
        )

    def test_bad_frame_and_vlan_reject_make_no_copy(self):
        # runt 坏帧不生成镜像；access p1 的 tagged 帧准入拒绝亦不生成
        events = [
            check_frame(0, "p1", src="00:00:00:00:00:01", length=10),
            check_frame(1, "p1", src="00:00:00:00:00:02", vlan=2),
        ]
        log_bytes = mirror_log(events)
        code, out, err, _ = run_mirror(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(
            json.loads(out.decode("utf-8"))["sources"],
            [{"name": "p1", "ingress": 0, "egress": 0, "total": 0}],
        )

    def test_prefix_matches_direct_simulation_for_every_offset(self):
        cfg = make_config()
        events = [
            link_event(0, "L2", True),
            check_frame(2, "p1"),
            check_frame(3, "p1", src="00:00:00:00:00:02", length=10),
            member_event(4, "p5", True),
            member_event(5, "p5", False),
            link_event(7, "L2", False),
        ]
        log_bytes = mirror_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for offset in range(len(events) + 1):
            code, out, err, _ = run_mirror(
                log_bytes, source + ":%d" % offset
            )
            self.assertEqual(code, 0, (offset, err))
            doc = json.loads(out.decode("utf-8"))
            target, sources = simulate_sources(cfg, events[:offset])
            self.assertEqual(doc["target"], target)
            self.assertEqual(doc["sources"], sources)

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
        log_bytes = mirror_log(two_good_frames()[:1])
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
        log_bytes = mirror_log(two_good_frames()[:1])
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
        log_bytes = mirror_log(two_good_frames()[:1])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for token in ("", "0", "-1", "01", "1.0", "1 ", "x", "1e3"):
            code, _, _, _ = run_mirror(log_bytes, source + ":0", token)
            self.assertEqual(code, 2, token)
            code, _, _, _ = run_mirror(log_bytes, "*", token)
            self.assertEqual(code, 2, token)

    def test_arbitrary_length_decimal_max_work_accepted(self):
        log_bytes = mirror_log(two_good_frames()[:1])
        code, _, err, _ = run_mirror(log_bytes, "*", "9" * 60)
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_mirror(log_bytes, "*", "9" * 5000)
        self.assertEqual(code, 0, err)

    def test_five_thousand_digit_cursor_offset_unbounded(self):
        log_bytes = mirror_log(two_good_frames()[:1])
        code, out, err, after = run_mirror(
            log_bytes, "0" * 64 + ":" + "1" * 5000
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
        log_bytes = mirror_log(two_good_frames()[:1])
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
        log_bytes = mirror_log(two_good_frames()[:1])
        code, out, err, _ = run_mirror(log_bytes, "0" * 64 + ":0")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_offset_beyond_record_count_invalid_input(self):
        log_bytes = mirror_log(two_good_frames()[:1])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_mirror(log_bytes, source + ":2")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_plain_mirror_mode_rejected(self):
        # mirror（无 max_frame）配置与五键帧：静态合法但非 mirror-check
        from test_record_mirror import make_config as plain_config
        from test_record_mirror import frame as plain_frame
        cfg = plain_config()
        events = [plain_frame(0, "p2", "00:00:00:00:00:01")]
        log_bytes = record(cfg, events)
        code, out, err, after = run_mirror(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_qos_check_mode_rejected(self):
        from test_log_qos import qos_log, good_frame
        log_bytes = qos_log([good_frame(0, "p1", "00:00:00:00:00:01")])
        code, out, err, after = run_mirror(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_tampered_records_fail_verification(self):
        # 帧恒 applied=true；篡改为 false 并重算内部摘要 → 记录核对失败
        log_bytes = mirror_log(two_good_frames()[:1])
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["records"][0]["applied"] = False
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
        log_bytes = mirror_log(two_good_frames()[:1])
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
    def test_frame_charge_uses_mirror_check_formula(self):
        # make_config：B=2、L=1、初始 U=1 → 初始 2+1+2=5；一条 good 帧
        # X=0 计 2P+M+1=12+2+1=15，offset=1 累计 20。等于上限合法，20-1
        # 首次超过报 mirror_work_limit/5
        log_bytes = mirror_log(two_good_frames()[:1])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, _, err, _ = run_mirror(log_bytes, source + ":1", "20")
        self.assertEqual(code, 0, err)
        code, out, err, after = run_mirror(
            log_bytes, source + ":1", "19"
        )
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"mirror_work_limit"}\n')
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_work_counts_only_prefix_events(self):
        # make_config：初始 5。首帧 X=0 计 15（累计 20），学习 1 项 + 广播
        # 速率 1 项后 X=2，次帧计 K+H+Q+1+2P+M=1+0+1+1+12+2=17（累计
        # 37）；offset=1 仅 20；offset=0 仅初始收敛 5
        log_bytes = mirror_log(two_good_frames())
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, _, err, _ = run_mirror(log_bytes, source + ":2", "37")
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_mirror(log_bytes, source + ":2", "36")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"mirror_work_limit"}\n')
        code, _, err, _ = run_mirror(log_bytes, source + ":1", "20")
        self.assertEqual(code, 0, err)
        code, out, err, _ = run_mirror(log_bytes, source + ":0", "5")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out.decode())["offset"], 0)
        code, _, err, _ = run_mirror(log_bytes, source + ":0", "4")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"mirror_work_limit"}\n')

    def test_bad_frame_still_billed(self):
        # 坏帧不生成副本但仍按帧计费：单桥 B=1、L=0 → 初始 1；runt 帧计
        # 2P+M+1=15，累计 16
        cfg = make_config()
        cfg["bridges"] = ["b1"]
        cfg["links"] = []
        events = [check_frame(0, "p1", length=10)]
        log_bytes = mirror_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, _, err, _ = run_mirror(log_bytes, source + ":1", "16")
        self.assertEqual(code, 0, err)
        code, out, err, _ = run_mirror(log_bytes, source + ":1", "15")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"mirror_work_limit"}\n')
        self.assertEqual(out, b"")

    def test_default_max_work_is_ten_million(self):
        code, _, err, _ = run_mirror(mirror_log([]), "*")
        self.assertEqual(code, 0, err)


if __name__ == "__main__":
    unittest.main()
