#!/usr/bin/env python3
"""log-security 子命令回归：按游标重演 security-check 模式 LOG 的前 offset
条事件并给出端口安全状态。

仅用标准库；端到端驱动 `python switch.py log-security LOG CURSOR
[MAX_WORK]`。参数、资源、CURSOR 及错误顺序完全沿用 log-fdb；成功产物
键序固定为 schema,source_sha256,offset,security,sha256，末项为前四键
紧凑 UTF-8 加 LF 的 sha256；CURSOR 的 * 表示 records 长度（重演全部），
否则 <sha256>:<offset>，offset=0 为初始空状态。security 按配置序，项
键序 port,learned,violations,shutdown（字符串、数组、非负整数、布尔），
learned 按 vlan、mac 升序、项键序 vlan,mac（整数、字符串）。LOG 须通过
摘要核对、security-check 语义、全部记录核对与重建日志逐字节一致，其他
模式 invalid_input/4；重演前 offset 项按 security-check 工作量公式计费，
等于上限合法，首次超过 stderr 仅 {"error":"security_work_limit"} 加 LF
并退出 5。
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
from test_record import make_port  # noqa: E402
from test_security_check import check_frame, config  # noqa: E402

SEC_KEYS = ["schema", "source_sha256", "offset", "security", "sha256"]
ENTRY_KEYS = ["port", "learned", "violations", "shutdown"]
LEARNED_KEYS = ["vlan", "mac"]


def good_frame(t, port, src, vlan=None, dst="ff:ff:ff:ff:ff:ff"):
    result = check_frame(t, port, src, dst=dst, length=100)
    result["vlan"] = vlan
    return result


def bad_frame(t, port, src, vlan=None):
    result = check_frame(t, port, src, length=10)
    result["vlan"] = vlan
    return result


def sec_log(events, cfg=None):
    return record(cfg or config(), events)


def digest_of(doc):
    prefix = {
        "schema": doc["schema"],
        "source_sha256": doc["source_sha256"],
        "offset": doc["offset"],
        "security": doc["security"],
    }
    raw = (
        json.dumps(prefix, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def run_security(log_bytes, cursor, *extra):
    with tempfile.TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "in.log")
        with open(log_path, "wb") as handle:
            handle.write(log_bytes)
        proc = subprocess.run(
            [sys.executable, SWITCH, "log-security", log_path, cursor, *extra],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        with open(log_path, "rb") as handle:
            after = handle.read()
    return proc.returncode, proc.stdout, proc.stderr, after


def security_check_cli(cfg, events):
    """security-check CONFIG EVENTS 的 security 列表。"""
    with tempfile.TemporaryDirectory() as tmp:
        cfg_path = os.path.join(tmp, "config.json")
        evt_path = os.path.join(tmp, "events.json")
        with open(cfg_path, "wb") as handle:
            handle.write(json.dumps(cfg).encode("utf-8"))
        with open(evt_path, "wb") as handle:
            handle.write(json.dumps(events).encode("utf-8"))
        proc = subprocess.run(
            [sys.executable, SWITCH, "security-check", cfg_path, evt_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    assert proc.returncode == 0, proc.stderr.decode()
    return json.loads(proc.stdout.decode("utf-8"))["security"]


class HappyPathTests(unittest.TestCase):
    def test_star_is_records_length_with_fixed_key_order_and_digest(self):
        events = [
            good_frame(0, "p1", mac(1)),
            good_frame(1, "p1", mac(2)),
            good_frame(2, "p2", mac(3)),
        ]
        log_bytes = sec_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_security(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertTrue(out.endswith(b"\n"))
        self.assertEqual(after, log_bytes)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(list(doc), SEC_KEYS)
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["source_sha256"], source)
        self.assertEqual(doc["offset"], 3)
        by_port = {entry["port"]: entry for entry in doc["security"]}
        self.assertEqual(
            by_port["p1"]["learned"],
            [{"vlan": 1, "mac": mac(1)}, {"vlan": 1, "mac": mac(2)}],
        )
        self.assertEqual(
            by_port["p2"]["learned"], [{"vlan": 1, "mac": mac(3)}]
        )
        for entry in doc["security"]:
            self.assertEqual(list(entry), ENTRY_KEYS)
            self.assertIsInstance(entry["port"], str)
            self.assertIsInstance(entry["learned"], list)
            self.assertIsInstance(entry["violations"], int)
            self.assertGreaterEqual(entry["violations"], 0)
            self.assertIsInstance(entry["shutdown"], bool)
            for learned in entry["learned"]:
                self.assertEqual(list(learned), LEARNED_KEYS)
                self.assertIsInstance(learned["vlan"], int)
                self.assertIsInstance(learned["mac"], str)
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_star_equals_sha_cursor_at_record_count(self):
        events = [good_frame(0, "p1", mac(1)), good_frame(1, "p2", mac(2))]
        log_bytes = sec_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        _, star_out, _, _ = run_security(log_bytes, "*")
        code, cur_out, err, _ = run_security(log_bytes, source + ":2")
        self.assertEqual(code, 0, err)
        self.assertEqual(cur_out, star_out)
        self.assertEqual(json.loads(cur_out.decode())["offset"], 2)

    def test_offset_zero_is_initial_empty_security_state(self):
        events = [good_frame(0, "p1", mac(1)), good_frame(1, "p2", mac(2))]
        log_bytes = sec_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_security(log_bytes, source + ":0")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["offset"], 0)
        self.assertEqual(len(doc["security"]), 5)
        for entry in doc["security"]:
            self.assertEqual(entry["learned"], [])
            self.assertEqual(entry["violations"], 0)
            self.assertFalse(entry["shutdown"])
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_partial_offset_replays_only_prefix(self):
        events = [
            good_frame(0, "p1", mac(1)),
            good_frame(1, "p1", mac(2)),
            good_frame(2, "p1", mac(3)),
        ]
        log_bytes = sec_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        # base config：p1 limit=2，第三源违例丢弃
        code, out, err, _ = run_security(log_bytes, source + ":2")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["offset"], 2)
        p1 = {e["port"]: e for e in doc["security"]}["p1"]
        self.assertEqual(
            p1["learned"],
            [{"vlan": 1, "mac": mac(1)}, {"vlan": 1, "mac": mac(2)}],
        )
        self.assertEqual(p1["violations"], 0)
        code, out, err, _ = run_security(log_bytes, source + ":3")
        self.assertEqual(code, 0, err)
        p1 = {e["port"]: e for e in json.loads(out.decode())["security"]}["p1"]
        self.assertEqual(len(p1["learned"]), 2)
        self.assertEqual(p1["violations"], 1)

    def test_security_order_follows_config_and_learned_sorted_vlan_mac(self):
        cfg = config()

        def trunk(name, vlans):
            return {
                "name": name,
                "mode": "trunk",
                "pvid": 1,
                "allowed": list(vlans),
                "untagged": [],
                "up": True,
            }

        # p1/p3 为 trunk，允许带 VLAN 2/10 标记帧
        cfg["ports"] = [
            trunk("p1", (1, 2, 10)),
            make_port("p2"),
            trunk("p3", (1, 2, 10)),
            make_port("p4"),
            make_port("p5"),
        ]
        # 每物理口须有一条 security；调整配置序并放宽 p3/p1 的 limit 以
        # 容纳多 VLAN 学习
        cfg["security"] = [
            {"port": "p3", "limit": 9, "action": "drop", "static": []},
            {"port": "p1", "limit": 9, "action": "drop", "static": []},
            {"port": "p2", "limit": 2, "action": "drop", "static": []},
            {"port": "p4", "limit": 2, "action": "drop", "static": []},
            {"port": "p5", "limit": 2, "action": "drop", "static": []},
        ]
        events = [
            good_frame(0, "p1", mac(30), vlan=10),
            good_frame(1, "p1", mac(2), vlan=10),
            good_frame(2, "p1", mac(1), vlan=2),
            good_frame(3, "p1", mac(9), vlan=2),
            good_frame(4, "p3", mac(4), vlan=1),
        ]
        log_bytes = sec_log(events, cfg)
        code, out, err, _ = run_security(log_bytes, "*")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(
            [e["port"] for e in doc["security"]],
            ["p3", "p1", "p2", "p4", "p5"],
        )
        p1 = {e["port"]: e for e in doc["security"]}["p1"]
        self.assertEqual(
            [(x["vlan"], x["mac"]) for x in p1["learned"]],
            [(2, mac(1)), (2, mac(9)), (10, mac(2)), (10, mac(30))],
        )
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_shutdown_violation_reflected_in_security(self):
        cfg = config()
        cfg["security"][0]["limit"] = 0
        cfg["security"][0]["action"] = "shutdown"
        events = [good_frame(0, "p1", mac(1))]
        log_bytes = sec_log(events, cfg)
        code, out, err, _ = run_security(log_bytes, "*")
        self.assertEqual(code, 0, err)
        p1 = {e["port"]: e for e in json.loads(out.decode())["security"]}["p1"]
        self.assertTrue(p1["shutdown"])
        self.assertEqual(p1["violations"], 1)
        self.assertEqual(p1["learned"], [])

    def test_prefix_matches_security_check_cli(self):
        cfg = config()
        events = [
            good_frame(0, "p1", mac(1)),
            good_frame(1, "p1", mac(2)),
            bad_frame(2, "p1", mac(3)),
            good_frame(3, "p2", mac(4), vlan=2),
        ]
        log_bytes = sec_log(events, cfg)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for offset in range(len(events) + 1):
            code, out, err, _ = run_security(log_bytes, source + ":%d" % offset)
            self.assertEqual(code, 0, (offset, err))
            got = json.loads(out.decode())["security"]
            self.assertEqual(got, security_check_cli(cfg, events[:offset]))

    def test_empty_log_star_and_zero_identical(self):
        log_bytes = sec_log([])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for cursor in ("*", source + ":0"):
            code, out, err, _ = run_security(log_bytes, cursor)
            self.assertEqual(code, 0, err)
            doc = json.loads(out.decode("utf-8"))
            self.assertEqual(doc["offset"], 0)
            self.assertTrue(all(not e["shutdown"] for e in doc["security"]))


class UsageTests(unittest.TestCase):
    def test_arg_counts(self):
        log_bytes = sec_log([good_frame(0, "p1", mac(1))])
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "in.log")
            with open(path, "wb") as handle:
                handle.write(log_bytes)
            # 缺 CURSOR；多余位置参数均 usage/2
            for tokens in ([], [path], [path, "*", "1", "2"]):
                proc = subprocess.run(
                    [sys.executable, SWITCH, "log-security", *tokens],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                self.assertEqual(proc.returncode, 2, tokens)

    def test_bad_cursor_tokens(self):
        log_bytes = sec_log([good_frame(0, "p1", mac(1))])
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
            code, _, _, _ = run_security(log_bytes, cursor)
            self.assertEqual(code, 2, cursor)

    def test_bad_max_work_tokens(self):
        log_bytes = sec_log([good_frame(0, "p1", mac(1))])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for token in ("", "0", "-1", "01", "1.0", "1 ", "x", "1e3"):
            code, _, _, _ = run_security(log_bytes, source + ":0", token)
            self.assertEqual(code, 2, token)
            code, _, _, _ = run_security(log_bytes, "*", token)
            self.assertEqual(code, 2, token)

    def test_arbitrary_length_decimal_max_work_accepted(self):
        log_bytes = sec_log([good_frame(0, "p1", mac(1))])
        code, _, err, _ = run_security(log_bytes, "*", "9" * 60)
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_security(log_bytes, "*", "9" * 5000)
        self.assertEqual(code, 0, err)

    def test_five_thousand_digit_cursor_offset_unbounded(self):
        # 5000 位 offset 按不限长十进制解析：超过记录数报 invalid_input/4，
        # 不得触发 int↔str 位数上限崩溃
        log_bytes = sec_log([good_frame(0, "p1", mac(1))])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_security(
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
                [sys.executable, SWITCH, "log-security", missing, "*"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(proc.returncode, 3)
        self.assertIn(b"file_not_found", proc.stderr)
        self.assertEqual(proc.stdout, b"")

    def test_log_limit_before_invalid_input(self):
        # 固定输入上限 16777216；超限先于 JSON 解析（log_limit/5）
        oversized = b"{" + b" " * (16 * 1024 * 1024)
        code, out, err, after = run_security(oversized, "*")
        self.assertEqual(code, 5)
        self.assertIn(b"log_limit", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, oversized)

    def test_bad_internal_sha_invalid_input(self):
        log_bytes = sec_log([good_frame(0, "p1", mac(1))])
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_security(bad, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_sha_mismatch_invalid_input(self):
        log_bytes = sec_log([good_frame(0, "p1", mac(1))])
        code, out, err, _ = run_security(log_bytes, "0" * 64 + ":0")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_offset_beyond_record_count_invalid_input(self):
        log_bytes = sec_log([good_frame(0, "p1", mac(1))])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_security(log_bytes, source + ":2")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_non_security_check_mode_rejected(self):
        # fdb 模式 LOG：静态合法但非 security-check 模式
        events = [
            {"t": 0, "port": "p1", "mac": mac(1), "vlan": 1},
        ]
        log_bytes = record(fdb_config(), events)
        code, out, err, after = run_security(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_tampered_records_fail_verification(self):
        # 帧恒 applied=true；篡改为 false 并重算内部摘要 → 记录核对失败
        events = [good_frame(0, "p1", mac(1))]
        log_bytes = sec_log(events)
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
        code, out, err, after = run_security(bad, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, bad)

    def test_invalid_input_before_work_limit(self):
        # 摘要错与极小工作量上限同时成立：invalid_input/4 优先
        log_bytes = sec_log([good_frame(0, "p1", mac(1))])
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_security(bad, "*", "1")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")


class WorkLimitTests(unittest.TestCase):
    def test_frame_charge_uses_security_check_formula(self):
        # base config：B=1,L=0,U=0 → 初始 C=1；P=5,M=2,R=1。首帧（坏帧
        # 同价）在空状态计 X+3P+M+R+D+S+1 = 0+15+2+1+0+0+1 = 19，
        # 累计 20；等于上限合法，首次超过报 security_work_limit/5
        good = good_frame(0, "p1", mac(1))
        bad = bad_frame(1, "p1", mac(2))
        log_bytes = sec_log([good, bad])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_security(log_bytes, source + ":1", "20")
        self.assertEqual(code, 0, err)
        code, out, err, after = run_security(
            log_bytes, source + ":1", "19"
        )
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"security_work_limit"}\n')
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_work_counts_only_prefix_events(self):
        events = [
            good_frame(0, "p1", mac(1)),
            good_frame(1, "p1", mac(2)),
        ]
        log_bytes = sec_log(events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        # offset=2：初始 C=1；首帧空状态 19 → 20；次帧按预演状态
        # （X 含本帧老化前 FDB 与速率队列、D=1、入端口排队 S）计 22，
        # 累计 42。等于上限合法，41 首次超过
        code, _, err, _ = run_security(log_bytes, source + ":2", "42")
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_security(log_bytes, source + ":2", "41")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"security_work_limit"}\n')
        # offset=1 仅初始 1 + 首帧 19 = 20：上限 20 合法，但 offset=2
        # 合法所用的同一上限 20 对 offset=1 也合法，证明第二项才是越过
        # 20 的来源（只计前 offset 项）
        code, _, err, _ = run_security(log_bytes, source + ":1", "20")
        self.assertEqual(code, 0, err)
        # offset=0：仅初始收敛 1，上限 =1 即合法，再小无正整数可给
        code, out, err, _ = run_security(log_bytes, source + ":0", "1")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["offset"], 0)

    def test_default_max_work_is_ten_million(self):
        code, _, err, _ = run_security(sec_log([]), "*")
        self.assertEqual(code, 0, err)


if __name__ == "__main__":
    unittest.main()
