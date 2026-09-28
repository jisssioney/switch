#!/usr/bin/env python3
"""log-counters 子命令回归：从空 FDB 重演 forward 旧/新配置的 LOG 计数。

仅用标准库；端到端驱动 `python switch.py log-counters LOG
[MAX_LOG_BYTES MAX_OUTPUT_BYTES MAX_STATS_WORK]`。成功产物键序固定为
schema,source_sha256,ports,vlans,sha256，末项为前四键紧凑 UTF-8 加 LF
的 sha256；ports 按配置序（项键序 name,rx,tx,drop），vlans 按数值升序
（项键序 vlan,rx,tx,drop）。计数与 forward 入口重演结果一致；LOG 须通过
record 结构与摘要校验且仅接受 forward 旧/新配置，其他模式 invalid_input/4；
逐帧 K+P+1（K 为老化前动态 FDB 数，P 为端口数，拒绝与 down 口帧也计），
等于上限合法，首次超过报 stats_work_limit/5。
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
from test_log_summary import rehash  # noqa: E402
from test_log_summary import synthetic_log  # noqa: E402

COUNTERS_KEYS = ["schema", "source_sha256", "ports", "vlans", "sha256"]


def old_config(names=("p1", "p2", "p3"), vlans=None, up=None, age=100):
    """旧式 access 配置：name/vlan/up。"""
    up = up or {}
    vlans = vlans or {}
    return {
        "ports": [
            {"name": name, "vlan": vlans.get(name, 1), "up": up.get(name, True)}
            for name in names
        ],
        "age": age,
    }


def v2_port(name, pvid, allowed, untagged, mode="trunk", up=True):
    return {
        "name": name,
        "mode": mode,
        "pvid": pvid,
        "allowed": allowed,
        "untagged": untagged,
        "up": up,
    }


def v2_config(ports, age=100):
    """新式 802.1Q 配置：name/mode/pvid/allowed/untagged/up。"""
    return {"ports": ports, "age": age}


def old_frame(t, port, src, dst="ff:ff:ff:ff:ff:ff"):
    return {"t": t, "port": port, "src": src, "dst": dst}


def v2_frame(t, port, src, dst="ff:ff:ff:ff:ff:ff", vlan=None):
    return {"t": t, "port": port, "src": src, "dst": dst, "vlan": vlan}


def record(cfg, events):
    """record CONFIG EVENTS → LOG 字节（断言成功）。"""
    with tempfile.TemporaryDirectory() as tmp:
        cp = os.path.join(tmp, "config.json")
        ep = os.path.join(tmp, "events.json")
        lp = os.path.join(tmp, "out.log")
        with open(cp, "w", encoding="utf-8") as handle:
            json.dump(cfg, handle)
        with open(ep, "w", encoding="utf-8") as handle:
            json.dump(events, handle)
        proc = subprocess.run(
            [sys.executable, SWITCH, "record", cp, ep, lp],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        assert proc.returncode == 0, proc.stderr.decode()
        with open(lp, "rb") as handle:
            return handle.read()


def forward_stdout(cfg, events):
    """直接执行 forward 入口的 stdout（含 results/ports/vlans）。"""
    with tempfile.TemporaryDirectory() as tmp:
        cp = os.path.join(tmp, "config.json")
        ep = os.path.join(tmp, "events.json")
        with open(cp, "w", encoding="utf-8") as handle:
            json.dump(cfg, handle)
        with open(ep, "w", encoding="utf-8") as handle:
            json.dump(events, handle)
        proc = subprocess.run(
            [sys.executable, SWITCH, "forward", cp, ep],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        assert proc.returncode == 0, proc.stderr.decode()
        return proc.stdout


def run_counters(log_bytes, *args):
    """写 in.log，原样透传参数，回读 LOG。"""
    with tempfile.TemporaryDirectory() as tmp:
        lp = os.path.join(tmp, "in.log")
        with open(lp, "wb") as handle:
            handle.write(log_bytes)
        proc = subprocess.run(
            [sys.executable, SWITCH, "log-counters", lp, *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        with open(lp, "rb") as handle:
            after = handle.read()
    return proc.returncode, proc.stdout, proc.stderr, after


def digest_of(doc):
    prefix = {key: doc[key] for key in COUNTERS_KEYS[:4]}
    raw = (
        json.dumps(prefix, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def old_scenario():
    cfg = old_config(
        ("p1", "p2", "p3"),
        vlans={"p1": 1, "p2": 1, "p3": 2},
        up={"p3": False},
    )
    events = [
        old_frame(0, "p1", "00:00:00:00:00:01"),
        old_frame(1, "p2", "00:00:00:00:00:02", "00:00:00:00:00:01"),
        old_frame(2, "p3", "00:00:00:00:00:03"),
    ]
    return cfg, events


def v2_scenario():
    cfg = v2_config([
        v2_port("p1", 10, [10], [10], mode="access"),
        v2_port("p2", 10, [10, 20], []),
        v2_port("p3", 20, [20], [20], mode="access"),
    ])
    events = [
        v2_frame(0, "p1", "00:00:00:00:00:01"),
        v2_frame(1, "p2", "00:00:00:00:00:02", "00:00:00:00:00:01", 10),
        # 带标 20 从 access 口进入：准入拒绝，不计 VLAN
        v2_frame(2, "p1", "00:00:00:00:00:09", vlan=20),
        v2_frame(3, "p2", "00:00:00:00:00:04", vlan=20),
    ]
    return cfg, events


class HappyPathTests(unittest.TestCase):
    def test_key_order_and_digest_old_config(self):
        cfg, events = old_scenario()
        code, out, err, _ = run_counters(record(cfg, events))
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertTrue(out.endswith(b"\n"))
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(list(doc), COUNTERS_KEYS)
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_key_order_and_digest_v2_config(self):
        cfg, events = v2_scenario()
        code, out, err, _ = run_counters(record(cfg, events))
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(list(doc), COUNTERS_KEYS)
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_schema_and_source_sha256(self):
        cfg, events = old_scenario()
        log_bytes = record(cfg, events)
        code, out, err, _ = run_counters(log_bytes)
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(
            doc["source_sha256"], json.loads(log_bytes)["sha256"]
        )

    def test_ports_config_order_and_item_key_order(self):
        cfg, events = old_scenario()
        code, out, err, _ = run_counters(record(cfg, events))
        self.assertEqual(code, 0, err)
        ports = json.loads(out.decode("utf-8"))["ports"]
        self.assertEqual([item["name"] for item in ports], ["p1", "p2", "p3"])
        for item in ports:
            self.assertEqual(list(item), ["name", "rx", "tx", "drop"])
            for key in ("rx", "tx", "drop"):
                self.assertIsInstance(item[key], int)

    def test_vlans_numeric_order_and_item_key_order(self):
        cfg = old_config(
            ("p1", "p2", "p3"),
            vlans={"p1": 30, "p2": 10, "p3": 20},
        )
        events = [
            old_frame(0, "p1", "00:00:00:00:00:01"),
            old_frame(1, "p2", "00:00:00:00:00:02"),
            old_frame(2, "p3", "00:00:00:00:00:03"),
        ]
        code, out, err, _ = run_counters(record(cfg, events))
        self.assertEqual(code, 0, err)
        vlans = json.loads(out.decode("utf-8"))["vlans"]
        self.assertEqual([item["vlan"] for item in vlans], [10, 20, 30])
        for item in vlans:
            self.assertEqual(list(item), ["vlan", "rx", "tx", "drop"])
            for key in ("rx", "tx", "drop"):
                self.assertIsInstance(item[key], int)

    def test_counters_match_forward_entry_old(self):
        cfg, events = old_scenario()
        expected = json.loads(forward_stdout(cfg, events).decode("utf-8"))
        code, out, err, _ = run_counters(record(cfg, events))
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["ports"], expected["ports"])
        self.assertEqual(doc["vlans"], expected["vlans"])

    def test_counters_match_forward_entry_v2(self):
        cfg, events = v2_scenario()
        expected = json.loads(forward_stdout(cfg, events).decode("utf-8"))
        code, out, err, _ = run_counters(record(cfg, events))
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["ports"], expected["ports"])
        self.assertEqual(doc["vlans"], expected["vlans"])

    def test_down_port_frame_still_counted_rx_and_drop(self):
        cfg = old_config(("p1", "p2"), up={"p1": False})
        events = [old_frame(0, "p1", "00:00:00:00:00:01")]
        code, out, err, _ = run_counters(record(cfg, events))
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        # down 口入帧计 rx，但不学习、丢弃
        self.assertEqual(doc["ports"][0], {"name": "p1", "rx": 1, "tx": 0,
                                           "drop": 1})

    def test_empty_records_zero_counters(self):
        cfg = old_config()
        code, out, err, _ = run_counters(record(cfg, []))
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(
            doc["ports"],
            [
                {"name": "p1", "rx": 0, "tx": 0, "drop": 0},
                {"name": "p2", "rx": 0, "tx": 0, "drop": 0},
                {"name": "p3", "rx": 0, "tx": 0, "drop": 0},
            ],
        )
        # 旧式 forward 对每个端口 VLAN 预置零计数（三端口均在 vlan 1）
        self.assertEqual(doc["vlans"], [
            {"vlan": 1, "rx": 0, "tx": 0, "drop": 0},
        ])
        self.assertEqual(doc["sha256"], digest_of(doc))


class WorkLimitTests(unittest.TestCase):
    def _two_port_log(self, events):
        return record(old_config(("p1", "p2"), age=100), events)

    def test_single_frame_cost_k_plus_p_plus_1(self):
        # 空 FDB：K=0，P=2 → 3
        log_bytes = self._two_port_log(
            [old_frame(0, "p1", "00:00:00:00:00:01")]
        )
        size = len(log_bytes)
        # 等于上限合法
        code, _, err, _ = run_counters(
            log_bytes, str(size), "1000000", "3"
        )
        self.assertEqual(code, 0, err)
        # 首次超过报 stats_work_limit/5
        code, out, err, after = run_counters(
            log_bytes, str(size), "1000000", "2"
        )
        self.assertEqual(code, 5)
        self.assertIn(b"stats_work_limit", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_k_is_count_before_aging(self):
        # age=100：t=0 学习一项；t=99 时 99<100 未老化，K=1 → 3+(1+3)=7
        fresh = [
            old_frame(0, "p1", "00:00:00:00:00:01"),
            old_frame(99, "p2", "00:00:00:00:00:02"),
        ]
        log_bytes = self._two_port_log(fresh)
        size = len(log_bytes)
        code, _, err, _ = run_counters(
            log_bytes, str(size), "1000000", "7"
        )
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_counters(
            log_bytes, str(size), "1000000", "6"
        )
        self.assertEqual(code, 5)
        self.assertIn(b"stats_work_limit", err)

    def test_aged_entry_not_counted_after_aging_frame(self):
        # f0 t=0 学 A（K0+3=3）；f1 t=100 从 down 口进入：计费仍取老化前
        # K=1（+3 端口固定额，共 7），随后 A 因 t-seen≥age 老化、down 口不
        # 学习，FDB 清空；f2 t=101 时 K=0（+3，共 10）
        events = [
            old_frame(0, "p1", "00:00:00:00:00:01"),
            old_frame(100, "p2", "00:00:00:00:00:02"),
            old_frame(101, "p1", "00:00:00:00:00:03"),
        ]
        log_bytes = record(
            old_config(("p1", "p2"), up={"p2": False}, age=100), events
        )
        size = len(log_bytes)
        code, _, err, _ = run_counters(
            log_bytes, str(size), "1000000", "10"
        )
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_counters(
            log_bytes, str(size), "1000000", "9"
        )
        self.assertEqual(code, 5)
        self.assertIn(b"stats_work_limit", err)

    def test_without_aging_kept_entry_counted(self):
        # 同帧序但 age=1000：f1 不老化、down 口不清空，f2 时 K=1，共 11
        events = [
            old_frame(0, "p1", "00:00:00:00:00:01"),
            old_frame(100, "p2", "00:00:00:00:00:02"),
            old_frame(101, "p1", "00:00:00:00:00:03"),
        ]
        log_bytes = record(
            old_config(("p1", "p2"), up={"p2": False}, age=1000), events
        )
        size = len(log_bytes)
        code, _, err, _ = run_counters(
            log_bytes, str(size), "1000000", "11"
        )
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_counters(
            log_bytes, str(size), "1000000", "10"
        )
        self.assertEqual(code, 5)

    def test_down_port_ingress_does_not_learn_but_costs(self):
        # 首帧 down 口：计费 3 但不学习；次帧 K 仍为 0 → 共 6
        events = [
            old_frame(0, "p1", "00:00:00:00:00:01"),
            old_frame(1, "p2", "00:00:00:00:00:02"),
        ]
        log_bytes = record(
            old_config(("p1", "p2"), up={"p1": False}), events
        )
        size = len(log_bytes)
        code, _, err, _ = run_counters(
            log_bytes, str(size), "1000000", "6"
        )
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_counters(
            log_bytes, str(size), "1000000", "5"
        )
        self.assertEqual(code, 5)

    def test_rejected_v2_frame_costs(self):
        # 单端口 P=1，带不允许的标进入 access 口被拒：仍计 K+P+1=2
        cfg = v2_config(
            [v2_port("p1", 10, [10], [10], mode="access")]
        )
        events = [v2_frame(0, "p1", "00:00:00:00:00:09", vlan=20)]
        log_bytes = record(cfg, events)
        size = len(log_bytes)
        code, _, err, _ = run_counters(
            log_bytes, str(size), "1000000", "2"
        )
        self.assertEqual(code, 0, err)
        code, out, err, _ = run_counters(
            log_bytes, str(size), "1000000", "1"
        )
        self.assertEqual(code, 5)
        self.assertIn(b"stats_work_limit", err)
        self.assertEqual(out, b"")

    def test_default_stats_work_constant(self):
        self.assertEqual(switch.DEFAULT_MAX_STATS_WORK, 10000000)


class UsageTests(unittest.TestCase):
    def setUp(self):
        self.log_bytes = record(*old_scenario())

    def test_limits_omitted_or_all_given(self):
        # 0 个上限合法
        self.assertEqual(run_counters(self.log_bytes)[0], 0)
        # 3 个上限合法
        size = len(self.log_bytes)
        self.assertEqual(
            run_counters(
                self.log_bytes, str(size), "1000000", "10000000"
            )[0],
            0,
        )
        # 1、2、4 个均 usage
        for extra in (
            ("16777216",),
            ("16777216", "16777216"),
            ("16777216", "16777216", "10000000", "1"),
        ):
            self.assertEqual(
                run_counters(self.log_bytes, *extra)[0], 2, extra
            )

    def test_bad_limit_tokens(self):
        size = len(self.log_bytes)
        for tokens in (
            ("0", "16777216", "10000000"),
            ("-1", "16777216", "10000000"),
            ("01", "16777216", "10000000"),
            ("abc", "16777216", "10000000"),
            (str(size), "0", "10000000"),
            (str(size), "16777216", "0"),
            (str(size), "16777216", "-1"),
            (str(size), "16777216", "01"),
        ):
            self.assertEqual(
                run_counters(self.log_bytes, *tokens)[0], 2, tokens
            )

    def test_arbitrary_length_decimal_limits(self):
        # 不限长正十进制；超大值按数学整数处理，不溢出
        code, _, err, _ = run_counters(
            self.log_bytes, "9" * 100, "9" * 100, "9" * 100
        )
        self.assertEqual(code, 0, err)


class ErrorPrecedenceTests(unittest.TestCase):
    def test_file_not_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "nope.log")
            proc = subprocess.run(
                [sys.executable, SWITCH, "log-counters", missing],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(proc.returncode, 3)
        self.assertIn(b"file_not_found", proc.stderr)
        self.assertEqual(proc.stdout, b"")

    def test_log_limit_before_invalid_input(self):
        log_bytes = record(*old_scenario())
        code, out, err, after = run_counters(
            log_bytes, str(len(log_bytes) - 1), "1000000", "10000000"
        )
        self.assertEqual(code, 5)
        self.assertIn(b"log_limit", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_other_mode_fdb_rejected(self):
        cfg = {"ports": ["p1", "p2"], "age": 100}
        events = [
            {"t": 0, "port": "p1", "mac": "00:00:00:00:00:01", "vlan": 1}
        ]
        code, out, err, after = run_counters(record(cfg, events))
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, record(cfg, events))

    def test_other_mode_security_config_rejected(self):
        # config 为空对象（静态合法 LOG）按 record 路由此为 port-security
        log_bytes = synthetic_log([])
        code, out, err, _ = run_counters(log_bytes)
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_bad_sha256_invalid_input(self):
        log_bytes = record(*old_scenario())
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, ensure_ascii=False, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, after = run_counters(bad)
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, bad)

    def test_malformed_json_invalid_input(self):
        code, out, err, _ = run_counters(b"{not json\n")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_replay_contract_applied_mismatch_invalid(self):
        # 静态合法（摘要自洽）但 applied 与重演不符：log-summary 接受，
        # log-counters 按 replay 合同拒绝
        log_bytes = record(*old_scenario())
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["records"][0]["applied"] = False
        code, out, err, after = run_counters(rehash(doc))
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, rehash(doc))

    def test_replay_contract_output_mismatch_invalid(self):
        log_bytes = record(*old_scenario())
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["records"][0]["output"]["ports"] = ["p3"]
        rewritten = rehash(doc)
        self.assertNotEqual(rewritten, log_bytes)
        code, out, err, after = run_counters(rewritten)
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, rewritten)
        # 原 LOG 仍可成功重演
        self.assertEqual(run_counters(log_bytes)[0], 0)

    def test_stats_work_limit_before_output_limit(self):
        log_bytes = record(*old_scenario())
        # output 上限 1 必超限，但工作量先超限
        code, out, err, after = run_counters(
            log_bytes, str(len(log_bytes)), "1", "1"
        )
        self.assertEqual(code, 5)
        self.assertIn(b"stats_work_limit", err)
        self.assertNotIn(b"output_limit", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_invalid_input_before_stats_work_limit(self):
        # 静态自洽但重演不符（applied 改假），同时工作量上限 1 必超：
        # invalid_input 先于 stats_work_limit
        log_bytes = record(*old_scenario())
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["records"][0]["applied"] = False
        rewritten = rehash(doc)
        code, out, err, after = run_counters(
            rewritten, str(len(rewritten)), "1000000", "1"
        )
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertNotIn(b"stats_work_limit", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, rewritten)

    def test_output_limit_last(self):
        log_bytes = record(*old_scenario())
        code, out, err, after = run_counters(
            log_bytes, str(len(log_bytes)), "1", "10000000"
        )
        self.assertEqual(code, 5)
        self.assertIn(b"output_limit", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_output_limit_equal_size_legal(self):
        log_bytes = record(*old_scenario())
        code, out, err, _ = run_counters(log_bytes)
        self.assertEqual(code, 0, err)
        size = len(out)
        code, _, err, _ = run_counters(
            log_bytes, str(len(log_bytes)), str(size), "10000000"
        )
        self.assertEqual(code, 0, err)


if __name__ == "__main__":
    unittest.main()
