#!/usr/bin/env python3
"""log-counters 子命令回归：重演 forward 旧/新配置日志并汇总端口/VLAN 计数。

仅用标准库；端到端驱动 `python switch.py log-counters LOG
[MAX_LOG_BYTES MAX_OUTPUT_BYTES MAX_STATS_WORK]`。成功产物键序固定为
schema,source_sha256,ports,vlans,sha256，末项为前四键紧凑 UTF-8 加 LF
的 sha256；ports 按配置序（name,rx,tx,drop），vlans 按数值升序
（vlan,rx,tx,drop）。仅接受 record 产出的 forward 旧（access）/新
（802.1Q）日志，其他模式 invalid_input/4；按 replay 合同从空 FDB 核对
重演，逐帧累计 K+P+1，等于上限合法、首次超过 stats_work_limit/5。
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

BCAST = "ff:ff:ff:ff:ff:ff"
M1 = "00:00:00:00:00:01"
M2 = "00:00:00:00:00:02"
M3 = "00:00:00:00:00:03"

COUNTERS_KEYS = ["schema", "source_sha256", "ports", "vlans", "sha256"]


def access_port(name, vlan=1, up=True):
    return {"name": name, "vlan": vlan, "up": up}


def v2_port(name, pvid=1, allowed=None, untagged=None, mode="access",
            up=True):
    if allowed is None:
        allowed = [pvid]
    if untagged is None:
        untagged = [pvid] if mode == "access" else []
    return {
        "name": name,
        "mode": mode,
        "pvid": pvid,
        "allowed": allowed,
        "untagged": untagged,
        "up": up,
    }


def access_config():
    return {
        "age": 100,
        "ports": [
            access_port("p1", 1, True),
            access_port("p2", 1, True),
            access_port("p3", 2, False),
        ],
    }


def v2_config():
    return {
        "age": 100,
        "ports": [
            v2_port("p1", mode="trunk", pvid=1, allowed=[1, 2],
                    untagged=[], up=True),
            v2_port("p2", pvid=1, up=True),
            v2_port("p3", pvid=2, up=False),
        ],
    }


def access_frames():
    return [
        {"t": 0, "port": "p1", "src": M1, "dst": BCAST},
        {"t": 1, "port": "p2", "src": M2, "dst": M1},
        {"t": 2, "port": "p3", "src": M3, "dst": BCAST},
    ]


def v2_frames():
    return [
        {"t": 0, "port": "p1", "src": M1, "dst": BCAST, "vlan": 2},
        {"t": 1, "port": "p2", "src": M2, "dst": M1, "vlan": None},
        {"t": 2, "port": "p3", "src": M3, "dst": BCAST, "vlan": None},
    ]


def record(config_doc, frames):
    """record 一对 config/frames，返回 LOG 原始字节。"""
    with tempfile.TemporaryDirectory() as tmp:
        cfg = os.path.join(tmp, "config.json")
        evs = os.path.join(tmp, "events.json")
        log = os.path.join(tmp, "out.log")
        with open(cfg, "wb") as handle:
            handle.write(json.dumps(config_doc).encode("utf-8"))
        with open(evs, "wb") as handle:
            handle.write(json.dumps(frames).encode("utf-8"))
        proc = subprocess.run(
            [sys.executable, SWITCH, "record", cfg, evs, log],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        assert proc.returncode == 0, proc.stderr
        with open(log, "rb") as handle:
            return handle.read()


def rehash(doc):
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


def run_counters(log_bytes, *args):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "in.log")
        with open(path, "wb") as handle:
            handle.write(log_bytes)
        proc = subprocess.run(
            [sys.executable, SWITCH, "log-counters", path, *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        with open(path, "rb") as handle:
            after = handle.read()
    return proc.returncode, proc.stdout, proc.stderr, after


def digest_of(doc):
    prefix = {key: doc[key] for key in COUNTERS_KEYS[:4]}
    raw = (
        json.dumps(prefix, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class AccessHappyPathTests(unittest.TestCase):
    def test_matches_replay_counters_and_key_order(self):
        log_bytes = record(access_config(), access_frames())
        code, out, err, _ = run_counters(log_bytes)
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertTrue(out.endswith(b"\n"))
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(list(doc), COUNTERS_KEYS)
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(
            doc["source_sha256"],
            json.loads(log_bytes.decode("utf-8"))["sha256"],
        )
        # 与 replay 结果的 ports/vlans 逐字节一致
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "in.log")
            with open(path, "wb") as handle:
                handle.write(log_bytes)
            rep = subprocess.run(
                [sys.executable, SWITCH, "replay", path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(rep.returncode, 0, rep.stderr)
        replayed = json.loads(rep.stdout.decode("utf-8"))
        self.assertEqual(doc["ports"], replayed["ports"])
        self.assertEqual(doc["vlans"], replayed["vlans"])
        # ports 配置序、固定项键序
        self.assertEqual(
            [item["name"] for item in doc["ports"]], ["p1", "p2", "p3"]
        )
        for item in doc["ports"]:
            self.assertEqual(list(item), ["name", "rx", "tx", "drop"])
            for key in ("rx", "tx", "drop"):
                self.assertIsInstance(item[key], int)
        # vlans 数值升序、固定项键序
        self.assertEqual([item["vlan"] for item in doc["vlans"]], [1, 2])
        for item in doc["vlans"]:
            self.assertEqual(list(item), ["vlan", "rx", "tx", "drop"])
            for key in ("rx", "tx", "drop"):
                self.assertIsInstance(item[key], int)
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_down_port_frame_counts_rx_drop(self):
        # p3 down：rx 计、drop 计，不学习不转发
        log_bytes = record(access_config(), access_frames())
        code, out, err, _ = run_counters(log_bytes)
        self.assertEqual(code, 0, err)
        ports = {item["name"]: item for item in
                 json.loads(out.decode("utf-8"))["ports"]}
        self.assertEqual(
            (ports["p1"]["rx"], ports["p1"]["tx"], ports["p1"]["drop"]),
            (1, 1, 0),
        )
        self.assertEqual(
            (ports["p2"]["rx"], ports["p2"]["tx"], ports["p2"]["drop"]),
            (1, 1, 0),
        )
        self.assertEqual(
            (ports["p3"]["rx"], ports["p3"]["tx"], ports["p3"]["drop"]),
            (1, 0, 1),
        )

    def test_empty_records_zero_counters(self):
        log_bytes = record(access_config(), [])
        code, out, err, _ = run_counters(log_bytes)
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(len(doc["ports"]), 3)
        for item in doc["ports"]:
            self.assertEqual((item["rx"], item["tx"], item["drop"]), (0, 0, 0))
        for item in doc["vlans"]:
            self.assertEqual((item["rx"], item["tx"], item["drop"]), (0, 0, 0))
        self.assertEqual(doc["sha256"], digest_of(doc))


class V2HappyPathTests(unittest.TestCase):
    def test_v2_matches_replay_and_digest(self):
        log_bytes = record(v2_config(), v2_frames())
        code, out, err, _ = run_counters(log_bytes)
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(list(doc), COUNTERS_KEYS)
        self.assertEqual(
            [item["name"] for item in doc["ports"]], ["p1", "p2", "p3"]
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "in.log")
            with open(path, "wb") as handle:
                handle.write(log_bytes)
            rep = subprocess.run(
                [sys.executable, SWITCH, "replay", path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(rep.returncode, 0, rep.stderr)
        replayed = json.loads(rep.stdout.decode("utf-8"))
        self.assertEqual(doc["ports"], replayed["ports"])
        self.assertEqual(doc["vlans"], replayed["vlans"])
        self.assertEqual(doc["sha256"], digest_of(doc))


class UsageTests(unittest.TestCase):
    def test_arg_counts(self):
        log_bytes = record(access_config(), access_frames())
        self.assertEqual(run_counters(log_bytes)[0], 0)
        self.assertEqual(
            run_counters(
                log_bytes, "16777216", "16777216", "10000000"
            )[0],
            0,
        )
        # 三上限须省略或全给
        for count in (1, 2, 4, 5):
            self.assertEqual(
                run_counters(log_bytes, *["16777216"] * count)[0],
                2,
                count,
            )

    def test_bad_limit_tokens(self):
        log_bytes = record(access_config(), access_frames())
        for tokens in (
            ("0", "16777216", "10000000"),
            ("-1", "16777216", "10000000"),
            ("01", "16777216", "10000000"),
            ("abc", "16777216", "10000000"),
            ("16777216", "0", "10000000"),
            ("16777216", "16777216", "0"),
        ):
            self.assertEqual(
                run_counters(log_bytes, *tokens)[0], 2, tokens
            )


class ModeTests(unittest.TestCase):
    def test_non_forward_modes_rejected(self):
        fdb_config = {"age": 100, "ports": ["p1", "p2"]}
        fdb_events = [
            {"t": 0, "port": "p1", "mac": M1, "vlan": 1},
        ]
        log_bytes = record(fdb_config, fdb_events)
        code, out, err, after = run_counters(log_bytes)
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_corrupt_log_invalid_input(self):
        good = record(access_config(), access_frames())
        doc = json.loads(good.decode("utf-8"))
        # 未知端口：语义校验失败
        bad = copy.deepcopy(doc)
        bad["records"][0]["event"]["port"] = "pX"
        bad_bytes = rehash(bad)
        code, out, err, after = run_counters(bad_bytes)
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, bad_bytes)

    def test_bad_internal_sha_invalid_input(self):
        good = record(access_config(), access_frames())
        doc = json.loads(good.decode("utf-8"))
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, ensure_ascii=False, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_counters(bad)
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")


class WorkLimitTests(unittest.TestCase):
    def test_per_frame_formula_equal_legal_first_exceed(self):
        # 3 帧、P=3；老化前动态 FDB 项数 K 依次 0,1,2
        # 成本 (0+3+1)+(1+3+1)+(2+3+1) = 4+5+6 = 15；down 口帧同样计
        log_bytes = record(access_config(), access_frames())
        code, _, err, _ = run_counters(
            log_bytes, "16777216", "16777216", "15"
        )
        self.assertEqual(code, 0, err)
        code, out, err, after = run_counters(
            log_bytes, "16777216", "16777216", "14"
        )
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"stats_work_limit"}\n')
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_down_port_frame_still_charged(self):
        # 仅一个 down 口帧：K=0、P=3，成本 4；上限 3 首次超过
        frames = [{"t": 0, "port": "p3", "src": M3, "dst": BCAST}]
        log_bytes = record(access_config(), frames)
        self.assertEqual(
            run_counters(log_bytes, "16777216", "16777216", "4")[0], 0
        )
        code, out, err, _ = run_counters(
            log_bytes, "16777216", "16777216", "3"
        )
        self.assertEqual(code, 5)
        self.assertIn(b"stats_work_limit", err)
        self.assertEqual(out, b"")

    def test_rejected_v2_frame_still_charged(self):
        # access 口收带标签帧被拒绝，但仍逐帧计费：K=0、P=3，成本 4
        frames = [
            {"t": 0, "port": "p2", "src": M2, "dst": BCAST, "vlan": 9},
        ]
        log_bytes = record(v2_config(), frames)
        self.assertEqual(
            run_counters(log_bytes, "16777216", "16777216", "4")[0], 0
        )
        code, _, err, _ = run_counters(
            log_bytes, "16777216", "16777216", "3"
        )
        self.assertEqual(code, 5)
        self.assertIn(b"stats_work_limit", err)

    def test_invalid_input_precedes_work_limit(self):
        # 语义非法（未知端口）即便工作量上限极小，也先报 invalid_input
        good = record(access_config(), access_frames())
        doc = json.loads(good.decode("utf-8"))
        bad = copy.deepcopy(doc)
        bad["records"][0]["event"]["port"] = "pX"
        bad_bytes = rehash(bad)
        code, out, err, _ = run_counters(
            bad_bytes, "16777216", "16777216", "1"
        )
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")


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

    def test_log_limit_before_validation(self):
        log_bytes = record(access_config(), access_frames())
        code, out, err, after = run_counters(
            log_bytes, str(len(log_bytes) - 1), "16777216", "10000000"
        )
        self.assertEqual(code, 5)
        self.assertIn(b"log_limit", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_work_limit_before_output_limit(self):
        log_bytes = record(access_config(), access_frames())
        code, out, err, _ = run_counters(
            log_bytes, "16777216", "1", "1"
        )
        self.assertEqual(code, 5)
        self.assertIn(b"stats_work_limit", err)
        self.assertEqual(out, b"")

    def test_output_limit_after_successful_replay(self):
        log_bytes = record(access_config(), access_frames())
        code, out, err, after = run_counters(
            log_bytes, "16777216", "1", "10000000"
        )
        self.assertEqual(code, 5)
        self.assertIn(b"output_limit", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)


if __name__ == "__main__":
    unittest.main()
