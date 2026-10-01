#!/usr/bin/env python3
"""record / replay 对 link-flow-decode 模式的支持回归。

含 queue_bytes 与每口 flow_control 的链路配置下，record/replay 按
link-flow-decode 路由：成功 stdout 与直接执行 link-flow-decode 逐字节
一致，产生的 schema 1 日志可被 replay 接受（applied 与连续 output 语义
同 link-wire-decode；PAUSE 帧为 frame 记录恒 applied），重放字节稳定。
record/replay 工作量超限分别报 record_work_limit / replay_work_limit。

仅用标准库；端到端驱动 record / replay / link-flow-decode。
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

from test_record import LOG_KEYS  # noqa: E402
from test_record import RECORD_KEYS  # noqa: E402
from test_record import canonical_key_order  # noqa: E402
from test_link_flow_decode import MAC1  # noqa: E402
from test_link_flow_decode import MAC2  # noqa: E402
from test_link_flow_decode import advance  # noqa: E402
from test_link_flow_decode import config  # noqa: E402
from test_link_flow_decode import data_frame  # noqa: E402
from test_link_flow_decode import link  # noqa: E402
from test_link_flow_decode import pause_frame  # noqa: E402
from test_link_flow_decode import port  # noqa: E402


def write_inputs(cfg, events):
    tmp = tempfile.mkdtemp()
    cfg_path = os.path.join(tmp, "config.json")
    evt_path = os.path.join(tmp, "events.json")
    with open(cfg_path, "wb") as handle:
        handle.write(json.dumps(cfg).encode("utf-8"))
    with open(evt_path, "wb") as handle:
        handle.write(json.dumps(events).encode("utf-8"))
    return tmp, cfg_path, evt_path


def run(argv, log_path=None):
    proc = subprocess.run(
        [sys.executable, SWITCH, *argv],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    after = None
    if log_path is not None and os.path.exists(log_path):
        with open(log_path, "rb") as handle:
            after = handle.read()
    return proc.returncode, proc.stdout, proc.stderr, after


def direct_stdout(cfg, events):
    tmp, cfg_path, evt_path = write_inputs(cfg, events)
    code, out, err, _ = run(["link-flow-decode", cfg_path, evt_path])
    assert code == 0, (code, err.decode())
    return out


def record_log(cfg, events, *limits, log_name="out.log"):
    tmp, cfg_path, evt_path = write_inputs(cfg, events)
    log_path = os.path.join(tmp, log_name)
    code, out, err, after = run(
        ["record", cfg_path, evt_path, log_path,
         *[str(x) for x in limits]],
        log_path=log_path,
    )
    return code, out, err, after, log_path


def record_success(cfg, events):
    code, out, err, log_bytes, _ = record_log(cfg, events)
    assert code == 0, (code, err.decode())
    return out, log_bytes


def replay_log(log_bytes, *extra):
    with tempfile.TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "in.log")
        with open(log_path, "wb") as handle:
            handle.write(log_bytes)
        proc = subprocess.run(
            [sys.executable, SWITCH, "replay", log_path,
             *[str(x) for x in extra]],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        with open(log_path, "rb") as handle:
            after = handle.read()
    return proc.returncode, proc.stdout, proc.stderr, after


def two_port(delay=1, queue=1000000, flow_control=True):
    return config(
        [port("p1", rates=[1000], modes=["full"], queue_bytes=queue,
              flow_control=flow_control),
         port("p2", rates=[1000], modes=["full"], queue_bytes=queue,
              flow_control=flow_control)],
        delay=delay,
    )


def rich_events():
    return [
        link(0, "p1"),
        link(0, "p2"),
        data_frame(10, "p1"),
        pause_frame(100, "p2", 10),
        advance(6000),
        pause_frame(7000, "p2", 0),
        data_frame(8000, "p1", src=MAC2),
        advance(20000),
    ]


class ByteIdenticalTests(unittest.TestCase):
    def test_record_stdout_matches_direct(self):
        cfg = two_port()
        events = rich_events()
        out, _ = record_success(cfg, events)
        self.assertEqual(out, direct_stdout(cfg, events))

    def test_replay_stdout_matches_record_and_direct(self):
        cfg = two_port()
        events = rich_events()
        rec_out, log_bytes = record_success(cfg, events)
        code, rep_out, err, after = replay_log(log_bytes)
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertEqual(rep_out, rec_out)
        self.assertEqual(rep_out, direct_stdout(cfg, events))
        self.assertEqual(after, log_bytes)

    def test_same_input_records_identical_bytes(self):
        cfg = two_port()
        events = rich_events()
        _, log_a = record_success(cfg, events)
        _, log_b = record_success(cfg, events)
        self.assertEqual(log_a, log_b)

    def test_replay_twice_stable(self):
        cfg = two_port()
        _, log_bytes = record_success(cfg, rich_events())
        code1, out1, _, _ = replay_log(log_bytes)
        code2, out2, _, _ = replay_log(log_bytes)
        self.assertEqual((code1, code2), (0, 0))
        self.assertEqual(out1, out2)

    def test_empty_events(self):
        cfg = two_port()
        out, log_bytes = record_success(cfg, [])
        self.assertEqual(out, direct_stdout(cfg, []))
        code, rep_out, err, _ = replay_log(log_bytes)
        self.assertEqual(code, 0, err)
        self.assertEqual(rep_out, out)


class LogShapeTests(unittest.TestCase):
    def setUp(self):
        self.cfg = two_port()
        self.events = rich_events()
        _, self.log_bytes = record_success(self.cfg, self.events)
        self.doc = json.loads(self.log_bytes.decode())

    def test_top_and_record_key_order(self):
        self.assertEqual(list(self.doc), LOG_KEYS)
        self.assertEqual(self.doc["schema"], 1)
        self.assertTrue(self.log_bytes.endswith(b"\n"))
        self.assertFalse(self.log_bytes.endswith(b"\n\n"))
        self.assertTrue(canonical_key_order(self.doc["config"]))
        for record in self.doc["records"]:
            self.assertEqual(list(record), RECORD_KEYS)
            self.assertTrue(canonical_key_order(record["event"]))

    def test_one_record_per_event(self):
        self.assertEqual(len(self.doc["records"]), len(self.events))
        kinds = [
            "advance" if "advance" in r["event"] else
            "link" if "admin" in r["event"] else "frame"
            for r in self.doc["records"]
        ]
        self.assertEqual(
            kinds, ["link", "link", "frame", "frame", "advance",
                    "frame", "frame", "advance"]
        )

    def test_pause_record_output(self):
        # 第 4 条记录（t=100）为合法 PAUSE：单元素 output 含完整五键
        rec = self.doc["records"][3]
        self.assertTrue(rec["applied"])
        self.assertEqual(len(rec["output"]), 1)
        out = rec["output"][0]
        self.assertEqual(
            list(out), ["t", "port", "action", "quanta", "until"]
        )
        self.assertEqual(out["action"], "pause")
        self.assertEqual(out["until"], 5220)

    def test_outputs_concatenate_to_direct_results(self):
        flat = [item for r in self.doc["records"]
                for item in r["output"]]
        direct = json.loads(direct_stdout(self.cfg, self.events).decode())
        self.assertEqual(flat, direct["results"])

    def test_digest(self):
        prefix = {
            "schema": self.doc["schema"],
            "config": self.doc["config"],
            "records": self.doc["records"],
        }
        digest = hashlib.sha256(
            (json.dumps(prefix, ensure_ascii=False, separators=(",", ":"))
             + "\n").encode("utf-8")
        ).hexdigest()
        self.assertEqual(self.doc["sha256"], digest)


class AppliedVersionTests(unittest.TestCase):
    def test_version_only_applied_links_increment(self):
        cfg = two_port(delay=100)
        events = [
            link(0, "p1"),
            link(1, "p1"),                  # 幂等 link：applied False
            pause_frame(2, "p1", 1),        # wait 中：frame 不计 version
            advance(50),
        ]
        _, log_bytes = record_success(cfg, events)
        records = json.loads(log_bytes.decode())["records"]
        self.assertEqual([r["version"] for r in records], [1, 1, 1, 1])
        self.assertEqual([r["applied"] for r in records],
                         [True, False, True, False])

    def test_unsupported_pause_is_applied_frame(self):
        cfg = two_port(flow_control=False)
        events = [link(0, "p1"), link(0, "p2"), pause_frame(10, "p1", 1)]
        _, log_bytes = record_success(cfg, events)
        records = json.loads(log_bytes.decode())["records"]
        frame_rec = records[-1]
        self.assertTrue(frame_rec["applied"])
        self.assertEqual(
            frame_rec["output"][0]["action"], "pause_unsupported"
        )


class ReplayIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.cfg = two_port()
        self.events = rich_events()
        _, self.log_bytes = record_success(self.cfg, self.events)

    def _rehash(self, doc):
        prefix = {
            "schema": doc["schema"],
            "config": doc["config"],
            "records": doc["records"],
        }
        doc["sha256"] = hashlib.sha256(
            (json.dumps(prefix, ensure_ascii=False, separators=(",", ":"))
             + "\n").encode("utf-8")
        ).hexdigest()
        return (
            json.dumps(
                {key: doc[key] for key in LOG_KEYS},
                ensure_ascii=False, separators=(",", ":"),
            ) + "\n"
        ).encode("utf-8")

    def test_tampered_quanta_fails(self):
        doc = json.loads(self.log_bytes.decode())
        pause_rec = next(
            r for r in doc["records"]
            if r["output"] and r["output"][0].get("action") == "pause"
        )
        pause_rec["event"]["data"] = pause_frame(
            pause_rec["event"]["t"], "p2", 11
        )["data"]
        bad = self._rehash(doc)
        code, out, err, after = replay_log(bad)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertIn(b"invalid_input", err)
        self.assertEqual(after, bad)

    def test_tampered_output_until_fails(self):
        doc = json.loads(self.log_bytes.decode())
        rec = next(
            r for r in doc["records"]
            if r["output"] and r["output"][0].get("action") == "pause"
        )
        rec["output"][0]["until"] += 1
        code, out, err, _ = replay_log(self._rehash(doc))
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")

    def test_expect_sha_success_and_mismatch(self):
        commit = json.loads(self.log_bytes.decode())["sha256"]
        code, _, _, after = replay_log(
            self.log_bytes, "--expect-sha256", commit
        )
        self.assertEqual(code, 0)
        self.assertEqual(after, self.log_bytes)
        code, out, err, _ = replay_log(
            self.log_bytes, "--expect-sha256", "0" * 64
        )
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertIn(b"invalid_input", err)

    def test_replay_rebuilds_byte_identical_log(self):
        # replay 内部重建的日志须与原文件逐字节一致（重放字节稳定）
        code, out, err, after = replay_log(self.log_bytes)
        self.assertEqual(code, 0, err)
        self.assertEqual(after, self.log_bytes)


class ModeRoutingTests(unittest.TestCase):
    def test_flow_control_config_routes_to_flow_mode(self):
        cfg = two_port()
        events = [link(0, "p1"), pause_frame(10, "p1", 1)]
        out, log_bytes = record_success(cfg, events)
        direct = direct_stdout(cfg, events)
        self.assertEqual(out, direct)
        doc = json.loads(log_bytes.decode())
        # 结果端口含 flow 专属统计
        result = json.loads(out.decode())
        self.assertIn("pause_frames", result["ports"][0])

    def test_mixed_abstract_and_raw_frames_invalid(self):
        cfg = two_port()
        tmp, cfg_path, evt_path = write_inputs(cfg, [])
        abstract = {
            "t": 10, "port": "p1", "src": MAC1, "dst": "ff:ff:ff:ff:ff:ff",
            "vlan": None, "length": 64, "fcs": True, "alignment": True,
        }
        events = [link(0, "p1"), abstract, pause_frame(11, "p1", 1)]
        with open(evt_path, "wb") as handle:
            handle.write(json.dumps(events).encode("utf-8"))
        log_path = os.path.join(tmp, "o.log")
        code, out, err, after = run(
            ["record", cfg_path, evt_path, log_path], log_path=log_path
        )
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertIn(b"invalid_input", err)
        self.assertFalse(os.path.exists(log_path))


class WorkLimitTests(unittest.TestCase):
    def test_record_work_limit(self):
        cfg = two_port()
        events = [link(0, "p1"), link(0, "p2")]
        # W：P=2；两个 link 事件各 +2 => 6；限 5 首次超过
        code, out, err, _, _ = record_log(
            cfg, events, 100000, 1000000, 1000000, 1000000, 1000000, 5
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertIn(b"record_work_limit", err)

    def test_replay_work_limit(self):
        cfg = two_port()
        events = [link(0, "p1"), link(0, "p2")]
        _, log_bytes = record_success(cfg, events)
        code, out, err, _ = replay_log(
            log_bytes, 100000, 1000000, 1000000, 5
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertIn(b"replay_work_limit", err)


if __name__ == "__main__":
    unittest.main()
