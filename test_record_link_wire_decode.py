#!/usr/bin/env python3
"""record / replay 对 link-wire-decode 模式的支持回归。

含 queue_bytes 的链路配置下，帧事件为 {t,port,data} 原始帧（link 与
advance 保持 link-wire 原语义）时，record/replay 按 link-wire-decode
路由：成功 stdout 与直接执行 link-wire-decode 逐字节一致，并产生可被
replay 接受的 schema 1 日志，记录顺序、applied、output 连续数组语义与
link-wire 完全相同。仅含 link 或 advance 的既有 link-wire 日志仍按原
link-wire 模式解释，旧日志哈希与字节逐字节不变；抽象帧与原始帧混用为
非法输入。

仅用标准库；端到端驱动 record / replay / link-wire(-decode)。
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
SWITCH = os.path.join(HERE, "switch.py")
sys.path.insert(0, HERE)

from test_record import LOG_KEYS  # noqa: E402
from test_record import RECORD_KEYS  # noqa: E402
from test_record import canonical_key_order  # noqa: E402
from test_link_wire import advance  # noqa: E402
from test_link_wire import config  # noqa: E402
from test_link_wire import link  # noqa: E402
from test_link_wire import port  # noqa: E402
from test_link_wire_decode import BCAST  # noqa: E402
from test_link_wire_decode import MAC1  # noqa: E402
from test_link_wire_decode import MAC2  # noqa: E402
from test_link_wire_decode import abstract_frame  # noqa: E402
from test_link_wire_decode import raw_frame  # noqa: E402


def raw_event(*args, **kwargs):
    event, _, _ = raw_frame(*args, **kwargs)
    return event


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
    code, out, err, _ = run(["link-wire-decode", cfg_path, evt_path])
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


def two_port(delay=10, queue=1000000):
    return config(
        [port("p1", rates=[1000], modes=["full"], queue_bytes=queue),
         port("p2", rates=[1000], modes=["full"], queue_bytes=queue)],
        delay=delay,
    )


def rich_events():
    return [
        link(0, "p1"),
        link(0, "p2"),
        raw_event(10, "p1", BCAST, MAC1, None, 46),
        advance(970),
        raw_event(2000, "p1", BCAST, MAC1, None, 46, fcs_good=False),
        advance(5000),
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

    def test_empty_events(self):
        cfg = two_port()
        out, log_bytes = record_success(cfg, [])
        self.assertEqual(out, direct_stdout(cfg, []))
        code, rep_out, err, _ = replay_log(log_bytes)
        self.assertEqual(code, 0, err)
        self.assertEqual(rep_out, out)

    def test_matches_converted_link_wire(self):
        # 与“同一原始帧准确转换为抽象帧后调用 link-wire”逐字节一致
        cfg = two_port(delay=1)
        e, length, fcs = raw_frame(10, "p1", BCAST, MAC1, None, 1000 - 18)
        dec_events = [link(0, "p1"), link(0, "p2"), e, advance(100000)]
        abs_events = [
            link(0, "p1"), link(0, "p2"),
            abstract_frame(10, "p1", MAC1, BCAST, None, length, fcs),
            advance(100000),
        ]
        rec_out, _ = record_success(cfg, dec_events)
        tmp, cp, ap = write_inputs(cfg, abs_events)
        code, wire_out, err, _ = run(["link-wire", cp, ap])
        self.assertEqual(code, 0, err)
        self.assertEqual(rec_out, wire_out)


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

    def test_one_record_per_event_and_frame_event_is_raw(self):
        self.assertEqual(len(self.doc["records"]), len(self.events))
        frame_records = [r for r in self.doc["records"]
                         if frozenset(r["event"]) == frozenset(
                             ("t", "port", "data"))]
        # 两条原始帧（good 与 bad_fcs）
        self.assertEqual(len(frame_records), 2)
        for record in frame_records:
            self.assertEqual(list(record["event"]), ["data", "port", "t"])
            self.assertIsInstance(record["output"], list)
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

    def test_outputs_concatenate_to_direct_results(self):
        flat = [item for r in self.doc["records"]
                for item in r["output"]]
        direct = json.loads(direct_stdout(self.cfg, self.events).decode())
        self.assertEqual(flat, direct["results"])

    def test_bad_fcs_frame_recorded_as_drop_and_applied(self):
        records = self.doc["records"]
        bad = next(r for r in records
                   if r["event"]["t"] == 2000)
        self.assertTrue(bad["applied"])
        self.assertEqual(len(bad["output"]), 1)
        self.assertEqual(bad["output"][0]["class"], "bad_fcs")
        self.assertEqual(bad["output"][0]["action"], "drop")


class ProcessingOrderTests(unittest.TestCase):
    def test_same_time_sorted_by_port_with_advance_last(self):
        cfg = two_port()
        events = [
            advance(0),
            raw_event(0, "p2", BCAST, MAC2),
            link(0, "p2"),
            link(0, "p1"),
        ]
        _, log_bytes = record_success(cfg, events)
        doc = json.loads(log_bytes.decode())
        seq = [
            ("advance" if "advance" in r["event"] else r["event"]["port"])
            for r in doc["records"]
        ]
        self.assertEqual(seq, ["p1", "p2", "p2", "advance"])
        kinds = []
        for r in doc["records"]:
            ev = r["event"]
            kinds.append(
                "advance" if "advance" in ev else
                "link" if "admin" in ev else "frame"
            )
        self.assertEqual(kinds, ["link", "frame", "link", "advance"])

    def test_version_only_applied_links_increment(self):
        cfg = two_port(delay=100)
        events = [
            link(0, "p1"),
            link(1, "p1"),                              # 幂等 link
            raw_event(2, "p1", BCAST, MAC1),           # 帧不计 version
            advance(50),                               # advance 不计 version
        ]
        _, log_bytes = record_success(cfg, events)
        records = json.loads(log_bytes.decode())["records"]
        self.assertEqual([r["version"] for r in records], [1, 1, 1, 1])
        self.assertEqual([r["applied"] for r in records],
                         [True, False, True, False])


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

    def test_tampered_frame_event_fails(self):
        doc = json.loads(self.log_bytes.decode())
        frame_record = next(
            r for r in doc["records"] if "data" in r["event"]
        )
        frame_record["event"]["data"] = "00" * 64
        bad = self._rehash(doc)
        code, out, err, after = replay_log(bad)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertEqual(after, bad)

    def test_tampered_applied_fails(self):
        doc = json.loads(self.log_bytes.decode())
        doc["records"][0]["applied"] = not doc["records"][0]["applied"]
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
        code, _, err, after = replay_log(self.log_bytes)
        self.assertEqual(code, 0, err)
        self.assertEqual(after, self.log_bytes)


class MixedShapeTests(unittest.TestCase):
    def _record_4(self, cfg, events):
        code, out, err, _, _ = record_log(cfg, events)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')

    def test_abstract_and_raw_frames_mixed_rejected(self):
        cfg = two_port()
        e, length, fcs = raw_frame(10, "p1", BCAST, MAC1)
        events = [
            link(0, "p1"), link(0, "p2"),
            e,
            abstract_frame(11, "p1", MAC1, BCAST, None, length, fcs),
        ]
        self._record_4(cfg, events)

    def test_raw_frame_invalid_mac_rejected(self):
        cfg = two_port()
        self._record_4(cfg, [
            raw_event(0, "p1", dst="00:00:00:00:00:00", src=MAC1),
        ])
        self._record_4(cfg, [
            raw_event(0, "p1", dst=BCAST, src="01:00:00:00:00:01"),
        ])

    def test_double_tag_rejected(self):
        cfg = two_port()
        e = raw_event(0, "p1", BCAST, MAC1, vlan=1, payload_len=42)
        raw = bytes.fromhex(e["data"])
        double = dict(e, data=(raw[:16] + b"\x81\x00\x10\x00"
                               + raw[16:]).hex())
        self._record_4(cfg, [double])


class LegacyLinkWireLogTests(unittest.TestCase):
    """仅含 link/advance 或抽象帧的既有 link-wire 日志必须字节不变。"""

    def test_abstract_frame_log_unchanged_and_replays_as_link_wire(self):
        from test_link_wire import frame as abstract_frame_event

        cfg = two_port()
        events = [
            link(0, "p1"),
            link(0, "p2"),
            abstract_frame_event(10, "p1", MAC1, length=100),
            advance(970),
        ]
        code, out, err, log_bytes, _ = record_log(cfg, events)
        self.assertEqual(code, 0)
        doc = json.loads(log_bytes.decode())
        # 抽象帧事件形状（含 src/dst/vlan/length/fcs/alignment）
        frame_events = [r["event"] for r in doc["records"]
                        if "admin" not in r["event"]
                        and "advance" not in r["event"]]
        self.assertTrue(frame_events)
        self.assertIn("src", frame_events[0])
        self.assertNotIn("data", frame_events[0])
        # 旧日志可被 replay 接受且字节不变；stdout 同直接 link-wire
        code2, rep_out, err, after = replay_log(log_bytes)
        self.assertEqual(code2, 0, err)
        self.assertEqual(after, log_bytes)
        tmp, cp, ep = write_inputs(cfg, events)
        code3, wire_out, werr, _ = run(["link-wire", cp, ep])
        self.assertEqual(code3, 0, werr)
        self.assertEqual(rep_out, wire_out)
        self.assertEqual(out, wire_out)

    def test_link_advance_only_log_unchanged(self):
        cfg = two_port(delay=10)
        events = [link(0, "p1"), advance(10), advance(11)]
        code, out, err, log_bytes, _ = record_log(cfg, events)
        self.assertEqual(code, 0)
        # 再 record 一次，字节稳定（旧哈希不变）
        code2, out2, err2, log_bytes2, _ = record_log(cfg, events)
        self.assertEqual(code2, 0)
        self.assertEqual(log_bytes, log_bytes2)
        code3, rep_out, err3, after = replay_log(log_bytes)
        self.assertEqual(code3, 0, err3)
        self.assertEqual(after, log_bytes)
        self.assertEqual(rep_out, out)


class WorkLimitTests(unittest.TestCase):
    HEAD = ("100000", "16777216", "1048576", "16777216", "16777216")

    def test_record_work_boundary_matches_link_wire(self):
        # 同 test_record_link_wire：P=2，首个 link settle +1、结果 +1 => 4
        cfg = two_port()
        events = [link(0, "p1")]
        code, out, err, _, log_path = record_log(
            cfg, events, *self.HEAD, 4
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(out, direct_stdout(cfg, events))
        code, out, err, _, log_path = record_log(
            cfg, events, *self.HEAD, 3
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"record_work_limit"}\n')
        self.assertFalse(os.path.exists(log_path))

    def test_replay_work_boundary(self):
        cfg = two_port()
        events = [link(0, "p1")]
        _, log_bytes = record_success(cfg, events)
        code, out, err, _ = replay_log(
            log_bytes, "100000", "16777216", "16777216", 3
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"replay_work_limit"}\n')
        code, _, err, after = replay_log(
            log_bytes, "100000", "16777216", "16777216", 4
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(after, log_bytes)


if __name__ == "__main__":
    unittest.main()
