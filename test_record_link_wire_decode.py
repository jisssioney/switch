#!/usr/bin/env python3
"""record / replay 对 link-wire-decode（原始以太帧线速仿真）的支持回归。

含 queue_bytes 的配置与 link-wire 共享：record/replay 按帧形状区分模式——
帧项含 src（八键抽象帧）按 link-wire，帧项仅含 t/port/data（完整以太帧的
小写偶数位十六进制）按 link-wire-decode，两种形状混用整次操作
invalid_input/4；只含 link/advance 项或空事件仍按既有 link-wire 解释，
旧日志哈希与所有既有子命令行为不变。新模式成功 stdout 与直接
link-wire-decode 逐字节一致，replay 逐字节复现；记录按 link-wire 同一
实际处理顺序（同一时刻端口配置序、advance 最后）保存，frame 恒 applied
（坏帧、碰撞、队列满亦然），version 仅在 applied 的 link 记录增长。

仅用标准库；端到端驱动 `python switch.py record/replay/link-wire-decode`。
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
from test_link_wire import config  # noqa: E402
from test_link_wire import frame  # noqa: E402
from test_link_wire import link  # noqa: E402
from test_link_wire import port  # noqa: E402
from test_link_wire_decode import abstract_from_raw  # noqa: E402
from test_link_wire_decode import raw_bytes  # noqa: E402
from test_link_wire_decode import raw_frame  # noqa: E402

BCAST = "ff:ff:ff:ff:ff:ff"
MAC1 = "00:00:00:00:00:01"
MAC2 = "00:00:00:00:00:02"


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


def direct_decode(cfg, events, *limits):
    tmp, cfg_path, evt_path = write_inputs(cfg, events)
    code, out, err, _ = run(
        ["link-wire-decode", cfg_path, evt_path, *[str(x) for x in limits]]
    )
    assert code == 0, (code, err.decode())
    return out


def direct_wire(cfg, events, *limits):
    tmp, cfg_path, evt_path = write_inputs(cfg, events)
    code, out, err, _ = run(
        ["link-wire", cfg_path, evt_path, *[str(x) for x in limits]]
    )
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


def record_success(cfg, events, *limits):
    code, out, err, log_bytes, _ = record_log(cfg, events, *limits)
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


def rehash(doc):
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


def two_port(delay=10, queue=1000000):
    return config(
        [port("p1", rates=[1000], modes=["full"], queue_bytes=queue),
         port("p2", rates=[1000], modes=["full"], queue_bytes=queue)],
        delay=delay,
    )


def raw_events():
    return [
        link(0, "p1"),
        link(0, "p2"),
        raw_frame(10, "p1", payload_len=100 - 14 - 4),
        {"t": 970, "advance": True},
        raw_frame(2000, "p1", bad_fcs=True),
        {"t": 5000, "advance": True},
    ]


def abstract_events(events):
    return [
        event if "data" not in event else abstract_from_raw(event)
        for event in events
    ]


class ByteIdenticalTests(unittest.TestCase):
    def test_record_stdout_matches_direct_decode(self):
        cfg = two_port()
        events = raw_events()
        out, _ = record_success(cfg, events)
        self.assertEqual(out, direct_decode(cfg, events))

    def test_replay_stdout_matches_record_and_direct(self):
        cfg = two_port()
        events = raw_events()
        rec_out, log_bytes = record_success(cfg, events)
        code, rep_out, err, after = replay_log(log_bytes)
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertEqual(rep_out, rec_out)
        self.assertEqual(rep_out, direct_decode(cfg, events))
        self.assertEqual(after, log_bytes)

    def test_matches_abstract_link_wire_on_converted_input(self):
        # 同一原始帧准确转换后：decode 直接结果 == link-wire 直接结果，
        # record/replay 三方逐字节一致
        cfg = two_port()
        events = raw_events()
        out_decode = direct_decode(cfg, events)
        out_wire = direct_wire(cfg, abstract_events(events))
        self.assertEqual(out_decode, out_wire)
        _, log_bytes = record_success(cfg, events)
        code, rep_out, _, _ = replay_log(log_bytes)
        self.assertEqual(code, 0)
        self.assertEqual(rep_out, out_wire)

    def test_same_input_records_identical_bytes(self):
        cfg = two_port()
        events = raw_events()
        _, log_a = record_success(cfg, events)
        _, log_b = record_success(cfg, events)
        self.assertEqual(log_a, log_b)

    def test_empty_events(self):
        cfg = two_port()
        out, log_bytes = record_success(cfg, [])
        self.assertEqual(out, direct_decode(cfg, []))
        doc = json.loads(log_bytes.decode())
        self.assertEqual(doc["records"], [])
        code, rep_out, err, _ = replay_log(log_bytes)
        self.assertEqual(code, 0, err)
        self.assertEqual(rep_out, out)


class LogShapeTests(unittest.TestCase):
    def setUp(self):
        self.cfg = two_port()
        self.events = raw_events()
        _, self.log_bytes = record_success(self.cfg, self.events)
        self.doc = json.loads(self.log_bytes.decode())

    def test_frame_records_hold_raw_events(self):
        frame_records = [
            r for r in self.doc["records"]
            if "data" in r["event"]
        ]
        self.assertTrue(frame_records)
        for record in frame_records:
            self.assertEqual(
                set(record["event"]), {"t", "port", "data"}
            )
            self.assertEqual(list(record), RECORD_KEYS)
            self.assertTrue(canonical_key_order(record["event"]))
            # data 为小写偶数位十六进制
            data = record["event"]["data"]
            self.assertEqual(len(data) % 2, 0)
            self.assertEqual(data, data.lower())
            self.assertRegex(data, r"[0-9a-f]+")

    def test_one_record_per_event_and_digest(self):
        self.assertEqual(len(self.doc["records"]), len(self.events))
        self.assertEqual(list(self.doc), LOG_KEYS)
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

    def test_output_is_always_list(self):
        for record in self.doc["records"]:
            self.assertIsInstance(record["output"], list)


class OldLogCompatTests(unittest.TestCase):
    def test_link_and_advance_only_still_link_wire(self):
        # 无任何帧项：仍按既有 link-wire 模式解释，replay 输出等于直接
        # link-wire，且不被识别为 decode 模式
        cfg = two_port()
        events = [
            link(0, "p1"), link(0, "p2"),
            {"t": 970, "advance": True},
        ]
        out, log_bytes = record_success(cfg, events)
        self.assertEqual(out, direct_wire(cfg, events))
        code, rep_out, err, _ = replay_log(log_bytes)
        self.assertEqual(code, 0, err)
        self.assertEqual(rep_out, out)

    def test_abstract_frames_still_link_wire(self):
        # 八键抽象帧仍走 link-wire：replay 输出等于直接 link-wire
        cfg = two_port()
        events = [
            link(0, "p1"), link(0, "p2"),
            frame(10, "p1", MAC1, length=100),
            {"t": 970, "advance": True},
        ]
        out, log_bytes = record_success(cfg, events)
        self.assertEqual(out, direct_wire(cfg, events))
        code, rep_out, _, _ = replay_log(log_bytes)
        self.assertEqual(code, 0)
        self.assertEqual(rep_out, out)
        doc = json.loads(log_bytes.decode())
        self.assertFalse(
            any("data" in r["event"] for r in doc["records"])
        )


class ProcessingOrderTests(unittest.TestCase):
    def test_same_time_port_order_with_advance_last(self):
        cfg = two_port()
        events = [
            {"t": 0, "advance": True},
            raw_frame(0, "p2", MAC2, payload_len=100 - 14 - 4),
            link(0, "p2"),
            link(0, "p1"),
        ]
        _, log_bytes = record_success(cfg, events)
        doc = json.loads(log_bytes.decode())
        seq = []
        for r in doc["records"]:
            ev = r["event"]
            if "advance" in ev:
                seq.append("advance")
            elif "data" in ev:
                seq.append("frame:" + ev["port"])
            else:
                seq.append("link:" + ev["port"])
        self.assertEqual(seq, ["link:p1", "frame:p2", "link:p2", "advance"])

    def test_outputs_concatenate_to_direct_results(self):
        cfg = two_port()
        events = raw_events()
        direct = json.loads(direct_decode(cfg, events))
        _, log_bytes = record_success(cfg, events)
        doc = json.loads(log_bytes.decode())
        concat = []
        for record in doc["records"]:
            concat.extend(record["output"])
        self.assertEqual(concat, direct["results"])


class AppliedAndVersionTests(unittest.TestCase):
    def test_frame_always_applied_even_bad_fcs(self):
        cfg = two_port()
        events = [
            link(0, "p1"), link(0, "p2"),
            raw_frame(10, "p1", bad_fcs=True),
        ]
        _, log_bytes = record_success(cfg, events)
        doc = json.loads(log_bytes.decode())
        frame_records = [r for r in doc["records"] if "data" in r["event"]]
        self.assertEqual(len(frame_records), 1)
        self.assertIs(frame_records[0]["applied"], True)
        drop = frame_records[0]["output"][0]
        self.assertEqual(drop["class"], "bad_fcs")
        self.assertEqual(drop["action"], "drop")

    def test_version_only_increments_on_applied_link(self):
        cfg = two_port()
        events = [
            link(0, "p1"),                       # applied -> v1
            link(0, "p2"),                       # applied -> v2
            raw_frame(10, "p1"),                 # frame: v2，t=10 协商到期
            link(20, "p1"),                     # 目标未变 -> 仍 v2
            {"t": 970, "advance": True},         # 结算完成发送 -> v2
            link(2000, "p1", admin=False),       # applied -> v3
        ]
        _, log_bytes = record_success(cfg, events)
        doc = json.loads(log_bytes.decode())
        versions = [r["version"] for r in doc["records"]]
        self.assertEqual(versions, [1, 2, 2, 2, 2, 3])
        applied = [r["applied"] for r in doc["records"]]
        self.assertEqual(applied, [True, True, True, False, True, True])


class ReplayIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.cfg = two_port()
        _, self.log_bytes = record_success(self.cfg, raw_events())

    def _replay_raw(self, raw):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "x.log")
            with open(path, "wb") as handle:
                handle.write(raw)
            proc = subprocess.run(
                [sys.executable, SWITCH, "replay", path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        return proc.returncode, proc.stdout, proc.stderr

    def test_tampered_data_fails(self):
        doc = json.loads(self.log_bytes.decode())
        for record in doc["records"]:
            if "data" in record["event"]:
                data = record["event"]["data"]
                flipped = "00" if data[-2:] != "00" else "01"
                record["event"]["data"] = data[:-2] + flipped
        code, out, _ = self._replay_raw(rehash(doc))
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")

    def test_swap_raw_for_abstract_fails(self):
        # 保持 config（queue_bytes）不变，把原始帧记录改为抽象帧：模式判为
        # link-wire，重建日志必不逐字节一致 -> invalid_input
        doc = json.loads(self.log_bytes.decode())
        for record in doc["records"]:
            if "data" in record["event"]:
                record["event"] = abstract_from_raw(
                    {"t": record["event"]["t"],
                     "port": record["event"]["port"],
                     "data": record["event"]["data"]}
                )
        code, out, _ = self._replay_raw(rehash(doc))
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")

    def test_tampered_applied_fails(self):
        doc = json.loads(self.log_bytes.decode())
        doc["records"][2]["applied"] = not doc["records"][2]["applied"]
        code, _, _ = self._replay_raw(rehash(doc))
        self.assertEqual(code, 4)

    def test_digest_mismatch_fails(self):
        doc = json.loads(self.log_bytes.decode())
        doc["sha256"] = "0" * 64
        raw = (
            json.dumps({key: doc[key] for key in LOG_KEYS},
                       ensure_ascii=False, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, _ = self._replay_raw(raw)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")


class ValidationTests(unittest.TestCase):
    def test_mixed_frame_shapes_exit4(self):
        cfg = two_port()
        events = [
            link(0, "p1"),
            frame(10, "p1", MAC1, length=64),
            raw_frame(20, "p1"),
        ]
        code, out, err, log, path = record_log(cfg, events)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertIn(b"invalid_input", err)
        self.assertFalse(os.path.exists(path))

    def test_invalid_raw_frame_exit4_no_log(self):
        cfg = two_port()
        for bad_event in (
            raw_frame(10, "p1", dst="00:00:00:00:00:00"),
            raw_frame(10, "p1", src="00:00:00:00:00:00"),
            raw_frame(10, "p1", src="01:00:5e:00:00:01"),
            {"t": 10, "port": "p1", "data": "abc"},
        ):
            code, out, err, _, path = record_log(cfg, [bad_event])
            self.assertEqual(code, 4, bad_event)
            self.assertEqual(out, b"")
            self.assertFalse(os.path.exists(path))

    def test_t_not_monotonic_exit4(self):
        cfg = two_port()
        code, _, _, _, path = record_log(
            cfg, [raw_frame(10, "p1"), raw_frame(9, "p1")]
        )
        self.assertEqual(code, 4)
        self.assertFalse(os.path.exists(path))


class LimitTests(unittest.TestCase):
    # record 上限顺序：max_events, max_log_bytes, max_config_bytes,
    # max_events_bytes, max_output_bytes
    HEAD = ("100000", "16777216", "1048576", "16777216", "16777216")

    def test_record_work_limit_boundary(self):
        cfg = two_port()
        events = [link(0, "p1")]
        # W：P=2 + 结算 1 + link 记录 1 = 4
        code, _, _, _, _ = record_log(cfg, events, *self.HEAD, 4)
        self.assertEqual(code, 0)
        code, out, err, _, path = record_log(cfg, events, *self.HEAD, 3)
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"record_work_limit"}\n')
        self.assertFalse(os.path.exists(path))

    def test_replay_work_limit(self):
        cfg = two_port()
        _, log_bytes = record_success(cfg, raw_events())
        # replay 上限顺序：max_events, max_log_bytes, max_output_bytes, work
        code, out, err, _ = replay_log(
            log_bytes, "100000", "16777216", "16777216", 1
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"replay_work_limit"}\n')

    def test_event_limit(self):
        cfg = two_port()
        code, out, err, _, log_path = record_log(
            cfg, [link(0, "p1"), link(1, "p2")], 1, *self.HEAD[1:]
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertIn(b"event_limit", err)
        self.assertFalse(os.path.exists(log_path))


if __name__ == "__main__":
    unittest.main()
