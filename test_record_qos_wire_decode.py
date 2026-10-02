#!/usr/bin/env python3
"""record / replay 对 qos-wire-decode 模式的支持回归。

端口配置含 queue_bytes、flow_control 与顶层 qos 且每口均无 pfc 字段时，
record/replay 按 qos-wire-decode 路由：成功 stdout 与直接执行
qos-wire-decode 逐字节一致，产生可被 replay 接受的 schema 1 日志；记录
顺序、applied、output 连续数组语义与 link-wire 相同（frame 恒 applied，
link 仅状态实际改变时 applied，advance 仅在产生到期协商或发送结果时
applied，version 只随已应用的 link 事件递增）。混合 pfc 端口形状返回
invalid_input/4；工作量上限等于可成功，首次超过返回 record_work_limit/
replay_work_limit，退出 5。

仅用标准库；端到端驱动 record / replay / qos-wire-decode。
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

from test_record import LOG_KEYS  # noqa: E402
from test_record import RECORD_KEYS  # noqa: E402
from test_record import canonical_key_order  # noqa: E402
from test_qos_wire_decode import MAC1  # noqa: E402
from test_qos_wire_decode import advance  # noqa: E402
from test_qos_wire_decode import config  # noqa: E402
from test_qos_wire_decode import link  # noqa: E402
from test_qos_wire_decode import pause_event  # noqa: E402
from test_qos_wire_decode import qos  # noqa: E402
from test_qos_wire_decode import raw_frame  # noqa: E402
from test_qos_pfc_decode import pfc_event  # noqa: E402
from test_qos_pfc_decode import port as pfc_port  # noqa: E402


def write_inputs(cfg, events):
    tmp = tempfile.mkdtemp()
    cfg_path = os.path.join(tmp, "config.json")
    evt_path = os.path.join(tmp, "events.json")
    with open(cfg_path, "wb") as handle:
        handle.write(json.dumps(cfg).encode("utf-8"))
    with open(evt_path, "wb") as handle:
        handle.write(json.dumps(events).encode("utf-8"))
    return tmp, cfg_path, evt_path


def run_keep(argv):
    proc = subprocess.run(
        [sys.executable, SWITCH, *argv],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return proc.returncode, proc.stdout, proc.stderr


def direct_stdout(cfg, events):
    tmp, cfg_path, evt_path = write_inputs(cfg, events)
    code, out, err = run_keep(["qos-wire-decode", cfg_path, evt_path])
    assert code == 0, (code, err.decode())
    return out


def record_log(cfg, events, *limits, log_name="out.log"):
    tmp, cfg_path, evt_path = write_inputs(cfg, events)
    log_path = os.path.join(tmp, log_name)
    code, out, err = run_keep(
        ["record", cfg_path, evt_path, log_path,
         *[str(x) for x in limits]]
    )
    after = b""
    if os.path.exists(log_path):
        with open(log_path, "rb") as handle:
            after = handle.read()
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


def rich_events():
    return [
        link(0, "p1"),
        link(0, "p2"),
        raw_frame(100, "p1", prio=0),
        raw_frame(150, "p1", src="00:00:00:00:00:02", prio=3),
        pause_event(200, "p2", 10),
        raw_frame(300, "p2", prio=1),
        advance(100000),
    ]


class ByteIdenticalTests(unittest.TestCase):
    def test_record_stdout_matches_direct(self):
        cfg = config()
        events = rich_events()
        out, _ = record_success(cfg, events)
        self.assertEqual(out, direct_stdout(cfg, events))

    def test_replay_stdout_matches_record_and_direct(self):
        cfg = config()
        events = rich_events()
        rec_out, log_bytes = record_success(cfg, events)
        code, rep_out, err, after = replay_log(log_bytes)
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertEqual(rep_out, rec_out)
        self.assertEqual(rep_out, direct_stdout(cfg, events))
        self.assertEqual(after, log_bytes)

    def test_same_input_records_identical_bytes(self):
        cfg = config()
        events = rich_events()
        _, log_a = record_success(cfg, events)
        _, log_b = record_success(cfg, events)
        self.assertEqual(log_a, log_b)

    def test_empty_events(self):
        cfg = config()
        out, log_bytes = record_success(cfg, [])
        self.assertEqual(out, direct_stdout(cfg, []))
        code, rep_out, err, _ = replay_log(log_bytes)
        self.assertEqual(code, 0, err)
        self.assertEqual(rep_out, out)


class LogShapeTests(unittest.TestCase):
    def setUp(self):
        self.cfg = config()
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

    def test_one_record_per_event_with_raw_data_preserved(self):
        self.assertEqual(len(self.doc["records"]), len(self.events))
        # 原始 data 事件原样保存（含 Pause 帧原始字节）
        for record, event in zip(self.doc["records"], self.events):
            self.assertEqual(record["event"], event)
        for pdoc in self.doc["config"]["ports"]:
            self.assertIn("flow_control", pdoc)
            self.assertNotIn("pfc", pdoc)

    def test_outputs_concatenate_to_direct_results(self):
        flat = [item for r in self.doc["records"]
                for item in r["output"]]
        direct = json.loads(direct_stdout(self.cfg, self.events).decode())
        self.assertEqual(flat, direct["results"])

    def test_pause_output_preserved(self):
        flat = [item for r in self.doc["records"]
                for item in r["output"]]
        pauses = [r for r in flat if r.get("action") == "pause"]
        self.assertEqual(len(pauses), 1)
        self.assertEqual(pauses[0]["quanta"], 10)

    def test_records_are_contiguous_nonoverlapping(self):
        offsets = []
        for record in self.doc["records"]:
            offsets.append((len(record["output"]), record["applied"]))
        # 每条记录的 output 都是连续片段（拼接等价已在另例验证），空片段
        # 只能出现在未 applied 的 link/advance
        direct = json.loads(direct_stdout(self.cfg, self.events).decode())
        total = sum(n for n, _ in offsets)
        self.assertEqual(total, len(direct["results"]))


class AppliedAndVersionTests(unittest.TestCase):
    def test_frame_records_all_applied_even_when_dropped(self):
        # 第二副本因队列配额被丢弃，帧记录仍 applied
        cfg = config(q=qos(cap=100))
        events = [
            link(0, "p1"), link(0, "p2"),
            raw_frame(100, "p1", prio=0),
            raw_frame(101, "p1", src="00:00:00:00:00:02", prio=0),
            advance(5000),
        ]
        _, log_bytes = record_success(cfg, events)
        doc = json.loads(log_bytes.decode())
        for record in doc["records"]:
            if "data" in record["event"]:
                self.assertTrue(record["applied"])
        flat = [o for r in doc["records"] for o in r["output"]]
        self.assertIn("quota_full", [o.get("reason") for o in flat])

    def test_same_time_sorted_by_port_with_advance_last(self):
        cfg = config()
        events = [
            advance(0),
            pause_event(0, "p2", 10),
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

    def test_version_only_applied_links_increment(self):
        cfg = config(delay=100)
        events = [
            link(0, "p1"),
            link(1, "p1"),                  # 幂等 link，不 applied
            pause_event(2, "p1", 10),      # 帧不计 version
            advance(50),                   # advance 不计 version
        ]
        _, log_bytes = record_success(cfg, events)
        records = json.loads(log_bytes.decode())["records"]
        self.assertEqual([r["version"] for r in records], [1, 1, 1, 1])
        self.assertEqual([r["applied"] for r in records],
                         [True, False, True, False])

    def test_advance_applied_only_when_it_settles(self):
        cfg = config(delay=100)
        events = [
            link(0, "p1"),
            advance(50),     # 协商未到期
            advance(100),    # 协商到期：applied 但结算本身不产出结果项
        ]
        _, log_bytes = record_success(cfg, events)
        records = json.loads(log_bytes.decode())["records"]
        applied = [r["applied"] for r in records]
        outputs = [len(r["output"]) for r in records]
        self.assertEqual(applied, [True, False, True])
        self.assertEqual(outputs, [1, 0, 0])


class ReplayIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.cfg = config()
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

    def test_tampered_output_fails(self):
        doc = json.loads(self.log_bytes.decode())
        record = next(r for r in doc["records"] if r["output"])
        record["output"][0]["t"] += 1
        bad = self._rehash(doc)
        code, out, err, after = replay_log(bad)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertEqual(after, bad)

    def test_tampered_raw_data_event_fails(self):
        doc = json.loads(self.log_bytes.decode())
        for r in doc["records"]:
            if "data" in r["event"]:
                r["event"]["data"] = "00" * 68
                break
        bad = self._rehash(doc)
        code, out, err, _ = replay_log(bad)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")

    def test_tampered_version_fails(self):
        doc = json.loads(self.log_bytes.decode())
        doc["records"][-1]["version"] += 1
        bad = self._rehash(doc)
        code, out, err, _ = replay_log(bad)
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


class ShapeRoutingTests(unittest.TestCase):
    def _record_4(self, cfg, events):
        code, out, err, _, _ = record_log(cfg, events)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')

    def test_mixed_pfc_ports_rejected(self):
        cfg = config(ports=[
            pfc_port("p1", pfc=(3,)),
            {k: v for k, v in pfc_port("p2").items() if k != "pfc"},
        ])
        self._record_4(cfg, [link(0, "p1"), link(0, "p2")])

    def test_mixed_pfc_ports_empty_events_rejected(self):
        cfg = config(ports=[
            pfc_port("p1", pfc=[]),
            {k: v for k, v in pfc_port("p2").items() if k != "pfc"},
        ])
        self._record_4(cfg, [])

    def test_service_event_rejected(self):
        cfg = config()
        self._record_4(cfg, [{"t": 1, "port": "p2", "count": 1}])

    def test_pfc_event_shape_routes_when_all_ports_have_pfc(self):
        # 每口均带 pfc 键（含空数组）即路由 qos-pfc-decode，PFC 帧可被
        # 识别为 pfc 系列结果而非普通数据帧
        cfg = config(ports=[pfc_port("p1", pfc=[]), pfc_port("p2", pfc=[])])
        events = [
            link(0, "p1"), link(0, "p2"),
            pfc_event(100, "p2", enable=(3,),
                      quanta8=[0, 0, 0, 10] + [0] * 4),
        ]
        code, out, err, log_bytes, _ = record_log(cfg, events)
        self.assertEqual(code, 0, err)
        # p2 的 pfc 允许集为空 -> pfc_unsupported 是 pfc 模式独有结果
        flat = [o for r in json.loads(log_bytes.decode())["records"]
                for o in r["output"]]
        self.assertTrue(
            any(o.get("action") == "pfc_unsupported" for o in flat)
        )
        self.assertEqual(json.loads(out.decode())["results"], flat)


class WorkLimitTests(unittest.TestCase):
    HEAD = ("100000", "16777216", "1048576", "16777216", "16777216")

    def test_record_work_boundary(self):
        # P=2，首个 link：settle +1、link 结果 +1 => 4
        cfg = config()
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
        cfg = config()
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

    def test_unreadable_log_is_3(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "nope.log")
            code, out, err = run_keep(["replay", missing])
        self.assertEqual(code, 3)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"file_not_found"}\n')

    def test_bad_arguments_are_2(self):
        code, out, err = run_keep(["replay", "/tmp/x", "not-a-number"])
        self.assertEqual(code, 2)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"usage"}\n')


if __name__ == "__main__":
    unittest.main()
