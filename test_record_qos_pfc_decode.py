#!/usr/bin/env python3
"""record / replay 对 qos-pfc-decode 模式的支持回归。

qos-wire 五键配置的每口均带 pfc（严格递增 0..7 子序，空数组表示不支持）
时，record/replay 按 qos-pfc-decode 路由：成功 stdout 与直接执行
qos-pfc-decode 逐字节一致，产生可被 replay 接受的 schema 1 日志；PFC 的
action/items/until 与逐优先级 pfc_duration_ns 统计完整保存，记录顺序、
applied、output 连续数组与 version 语义同 qos-wire-decode。混合 pfc 形状
返回 invalid_input/4；工作量上限等于可成功，首次超过返回
record_work_limit/replay_work_limit，退出 5。

仅用标准库；端到端驱动 record / replay / qos-pfc-decode。
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

from test_record import LOG_KEYS  # noqa: E402
from test_record import RECORD_KEYS  # noqa: E402
from test_record import canonical_key_order  # noqa: E402
from test_qos_pfc_decode import MAC2  # noqa: E402
from test_qos_pfc_decode import advance  # noqa: E402
from test_qos_pfc_decode import config  # noqa: E402
from test_qos_pfc_decode import link  # noqa: E402
from test_qos_pfc_decode import pfc_event  # noqa: E402
from test_qos_pfc_decode import port  # noqa: E402
from test_qos_pfc_decode import qos  # noqa: E402
from test_qos_pfc_decode import raw_frame  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
SWITCH = os.path.join(HERE, "switch.py")


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
    code, out, err = run_keep(["qos-pfc-decode", cfg_path, evt_path])
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
        pfc_event(
            200, "p2", enable=(3,),
            quanta8=[0, 0, 0, 10] + [0] * 4,
        ),
        raw_frame(300, "p1", src=MAC2, prio=3),
        raw_frame(350, "p1", src="00:00:00:00:00:03", prio=1),
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

    def test_empty_events_and_empty_pfc_lists(self):
        cfg = config(ports=[port("p1", pfc=[]), port("p2", pfc=[])])
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

    def test_one_record_per_event_raw_data_preserved(self):
        self.assertEqual(len(self.doc["records"]), len(self.events))
        for record, event in zip(self.doc["records"], self.events):
            self.assertEqual(record["event"], event)
        # 每口 pfc 配置完整保留
        for pdoc in self.doc["config"]["ports"]:
            self.assertIn("pfc", pdoc)
            self.assertIn("flow_control", pdoc)

    def test_outputs_concatenate_to_direct_results(self):
        flat = [item for r in self.doc["records"]
                for item in r["output"]]
        direct = json.loads(direct_stdout(self.cfg, self.events).decode())
        self.assertEqual(flat, direct["results"])

    def test_pfc_outputs_preserved(self):
        flat = [item for r in self.doc["records"]
                for item in r["output"]]
        pfcs = [r for r in flat if r.get("action") == "pfc"]
        self.assertEqual(len(pfcs), 1)
        self.assertEqual(pfcs[0]["items"],
                         [{"priority": 3, "quanta": 10, "until": 5320}])

    def test_pfc_duration_stats_preserved_in_stdout(self):
        out = json.loads(direct_stdout(self.cfg, self.events).decode())
        # p3 门控产生实际阻塞：p2 的 pfc_duration_ns[3] 为正
        self.assertGreater(out["ports"][1]["pfc_duration_ns"][3], 0)
        self.assertEqual(
            len(out["ports"][1]["pfc_duration_ns"]), 8
        )


class AppliedAndVersionTests(unittest.TestCase):
    def test_same_time_sorted_by_port_with_advance_last(self):
        cfg = config()
        events = [
            advance(0),
            pfc_event(0, "p2", enable=(3,)),
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

    def test_version_only_applied_links(self):
        cfg = config(delay=100)
        events = [
            link(0, "p1"),
            link(1, "p1"),                            # 幂等 link
            pfc_event(2, "p1", enable=(3,)),         # 帧不计 version
            advance(50),                             # 协商未到期
            advance(100),                            # 协商到期
        ]
        _, log_bytes = record_success(cfg, events)
        records = json.loads(log_bytes.decode())["records"]
        self.assertEqual(
            [r["version"] for r in records], [1, 1, 1, 1, 1]
        )
        self.assertEqual(
            [r["applied"] for r in records],
            [True, False, True, False, True],
        )

    def test_frames_applied_even_when_unsupported_or_dropped(self):
        # p2 不允许 p3：PFC 帧记 pfc_unsupported，但帧记录仍 applied
        cfg = config(ports=[port("p1", pfc=(0,)), port("p2", pfc=(0,))])
        events = [
            link(0, "p1"), link(0, "p2"),
            pfc_event(100, "p2", enable=(3,)),
        ]
        _, log_bytes = record_success(cfg, events)
        records = json.loads(log_bytes.decode())["records"]
        self.assertTrue(
            all(r["applied"] for r in records if "data" in r["event"])
        )
        flat = [o for r in records for o in r["output"]]
        self.assertTrue(
            any(o.get("action") == "pfc_unsupported" for o in flat)
        )


class ReplayIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.cfg = config()
        self.events = rich_events()
        _, self.log_bytes = record_success(self.cfg, self.events)

    def test_tampered_pfc_item_fails(self):
        import hashlib
        doc = json.loads(self.log_bytes.decode())
        pfc_rec = next(
            r for r in doc["records"]
            if any(o.get("action") == "pfc" for o in r["output"])
        )
        pfc_out = next(o for o in pfc_rec["output"]
                       if o.get("action") == "pfc")
        pfc_out["items"][0]["quanta"] = 11
        prefix = {k: doc[k] for k in ("schema", "config", "records")}
        doc["sha256"] = hashlib.sha256(
            (json.dumps(prefix, ensure_ascii=False, separators=(",", ":"))
             + "\n").encode("utf-8")
        ).hexdigest()
        bad = (
            json.dumps(
                {k: doc[k] for k in LOG_KEYS},
                ensure_ascii=False, separators=(",", ":"),
            ) + "\n"
        ).encode("utf-8")
        code, out, err, after = replay_log(bad)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertEqual(after, bad)

    def test_replay_rebuilds_byte_identical_log(self):
        code, _, err, after = replay_log(self.log_bytes)
        self.assertEqual(code, 0, err)
        self.assertEqual(after, self.log_bytes)

    def test_expect_sha_mismatch(self):
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

    def test_missing_pfc_on_one_port_rejected(self):
        cfg = config(ports=[
            port("p1", pfc=(3,)),
            {k: v for k, v in port("p2").items() if k != "pfc"},
        ])
        self._record_4(cfg, [link(0, "p1"), link(0, "p2")])

    def test_bad_pfc_value_rejected(self):
        cfg = config(ports=[port("p1", pfc=(8,)), port("p2", pfc=(3,))])
        self._record_4(cfg, [])

    def test_abstract_frame_rejected(self):
        cfg = config()
        abstract = {
            "t": 1, "port": "p1", "src": "00:00:00:00:00:01",
            "dst": "ff:ff:ff:ff:ff:ff", "vlan": None, "length": 64,
            "fcs": True, "alignment": True,
        }
        self._record_4(cfg, [abstract])


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


if __name__ == "__main__":
    unittest.main()
