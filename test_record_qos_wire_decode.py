#!/usr/bin/env python3
"""record / replay 对 qos-wire-decode 模式的支持回归。

端口配置含 queue_bytes、flow_control 且顶层含 qos、每口均不含 pfc 时，
record/replay 按 qos-wire-decode 路由：成功 stdout 与直接执行
qos-wire-decode 逐字节一致，产生可被 replay 接受的 schema 1 日志，记录
顺序、applied、output 连续数组语义与 link-wire 相同（frame 恒 applied，
link 仅状态实际改变时 applied，advance 仅产生到期协商或发送时 applied，
version 只随已应用的 link 事件递增）；PAUSE 的 action/quanta/until 完整
保存在 output 中。工作量等于上限可成功，首次超过时 record 返回
record_work_limit、replay 返回 replay_work_limit，均退出 5 且不写日志、
不产生部分标准输出。

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
sys.path.insert(0, HERE)

from test_record import LOG_KEYS  # noqa: E402
from test_record import RECORD_KEYS  # noqa: E402
from test_record import canonical_key_order  # noqa: E402
from test_qos_wire_decode import BCAST  # noqa: E402
from test_qos_wire_decode import MAC1  # noqa: E402
from test_qos_wire_decode import advance  # noqa: E402
from test_qos_wire_decode import config  # noqa: E402
from test_qos_wire_decode import link  # noqa: E402
from test_qos_wire_decode import link_down  # noqa: E402
from test_qos_wire_decode import pause_event  # noqa: E402
from test_qos_wire_decode import port  # noqa: E402
from test_qos_wire_decode import qos  # noqa: E402
from test_qos_wire_decode import raw_frame  # noqa: E402


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


def two_port(delay=10, queue=1000000, flow_control=True, q=None):
    return config(
        q=q,
        ports=[
            port("p1", rates=[1000], modes=["full"], queue_bytes=queue,
                 flow_control=flow_control),
            port("p2", rates=[1000], modes=["full"], queue_bytes=queue,
                 flow_control=flow_control),
        ],
        delay=delay,
    )


def rich_events():
    return [
        link(0, "p1"),
        link(0, "p2"),
        raw_frame(100, "p2", prio=3),
        pause_event(200, "p1", 10),
        raw_frame(300, "p2", src="00:00:00:00:00:03"),
        pause_event(400, "p1", 0),
        advance(1000000),
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

    def test_one_record_per_event_raw_data_preserved(self):
        self.assertEqual(len(self.doc["records"]), len(self.events))
        # 配置保存 flow_control/queue_bytes 且不含 pfc；原始 data 事件保留
        for pdoc in self.doc["config"]["ports"]:
            self.assertIn("flow_control", pdoc)
            self.assertIn("queue_bytes", pdoc)
            self.assertNotIn("pfc", pdoc)
        raw = [e for e in self.events if "data" in e]
        logged = [r["event"] for r in self.doc["records"] if "data" in r["event"]]
        self.assertEqual(logged, raw)

    def test_pause_outputs_preserved(self):
        flat = [item for r in self.doc["records"]
                for item in r["output"]]
        pauses = [r for r in flat if r.get("action") == "pause"]
        self.assertEqual([r["quanta"] for r in pauses], [10, 0])
        self.assertIsNone(pauses[1]["until"])
        self.assertEqual(pauses[0]["until"], 200 + 10 * 512000 // 1000)

    def test_outputs_concatenate_to_direct_results(self):
        flat = [item for r in self.doc["records"]
                for item in r["output"]]
        direct = json.loads(direct_stdout(self.cfg, self.events).decode())
        self.assertEqual(flat, direct["results"])

    def test_frame_records_all_applied(self):
        for record in self.doc["records"]:
            if "data" in record["event"]:
                self.assertTrue(record["applied"])


class MalformedRuntimeTests(unittest.TestCase):
    def test_malformed_pause_is_recorded_applied(self):
        import zlib
        body = (
            bytes(int(x, 16) for x in "01:80:c2:00:00:01".split(":"))
            + bytes(int(x, 16) for x in MAC1.split(":"))
            + b"\x88\x08\x00\x02" + (10).to_bytes(2, "big") + b"\x00" * 42
        )
        fcs = (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little")
        bad = {"t": 100, "port": "p1", "data": (body + fcs).hex()}
        cfg = two_port()
        events = [link(0, "p1"), link(0, "p2"), bad]
        code, out, err, log_bytes, _ = record_log(cfg, events)
        self.assertEqual(code, 0, err)
        self.assertEqual(out, direct_stdout(cfg, events))
        doc = json.loads(log_bytes.decode())
        rec = next(r for r in doc["records"] if "data" in r["event"])
        self.assertTrue(rec["applied"])
        self.assertEqual(rec["output"][0]["action"], "malformed_pause")


class ProcessingOrderTests(unittest.TestCase):
    def test_same_time_sorted_by_port_with_advance_last(self):
        cfg = two_port()
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
        cfg = two_port(delay=100)
        events = [
            link(0, "p1"),
            link(1, "p1"),                  # 幂等 link，不 applied
            pause_event(2, "p1", 10),       # 帧不计 version
            advance(50),                    # advance 不计 version
        ]
        _, log_bytes = record_success(cfg, events)
        records = json.loads(log_bytes.decode())["records"]
        self.assertEqual([r["version"] for r in records], [1, 1, 1, 1])
        self.assertEqual([r["applied"] for r in records],
                         [True, False, True, False])

    def test_advance_applied_only_when_settles(self):
        cfg = two_port(delay=100)
        events = [link(0, "p1"), advance(50), advance(200)]
        _, log_bytes = record_success(cfg, events)
        records = json.loads(log_bytes.decode())["records"]
        applied = {("advance" if "advance" in r["event"] else "link"):
                   r["applied"] for r in records}
        # 第一次 advance（50<100）无到期；第二次（200>=100）协商到期
        flags = [r["applied"] for r in records]
        self.assertEqual(flags, [True, False, True])


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

    def test_tampered_pause_quanta_fails(self):
        doc = json.loads(self.log_bytes.decode())
        pause_rec = next(
            r for r in doc["records"]
            if any(o.get("action") == "pause" for o in r["output"])
        )
        pause_out = next(o for o in pause_rec["output"]
                         if o.get("action") == "pause")
        pause_out["quanta"] = 11
        bad = self._rehash(doc)
        code, out, err, after = replay_log(bad)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertEqual(after, bad)

    def test_tampered_event_fails(self):
        doc = json.loads(self.log_bytes.decode())
        for r in doc["records"]:
            if "data" in r["event"]:
                r["event"]["data"] = "00" * 64
                break
        code, out, err, _ = replay_log(self._rehash(doc))
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")

    def test_tampered_version_fails(self):
        doc = json.loads(self.log_bytes.decode())
        doc["records"][0]["version"] = 5
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


class ShapeRoutingTests(unittest.TestCase):
    def _record_4(self, cfg, events):
        code, out, err, _, _ = record_log(cfg, events)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')

    def test_service_event_rejected(self):
        cfg = two_port()
        self._record_4(cfg, [link(0, "p1"),
                             {"t": 1, "port": "p2", "count": 1}])

    def test_abstract_frame_rejected(self):
        cfg = two_port()
        events = [
            link(0, "p1"), link(0, "p2"),
            {"t": 100, "port": "p1", "src": MAC1, "dst": BCAST,
             "vlan": None, "length": 64, "fcs": True, "alignment": True},
        ]
        self._record_4(cfg, events)

    def test_member_event_rejected(self):
        self._record_4(two_port(), [{"t": 1, "member": "p2", "up": True}])

    def test_bad_qos_config_rejected(self):
        cfg = two_port(q=qos(mode="rr"))
        self._record_4(cfg, [])

    def test_config_with_pfc_key_is_not_wire_mode(self):
        # 给某一口加 pfc 而另一口不加：混合形状 invalid_input（既不能按
        # qos-wire 也不能按 qos-pfc 路由）
        p1 = port("p1")
        p2 = port("p2")
        p2["pfc"] = [3]
        cfg = config(ports=[p1, p2])
        self._record_4(cfg, [link(0, "p1"), link(0, "p2")])


class SchedulingContentTests(unittest.TestCase):
    def test_wrr_drops_and_tx_preserved_via_record(self):
        events = [
            link(0, "p1"), link(0, "p2"),
            raw_frame(100, "p1", prio=0),
            raw_frame(101, "p1", src="00:00:00:00:00:02", prio=0),
            advance(5000),
        ]
        cfg = two_port(q=qos(cap=100))
        out, _ = record_success(cfg, events)
        doc = json.loads(out.decode())
        reasons = [r["reason"] for r in doc["results"] if "reason" in r]
        self.assertEqual(reasons, ["quota_full"])
        self.assertEqual(doc["ports"][1]["quota_full_frames"], 1)

    def test_link_down_drops_in_output_fragments(self):
        events = [
            link(0, "p1"), link(0, "p2"),
            raw_frame(100, "p1", prio=0),
            raw_frame(101, "p1", src="00:00:00:00:00:02", prio=3),
            link_down(200, "p2"),
            advance(5000),
        ]
        cfg = two_port()
        _, log_bytes = record_success(cfg, events)
        flat = [item for r in json.loads(log_bytes.decode())["records"]
                for item in r["output"]]
        dropped = [r for r in flat if r.get("reason") == "link_down"]
        self.assertEqual(len(dropped), 2)
        self.assertEqual({r["queue"] for r in dropped}, {0, 3})


class WorkLimitTests(unittest.TestCase):
    HEAD = ("100000", "16777216", "1048576", "16777216", "16777216")

    def test_record_work_boundary(self):
        # P=2，首个 link：settle +1、link 结果 +1 => 4
        cfg = two_port()
        events = [link(0, "p1")]
        code, out, err, _, log_path = record_log(
            cfg, events, *self.HEAD, 4
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(out, direct_stdout(cfg, events))
        # 全新目标路径：超限时不得写日志
        code, out, err, _, log_path = record_log(
            cfg, events, *self.HEAD, 3, log_name="fresh.log"
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


class FileAndUsageTests(unittest.TestCase):
    def test_record_missing_file_exit_3(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "o.log")
            code, out, err = run_keep(
                ["record", "/nope/c", "/nope/e", log_path]
            )
        self.assertEqual(code, 3)
        self.assertEqual(out, b"")
        self.assertEqual(err.strip(), b'{"error":"file_not_found"}')

    def test_replay_missing_file_exit_3(self):
        code, out, err = run_keep(["replay", "/nope/log"])
        self.assertEqual(code, 3)
        self.assertEqual(out, b"")
        self.assertEqual(err.strip(), b'{"error":"file_not_found"}')

    def test_record_bad_arity_exit_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, _, err = run_keep(
                ["record", os.path.join(tmp, "c"), os.path.join(tmp, "e")]
            )
        self.assertEqual(code, 2)
        self.assertEqual(err, b'{"error":"usage"}\n')


if __name__ == "__main__":
    unittest.main()
