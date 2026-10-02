#!/usr/bin/env python3
"""record / replay 对 qos-pfc-decode 模式的支持回归。

端口配置含 queue_bytes、flow_control、qos 且每口均含 pfc 时，record/
replay 按 qos-pfc-decode 路由：成功 stdout 与直接执行 qos-pfc-decode
逐字节一致，产生可被 replay 接受的 schema 1 日志；记录顺序、applied、
output 连续数组语义与 qos-wire-decode 相同（frame 恒 applied，link 仅
状态实际改变时 applied，version 只随已应用 link 事件递增）；PFC 的
action/items/until 与 pfc_unsupported、malformed_pfc 完整保存在 output
中。配置端口 pfc 形状混合（有的口含 pfc、有的不含）返回 invalid_input
并退出 4。工作量等于上限可成功，首次超过时 record 返回
record_work_limit、replay 返回 replay_work_limit，均退出 5 且不写日志、
不产生部分标准输出。

仅用标准库；端到端驱动 record / replay / qos-pfc-decode。
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
from test_qos_pfc_decode import BCAST  # noqa: E402
from test_qos_pfc_decode import MAC1  # noqa: E402
from test_qos_pfc_decode import advance  # noqa: E402
from test_qos_pfc_decode import config  # noqa: E402
from test_qos_pfc_decode import link  # noqa: E402
from test_qos_pfc_decode import pause_event  # noqa: E402
from test_qos_pfc_decode import pfc_event  # noqa: E402
from test_qos_pfc_decode import port  # noqa: E402
from test_qos_pfc_decode import qos  # noqa: E402
from test_qos_pfc_decode import raw_frame  # noqa: E402


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


def two_port(delay=10, queue=1000000, flow_control=True, q=None,
             pfc=(3,)):
    return config(
        q=q,
        ports=[
            port("p1", rates=[1000], modes=["full"], queue_bytes=queue,
                 flow_control=flow_control, pfc=pfc),
            port("p2", rates=[1000], modes=["full"], queue_bytes=queue,
                 flow_control=flow_control, pfc=pfc),
        ],
        delay=delay,
    )


def rich_events():
    return [
        link(0, "p1"),
        link(0, "p2"),
        raw_frame(100, "p2", prio=3),
        pfc_event(200, "p1", enable=(3,),
                  quanta8=[0, 0, 0, 10, 0, 0, 0, 0]),
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

    def test_empty_events_and_empty_pfc_lists(self):
        # 每口 pfc 为空数组（均含 pfc 键）仍按 qos-pfc-decode 路由
        cfg = two_port(pfc=())
        out, log_bytes = record_success(cfg, [])
        self.assertEqual(out, direct_stdout(cfg, []))
        doc = json.loads(log_bytes.decode())
        self.assertEqual([p["pfc"] for p in doc["config"]["ports"]], [[], []])
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
        # 每口配置均含 pfc；原始 data 事件逐字保留
        for pdoc in self.doc["config"]["ports"]:
            self.assertIn("flow_control", pdoc)
            self.assertIn("pfc", pdoc)
            self.assertEqual(pdoc["pfc"], [3])
        raw = [e for e in self.events if "data" in e]
        logged = [r["event"] for r in self.doc["records"] if "data" in r["event"]]
        self.assertEqual(logged, raw)

    def test_pfc_and_pause_outputs_preserved(self):
        flat = [item for r in self.doc["records"]
                for item in r["output"]]
        pfcs = [r for r in flat if r.get("action") == "pfc"]
        self.assertEqual(len(pfcs), 1)
        items = pfcs[0]["items"]
        self.assertEqual([it["priority"] for it in items], [3])
        self.assertEqual(items[0]["quanta"], 10)
        self.assertEqual(items[0]["until"], 200 + 10 * 512000 // 1000)
        pauses = [r for r in flat if r.get("action") == "pause"]
        self.assertEqual([r["quanta"] for r in pauses], [0])
        self.assertIsNone(pauses[0]["until"])

    def test_outputs_concatenate_to_direct_results(self):
        flat = [item for r in self.doc["records"]
                for item in r["output"]]
        direct = json.loads(direct_stdout(self.cfg, self.events).decode())
        self.assertEqual(flat, direct["results"])

    def test_frame_records_all_applied(self):
        for record in self.doc["records"]:
            if "data" in record["event"]:
                self.assertTrue(record["applied"])


class PfcRuntimeTests(unittest.TestCase):
    def test_pfc_unsupported_priority_is_recorded(self):
        # 入端口仅允许优先级 3；PFC 置位优先级 2 => pfc_unsupported
        cfg = two_port(pfc=(3,))
        events = [
            link(0, "p1"), link(0, "p2"),
            pfc_event(100, "p1", enable=(2,),
                      quanta8=[0, 0, 5, 0, 0, 0, 0, 0]),
        ]
        code, out, err, log_bytes, _ = record_log(cfg, events)
        self.assertEqual(code, 0, err)
        self.assertEqual(out, direct_stdout(cfg, events))
        doc = json.loads(log_bytes.decode())
        flat = [item for r in doc["records"] for item in r["output"]]
        self.assertTrue(
            any(r.get("action") == "pfc_unsupported" for r in flat)
        )
        result = json.loads(out.decode())
        self.assertEqual(result["ports"][0]["pfc_unsupported_frames"], 1)

    def test_malformed_pfc_is_runtime_result_applied(self):
        bad = pfc_event(100, "p1", enable=(3,),
                        quanta8=[0, 0, 0, 10, 0, 0, 0, 0],
                        tail=b"\x01" * 26)
        cfg = two_port()
        events = [link(0, "p1"), link(0, "p2"), bad]
        code, out, err, log_bytes, _ = record_log(cfg, events)
        self.assertEqual(code, 0, err)
        doc = json.loads(log_bytes.decode())
        rec = next(r for r in doc["records"] if "data" in r["event"])
        self.assertTrue(rec["applied"])
        self.assertEqual(rec["output"][0]["action"], "malformed_pfc")

    def test_pfc_gates_mapped_queue_in_outputs(self):
        # 优先级 3 经 map 入队列 3：PFC 后等待副本开始时刻不早于截止
        events = [
            link(0, "p1"), link(0, "p2"),
            raw_frame(100, "p1", prio=3),
            raw_frame(150, "p1", src="00:00:00:00:00:02", prio=3),
            pfc_event(200, "p2", enable=(3,),
                      quanta8=[0, 0, 0, 10, 0, 0, 0, 0]),
            advance(100000),
        ]
        cfg = two_port()
        out, _ = record_success(cfg, events)
        self.assertEqual(out, direct_stdout(cfg, events))
        result = json.loads(out.decode())
        tx = [r for r in result["results"]
              if "start" in r and "reason" not in r]
        self.assertEqual(tx[1]["start"], 200 + 10 * 512000 // 1000)


class ProcessingOrderTests(unittest.TestCase):
    def test_same_time_sorted_by_port_with_advance_last(self):
        cfg = two_port()
        events = [
            advance(0),
            pfc_event(0, "p2", enable=(3,),
                      quanta8=[0, 0, 0, 10, 0, 0, 0, 0]),
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
        cfg_pfc = two_port(delay=100)
        events = [
            link(0, "p1"),
            link(1, "p1"),                       # 幂等 link
            pfc_event(2, "p1", enable=(3,),
                      quanta8=[0, 0, 0, 10, 0, 0, 0, 0]),  # 帧不计 version
            advance(50),                         # advance 不计 version
        ]
        _, log_bytes = record_success(cfg_pfc, events)
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

    def test_tampered_pfc_quanta_fails(self):
        doc = json.loads(self.log_bytes.decode())
        pfc_rec = next(
            r for r in doc["records"]
            if any(o.get("action") == "pfc" for o in r["output"])
        )
        pfc_out = next(o for o in pfc_rec["output"]
                       if o.get("action") == "pfc")
        pfc_out["items"][0]["quanta"] = 11
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

    def test_tampered_pfc_config_fails(self):
        doc = json.loads(self.log_bytes.decode())
        doc["config"]["ports"][0]["pfc"] = [2]
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

    def test_mixed_pfc_shape_rejected(self):
        # 一口含 pfc、一口不含：混合形状，invalid_input
        p1 = port("p1")
        p2 = port("p2")
        del p2["pfc"]
        cfg = config(ports=[p1, p2])
        self._record_4(cfg, [link(0, "p1"), link(0, "p2")])

    def test_mixed_pfc_shape_log_rejected_on_replay(self):
        # 手工构造混合形状的自洽日志，replay 仍须在模式路由阶段报
        # invalid_input（且日志保持不动）
        p1 = port("p1")
        p2 = port("p2")
        del p2["pfc"]
        cfg = config(ports=[p1, p2])
        prefix_doc = {"schema": 1, "config": cfg, "records": []}
        prefix = (
            json.dumps(prefix_doc, ensure_ascii=False,
                       separators=(",", ":")) + "\n"
        ).encode("utf-8")
        doc = dict(prefix_doc)
        doc["sha256"] = hashlib.sha256(prefix).hexdigest()
        log_bytes = (
            json.dumps(
                {key: doc[key] for key in LOG_KEYS},
                ensure_ascii=False, separators=(",", ":"),
            ) + "\n"
        ).encode("utf-8")
        code, out, err, after = replay_log(log_bytes)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertEqual(after, log_bytes)

    def test_service_event_rejected(self):
        cfg = two_port()
        self._record_4(cfg, [link(0, "p1"),
                             {"t": 1, "port": "p2", "count": 1}])

    def test_bad_pfc_list_rejected(self):
        # pfc 含非递增/越界值：全量配置校验 invalid_input
        p1 = port("p1", pfc=(2, 2))
        p2 = port("p2", pfc=(2, 2))
        cfg = config(ports=[p1, p2])
        self._record_4(cfg, [])

    def test_all_ports_without_pfc_routes_wire_not_pfc(self):
        # 均不含 pfc：按 qos-wire-decode 路由，日志配置无 pfc 键
        p1 = port("p1")
        p2 = port("p2")
        del p1["pfc"]
        del p2["pfc"]
        cfg = config(ports=[p1, p2])
        events = [link(0, "p1"), link(0, "p2")]
        code, out, err, log_bytes, _ = record_log(cfg, events)
        self.assertEqual(code, 0, err)
        self.assertEqual(out, direct_stdout_wire(cfg, events))
        doc = json.loads(log_bytes.decode())
        for pdoc in doc["config"]["ports"]:
            self.assertNotIn("pfc", pdoc)


def direct_stdout_wire(cfg, events):
    tmp = tempfile.mkdtemp()
    cfg_path = os.path.join(tmp, "config.json")
    evt_path = os.path.join(tmp, "events.json")
    with open(cfg_path, "wb") as handle:
        handle.write(json.dumps(cfg).encode("utf-8"))
    with open(evt_path, "wb") as handle:
        handle.write(json.dumps(events).encode("utf-8"))
    code, out, err = run_keep(["qos-wire-decode", cfg_path, evt_path])
    assert code == 0, err
    return out


class WorkLimitTests(unittest.TestCase):
    HEAD = ("100000", "16777216", "1048576", "16777216", "16777216")

    def test_record_work_boundary(self):
        cfg = two_port()
        events = [link(0, "p1")]  # P=2, settle +1, link 结果 +1 => 4
        code, out, err, _, log_path = record_log(
            cfg, events, *self.HEAD, 4
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(out, direct_stdout(cfg, events))
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
