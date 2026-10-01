#!/usr/bin/env python3
"""record / replay 对 link-wire 物理链路仿真的支持回归。

record 对含 queue_bytes 的链路配置及 link、frame、advance 混合事件采用与
直接执行 link-wire 完全相同的全量校验、同一时刻排序、工作量计费与仿真
语义：成功 stdout 与直接 link-wire 逐字节一致，并以原子写产生可被 replay
接受的 schema 1 日志。日志按实际处理顺序（同一时刻按端口配置序、advance
最后）为每个输入事件保存一条记录；frame 恒 applied（坏帧、VLAN 准入、
碰撞、队列满丢弃亦然），link 仅目标链路状态实际改变时 applied，advance
仅实际完成至少一个到期协商或发送时 applied；output 为该事件开始时到期
结算结果后接事件自身结果的连续数组，各记录 output 依次拼接即直接结果
数组。末事件后不自动排空。

仅用标准库；端到端驱动 `python switch.py record/replay/link-wire ...`。
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
from test_link_wire import advance  # noqa: E402
from test_link_wire import config  # noqa: E402
from test_link_wire import frame  # noqa: E402
from test_link_wire import link  # noqa: E402
from test_link_wire import port  # noqa: E402

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


def direct_stdout(cfg, events):
    tmp, cfg_path, evt_path = write_inputs(cfg, events)
    code, out, err, _ = run(["link-wire", cfg_path, evt_path])
    assert code == 0, (code, err.decode())
    return out


def record_log(cfg, events, *limits, log_name="out.log"):
    """返回 (returncode, stdout, stderr, log_bytes_or_None)。"""
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


def rich_events():
    # up 两条全双工链路；good 广播入队；advance 完成发送；坏帧丢弃
    return [
        link(0, "p1"),
        link(0, "p2"),
        frame(10, "p1", MAC1, length=100),
        advance(970),
        frame(2000, "p1", MAC1, fcs=False),
        advance(5000),
    ]


class ByteIdenticalTests(unittest.TestCase):
    def test_record_stdout_matches_direct_link_wire(self):
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
        doc = json.loads(log_bytes.decode())
        self.assertEqual(doc["records"], [])
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
        self.assertEqual(
            self.doc["config"], json.loads(json.dumps(self.cfg))
        )
        for record in self.doc["records"]:
            self.assertEqual(list(record), RECORD_KEYS)
            self.assertTrue(canonical_key_order(record["event"]))

    def test_one_record_per_event_and_internal_digest(self):
        self.assertEqual(
            len(self.doc["records"]), len(self.events)
        )
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

    def test_output_is_always_a_list(self):
        for record in self.doc["records"]:
            self.assertIsInstance(record["output"], list)


class ProcessingOrderTests(unittest.TestCase):
    def test_same_time_sorted_by_port_with_advance_last(self):
        cfg = two_port()
        # 输入同刻乱序：p2 帧在 p2 链路之前、advance 在最前；处理序按
        # 端口配置序，同口同刻保原序：p1 link、p2 frame、p2 link、advance
        events = [
            advance(0),
            frame(0, "p2", MAC2, length=100),
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
        # 同口同刻保原序：p2 的帧（原序 1）先于 p2 链路（原序 2）
        kinds = []
        for r in doc["records"]:
            ev = r["event"]
            kinds.append(
                "advance" if "advance" in ev else
                "link" if "admin" in ev else "frame"
            )
        self.assertEqual(kinds, ["link", "frame", "link", "advance"])

    def test_outputs_concatenate_to_direct_results(self):
        cfg = two_port()
        events = [
            link(0, "p1"),
            link(0, "p2"),
            frame(10, "p1", MAC1, length=100),
            advance(970),
            advance(2000),
        ]
        rec_out, log_bytes = record_success(cfg, events)
        doc = json.loads(log_bytes.decode())
        flat = [item for r in doc["records"] for item in r["output"]]
        direct = json.loads(rec_out.decode())
        self.assertEqual(flat, direct["results"])

    def test_due_results_attribute_to_first_processed_event_only(self):
        # t=970 同时给 advance 与一条幂等 link 事件（输入里 advance 在前）：
        # 处理序 link 先、advance 后；到期的发送完成只归 link，advance 无
        # 新增结果、applied 为 false
        cfg = two_port()
        events = [
            link(0, "p1"),
            link(0, "p2"),
            frame(10, "p1", MAC1, length=100),
            advance(970),
            link(970, "p2"),
        ]
        _, log_bytes = record_success(cfg, events)
        records = json.loads(log_bytes.decode())["records"]
        link_rec = next(
            r for r in records
            if r["t"] == 970 and "admin" in r["event"]
        )
        adv_rec = next(
            r for r in records if r["t"] == 970 and "advance" in r["event"]
        )
        done = [o for o in link_rec["output"] if "start" in o]
        self.assertEqual(len(done), 1)
        self.assertEqual(done[0]["t"], 970)
        self.assertEqual(adv_rec["output"], [])
        self.assertFalse(adv_rec["applied"])

    def test_advance_applied_true_when_settles(self):
        cfg = two_port()
        events = [
            link(0, "p1"),
            link(0, "p2"),
            frame(10, "p1", MAC1, length=100),
            advance(970),
        ]
        _, log_bytes = record_success(cfg, events)
        records = json.loads(log_bytes.decode())["records"]
        adv = records[-1]
        self.assertTrue(adv["applied"])
        self.assertEqual(len(adv["output"]), 1)
        self.assertIn("start", adv["output"][0])

    def test_advance_applied_true_when_only_negotiation_due(self):
        # 协商到期本身不产生 results 记录，但 advance 完成它仍须 applied；
        # output 为空数组
        cfg = two_port(delay=10)
        events = [
            link(0, "p1"),
            advance(10),
            advance(11),
        ]
        rec_out, log_bytes = record_success(cfg, events)
        records = json.loads(log_bytes.decode())["records"]
        adv10, adv11 = records[-2], records[-1]
        self.assertTrue(adv10["applied"])
        self.assertEqual(adv10["output"], [])
        # 第二条 advance 无任何到期项：applied false
        self.assertFalse(adv11["applied"])
        self.assertEqual(adv11["output"], [])
        # 直接结果数组此时只有一条 wait 状态结果
        self.assertEqual(
            len(json.loads(rec_out.decode())["results"]), 1
        )


class AppliedAndVersionTests(unittest.TestCase):
    def test_frame_always_applied_even_when_dropped(self):
        cfg = config([
            port("p1", mode="trunk", pvid=2, allowed=[2], untagged=[],
                 rates=[10000], modes=["full"]),
        ], delay=1)
        events = [
            link(0, "p1"),
            frame(10, "p1", MAC1, fcs=False),                 # bad_fcs
            frame(11, "p1", MAC1, length=63),                # runt
            frame(12, "p1", MAC1, length=2000),               # giant
            frame(13, "p1", MAC1, alignment=False),           # alignment
            frame(14, "p1", MAC1, vlan=1),                    # VLAN 拒绝
        ]
        _, log_bytes = record_success(cfg, events)
        records = json.loads(log_bytes.decode())["records"]
        self.assertTrue(all(r["applied"] for r in records[1:]))
        # 每帧 output 恰含一条 drop 结果
        for rec in records[1:]:
            self.assertEqual(len(rec["output"]), 1)
            self.assertEqual(rec["output"][0]["action"], "drop")

    def test_link_applied_only_on_state_change(self):
        cfg = two_port(delay=100)
        events = [
            link(0, "p1"),
            link(1, "p1"),  # 目标未变：幂等
            link(2, "p1", admin=False),  # 立即 down：变化
        ]
        _, log_bytes = record_success(cfg, events)
        records = json.loads(log_bytes.decode())["records"]
        self.assertEqual(
            [r["applied"] for r in records], [True, False, True]
        )
        # 仅 applied 链路项增加 version；frame/advance 永不增加
        self.assertEqual(
            [r["version"] for r in records], [1, 1, 2]
        )

    def test_frame_and_advance_do_not_increment_version(self):
        cfg = two_port()
        events = [
            link(0, "p1"),
            link(0, "p2"),
            frame(10, "p1", MAC1, length=100),
            advance(970),
        ]
        _, log_bytes = record_success(cfg, events)
        records = json.loads(log_bytes.decode())["records"]
        self.assertEqual(
            [r["version"] for r in records], [1, 2, 2, 2]
        )

    def test_collision_frame_applied(self):
        cfg = config([
            port("p1", rates=[1000], modes=["half"]),
            port("p2", rates=[1000], modes=["half"]),
        ], delay=1)
        events = [
            link(0, "p1"),
            link(0, "p2"),
            frame(10, "p1", MAC1, length=1000),
            frame(11, "p2", MAC2, length=1000),  # 碰撞
        ]
        _, log_bytes = record_success(cfg, events)
        records = json.loads(log_bytes.decode())["records"]
        col_rec = records[-1]
        self.assertTrue(col_rec["applied"])
        self.assertEqual(col_rec["output"][0]["reason"], "collision")

    def test_queue_full_frame_applied(self):
        cfg = config([
            port("p1", rates=[10000], modes=["full"]),
            port("p2", rates=[10000], modes=["full"], queue_bytes=200),
        ], delay=1)
        events = [
            link(0, "p1"),
            link(0, "p2"),
            frame(10, "p1", MAC1, length=100),  # 120 入队
            frame(11, "p1", MAC1, length=100),  # 240>200 队列满
        ]
        _, log_bytes = record_success(cfg, events)
        records = json.loads(log_bytes.decode())["records"]
        qf_rec = records[-1]
        self.assertTrue(qf_rec["applied"])
        reasons = [
            o.get("reason")
            for o in qf_rec["output"]
            if o.get("reason") == "queue_full"
        ]
        self.assertEqual(reasons, ["queue_full"])

    def test_link_down_in_link_output_and_applied(self):
        cfg = two_port(delay=1)
        events = [
            link(0, "p1"),
            link(0, "p2"),
            frame(10, "p1", MAC1, length=1000),  # p2 发送持续 8160ns
            link(50, "p2", admin=False),          # 未完成副本 link_down
        ]
        rec_out, log_bytes = record_success(cfg, events)
        records = json.loads(log_bytes.decode())["records"]
        down_rec = records[-1]
        self.assertTrue(down_rec["applied"])
        # output：先一条 link_down 丢弃结果，再一条链路状态结果
        self.assertEqual(len(down_rec["output"]), 2)
        self.assertEqual(down_rec["output"][0]["reason"], "link_down")
        self.assertEqual(down_rec["output"][1]["state"], "down")
        self.assertNotIn("reason", down_rec["output"][1])
        # 与直接结果一致
        flat = [o for r in records for o in r["output"]]
        self.assertEqual(flat, json.loads(rec_out.decode())["results"])


class ReplayIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.cfg = two_port()
        self.events = rich_events()
        _, self.log_bytes = record_success(self.cfg, self.events)

    def _rehash_and_replay(self, doc):
        bad = rehash(doc)
        code, out, err, after = replay_log(bad)
        return code, out, err, after, bad

    def test_tampered_applied_fails(self):
        doc = json.loads(self.log_bytes.decode())
        doc["records"][0]["applied"] = not doc["records"][0]["applied"]
        code, out, err, after, bad = self._rehash_and_replay(doc)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertEqual(after, bad)

    def test_tampered_output_fails(self):
        doc = json.loads(self.log_bytes.decode())
        doc["records"][-1]["output"] = [{"bogus": True}]
        code, out, err, _, _ = self._rehash_and_replay(doc)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")

    def test_tampered_event_fails(self):
        doc = json.loads(self.log_bytes.decode())
        doc["records"][0]["event"]["port"] = "p2"
        code, out, err, _, _ = self._rehash_and_replay(doc)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")

    def test_tampered_version_fails(self):
        doc = json.loads(self.log_bytes.decode())
        doc["records"][0]["version"] += 1
        code, out, err, _, _ = self._rehash_and_replay(doc)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")

    def test_internal_digest_mismatch_fails(self):
        doc = json.loads(self.log_bytes.decode())
        doc["sha256"] = "0" * 64
        bad = (json.dumps(doc, separators=(",", ":")) + "\n").encode()
        code, out, err, after = replay_log(bad)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertIn(b"invalid_input", err)
        self.assertEqual(after, bad)

    def test_expect_sha_success_and_mismatch(self):
        commit = json.loads(self.log_bytes.decode())["sha256"]
        code, out, err, after = replay_log(
            self.log_bytes, "--expect-sha256", commit
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(after, self.log_bytes)
        code, out, err, _ = replay_log(
            self.log_bytes, "--expect-sha256", "0" * 64
        )
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertIn(b"invalid_input", err)

    def test_replay_rebuilds_byte_identical_log(self):
        # 成功重放不改写日志；内部重建逐字节一致由退出 0 保证
        code, _, err, after = replay_log(self.log_bytes)
        self.assertEqual(code, 0, err)
        self.assertEqual(after, self.log_bytes)


class ValidationTests(unittest.TestCase):
    def _record_4(self, cfg, events):
        code, out, err, _, _ = record_log(cfg, events)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')

    def test_bad_queue_bytes(self):
        good = port("p1")
        for bad_cfg in (
            config([dict(good, queue_bytes=-1)]),
            config([dict(good, queue_bytes="1")]),
        ):
            self._record_4(bad_cfg, [])

    def test_without_queue_bytes_is_link_forward_mode(self):
        # 去掉 queue_bytes 即合法 link-forward 配置：record 成功，记录里
        # 无 advance
        good = port("p1")
        lf_cfg = config(
            [{k: v for k, v in good.items() if k != "queue_bytes"}]
        )
        code, out, err, log_bytes, _ = record_log(
            lf_cfg, [link(0, "p1")]
        )
        self.assertEqual(code, 0, err)
        doc = json.loads(log_bytes.decode())
        self.assertEqual(len(doc["records"]), 1)
        self.assertNotIn("advance", doc["records"][0]["event"])

    def test_bad_advance_shape(self):
        cfg = two_port()
        self._record_4(cfg, [{"t": 0}])
        self._record_4(cfg, [{"t": 0, "advance": 1}])
        self._record_4(cfg, [{"t": 0, "advance": True, "x": 1}])
        self._record_4(cfg, [{"t": -1, "advance": True}])

    def test_advance_rejected_for_link_forward_config(self):
        # 无 queue_bytes 即 link-forward 配置：advance 事件非法
        cfg = {
            "age": 100,
            "max_frame": 1518,
            "delay": 5,
            "ports": [
                {"name": "p1", "mode": "access", "pvid": 1,
                 "allowed": [1], "untagged": [1],
                 "rates": [1000], "modes": ["full"]},
            ],
        }
        self._record_4(cfg, [{"t": 0, "advance": True}])

    def test_t_monotonic_with_advance(self):
        self._record_4(two_port(), [
            advance(10), frame(9, "p1", MAC1),
        ])

    def test_unknown_port_event(self):
        self._record_4(two_port(), [frame(0, "ghost", MAC1)])


class FileErrorTests(unittest.TestCase):
    def test_missing_inputs_exit3(self):
        tmp = tempfile.mkdtemp()
        missing = os.path.join(tmp, "nope.json")
        evt = os.path.join(tmp, "events.json")
        with open(evt, "wb") as handle:
            handle.write(b"[]")
        code, out, err, _ = run(
            ["record", missing, evt, os.path.join(tmp, "o.log")]
        )
        self.assertEqual(code, 3)
        self.assertEqual(out, b"")
        self.assertIn(b"file_not_found", err)

    def test_missing_replay_log_exit3(self):
        code, out, err, _ = run(["replay", os.path.join(tempfile.mkdtemp(),
                                                        "x.log")])
        self.assertEqual(code, 3)
        self.assertEqual(out, b"")
        self.assertIn(b"file_not_found", err)


class LimitTests(unittest.TestCase):
    HEAD = ("100000", "16777216", "1048576", "16777216", "16777216")

    def test_event_limit(self):
        cfg = two_port()
        events = [link(0, "p1"), link(1, "p2")]
        code, out, err, after, log_path = record_log(
            cfg, events, 1, *self.HEAD[1:]
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertIn(b"event_limit", err)
        self.assertFalse(os.path.exists(log_path))

    def test_log_limit_no_partial_write(self):
        cfg = two_port()
        events = rich_events()
        code, out, err, after, log_path = record_log(
            cfg, events, 100000, 10, *self.HEAD[2:]
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertIn(b"log_limit", err)
        self.assertFalse(os.path.exists(log_path))

    def test_output_limit(self):
        cfg = two_port()
        events = rich_events()
        code, out, err, _, log_path = record_log(
            cfg, events, 100000, 16777216, 1048576, 16777216, 10
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertIn(b"output_limit", err)
        self.assertFalse(os.path.exists(log_path))

    def test_record_work_limit_boundary(self):
        # P=2：首个 link 事件事件费 +1（W=3）、link 结果 +1（W=4）
        cfg = two_port()
        events = [link(0, "p1")]
        code, out, err, log_bytes, _ = record_log(
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

    def test_replay_work_limit(self):
        cfg = two_port()
        events = [link(0, "p1")]
        _, log_bytes = record_success(cfg, events)
        code, out, err, _ = replay_log(
            log_bytes, "100000", "16777216", "16777216", 3
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"replay_work_limit"}\n')
        code, out, err, after = replay_log(
            log_bytes, "100000", "16777216", "16777216", 4
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(after, log_bytes)


class StaticToolTests(unittest.TestCase):
    def test_summary_appends_advance_bucket_when_present(self):
        cfg = two_port()
        # 两帧串行发往 p2（结束 970、1930），两条 advance 各完成一次发送
        events = [
            link(0, "p1"),
            link(0, "p2"),
            frame(10, "p1", MAC1, length=100),
            frame(11, "p1", MAC1, length=100),
            advance(970),
            advance(1930),
        ]
        _, log_bytes = record_success(cfg, events)
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "in.log")
            with open(log_path, "wb") as handle:
                handle.write(log_bytes)
            proc = subprocess.run(
                [sys.executable, SWITCH, "log-summary", log_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        doc = json.loads(proc.stdout.decode())
        kinds = {item["kind"]: item for item in doc["kinds"]}
        self.assertIn("advance", kinds)
        self.assertEqual(
            (kinds["advance"]["total"], kinds["advance"]["applied"]),
            (2, 2),
        )
        self.assertEqual(kinds["link"]["total"], 2)
        self.assertEqual(kinds["frame"]["total"], 2)

    def test_summary_seven_buckets_without_advance_records(self):
        cfg = two_port()
        events = [link(0, "p1"), link(0, "p2")]
        _, log_bytes = record_success(cfg, events)
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "in.log")
            with open(log_path, "wb") as handle:
                handle.write(log_bytes)
            proc = subprocess.run(
                [sys.executable, SWITCH, "log-summary", log_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(
            [item["kind"] for item in
             json.loads(proc.stdout.decode())["kinds"]],
            ["learn", "frame", "link", "member", "service", "reload",
             "rollback"],
        )

    def test_query_kind_advance(self):
        cfg = two_port()
        events = [
            link(0, "p1"),
            advance(50),
            frame(100, "p1", MAC1, length=100),
            advance(200),
        ]
        _, log_bytes = record_success(cfg, events)
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "in.log")
            with open(log_path, "wb") as handle:
                handle.write(log_bytes)
            proc = subprocess.run(
                [sys.executable, SWITCH, "log-query", log_path,
                 "*", "*", "advance", "*", "*", "9"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        records = json.loads(proc.stdout.decode())["records"]
        self.assertEqual([r["t"] for r in records], [50, 200])
        self.assertTrue(
            all("advance" in r["event"] for r in records)
        )


if __name__ == "__main__":
    unittest.main()
