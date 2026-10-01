#!/usr/bin/env python3
"""record / replay 对 link-wire 模式的回归：含 queue_bytes 的链路配置与
link/frame/advance 混合事件，全量校验、同刻排序、工作量计费与仿真语义
完全沿用直接 link-wire 入口；record stdout 与直接执行逐字节一致，LOG
可由 replay 接受且重放 stdout 一致、重建字节一致。

仅用标准库；端到端驱动 `python switch.py record ...` / `replay ...`。
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
import test_link_wire as lw  # noqa: E402
from test_record import LOG_KEYS, RECORD_KEYS, canonical_key_order  # noqa: E402
from test_record import prefix_digest, write_inputs  # noqa: E402


def config():
    # 两口 full、1000M、delay=10：线上 120 字节时长 960ns
    return lw.config(
        [
            lw.port("p1", rates=[1000], modes=["full"]),
            lw.port("p2", rates=[1000], modes=["full"]),
        ],
        delay=10,
    )


def events():
    # 输入序刻意打乱同刻顺序：
    # t=0 先给 p2 再给 p1（记录须按端口序 p1、p2）；
    # t=20 帧在 p1、幂等链路在 p2（帧先处理并取得 t=10 到期协商）。
    return [
        lw.link(0, "p2", rates=[1000], modes=["full"]),
        lw.link(0, "p1", rates=[1000], modes=["full"]),
        lw.advance(5),  # 协商截止 t=10、队列空：什么也不完成
        lw.frame(20, "p1", "00:00:00:00:00:01"),  # 泛洪到 p2，start=20
        lw.link(20, "p2", rates=[1000], modes=["full"]),  # 目标未变
        lw.advance(980),  # 完成 p2 上 end=980 的发送
    ]


# 记录处理顺序下的 (kind 标识, t, applied)
EXPECTED_ORDER = [
    ("link", 0, True),    # 输入 e1：p1
    ("link", 0, True),    # 输入 e0：p2
    ("advance", 5, False),
    ("frame", 20, True),
    ("link", 20, False),  # p2 目标未变
    ("advance", 980, True),
]
EXPECTED_VERSIONS = [1, 2, 2, 2, 2, 2]

# 工作量：W 初值 P=2；6 个输入事件各 +1；6 条 results（2 条 t=0 协商、
# 1 条帧转发、1 条入队、1 条 t=20 幂等链路、1 条 t=980 发送完成）各 +1；
# 无碰撞重排程。W = 2 + 6 + 6 = 14。
TOTAL = 14


def kind_of(event):
    return switch._event_kind(event)


class RecordLinkWireTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.cfg = os.path.join(d, "config.json")
        self.evt = os.path.join(d, "events.json")
        self.log = os.path.join(d, "out.log")
        self.config = config()
        self.events = events()
        with open(self.cfg, "wb") as handle:
            handle.write(json.dumps(self.config).encode())
        with open(self.evt, "wb") as handle:
            handle.write(json.dumps(self.events).encode())
        rec = subprocess.run(
            [sys.executable, SWITCH, "record", self.cfg, self.evt, self.log],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(rec.returncode, 0, rec.stderr)
        self.record_out = rec.stdout
        with open(self.log, "rb") as handle:
            self.log_bytes = handle.read()

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, *args):
        proc = subprocess.run(
            [sys.executable, SWITCH, *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        return proc.returncode, proc.stdout, proc.stderr

    def _replay(self, work="10000000", head=("100000", "16777216", "16777216"),
                expected=None):
        args = ["replay", self.log]
        if expected is not None:
            args += ["--expect-sha256", expected]
        args += [*head, str(work)]
        return self._run(*args)

    def test_work_constant_matches_formula(self):
        # 保护手算 TOTAL：正式校验后以独立空状态预演不超限
        (fwd_ports, caps, queues, age, max_frame, delay) = (
            switch.validate_link_wire_config(self.config)
        )
        lw_events = switch.validate_link_wire_events(self.events, fwd_ports)
        switch.link_wire_work(
            fwd_ports, caps, queues, age, max_frame, delay, lw_events, TOTAL
        )
        with self.assertRaises(switch.LinkWireWorkLimit):
            switch.link_wire_work(
                fwd_ports, caps, queues, age, max_frame, delay, lw_events,
                TOTAL - 1,
            )

    def test_record_matches_link_wire_and_replay_matches_record(self):
        # record stdout 与直接执行 link-wire 入口逐字节一致
        proc = subprocess.run(
            [sys.executable, SWITCH, "link-wire", self.cfg, self.evt],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.record_out, proc.stdout)
        # replay stdout 与 record 逐字节一致，且不改 LOG
        code, out, err = self._replay()
        self.assertEqual((code, out, err), (0, self.record_out, b""))
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)

    def test_external_sha256_commitment(self):
        digest = json.loads(self.log_bytes.decode())["sha256"]
        code, out, err = self._replay(expected=digest)
        self.assertEqual((code, out), (0, self.record_out))
        # 错误承诺：stdout 空、exit 4，LOG 不动
        wrong = "0" * 64
        code, out, err = self._replay(expected=wrong)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)

    def test_log_shape_and_canonical_order(self):
        doc = json.loads(self.log_bytes.decode())
        self.assertEqual(list(doc), LOG_KEYS)
        self.assertEqual(doc["schema"], 1)
        self.assertTrue(self.log_bytes.endswith(b"}" + b"\n"))
        self.assertFalse(self.log_bytes.endswith(b"\n\n"))
        self.assertEqual(doc["config"], json.loads(json.dumps(self.config)))
        self.assertTrue(canonical_key_order(doc["config"]))
        self.assertEqual(len(doc["records"]), len(self.events))
        for item in doc["records"]:
            self.assertEqual(list(item), RECORD_KEYS)
            self.assertTrue(canonical_key_order(item["event"]))
            self.assertIsInstance(item["output"], list)
        self.assertEqual(doc["sha256"], prefix_digest(doc)[0])

    def test_records_follow_processing_order(self):
        doc = json.loads(self.log_bytes.decode())
        records = doc["records"]
        # 同刻按端口配置序、advance 居末；同键保输入序
        self.assertEqual(
            [(kind_of(r["event"]), r["t"], r["applied"]) for r in records],
            EXPECTED_ORDER,
        )
        self.assertEqual([r["version"] for r in records], EXPECTED_VERSIONS)
        # 规范化事件保留：t=20 的帧在记录中位于 t=20 幂等链路之前
        self.assertEqual(records[3]["event"]["port"], "p1")
        self.assertEqual(records[4]["event"]["port"], "p2")

    def test_output_slices_are_contiguous_results(self):
        direct = json.loads(self.record_out.decode())["results"]
        doc = json.loads(self.log_bytes.decode())
        flattened = []
        for record in doc["records"]:
            flattened.extend(record["output"])
        # 每条 output 为直接 results 数组中的连续段，拼接即全部结果
        self.assertEqual(flattened, direct)
        records = doc["records"]
        # t=5 advance：无到期项 -> 空数组
        self.assertEqual(records[2]["output"], [])
        # t=20 帧的段以帧转发结果起、入队结果止（协商到期不产生记录）
        self.assertEqual(records[3]["output"], direct[2:4])
        self.assertEqual(records[3]["output"][0]["action"], "flood")
        self.assertEqual(records[3]["output"][1],
                         {"t": 20, "port": "p2", "vlan": None, "bytes": 120})
        # t=20 幂等链路仅自身结果；t=980 advance 取得到期发送完成
        self.assertEqual(
            records[4]["output"],
            [{"t": 20, "port": "p2", "state": "up", "rate": 1000,
              "mode": "full"}],
        )
        self.assertEqual(
            records[5]["output"],
            [{"t": 980, "port": "p2", "start": 20, "bytes": 120}],
        )

    def test_due_tx_before_advance_goes_to_first_processed_event(self):
        # 到期发送也可能被同刻的普通帧取得：构造 end=100 的发送，t=100
        # 的帧事件先于同刻 advance 处理，完成结果归该帧 output 段首
        cfg = lw.config(delay=1)
        evs = [
            lw.link(0, "p1", rates=[10000], modes=["full"]),
            lw.link(0, "p2", rates=[10000], modes=["full"]),
            lw.frame(10, "p1", "00:00:00:00:00:01", length=1000),  # end=826
            lw.frame(826, "p1", "00:00:00:00:00:03", length=64),
            lw.advance(826),
        ]
        files, _ = write_inputs(cfg, evs)
        with tempfile.TemporaryDirectory() as d:
            paths = {}
            for name, content in files.items():
                with open(os.path.join(d, name), "wb") as h:
                    h.write(content)
                paths[name] = os.path.join(d, name)
            logp = os.path.join(d, "x.log")
            rec = subprocess.run(
                [sys.executable, SWITCH, "record",
                 paths["config.json"], paths["events.json"], logp],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(rec.returncode, 0, rec.stderr)
            with open(logp, "rb") as handle:
                doc = json.loads(handle.read().decode())
            # 同刻 p1 帧（端口序 0）先于 advance；到期 tx 完成进入该帧段首，
            # 其后紧跟本帧自身的转发与入队结果
            frame_rec = next(
                r for r in doc["records"]
                if kind_of(r["event"]) == "frame" and r["t"] == 826
            )
            self.assertEqual(
                frame_rec["output"][0],
                {"t": 826, "port": "p2", "start": 10, "bytes": 1020},
            )
            self.assertEqual(len(frame_rec["output"]), 3)
            self.assertEqual(frame_rec["output"][1]["action"], "flood")
            self.assertEqual(frame_rec["output"][2]["bytes"], 84)
            # 同刻 advance 段为空（到期项已被帧取走）
            adv_rec = next(
                r for r in doc["records"]
                if kind_of(r["event"]) == "advance"
            )
            self.assertEqual(adv_rec["output"], [])
            self.assertFalse(adv_rec["applied"])

    def test_deterministic_identical_logs(self):
        # 相同输入多次记录产生完全相同的日志字节
        with tempfile.TemporaryDirectory() as d:
            logs = []
            for _ in range(2):
                logp = os.path.join(d, "x.log")
                if os.path.exists(logp):
                    os.unlink(logp)
                proc = subprocess.run(
                    [sys.executable, SWITCH, "record",
                     self.cfg, self.evt, logp],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                with open(logp, "rb") as handle:
                    logs.append(handle.read())
            self.assertEqual(logs[0], logs[1])
            self.assertEqual(logs[0], self.log_bytes)

    def test_record_work_limit_boundary(self):
        head = ("100000", "16777216", "1048576", "16777216", "16777216")
        # 等于上限合法且输出、LOG 逐字节一致
        code, out, err = self._run(
            "record", self.cfg, self.evt, self.log, *head, str(TOTAL)
        )
        self.assertEqual((code, out, err), (0, self.record_out, b""))
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)
        # 首次超过即报 record_work_limit，绝不触碰 LOG
        os.unlink(self.log)
        code, out, err = self._run(
            "record", self.cfg, self.evt, self.log, *head, str(TOTAL - 1)
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"record_work_limit"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_replay_work_limit_boundary(self):
        code, out, err = self._replay(TOTAL)
        self.assertEqual((code, out, err), (0, self.record_out, b""))
        code, out, err = self._replay(TOTAL - 1)
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"replay_work_limit"}\n')
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)

    def test_event_limit_does_not_touch_log(self):
        head = ("5", "16777216", "1048576", "16777216", "16777216", "10000000")
        os.unlink(self.log)
        code, out, err = self._run(
            "record", self.cfg, self.evt, self.log, *head
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"event_limit"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_log_limit_and_output_limit_preserve_file(self):
        original = self.log_bytes
        # 日志字节上界：超限时既有 LOG 不被部分覆盖
        code, out, err = self._run(
            "record", self.cfg, self.evt, self.log,
            "100000", "10", "1048576", "16777216", "16777216", "10000000",
        )
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"log_limit"}\n')
        self.assertEqual(out, b"")
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), original)
        # 输出字节上界
        code, out, err = self._run(
            "record", self.cfg, self.evt, self.log,
            "100000", "16777216", "1048576", "16777216", "10",
            "10000000",
        )
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"output_limit"}\n')
        self.assertEqual(out, b"")
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), original)

    def test_missing_files_exit3(self):
        code, out, err = self._run(
            "record", os.path.join(self.tmp.name, "nope.json"), self.evt,
            os.path.join(self.tmp.name, "o.log"),
        )
        self.assertEqual((code, out), (3, b""))
        self.assertIn(b"file_not_found", err)
        code, out, err = self._run(
            "replay", os.path.join(self.tmp.name, "nope.log")
        )
        self.assertEqual((code, out), (3, b""))
        self.assertIn(b"file_not_found", err)

    # ---- 非法输入：配置 / 事件 / 日志 ----

    def _record_expect4(self, cfg, evs):
        with tempfile.TemporaryDirectory() as d:
            cp = os.path.join(d, "c.json")
            ep = os.path.join(d, "e.json")
            lp = os.path.join(d, "o.log")
            with open(cp, "wb") as handle:
                handle.write(json.dumps(cfg).encode())
            with open(ep, "wb") as handle:
                handle.write(json.dumps(evs).encode())
            proc = subprocess.run(
                [sys.executable, SWITCH, "record", cp, ep, lp],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(proc.returncode, 4)
            self.assertEqual(proc.stdout, b"")
            self.assertIn(b"invalid_input", proc.stderr)
            self.assertFalse(os.path.exists(lp))

    def test_bad_queue_bytes_is_invalid(self):
        bad = json.loads(json.dumps(config()))
        bad["ports"][0]["queue_bytes"] = -1
        self._record_expect4(bad, events())
        missing = json.loads(json.dumps(config()))
        del missing["ports"][0]["queue_bytes"]
        self._record_expect4(missing, events())  # 缺键按 link-forward 路由，帧外 advance 非法

    def test_bad_advance_event_is_invalid(self):
        self._record_expect4(config(), [{"t": 0, "advance": 1}])
        self._record_expect4(
            config(), [lw.advance(10), lw.frame(9, "p1", "00:00:00:00:00:01")]
        )

    def test_tampered_log_is_invalid_and_untouched(self):
        for mutate in ("applied", "output", "event", "records_order"):
            doc = json.loads(self.log_bytes.decode())
            if mutate == "applied":
                doc["records"][0]["applied"] = False
            elif mutate == "output":
                doc["records"][3]["output"] = []
            elif mutate == "event":
                doc["records"][3]["event"]["length"] = 64
            else:
                doc["records"].reverse()
            doc["sha256"] = prefix_digest(doc)[0]  # 内部摘要自洽但语义不符
            with open(self.log, "wb") as handle:
                handle.write(
                    (json.dumps(doc, ensure_ascii=False,
                                separators=(",", ":")) + "\n").encode()
                )
            code, out, err = self._replay()
            self.assertEqual(code, 4, mutate)
            self.assertEqual(out, b"", mutate)
            self.assertEqual(err, b'{"error":"invalid_input"}\n', mutate)
            # 还原供下一次变异
            with open(self.log, "wb") as handle:
                handle.write(self.log_bytes)

    def test_bad_internal_digest_is_invalid(self):
        raw = bytearray(self.log_bytes)
        # 破坏 sha 字段一个十六进制字符（保持 64 位长度）
        i = raw.rfind(b'"sha256":"')
        pos = i + len(b'"sha256":"')
        raw[pos] = ord("a") if chr(raw[pos]) != "a" else ord("b")
        with open(self.log, "wb") as handle:
            handle.write(bytes(raw))
        code, out, err = self._replay()
        self.assertEqual((code, out), (4, b""))
        self.assertIn(b"invalid_input", err)

    # ---- 其他日志工具与新模式的边界 ----

    def test_log_filter_works_but_summary_rejects_advance(self):
        # log-filter 纯静态、按 t/applied 过滤，接受 link-wire 日志
        code, out, err = self._run(
            "log-filter", self.log, "*", "*", "*"
        )
        self.assertEqual(code, 0, err)
        kept = json.loads(out.decode())["records"]
        self.assertEqual(len(kept), len(self.events))
        # log-summary 的固定 kinds 词表不含 advance：invalid_input/4，
        # 既有七类日志的 summary 字节不受影响
        code, out, err = self._run("log-summary", self.log)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertIn(b"invalid_input", err)


class AppliedSemanticsTest(unittest.TestCase):
    """frame 恒 applied（坏帧/队列满/碰撞丢弃亦然），advance 语义。"""

    def _record(self, cfg, evs):
        files, _ = write_inputs(cfg, evs)
        with tempfile.TemporaryDirectory() as d:
            paths = {}
            for name, content in files.items():
                with open(os.path.join(d, name), "wb") as h:
                    h.write(content)
                paths[name] = os.path.join(d, name)
            logp = os.path.join(d, "o.log")
            proc = subprocess.run(
                [sys.executable, SWITCH, "record",
                 paths["config.json"], paths["events.json"], logp],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            with open(logp, "rb") as handle:
                records = json.loads(handle.read().decode())["records"]
            return proc.stdout, records

    def test_dropped_frames_still_applied_and_no_auto_drain(self):
        cfg = lw.config([
            lw.port("p1", rates=[10000], modes=["full"]),
            lw.port("p2", rates=[10000], modes=["full"], queue_bytes=200),
        ], delay=1)
        evs = [
            lw.link(0, "p1"), lw.link(0, "p2"),
            lw.frame(10, "p1", "00:00:00:00:00:01", fcs=False),  # 坏帧
            lw.frame(11, "p1", "00:00:00:00:00:01", length=100),  # 入队 120
            lw.frame(12, "p1", "00:00:00:00:00:01", length=100),  # 队列满
        ]
        out, records = self._record(cfg, evs)
        self.assertTrue(all(r["applied"] for r in records
                            if kind_of(r["event"]) == "frame"))
        # 末事件后不自动排空：无发送完成结果（未完成副本不写入日志）
        direct = json.loads(out.decode())["results"]
        self.assertFalse(any("start" in r and "reason" not in r
                             for r in direct))
        # 队列满记录在对应帧段内
        self.assertTrue(
            any(r.get("reason") == "queue_full" for r in records[-1]["output"])
        )

    def test_collision_frame_applied(self):
        cfg = lw.config([
            lw.port("p1", rates=[1000], modes=["half"]),
            lw.port("p2", rates=[1000], modes=["half"]),
        ], delay=1)
        evs = [
            lw.link(0, "p1"), lw.link(0, "p2"),
            lw.frame(10, "p1", "00:00:00:00:00:01", length=1000),
            lw.frame(11, "p2", "00:00:00:00:00:02", length=1000),
        ]
        out, records = self._record(cfg, evs)
        frames = [r for r in records if kind_of(r["event"]) == "frame"]
        self.assertTrue(all(r["applied"] for r in frames))
        self.assertTrue(
            any(r.get("reason") == "collision"
                for r in frames[-1]["output"])
        )

    def test_advance_without_pending_work_is_not_applied(self):
        cfg = lw.config(delay=1)
        evs = [
            lw.link(0, "p1", admin=False),
            lw.advance(100),
        ]
        _, records = self._record(cfg, evs)
        adv = next(r for r in records if kind_of(r["event"]) == "advance")
        self.assertFalse(adv["applied"])
        self.assertEqual(adv["output"], [])

    def test_advance_completing_only_negotiation_is_applied_empty_output(self):
        # 协商完成本身不产生 results 项：advance applied 为真但 output 为空；
        # 同刻随后的第二个 advance 不再完成任何项
        cfg = lw.config(delay=10)
        evs = [
            lw.link(0, "p1", rates=[1000], modes=["full"]),
            lw.advance(10),
            lw.advance(10),
        ]
        _, records = self._record(cfg, evs)
        advs = [r for r in records if kind_of(r["event"]) == "advance"]
        self.assertEqual([r["applied"] for r in advs], [True, False])
        self.assertEqual([r["output"] for r in advs], [[], []])


if __name__ == "__main__":
    unittest.main()
