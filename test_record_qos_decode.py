#!/usr/bin/env python3
"""record / replay 对 qos-decode 配置形状的回归。

端到端驱动：record CONFIG EVENTS LOG、replay LOG、qos-decode CONFIG
EVENTS；校验 stdout 逐字节一致、LOG 契约、逐项记录（原始帧与 service
applied=true、output 为对应 results 项；链路/成员仅状态实际改变时
applied、output=null；version 初值 0，仅 applied 链路/成员后加 1）与
qos-check 工作量（坏帧、准入拒绝、幂等事件均计费，等于上限合法）。
仅用标准库。
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

from test_qos import base_config  # noqa: E402

LOG_KEYS = ["schema", "config", "records", "sha256"]
RECORD_KEYS = ["t", "version", "event", "applied", "output"]
BCAST = "ff:ff:ff:ff:ff:ff"


def make_config(max_frame=1518):
    # 同 test_record_qos_check：B=2、L=1（p3 跨桥）、P=6、M=2、R=1、U=1
    result = json.loads(json.dumps(base_config(weights=[1, 1, 1, 1])))
    result["bridges"] = ["b1", "b2"]
    result["links"] = [
        {"id": "L2", "x": ["b1", "p3"], "y": ["b2", "x"],
         "cost": 1, "up": True}
    ]
    result["max_frame"] = max_frame
    return result


def raw_frame(t, port, dst, src, vlan=None, priority=0, payload_len=46):
    d = bytes(int(x, 16) for x in dst.split(":"))
    s = bytes(int(x, 16) for x in src.split(":"))
    if vlan is None:
        head = d + s + b"\x08\x00"
    else:
        tci = (priority << 13) | vlan
        head = d + s + b"\x81\x00" + tci.to_bytes(2, "big") + b"\x08\x00"
    body = head + b"\x00" * payload_len
    fcs = (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little")
    return {"t": t, "port": port, "data": (body + fcs).hex()}


def link_event(t, lid, up):
    return {"t": t, "id": lid, "up": up}


def member_event(t, member, up):
    return {"t": t, "member": member, "up": up}


def service_event(t, port, count):
    return {"t": t, "port": port, "count": count}


def canonical_key_order(value):
    if isinstance(value, dict):
        keys = list(value)
        return keys == sorted(keys) and all(
            canonical_key_order(value[k]) for k in keys
        )
    if isinstance(value, list):
        return all(canonical_key_order(item) for item in value)
    return True


def prefix_digest(doc):
    prefix = {
        "schema": doc["schema"],
        "config": doc["config"],
        "records": doc["records"],
    }
    raw = (
        json.dumps(prefix, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest(), raw


def make_events():
    # t=0 链路幂等；t=2 good 广播；t=3 runt 坏帧；t=4 成员幂等 up；
    # t=5 成员实际下线；t=6 service；t=7 链路实际断开
    return [
        link_event(0, "L2", True),
        raw_frame(2, "p1", BCAST, "00:00:00:00:00:01"),
        raw_frame(3, "p1", BCAST, "00:00:00:00:00:02", payload_len=0),
        member_event(4, "p5", True),
        member_event(5, "p5", False),
        service_event(6, "p2", 1),
        link_event(7, "L2", False),
    ]


class QosDecodeRecordTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.cfg = os.path.join(d, "config.json")
        self.evt = os.path.join(d, "events.json")
        self.log = os.path.join(d, "out.log")
        self.config = make_config()
        self.events = make_events()
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

    def _replay(self, work="10000000"):
        return self._run(
            "replay", self.log, "100000", "16777216", "16777216", work
        )

    def test_record_matches_entry_and_replay_matches_record(self):
        # record stdout 与直接执行 qos-decode 入口逐字节一致
        code, direct, err = self._run("qos-decode", self.cfg, self.evt)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.record_out, direct)
        self.assertTrue(self.record_out.endswith(b"\n"))
        # replay stdout 与 record 逐字节一致，且不改 LOG
        code, out, err = self._replay()
        self.assertEqual((code, out, err), (0, self.record_out, b""))
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)

    def test_replay_with_expect_sha_matches(self):
        doc = json.loads(self.log_bytes.decode())
        code, out, err = self._run(
            "replay", self.log, "--expect-sha256", doc["sha256"]
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(out, self.record_out)

    def test_log_contract(self):
        doc = json.loads(self.log_bytes.decode())
        self.assertEqual(list(doc), LOG_KEYS)
        self.assertEqual(doc["schema"], 1)
        self.assertTrue(self.log_bytes.endswith(b"}\n"))
        self.assertFalse(self.log_bytes.endswith(b"\n\n"))
        self.assertEqual(doc["config"], self.config)
        self.assertTrue(canonical_key_order(doc["config"]))
        self.assertEqual(doc["sha256"], prefix_digest(doc)[0])
        records = doc["records"]
        self.assertEqual(len(records), len(self.events))
        for item in records:
            self.assertEqual(list(item), RECORD_KEYS)
            self.assertTrue(canonical_key_order(item["event"]))
        # 幂等链路/成员 applied=false；两帧、service、实际状态改变项 true
        self.assertEqual(
            [item["applied"] for item in records],
            [False, True, True, False, True, True, True],
        )
        # version 初值 0，仅 applied 成员（t=5）/链路（t=7）后加 1
        self.assertEqual(
            [item["version"] for item in records],
            [0, 0, 0, 0, 1, 1, 2],
        )
        # 链路项 output 恒 null
        for index in (0, 6):
            self.assertIsNone(records[index]["output"])
        # 帧项：event 规范化为 {data,port,t}，output 键序含 dropped/mirrors
        for frame, item in zip(self.events[1:3], records[1:3]):
            self.assertEqual(item["event"], {
                "data": frame["data"], "port": frame["port"], "t": frame["t"],
            })
            self.assertEqual(list(item["event"]), ["data", "port", "t"])
            self.assertEqual(
                list(item["output"]),
                ["t", "class", "action", "ports", "dropped", "mirrors"],
            )
        self.assertEqual(records[1]["output"]["action"], "flood")
        self.assertEqual(records[2]["output"]["class"], "runt")
        self.assertEqual(records[2]["output"]["ports"], [])
        # service 项键序 t,port,frames,mirrors；坏帧 fid1 不入队
        self.assertEqual(
            list(records[5]["event"]), ["count", "port", "t"]
        )
        self.assertEqual(
            list(records[5]["output"]),
            ["t", "port", "frames", "mirrors"],
        )
        self.assertEqual(records[5]["output"]["frames"], [0])

    def test_outputs_match_results(self):
        doc = json.loads(self.log_bytes.decode())
        direct = json.loads(self.record_out.decode())
        outputs = [
            item["output"]
            for item in doc["records"]
            if item["output"] is not None
        ]
        self.assertEqual(outputs, direct["results"])
        self.assertEqual(
            [(out["t"], out.get("class"), out.get("action"))
             for out in direct["results"]],
            [(2, "good", "flood"), (3, "runt", "drop"), (6, None, None)],
        )

    def test_replay_rebuilds_byte_identical_log(self):
        code, out, err = self._replay()
        self.assertEqual(code, 0, err)
        self.assertEqual(out, self.record_out)
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)


class QosDecodeBillingTest(unittest.TestCase):
    # 解码帧与 qos-check 事件序同形（未标记 priority=0、vlan=null、
    # alignment 恒真），工作量公式与逐事件累计完全同 qos-check：
    # 初始 B+L+2U=5，七事件后累计 81（同 test_record_qos_check）。
    TOTAL = 81

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.cfg = os.path.join(d, "config.json")
        self.evt = os.path.join(d, "events.json")
        self.log = os.path.join(d, "out.log")
        self.config = make_config()
        self.events = make_events()
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

    def test_record_work_boundary(self):
        head = ("100000", "16777216", "1048576", "16777216", "16777216")
        code, out, err = self._run(
            "record", self.cfg, self.evt, self.log, *head, str(self.TOTAL)
        )
        self.assertEqual((code, out, err), (0, self.record_out, b""))
        os.unlink(self.log)
        code, out, err = self._run(
            "record", self.cfg, self.evt, self.log, *head,
            str(self.TOTAL - 1),
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"record_work_limit"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_replay_work_boundary(self):
        code, out, err = self._run(
            "replay", self.log, "100000", "16777216", "16777216",
            str(self.TOTAL),
        )
        self.assertEqual((code, out, err), (0, self.record_out, b""))
        code, out, err = self._run(
            "replay", self.log, "100000", "16777216", "16777216",
            str(self.TOTAL - 1),
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"replay_work_limit"}\n')
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)

    def test_entry_work_boundary_matches_formula(self):
        # qos-decode 入口同一 qos-check 公式：等于上限合法，首次超过报
        # qos_work_limit/5、stdout 空
        limits = ("1000000", "1000000", "1000000", "1000000")
        code, out, err = self._run(
            "qos-decode", self.cfg, self.evt, *limits, str(self.TOTAL)
        )
        self.assertEqual(code, 0, err)
        code, out, err = self._run(
            "qos-decode", self.cfg, self.evt, *limits, str(self.TOTAL - 1)
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"qos_work_limit"}\n')


class QosDecodeFailureTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.cfg = os.path.join(d, "config.json")
        self.evt = os.path.join(d, "events.json")
        self.log = os.path.join(d, "out.log")
        self.config = make_config()
        with open(self.cfg, "wb") as handle:
            handle.write(json.dumps(self.config).encode())
        with open(self.evt, "wb") as handle:
            handle.write(json.dumps(make_events()).encode())

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, *args):
        proc = subprocess.run(
            [sys.executable, SWITCH, *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        return proc.returncode, proc.stdout, proc.stderr

    def _write_events(self, events):
        with open(self.evt, "wb") as handle:
            handle.write(json.dumps(events).encode())

    def test_bad_config_is_invalid_and_matches_entry(self):
        bad = dict(self.config)
        bad["max_frame"] = 1  # 越界
        with open(self.cfg, "wb") as handle:
            handle.write(json.dumps(bad).encode())
        code, _, err = self._run("qos-decode", self.cfg, self.evt)
        self.assertEqual(code, 4, err)
        code, out, err = self._run("record", self.cfg, self.evt, self.log)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_double_tag_frame_is_invalid(self):
        frame = raw_frame(2, "p1", BCAST, "00:00:00:00:00:01", vlan=1)
        raw = bytes.fromhex(frame["data"])
        frame["data"] = (raw[:16] + b"\x81\x00\x10\x00" + raw[16:]).hex()
        self._write_events([frame])
        code, _, err = self._run("qos-decode", self.cfg, self.evt)
        self.assertEqual(code, 4, err)
        code, out, err = self._run("record", self.cfg, self.evt, self.log)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_bad_member_event_is_invalid(self):
        self._write_events([member_event(0, "p1", True)])  # p1 非 LAG 成员
        code, out, err = self._run("record", self.cfg, self.evt, self.log)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_bad_link_event_is_invalid(self):
        self._write_events([link_event(0, "NOPE", True)])
        code, out, err = self._run("record", self.cfg, self.evt, self.log)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_mixed_frame_shapes_rejected(self):
        check_frame = {
            "t": 2, "port": "p1", "src": "00:00:00:00:00:09",
            "dst": BCAST, "vlan": None, "ethertype": 2048, "priority": 0,
            "length": 100, "fcs": True, "alignment": True,
        }
        self._write_events([
            raw_frame(2, "p1", BCAST, "00:00:00:00:00:01"),
            check_frame,
        ])
        code, out, err = self._run("record", self.cfg, self.evt, self.log)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_tampered_replay_invalid_and_untouched(self):
        code, _, err = self._run("record", self.cfg, self.evt, self.log)
        self.assertEqual(code, 0, err)
        with open(self.log, "rb") as handle:
            original = handle.read()
        doc = json.loads(original.decode())
        doc["records"][0]["applied"] = True  # 幂等链路被改为 applied
        doc["sha256"] = prefix_digest(doc)[0]
        with open(self.log, "wb") as handle:
            handle.write(
                (json.dumps(doc, ensure_ascii=False, separators=(",", ":"))
                 + "\n").encode("utf-8")
            )
        code, out, err = self._run("replay", self.log)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        with open(self.log, "rb") as handle:
            tampered = handle.read()
        self.assertTrue(tampered)
        self.assertNotEqual(tampered, original)


if __name__ == "__main__":
    unittest.main()
