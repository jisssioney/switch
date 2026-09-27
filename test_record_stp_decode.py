#!/usr/bin/env python3
"""record / replay 对 stp-decode 配置形状的回归。

端到端驱动：record CONFIG EVENTS LOG、replay LOG、stp-decode CONFIG
EVENTS；校验 stdout 逐字节一致、LOG 契约、逐项记录（帧恒 applied 且
output 为 t,class,action,ports 结果；链路仅 up 改变才 applied 且
output=null；version 仅 applied 链路后加 1）与 forward-stp 工作量公式
（坏帧、准入拒绝、幂等链路均计费）。仅用标准库。
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

LOG_KEYS = ["schema", "config", "records", "sha256"]
RECORD_KEYS = ["t", "version", "event", "applied", "output"]
BCAST = "ff:ff:ff:ff:ff:ff"


def make_port(name, mode="access", pvid=1, allowed=None, untagged=None,
              up=True):
    if allowed is None:
        allowed = [pvid]
    if untagged is None:
        untagged = [] if mode == "trunk" else [pvid]
    return {
        "name": name,
        "mode": mode,
        "pvid": pvid,
        "allowed": allowed,
        "untagged": untagged,
        "up": up,
    }


def make_config(ports=None, age=100, max_frame=1518):
    if ports is None:
        ports = [
            make_port("p1", mode="trunk", allowed=[1, 2]),
            make_port("p2", mode="trunk", allowed=[1, 2]),
            make_port("p3"),
        ]
    return {
        "bridges": ["b1", "b2"],
        "links": [
            {"id": "L1", "x": ["b1", "p1"], "y": ["b2", "p1"],
             "cost": 1, "up": True},
            {"id": "L2", "x": ["b1", "p2"], "y": ["b2", "p2"],
             "cost": 1, "up": True},
        ],
        "delay": 2,
        "bridge": "b1",
        "ports": ports,
        "age": age,
        "max_frame": max_frame,
    }


def raw_frame(t, port, dst, src, vlan=None, payload_len=46):
    """构造单层 802.1Q 原始帧（默认 good：长度>=64、FCS 正确、无标签/单标签）。"""
    d = bytes(int(x, 16) for x in dst.split(":"))
    s = bytes(int(x, 16) for x in src.split(":"))
    if vlan is None:
        head = d + s + b"\x08\x00"
    else:
        head = d + s + b"\x81\x00" + vlan.to_bytes(2, "big") + b"\x08\x00"
    body = head + b"\x00" * payload_len
    fcs = (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little")
    return {"t": t, "port": port, "data": (body + fcs).hex()}


def link_event(t, lid, up):
    return {"t": t, "id": lid, "up": up}


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


class StpDecodeRecordTest(unittest.TestCase):
    # B=2、L=2、P=3、初始 U=2：初始收敛 B+L+2U=8。
    # t0 幂等链路（U=2,E=0）：+0*4+2+2+4+6+1=15            -> 23
    # t1 good 帧（E=0）：+0+3+1=4，E=1                     -> 27
    # t2 runt 帧（E=1）：+1+4=5，E=2                       -> 32
    # t3 L1 down 实际改变（U=1,E=2）：+2*4+2+2+2+6+1=21    -> 53
    # t4 good 帧（E=2）：+2+4=6，E=3                       -> 59
    # t5 L1 up 实际改变（U=2,E=3）：+3*4+2+2+4+6+1=27      -> 86
    # t6 L2 up 幂等（U=2,E=3）：+27                        -> 113
    # t7 准入拒绝帧（E=3）：+3+4=7，E=4                    -> 120
    TOTAL = 120

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.cfg = os.path.join(d, "config.json")
        self.evt = os.path.join(d, "events.json")
        self.log = os.path.join(d, "out.log")
        self.config = make_config()
        self.events = [
            link_event(0, "L1", True),    # 初始即 up：幂等
            raw_frame(1, "p3", BCAST, "00:00:00:00:00:01"),
            raw_frame(2, "p3", BCAST, "00:00:00:00:00:09", payload_len=0),
            link_event(3, "L1", False),   # 实际改变
            raw_frame(4, "p3", BCAST, "00:00:00:00:00:02"),
            link_event(5, "L1", True),    # 实际改变
            link_event(6, "L2", True),    # 幂等
            # access p3 收 vlan2 单标签：VLAN 准入拒绝（good/drop）
            raw_frame(7, "p3", BCAST, "00:00:00:00:00:03", vlan=2),
        ]
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
        # record stdout 与直接执行 stp-decode 入口逐字节一致
        code, direct, err = self._run("stp-decode", self.cfg, self.evt)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.record_out, direct)
        self.assertTrue(self.record_out.endswith(b"\n"))
        # replay stdout 与 record 逐字节一致，且不改 LOG
        code, out, err = self._replay()
        self.assertEqual((code, out, err), (0, self.record_out, b""))
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)

    def test_log_contract(self):
        doc = json.loads(self.log_bytes.decode())
        self.assertEqual(list(doc), LOG_KEYS)
        self.assertEqual(doc["schema"], 1)
        self.assertTrue(self.log_bytes.endswith(b"}\n"))
        self.assertFalse(self.log_bytes.endswith(b"\n\n"))
        self.assertEqual(doc["config"], self.config)
        self.assertTrue(canonical_key_order(doc["config"]))
        self.assertEqual(doc["sha256"], prefix_digest(doc)[0])
        # records 与事件等长、同序；项键序 t,version,event,applied,output
        self.assertEqual(len(doc["records"]), len(self.events))
        for event, item in zip(self.events, doc["records"]):
            self.assertEqual(list(item), RECORD_KEYS)
            self.assertEqual(item["t"], event["t"])
            # event 为规范化原事件（键按码点升序）
            self.assertEqual(item["event"], dict(sorted(event.items())))
            self.assertEqual(list(item["event"]), sorted(event))
        # 链路项：仅 up 实际改变才 applied、output 恒 null
        link_records = [
            (i, item) for i, item in enumerate(doc["records"])
            if set(item["event"]) == {"id", "t", "up"}
        ]
        self.assertEqual(
            [item["applied"] for _, item in link_records],
            [False, True, True, False],
        )
        self.assertTrue(
            all(item["output"] is None for _, item in link_records)
        )
        # 帧项：恒 applied，output 为对应结果项（键序 t,class,action,ports）
        frame_records = [
            item for item in doc["records"]
            if set(item["event"]) == {"data", "port", "t"}
        ]
        self.assertEqual(len(frame_records), 4)
        self.assertTrue(all(item["applied"] for item in frame_records))
        for item in frame_records:
            self.assertEqual(
                list(item["output"]), ["t", "class", "action", "ports"]
            )
        self.assertEqual(
            [item["output"]["class"] for item in frame_records],
            ["good", "runt", "good", "good"],
        )
        direct = json.loads(self.record_out.decode())
        self.assertEqual(
            [item["output"] for item in frame_records], direct["results"]
        )

    def test_version_bumps_only_on_applied_links(self):
        doc = json.loads(self.log_bytes.decode())
        records = doc["records"]
        self.assertEqual(
            [item["applied"] for item in records],
            [False, True, True, True, True, True, False, True],
        )
        # version 初值 0，仅 applied 链路项后加 1 并记录事件后值；
        # 帧项（恒 applied）不加
        self.assertEqual(
            [item["version"] for item in records],
            [0, 0, 0, 1, 1, 2, 2, 2],
        )

    def test_replay_rebuilds_byte_identical_log(self):
        # 重放成功不重写文件；重建的 LOG 须与原文件逐字节一致（内部契约）
        code, out, err = self._replay()
        self.assertEqual(code, 0, err)
        self.assertEqual(out, self.record_out)
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)


class StpDecodeWorkBoundaryTest(unittest.TestCase):
    TOTAL = StpDecodeRecordTest.TOTAL

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.cfg = os.path.join(d, "config.json")
        self.evt = os.path.join(d, "events.json")
        self.log = os.path.join(d, "out.log")
        self.config = make_config()
        events = [
            link_event(0, "L1", True),
            raw_frame(1, "p3", BCAST, "00:00:00:00:00:01"),
            raw_frame(2, "p3", BCAST, "00:00:00:00:00:09", payload_len=0),
            link_event(3, "L1", False),
            raw_frame(4, "p3", BCAST, "00:00:00:00:00:02"),
            link_event(5, "L1", True),
            link_event(6, "L2", True),
            raw_frame(7, "p3", BCAST, "00:00:00:00:00:03", vlan=2),
        ]
        with open(self.cfg, "wb") as handle:
            handle.write(json.dumps(self.config).encode())
        with open(self.evt, "wb") as handle:
            handle.write(json.dumps(events).encode())
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
        # 等于上限合法，输出与 LOG 逐字节一致
        code, out, err = self._run(
            "record", self.cfg, self.evt, self.log, *head, str(self.TOTAL)
        )
        self.assertEqual((code, out, err), (0, self.record_out, b""))
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)
        # 首次超过即报 record_work_limit，绝不触碰 LOG
        os.unlink(self.log)
        code, out, err = self._run(
            "record", self.cfg, self.evt, self.log, *head,
            str(self.TOTAL - 1),
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"record_work_limit"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_record_over_limit_keeps_existing_log(self):
        head = ("100000", "16777216", "1048576", "16777216", "16777216")
        code, out, err = self._run(
            "record", self.cfg, self.evt, self.log, *head,
            str(self.TOTAL - 1),
        )
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"record_work_limit"}\n')
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)

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

    def test_empty_events_initial_converge_boundary(self):
        # 无事件时仍计初始收敛 B+L+2U=8：等于合法、超过报错
        d = self.tmp.name
        cfg = os.path.join(d, "empty.json")
        evt = os.path.join(d, "empty_events.json")
        log = os.path.join(d, "empty.log")
        with open(cfg, "wb") as handle:
            handle.write(json.dumps(self.config).encode())
        with open(evt, "wb") as handle:
            handle.write(b"[]")
        head = ("100000", "16777216", "1048576", "16777216", "16777216")
        code, rec_out, err = self._run(
            "record", cfg, evt, log, *head, "8"
        )
        self.assertEqual(code, 0, err)
        code, out, err = self._run(
            "replay", log, "100000", "16777216", "16777216", "8"
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(out, rec_out)
        doc = json.loads(rec_out.decode())
        self.assertEqual(doc["results"], [])
        code, out, err = self._run(
            "record", cfg, evt, os.path.join(d, "x.log"), *head, "7"
        )
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"record_work_limit"}\n')


class StpDecodeFailureTest(unittest.TestCase):
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
            handle.write(json.dumps(
                [raw_frame(0, "p3", BCAST, "00:00:00:00:00:01")]
            ).encode())

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, *args):
        proc = subprocess.run(
            [sys.executable, SWITCH, *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        return proc.returncode, proc.stdout, proc.stderr

    def test_bad_config_is_invalid_and_matches_entry(self):
        bad = dict(self.config)
        bad["max_frame"] = 1  # 越界
        with open(self.cfg, "wb") as handle:
            handle.write(json.dumps(bad).encode())
        code, _, err = self._run("stp-decode", self.cfg, self.evt)
        self.assertEqual(code, 4)
        code, out, err = self._run("record", self.cfg, self.evt, self.log)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_bad_frame_is_invalid_and_matches_entry(self):
        # 双标签帧：stp-decode 入口与 record 均按非法输入拒绝
        double = raw_frame(0, "p3", BCAST, "00:00:00:00:00:01", vlan=1)
        raw = bytes.fromhex(double["data"])
        double["data"] = (
            raw[:16] + b"\x81\x00\x10\x00" + raw[16:]
        ).hex()
        with open(self.evt, "wb") as handle:
            handle.write(json.dumps([double]).encode())
        code, _, _ = self._run("stp-decode", self.cfg, self.evt)
        self.assertEqual(code, 4)
        code, out, err = self._run("record", self.cfg, self.evt, self.log)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_zero_dst_is_invalid(self):
        with open(self.evt, "wb") as handle:
            handle.write(json.dumps(
                [raw_frame(0, "p3", "00:00:00:00:00:00",
                           "00:00:00:00:00:01")]
            ).encode())
        code, out, err = self._run("record", self.cfg, self.evt, self.log)
        self.assertEqual(code, 4)
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_tampered_replay_invalid_and_untouched(self):
        code, _, err = self._run("record", self.cfg, self.evt, self.log)
        self.assertEqual(code, 0, err)
        with open(self.log, "rb") as handle:
            original = handle.read()
        doc = json.loads(original.decode())
        doc["records"][0]["applied"] = False  # 帧恒 applied：语义不符
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
            self.assertTrue(handle.read())  # 重放不改文件


if __name__ == "__main__":
    unittest.main()
