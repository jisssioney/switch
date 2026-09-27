#!/usr/bin/env python3
"""record / replay 对 storm-check 配置形状的回归。

端到端驱动：record CONFIG EVENTS LOG、replay LOG、storm-check CONFIG
EVENTS；校验 stdout 逐字节一致、LOG 契约、逐项记录（帧 applied=true、
output 为 t,class,action,ports 结果；链路仅 up 实际改变 applied、
output=null；version 初值 0，仅 applied 链路后加 1）与 forward-stp-storm
工作量（坏帧、准入拒绝、幂等链路均计费，等于上限合法）。仅用标准库。
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


def make_config(age=100, max_frame=1518):
    # B=2、L=1、P=3、delay=2、初始 U=1；p1 为跨桥链路口，p2/p3 边缘口
    return {
        "bridges": ["b1", "b2"],
        "links": [
            {"id": "L1", "x": ["b1", "p1"], "y": ["b2", "p1"],
             "cost": 1, "up": True},
        ],
        "delay": 2,
        "bridge": "b1",
        "ports": [
            make_port("p1", mode="trunk", allowed=[1, 2]),
            make_port("p2"),
            make_port("p3"),
        ],
        "age": age,
        "storm": {
            "window": 10,
            "limits": {"broadcast": 2, "multicast": 2, "unknown": 2},
            "move_limit": 2,
            "hold": 50,
        },
        "max_frame": max_frame,
    }


def check_frame(t, src, port="p2", dst=BCAST, vlan=None, length=100,
                fcs=True, alignment=True):
    return {
        "t": t,
        "port": port,
        "src": src,
        "dst": dst,
        "vlan": vlan,
        "length": length,
        "fcs": fcs,
        "alignment": alignment,
    }


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


def make_events():
    # t=0 链路幂等（初始即 up）；t=1 good 边缘广播（flood 入 p3，学习、
    # 占广播速率名额）；t=2 runt 坏帧；t=3 access 口带 vlan3（准入拒绝）；
    # t=4 链路实际断开（version 加 1）；t=5 good 边缘广播（p3 仍边缘
    # forwarding，flood，占第二个广播名额）；t=6 第三个广播被风暴抑制
    # drop；t=7 链路幂等断开
    return [
        link_event(0, "L1", True),
        check_frame(1, "00:00:00:00:00:01"),
        check_frame(2, "00:00:00:00:00:02", length=10),
        check_frame(3, "00:00:00:00:00:03", vlan=3),
        link_event(4, "L1", False),
        check_frame(5, "00:00:00:00:00:04"),
        check_frame(6, "00:00:00:00:00:05"),
        link_event(7, "L1", False),
    ]


class StormCheckRecordTest(unittest.TestCase):
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
        # record stdout 与直接执行 storm-check 入口逐字节一致
        code, direct, err = self._run("storm-check", self.cfg, self.evt)
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
        self.assertIsInstance(doc["sha256"], str)
        self.assertRegex(doc["sha256"], r"[0-9a-f]{64}")
        self.assertTrue(self.log_bytes.endswith(b"}\n"))
        self.assertFalse(self.log_bytes.endswith(b"\n\n"))
        self.assertEqual(doc["config"], self.config)
        self.assertTrue(canonical_key_order(doc["config"]))
        self.assertEqual(doc["sha256"], prefix_digest(doc)[0])
        # records 与事件等长、同序；项键序 t,version,event,applied,output
        records = doc["records"]
        self.assertEqual(len(records), len(self.events))
        for item in records:
            self.assertEqual(list(item), RECORD_KEYS)
            self.assertTrue(canonical_key_order(item["event"]))
        # 仅 t=4 链路实际断开 applied；五帧恒 applied，两条幂等链路不 applied
        self.assertEqual(
            [item["applied"] for item in records],
            [False, True, True, True, True, True, True, False],
        )
        # version 初值 0，仅 t=4 applied 链路项后加 1 并保持
        self.assertEqual(
            [item["version"] for item in records],
            [0, 0, 0, 0, 1, 1, 1, 1],
        )
        # 链路项：event 规范化为 {id,t,up}，output 恒 null
        link_indices = [0, 4, 7]
        for index, up in zip(link_indices, (True, False, False)):
            item = records[index]
            self.assertEqual(
                item["event"], {"id": "L1", "t": item["t"], "up": up}
            )
            self.assertEqual(list(item["event"]), ["id", "t", "up"])
            self.assertIsNone(item["output"])
        # 帧项：event 规范化，output 键序 t,class,action,ports
        for index in (1, 2, 3, 5, 6):
            item = records[index]
            self.assertEqual(
                list(item["event"]),
                ["alignment", "dst", "fcs", "length", "port", "src",
                 "t", "vlan"],
            )
            self.assertEqual(
                list(item["output"]), ["t", "class", "action", "ports"]
            )

    def test_frame_outputs_match_results(self):
        doc = json.loads(self.log_bytes.decode())
        direct = json.loads(self.record_out.decode())
        # 入口 results 仅含帧结果（链路项不产出），与帧记录一一对应
        frame_outputs = [
            item["output"]
            for item in doc["records"]
            if "port" in item["event"]
        ]
        self.assertEqual(frame_outputs, direct["results"])
        # t=1/5 good flood；t=2 runt drop；t=3 准入拒绝 good drop；
        # t=6 good 但广播超风暴速率被抑制 drop
        self.assertEqual(
            [(out["t"], out["class"], out["action"], len(out["ports"]))
             for out in direct["results"]],
            [(1, "good", "flood", 1), (2, "runt", "drop", 0),
             (3, "good", "drop", 0), (5, "good", "flood", 1),
             (6, "good", "drop", 0)],
        )
        # flood 出口为边缘口 p3，native VLAN 去标签（vlan=null）
        self.assertEqual(direct["results"][0]["ports"],
                         [{"name": "p3", "vlan": None}])

    def test_replay_rebuilds_byte_identical_log(self):
        code, out, err = self._replay()
        self.assertEqual(code, 0, err)
        self.assertEqual(out, self.record_out)
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)


class StormCheckBillingTest(unittest.TestCase):
    """forward-stp-storm 同口径：初始 B+L+2U=5；事件先取老化前
    K(FDB)/H(封锁)/Q(速率+迁移队列)：帧 K+H+Q+P+1；链路先应用 up，
    改变计 K+H+Q+B+L+2U+2P+1，幂等计 K+H+Q+1。

    B=2、L=1、P=3、初始 U=1，初始 work=5：
    t=0 幂等链路 K0 H0 Q0：+1                      累计 6
    t=1 good 广播（学习、占速率）K0 Q0：+4         累计 10
    t=2 runt 坏帧 K1 Q1：+6                        累计 16
    t=3 准入拒绝 K1 Q1：+6                         累计 22
    t=4 断开（changed,U=0）K1 Q1：1+1+2+1+0+6+1=12 累计 34
    t=5 good 广播（再学习、再占速率）K1 Q1：+6     累计 40
    t=6 第三广播被抑制（不计速率）K2 Q2：+8        累计 48
    t=7 幂等断开 K2 Q2：+5                         累计 53
    """

    TOTAL = 53

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
        # 等于上限合法，输出与 LOG 逐字节一致
        code, out, err = self._run(
            "record", self.cfg, self.evt, self.log, *head, str(self.TOTAL)
        )
        self.assertEqual((code, out, err), (0, self.record_out, b""))
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)
        # 首次超过即报 record_work_limit，stdout 空、绝不触碰 LOG
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
        self.assertEqual(out, b"")
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


class StormCheckFailureTest(unittest.TestCase):
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

    def test_bad_config_is_invalid_and_matches_entry(self):
        bad = dict(self.config)
        bad["max_frame"] = 1  # 越界
        with open(self.cfg, "wb") as handle:
            handle.write(json.dumps(bad).encode())
        code, _, err = self._run("storm-check", self.cfg, self.evt)
        self.assertEqual(code, 4, err)
        code, out, err = self._run("record", self.cfg, self.evt, self.log)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_bad_frame_is_invalid_and_matches_entry(self):
        # 非法 VLAN id：storm-check 入口与 record 均按非法输入拒绝
        events = [check_frame(0, "00:00:00:00:00:01", vlan=4096)]
        with open(self.evt, "wb") as handle:
            handle.write(json.dumps(events).encode())
        code, _, err = self._run("storm-check", self.cfg, self.evt)
        self.assertEqual(code, 4, err)
        code, out, err = self._run("record", self.cfg, self.evt, self.log)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_bad_link_event_is_invalid(self):
        events = [{"t": 0, "id": "NOPE", "up": True}]
        with open(self.evt, "wb") as handle:
            handle.write(json.dumps(events).encode())
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
        # 重放不改文件：篡改后的字节原样保留
        with open(self.log, "rb") as handle:
            tampered = handle.read()
        self.assertTrue(tampered)
        self.assertNotEqual(tampered, original)


if __name__ == "__main__":
    unittest.main()
