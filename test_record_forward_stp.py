#!/usr/bin/env python3
"""record / replay 对 forward-stp 配置形状的回归。

端到端驱动：record CONFIG EVENTS LOG、replay LOG、forward-stp CONFIG
EVENTS；校验 stdout 逐字节一致、LOG 契约、逐项记录（帧 applied=true、
output 为 t,action,ports 结果；链路仅 up 实际改变 applied、output=null；
version 仅 applied 链路后加 1）与 forward-stp 工作量（准入拒绝、幂等
链路均计费，等于上限合法）。仅用标准库。
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


def make_config(age=100):
    # B=2、L=1、P=3、delay=2、初始 U=1
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
    }


def link_event(t, lid, up):
    return {"t": t, "id": lid, "up": up}


def frame_event(t, port, src, dst=BCAST, vlan=None):
    return {"t": t, "port": port, "src": src, "dst": dst, "vlan": vlan}


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
    # t=0 链路幂等（初始即 up）；t=1 good 广播；t=2 access 口带 vlan3
    # （准入拒绝）；t=4 链路实际断开
    return [
        link_event(0, "L1", True),
        frame_event(1, "p2", "00:00:00:00:00:01"),
        frame_event(2, "p2", "00:00:00:00:00:08", vlan=3),
        link_event(4, "L1", False),
    ]


class ForwardStpRecordTest(unittest.TestCase):
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
        # record stdout 与直接执行 forward-stp 入口逐字节一致
        code, direct, err = self._run("forward-stp", self.cfg, self.evt)
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
        records = doc["records"]
        self.assertEqual(len(records), len(self.events))
        for item in records:
            self.assertEqual(list(item), RECORD_KEYS)
            self.assertTrue(canonical_key_order(item["event"]))
        # 仅 t=4 链路实际断开 applied；两帧恒 applied
        self.assertEqual(
            [item["applied"] for item in records],
            [False, True, True, True],
        )
        # version 初值 0，仅 applied 链路项后加 1 并记事件后值
        self.assertEqual(
            [item["version"] for item in records], [0, 0, 0, 1]
        )
        # 链路项：event 规范化为 {id,t,up}，output 恒 null
        link_records = [records[0], records[3]]
        self.assertEqual(
            link_records[0]["event"],
            {"id": "L1", "t": 0, "up": True},
        )
        self.assertEqual(
            list(link_records[0]["event"]), ["id", "t", "up"]
        )
        self.assertIsNone(link_records[0]["output"])
        self.assertEqual(
            link_records[1]["event"],
            {"id": "L1", "t": 4, "up": False},
        )
        self.assertIsNone(link_records[1]["output"])
        # 帧项：event 规范化为 {dst,port,src,t,vlan}，output 键序
        # t,action,ports
        for frame, item in zip(self.events[1:3], records[1:3]):
            self.assertEqual(item["event"], {
                "dst": frame["dst"], "port": frame["port"],
                "src": frame["src"], "t": frame["t"],
                "vlan": frame["vlan"],
            })
            self.assertEqual(
                list(item["event"]), ["dst", "port", "src", "t", "vlan"]
            )
            self.assertEqual(list(item["output"]), ["t", "action", "ports"])

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
        # t=1 广播 flood 至 p3；t=2 准入拒绝 drop
        self.assertEqual(
            [(out["t"], out["action"]) for out in direct["results"]],
            [(1, "flood"), (2, "drop")],
        )

    def test_replay_rebuilds_byte_identical_log(self):
        code, out, err = self._replay()
        self.assertEqual(code, 0, err)
        self.assertEqual(out, self.record_out)
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)

    def test_empty_events(self):
        d = self.tmp.name
        cfg = os.path.join(d, "empty_cfg.json")
        evt = os.path.join(d, "empty_events.json")
        log = os.path.join(d, "empty.log")
        with open(cfg, "wb") as handle:
            handle.write(json.dumps(self.config).encode())
        with open(evt, "wb") as handle:
            handle.write(b"[]")
        code, direct, err = self._run("forward-stp", cfg, evt)
        self.assertEqual(code, 0, err)
        code, out, err = self._run("record", cfg, evt, log)
        self.assertEqual((code, out, err), (0, direct, b""))
        with open(log, "rb") as handle:
            doc = json.loads(handle.read().decode())
        self.assertEqual(doc["records"], [])
        code, out, err = self._run("replay", log)
        self.assertEqual((code, out, err), (0, direct, b""))


class ForwardStpBillingTest(unittest.TestCase):
    """forward-stp 公式：初始 B+L+2U；帧计 E+P+1；
    链路计 E*(P+1)+B+L+2U+2P+1（幂等也计，U 先应用）。

    B=2、L=1、P=3、初始 U=1：初始 5。
    t=0 幂等链路 E=0,U=1：0+2+1+2+6+1=12          累计 17
    t=1 帧 E=0：0+3+1=4                            累计 21
    t=2 准入拒绝帧 E=1：1+3+1=5                    累计 26
    t=4 断开链路 E=2,U=0：2*4+2+1+0+6+1=18         累计 44
    """

    TOTAL = 44

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


class ForwardStpFailureTest(unittest.TestCase):
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
        bad["age"] = 0  # 越界
        with open(self.cfg, "wb") as handle:
            handle.write(json.dumps(bad).encode())
        code, _, err = self._run("forward-stp", self.cfg, self.evt)
        self.assertEqual(code, 4, err)
        code, out, err = self._run("record", self.cfg, self.evt, self.log)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_bad_frame_is_invalid_and_matches_entry(self):
        # 非法源 MAC（组播）：forward-stp 入口与 record 均按非法输入拒绝
        events = [frame_event(0, "p2", "01:00:00:00:00:01")]
        with open(self.evt, "wb") as handle:
            handle.write(json.dumps(events).encode())
        code, _, err = self._run("forward-stp", self.cfg, self.evt)
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
