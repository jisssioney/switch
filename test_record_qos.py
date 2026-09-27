#!/usr/bin/env python3
"""record / replay 对 qos 配置形状的回归。

端到端驱动：record CONFIG EVENTS LOG、replay LOG、qos CONFIG EVENTS；
校验 stdout 逐字节一致、LOG 契约、逐项记录（帧与 service applied=true、
output 为对应 results 项；链路/成员仅状态实际改变时 applied、output=null；
version 初值 0，仅 applied 链路/成员后加 1）与 qos 工作量（准入拒绝、
幂等事件均计费，等于上限合法）。仅用标准库。
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

from test_qos import base_config  # noqa: E402

LOG_KEYS = ["schema", "config", "records", "sha256"]
RECORD_KEYS = ["t", "version", "event", "applied", "output"]
BCAST = "ff:ff:ff:ff:ff:ff"


def make_config():
    # B=2、L=1（p3 为跨桥链路口）、P=6、M=2（p5/p6 LAG 成员）、R=1、
    # 初始 U=1；p1 入、p2 边缘出口、p4 镜像 target；p5/p6 属 vlan2，
    # vlan1 广播不入 LAG 队列
    result = json.loads(json.dumps(base_config(weights=[1, 1, 1, 1])))
    result["bridges"] = ["b1", "b2"]
    result["links"] = [
        {"id": "L2", "x": ["b1", "p3"], "y": ["b2", "x"],
         "cost": 1, "up": True}
    ]
    return result


def frame_event(t, port, dst=BCAST, priority=0,
                src="00:00:00:00:00:01", vlan=None):
    return {
        "t": t, "port": port, "src": src, "dst": dst, "vlan": vlan,
        "ethertype": 0x0800, "priority": priority,
    }


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
    # t=0 链路幂等（初始即 up）；t=2 good 广播（flood 入 p2/p3 队列）；
    # t=3 第二帧 good 广播（p2/p3 队列各 2 帧）；t=4 成员幂等 up；
    # t=5 成员实际下线（清 p5 空队）；t=6 service 从 p2 发 fid0；
    # t=7 链路实际断开（清 p3 队）
    return [
        link_event(0, "L2", True),
        frame_event(2, "p1"),
        frame_event(3, "p1", src="00:00:00:00:00:02"),
        member_event(4, "p5", True),
        member_event(5, "p5", False),
        service_event(6, "p2", 1),
        link_event(7, "L2", False),
    ]


class QosRecordTest(unittest.TestCase):
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
        # record stdout 与直接执行 qos 入口逐字节一致
        code, direct, err = self._run("qos", self.cfg, self.evt)
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
        # records 与事件等长、同序；项键序 t,version,event,applied,output
        records = doc["records"]
        self.assertEqual(len(records), len(self.events))
        for item in records:
            self.assertEqual(list(item), RECORD_KEYS)
            self.assertTrue(canonical_key_order(item["event"]))
        # 幂等链路/成员 applied=false；帧、service、实际状态改变的成员与
        # 链路 applied=true
        self.assertEqual(
            [item["applied"] for item in records],
            [False, True, True, False, True, True, True],
        )
        # version 初值 0，仅 applied 链路（t=7）/成员（t=5）后加 1
        self.assertEqual(
            [item["version"] for item in records],
            [0, 0, 0, 0, 1, 1, 2],
        )
        # 链路项：event 规范化 {id,t,up}，output 恒 null
        link_records = [records[0], records[6]]
        self.assertEqual(
            link_records[0]["event"], {"id": "L2", "t": 0, "up": True}
        )
        self.assertEqual(list(link_records[0]["event"]), ["id", "t", "up"])
        self.assertIsNone(link_records[0]["output"])
        self.assertEqual(
            link_records[1]["event"], {"id": "L2", "t": 7, "up": False}
        )
        self.assertIsNone(link_records[1]["output"])
        # 成员项：event 规范化 {member,t,up}，output 恒 null
        member_records = [records[3], records[4]]
        self.assertEqual(
            member_records[0]["event"],
            {"member": "p5", "t": 4, "up": True},
        )
        self.assertEqual(
            list(member_records[0]["event"]), ["member", "t", "up"]
        )
        self.assertIsNone(member_records[0]["output"])
        self.assertIsNone(member_records[1]["output"])
        # 帧项：event 规范化为 qos 原帧（无 class/length 等字段），
        # output 键序 t,action,ports,dropped,mirrors（无 class）
        for frame, item in zip(self.events[1:3], records[1:3]):
            self.assertEqual(
                item["event"],
                {
                    "dst": frame["dst"], "ethertype": frame["ethertype"],
                    "port": frame["port"], "priority": frame["priority"],
                    "src": frame["src"], "t": frame["t"],
                    "vlan": frame["vlan"],
                },
            )
            self.assertEqual(
                list(item["output"]),
                ["t", "action", "ports", "dropped", "mirrors"],
            )
        self.assertEqual(records[1]["output"]["action"], "flood")
        self.assertEqual(
            [entry["name"] for entry in records[1]["output"]["ports"]],
            ["p2", "p3"],
        )
        self.assertEqual(records[2]["output"]["action"], "flood")
        # service 项：event {count,port,t}，output 键序
        # t,port,frames,mirrors
        self.assertEqual(
            records[5]["event"], {"count": 1, "port": "p2", "t": 6}
        )
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
        # 入口 results 仅含帧与 service 结果（链路/成员项不产出），与帧/
        # service 记录一一对应、同序
        outputs = [
            item["output"]
            for item in doc["records"]
            if item["output"] is not None
        ]
        self.assertEqual(outputs, direct["results"])
        self.assertEqual(
            [(out["t"], out.get("action")) for out in direct["results"]],
            [(2, "flood"), (3, "flood"), (6, None)],
        )

    def test_replay_rebuilds_byte_identical_log(self):
        code, out, err = self._replay()
        self.assertEqual(code, 0, err)
        self.assertEqual(out, self.record_out)
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)


class QosBillingTest(unittest.TestCase):
    """qos 公式：初始 B+L+2U=5；帧计 X+3P+M+R+1；
    幂等链路 X+1；成员 up X+1、down X+队+1；service X+队+1；
    实际链路 X+N+(B+L+2U)+2P+1（U 取新值）。准入拒绝、幂等事件均计费。

    B=2、L=1、P=6、M=2、R=1、初始 U=1：初始 5。
    t=0 幂等链路 X=0：0+1=1                      累计 6
    t=2 good 帧 X=0：0+18+2+1+1=22               累计 28
    t=3 good 帧 X=2（FDB+广播速率各 1）：2+22=24  累计 52
    t=4 成员 up X=4（2 FDB+2 速率时间戳）：4+1=5 累计 57
    t=5 成员 down X=4、p5 队 0：4+0+1=5          累计 62
    t=6 service p2 X=4、p2 队 2：4+2+1=7         累计 69
    t=7 断链 X=4、N=3（p2 剩 1+p3 有 2）、U=0：
        4+3+3+12+1=23                             累计 92
    """

    TOTAL = 92

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


class QosFailureTest(unittest.TestCase):
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
        bad = json.loads(json.dumps(self.config))
        bad["qos"]["cap"] = 0  # cap 须为正整数
        with open(self.cfg, "wb") as handle:
            handle.write(json.dumps(bad).encode())
        code, _, err = self._run("qos", self.cfg, self.evt)
        self.assertEqual(code, 4, err)
        code, out, err = self._run("record", self.cfg, self.evt, self.log)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_bad_frame_field_is_invalid(self):
        events = [frame_event(0, "p1", priority=8)]
        with open(self.evt, "wb") as handle:
            handle.write(json.dumps(events).encode())
        code, _, err = self._run("qos", self.cfg, self.evt)
        self.assertEqual(code, 4, err)
        code, out, err = self._run("record", self.cfg, self.evt, self.log)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_bad_member_event_is_invalid(self):
        events = [member_event(0, "p1", True)]  # p1 非 LAG 成员
        with open(self.evt, "wb") as handle:
            handle.write(json.dumps(events).encode())
        code, out, err = self._run("record", self.cfg, self.evt, self.log)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_bad_link_event_is_invalid(self):
        events = [link_event(0, "NOPE", True)]
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
