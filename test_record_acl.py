#!/usr/bin/env python3
"""record / replay 对 acl 配置形状的回归。

端到端驱动：record CONFIG EVENTS LOG、replay LOG、acl CONFIG EVENTS；校验
stdout 逐字节一致、LOG 契约、逐项记录（帧恒 applied=true、output 为对应
t,action,ports,mirrors 结果项；链路/成员仅 up 实际改变时 applied、
output=null；version 初值 0，仅 applied 链路/成员后加 1）与 acl 工作量
（ACL 丢弃、remark 拒绝、准入拒绝、风暴抑制帧及幂等事件均计费，等于
上限合法）。仅用标准库。
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
HEAD = ("100000", "16777216", "1048576", "16777216", "16777216")


def make_config():
    # B=2、L=1（p3 为跨桥链路口）、P=6、M=2（p5/p6 LAG 成员）、R=2
    # （首条命中 src 09 drop）、初始 U=1；p1 入、p2/p3 vlan1 出口、p4
    # 镜像 target。较 qos 基线仅无 qos 键、改为双桥链路
    result = json.loads(json.dumps(base_config(weights=[1, 1, 1, 1])))
    del result["qos"]
    result["bridges"] = ["b1", "b2"]
    result["links"] = [
        {"id": "L2", "x": ["b1", "p3"], "y": ["b2", "x"],
         "cost": 1, "up": True}
    ]
    result["acl"].insert(
        0,
        {"src": "00:00:00:00:00:09", "dst": None, "vlan": None,
         "ethertype": None, "priority": None, "action": "drop",
         "to_vlan": None},
    )
    return result


def frame(t, port, src="00:00:00:00:00:01", dst=BCAST, vlan=None,
          ethertype=0x0800, priority=0):
    return {
        "t": t, "port": port, "src": src, "dst": dst, "vlan": vlan,
        "ethertype": ethertype, "priority": priority,
    }


def link_event(t, lid, up):
    return {"t": t, "id": lid, "up": up}


def member_event(t, member, up):
    return {"t": t, "member": member, "up": up}


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
    # t=0 链路幂等（初始即 up）；t=2 good 广播（flood 入 p2/p3）；t=3 帧
    # 命中首条 ACL drop；t=4 成员幂等 up；t=5 成员实际下线；t=7 链路实际断开
    return [
        link_event(0, "L2", True),
        frame(2, "p1", src="00:00:00:00:00:01"),
        frame(3, "p1", src="00:00:00:00:00:09"),
        member_event(4, "p5", True),
        member_event(5, "p5", False),
        link_event(7, "L2", False),
    ]


class AclRecordTest(unittest.TestCase):
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
        # record stdout 与直接执行 acl 入口逐字节一致
        code, direct, err = self._run("acl", self.cfg, self.evt)
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
        # 幂等链路/成员 applied=false；两帧、实际状态改变的成员与链路
        # applied=true
        self.assertEqual(
            [item["applied"] for item in records],
            [False, True, True, False, True, True],
        )
        # version 初值 0，仅 applied 链路（t=7）/成员（t=5）后加 1
        self.assertEqual(
            [item["version"] for item in records],
            [0, 0, 0, 0, 1, 2],
        )
        # 链路项：event 规范化 {id,t,up}，output 恒 null
        link_records = [records[0], records[5]]
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
        # 帧项：event 规范化、output 键序 t,action,ports,mirrors；ACL
        # 丢弃帧 output 为空 drop
        for item in records[1:3]:
            self.assertEqual(
                list(item["event"]),
                ["dst", "ethertype", "port", "priority", "src", "t",
                 "vlan"],
            )
            self.assertEqual(
                list(item["output"]), ["t", "action", "ports", "mirrors"]
            )
        self.assertEqual(records[1]["output"]["action"], "flood")
        self.assertTrue(records[1]["output"]["ports"])
        self.assertEqual(records[2]["output"]["action"], "drop")
        self.assertEqual(records[2]["output"]["ports"], [])
        self.assertEqual(records[2]["output"]["mirrors"], [])

    def test_outputs_match_results(self):
        doc = json.loads(self.log_bytes.decode())
        direct = json.loads(self.record_out.decode())
        # 入口 results 仅含帧结果（链路/成员项不产出），与帧记录一一
        # 对应、同序
        outputs = [
            item["output"]
            for item in doc["records"]
            if item["output"] is not None
        ]
        self.assertEqual(outputs, direct["results"])
        self.assertEqual(
            [(out["t"], out["action"]) for out in direct["results"]],
            [(2, "flood"), (3, "drop")],
        )

    def test_replay_rebuilds_byte_identical_log(self):
        code, out, err = self._replay()
        self.assertEqual(code, 0, err)
        self.assertEqual(out, self.record_out)
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)


class AclBillingTest(unittest.TestCase):
    """acl 公式：初始 B+L+2U=5；帧计 X+2P+M+R+1（X=K+H+Q）；幂等
    链路/成员 X+1；实际链路 X+(B+L+2U)+2P+1（U 先应用）。ACL 丢弃、
    remark 拒绝、准入拒绝、风暴抑制帧与幂等事件均计费。

    B=2、L=1、P=6、M=2、R=2、初始 U=1：初始 5。
    t=0 幂等链路 X=0：+1                    累计 6
    t=2 good 帧 X=0：+1+12+2+2=17           累计 23
      （学习 1 项 + 广播速率 1 项，X 变 2）
    t=3 ACL 丢弃帧 X=2：+19                 累计 42
    t=4 成员幂等 X=2：+3                    累计 45
    t=5 成员改变 X=2：+3                    累计 48
    t=7 断链 X=2、U=0：2+3+12+1=18          累计 66
    """

    TOTAL = 66

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

    def _single_frame_setup(self, config, events):
        d = self.tmp.name
        cfg = os.path.join(d, "single.json")
        evt = os.path.join(d, "single_events.json")
        log = os.path.join(d, "single.log")
        with open(cfg, "wb") as handle:
            handle.write(json.dumps(config).encode())
        with open(evt, "wb") as handle:
            handle.write(json.dumps(events).encode())
        return cfg, evt, log

    def test_record_work_boundary(self):
        # 等于上限合法，输出与 LOG 逐字节一致
        code, out, err = self._run(
            "record", self.cfg, self.evt, self.log, *HEAD, str(self.TOTAL)
        )
        self.assertEqual((code, out, err), (0, self.record_out, b""))
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)
        # 首次超过即报 record_work_limit，stdout 空、绝不触碰 LOG
        os.unlink(self.log)
        code, out, err = self._run(
            "record", self.cfg, self.evt, self.log, *HEAD,
            str(self.TOTAL - 1),
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"record_work_limit"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_record_over_limit_keeps_existing_log(self):
        code, out, err = self._run(
            "record", self.cfg, self.evt, self.log, *HEAD,
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

    def test_admission_reject_billed_like_frame(self):
        # 单桥（B=1、L=0、初始 1）；access p1 的 tagged vlan2 帧被准入
        # 拒绝：X=0，帧计 2P+M+R+1=16，累计 17
        config = json.loads(json.dumps(base_config(weights=[1, 1, 1, 1])))
        del config["qos"]
        events = [frame(0, "p1", vlan=2)]
        cfg, evt, log = self._single_frame_setup(config, events)
        code, _, err = self._run("record", cfg, evt, log, *HEAD, "17")
        self.assertEqual(code, 0, err)
        code, out, err = self._run("record", cfg, evt, log, *HEAD, "16")
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"record_work_limit"}\n')
        # 拒绝帧入口结果为空 drop
        code, direct, err = self._run("acl", cfg, evt)
        self.assertEqual(code, 0, err)
        result = json.loads(direct.decode())["results"][0]
        self.assertEqual(result["action"], "drop")
        self.assertEqual(result["ports"], [])
        self.assertEqual(result["mirrors"], [])

    def test_acl_drop_billed_like_frame(self):
        # R=2：good 帧在 ACL 匹配后丢弃，仍按全帧 2P+M+R+1=17 计费，
        # 初始 1，累计 18
        config = json.loads(json.dumps(base_config(weights=[1, 1, 1, 1])))
        del config["qos"]
        config["acl"].insert(
            0,
            {"src": "00:00:00:00:00:09", "dst": None, "vlan": None,
             "ethertype": None, "priority": None, "action": "drop",
             "to_vlan": None},
        )
        events = [frame(0, "p1", src="00:00:00:00:00:09")]
        cfg, evt, log = self._single_frame_setup(config, events)
        code, _, err = self._run("record", cfg, evt, log, *HEAD, "18")
        self.assertEqual(code, 0, err)
        code, out, err = self._run("record", cfg, evt, log, *HEAD, "17")
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"record_work_limit"}\n')
        code, direct, err = self._run("acl", cfg, evt)
        self.assertEqual(code, 0, err)
        result = json.loads(direct.decode())["results"][0]
        self.assertEqual(result["action"], "drop")

    def test_remark_rejected_billed_like_frame(self):
        # remark 目标 vlan2 不在入端口 p1 的 allowed：按 drop 处理，仍按
        # 全帧 2P+M+R+1=17（R=2）计费，初始 1，累计 18
        config = json.loads(json.dumps(base_config(weights=[1, 1, 1, 1])))
        del config["qos"]
        config["acl"].insert(
            0,
            {"src": "00:00:00:00:00:07", "dst": None, "vlan": None,
             "ethertype": None, "priority": None, "action": "remark",
             "to_vlan": 2},
        )
        events = [frame(0, "p1", src="00:00:00:00:00:07")]
        cfg, evt, log = self._single_frame_setup(config, events)
        code, rec_out, err = self._run(
            "record", cfg, evt, log, *HEAD, "18"
        )
        self.assertEqual(code, 0, err)
        code, out, err = self._run("record", cfg, evt, log, *HEAD, "17")
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"record_work_limit"}\n')
        code, direct, err = self._run("acl", cfg, evt)
        self.assertEqual(code, 0, err)
        self.assertEqual(direct, rec_out)
        result = json.loads(direct.decode())["results"][0]
        self.assertEqual(result["action"], "drop")
        self.assertEqual(result["ports"], [])
        self.assertEqual(result["mirrors"], [])

    def test_suppressed_frame_billed_like_frame(self):
        # broadcast 速率上限 1：第二个广播被抑制丢弃；初始 1，首帧 X=0
        # 计 1+12+2+1=16（R=1），次帧 X=2（FDB 1 + 速率 1）计 2+16=18，
        # 累计 35；35 合法、34 超限
        config = json.loads(json.dumps(base_config(weights=[1, 1, 1, 1])))
        del config["qos"]
        config["storm"]["limits"] = {
            "broadcast": 1, "multicast": 100, "unknown": 100
        }
        events = [
            frame(0, "p1", src="00:00:00:00:00:01"),
            frame(1, "p1", src="00:00:00:00:00:01"),
        ]
        cfg, evt, log = self._single_frame_setup(config, events)
        code, rec_out, err = self._run("record", cfg, evt, log, *HEAD, "35")
        self.assertEqual(code, 0, err)
        code, out, err = self._run("record", cfg, evt, log, *HEAD, "34")
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"record_work_limit"}\n')
        results = json.loads(rec_out.decode())["results"]
        self.assertEqual(
            [(r["t"], r["action"]) for r in results],
            [(0, "flood"), (1, "drop")],
        )


class AclFailureTest(unittest.TestCase):
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
        bad["acl"] = []  # acl 规则不得为空
        with open(self.cfg, "wb") as handle:
            handle.write(json.dumps(bad).encode())
        code, _, err = self._run("acl", self.cfg, self.evt)
        self.assertEqual(code, 4, err)
        code, out, err = self._run("record", self.cfg, self.evt, self.log)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_bad_frame_field_is_invalid(self):
        events = [frame(0, "p1", ethertype=70000)]
        with open(self.evt, "wb") as handle:
            handle.write(json.dumps(events).encode())
        code, _, err = self._run("acl", self.cfg, self.evt)
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

    def test_invalid_record_keeps_existing_log(self):
        sentinel = b"do-not-truncate"
        with open(self.log, "wb") as handle:
            handle.write(sentinel)
        events = [link_event(0, "NOPE", True)]
        with open(self.evt, "wb") as handle:
            handle.write(json.dumps(events).encode())
        code, out, err = self._run("record", self.cfg, self.evt, self.log)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), sentinel)

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
