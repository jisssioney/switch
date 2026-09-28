#!/usr/bin/env python3
"""record / replay 对 acl 配置形状的回归。

端到端驱动：record CONFIG EVENTS LOG、replay LOG、acl CONFIG EVENTS；校验
stdout 逐字节一致、LOG 契约、逐项记录（帧 applied=true、output 为
t,action,ports,mirrors 结果；链路/成员仅 up 实际改变 applied、output=null；
version 初值 0，仅 applied 链路/成员后加 1）与 acl 工作量（准入拒绝、
ACL 丢弃、remark 目标拒绝、风暴或迁移抑制帧及幂等链路/成员事件均计费，
等于上限合法）。仅用标准库。
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
HEAD = ("100000", "16777216", "1048576", "16777216", "16777216")


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


def acl_rule(src, action="drop", to_vlan=None):
    return {
        "src": src, "dst": None, "vlan": None, "ethertype": None,
        "priority": None, "action": action, "to_vlan": to_vlan,
    }


def make_config():
    # B=2、L=1、P=5、M=2、R=2、delay=2、初始 U=1；p1 为跨桥 trunk 链路口
    # 兼镜像 target，p2/p3 边缘口且为镜像 sources（both），p4/p5 为同一
    # LAG 成员。acl：src ...:05 命中 drop；src ...:06 命中 remark 到
    # vlan3（access p2 不允许 vlan3，按 drop 处理）
    config = {
        "bridges": ["b1", "b2"],
        "links": [
            {"id": "L1", "x": ["b1", "p1"], "y": ["b2", "p1"],
             "cost": 1, "up": True},
        ],
        "delay": 2,
        "bridge": "b1",
        "ports": [
            make_port("p1", mode="trunk", allowed=[1, 2], untagged=[]),
            make_port("p2"),
            make_port("p3"),
            make_port("p4"),
            make_port("p5"),
        ],
        "age": 100,
        "storm": {
            "window": 10,
            "limits": {"broadcast": 2, "multicast": 2, "unknown": 2},
            "move_limit": 2,
            "hold": 50,
        },
        "lags": [{"name": "LG1", "members": ["p4", "p5"], "hash": ["src"]}],
        "mirror": {
            "sources": ["p2", "p3"], "target": "p1", "direction": "both"
        },
        "acl": [
            acl_rule("00:00:00:00:00:05", "drop"),
            acl_rule("00:00:00:00:00:06", "remark", 3),
        ],
    }
    return config


def frame(t, port, src, dst=BCAST, vlan=None):
    return {
        "t": t, "port": port, "src": src, "dst": dst, "vlan": vlan,
        "ethertype": 0x0800, "priority": 0,
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
    # t=0 链路幂等；t=1/2/3 三帧边缘广播（flood 含 LAG 经哈希选中的 p4，
    # 入站副本先于 egress 副本）；t=4/5/6 成员 p4 断开、幂等、恢复；
    # t=7/8/9 链路断开、幂等、恢复；t=10 access 口带 vlan3（准入拒绝
    # drop，无镜像）；t=11 源 01 自 p3 入（迁移一）；t=12 同源自 p4 入
    # （迁移二达 move_limit，p4/vlan 被封锁，drop）；t=13 封锁期帧 drop；
    # t=14 命中 ACL drop；t=15 remark 到 vlan3 但 p2 不允许（remark
    # 拒绝，按 drop）
    return [
        link_event(0, "L1", True),
        frame(1, "p2", "00:00:00:00:00:01"),
        frame(2, "p3", "00:00:00:00:00:02"),
        frame(3, "p2", "00:00:00:00:00:03"),
        member_event(4, "p4", False),
        member_event(5, "p4", False),
        member_event(6, "p4", True),
        link_event(7, "L1", False),
        link_event(8, "L1", False),
        link_event(9, "L1", True),
        frame(10, "p2", "00:00:00:00:00:04", vlan=3),
        frame(11, "p3", "00:00:00:00:00:01"),
        frame(12, "p4", "00:00:00:00:00:01"),
        frame(13, "p4", "00:00:00:00:00:01"),
        frame(14, "p2", "00:00:00:00:00:05"),
        frame(15, "p2", "00:00:00:00:00:06"),
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
        # 外部承诺不符：stdout 空、退出 4、LOG 不动
        wrong = "0" * 64
        code, out, err = self._run(
            "replay", self.log, "--expect-sha256", wrong
        )
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
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
        # 帧恒 applied；链路仅 t=7/9 实际改变；成员仅 t=4/6 实际改变
        self.assertEqual(
            [item["applied"] for item in records],
            [False, True, True, True, True, False, True, True, False,
             True, True, True, True, True, True, True],
        )
        # version 初值 0，仅 applied 链路/成员项后加 1（帧不加）：
        # t=4->1、t=6->2、t=7->3、t=9->4，之后保持 4
        self.assertEqual(
            [item["version"] for item in records],
            [0, 0, 0, 0, 1, 1, 2, 3, 3, 4, 4, 4, 4, 4, 4, 4],
        )
        # 链路项：event 规范化为 {id,t,up}，output 恒 null
        for index, up in ((0, True), (7, False), (8, False), (9, True)):
            item = records[index]
            self.assertEqual(
                item["event"], {"id": "L1", "t": item["t"], "up": up}
            )
            self.assertEqual(list(item["event"]), ["id", "t", "up"])
            self.assertIsNone(item["output"])
        # 成员项：event 规范化为 {member,t,up}，output 恒 null
        for index, up in ((4, False), (5, False), (6, True)):
            item = records[index]
            self.assertEqual(
                item["event"], {"member": "p4", "t": item["t"], "up": up}
            )
            self.assertEqual(list(item["event"]), ["member", "t", "up"])
            self.assertIsNone(item["output"])
        # 帧项：event 规范化，output 键序 t,action,ports,mirrors
        for index in (1, 2, 3, 10, 11, 12, 13, 14, 15):
            item = records[index]
            self.assertEqual(
                list(item["event"]),
                ["dst", "ethertype", "port", "priority", "src", "t",
                 "vlan"],
            )
            self.assertEqual(
                list(item["output"]),
                ["t", "action", "ports", "mirrors"],
            )

    def test_frame_outputs_match_results(self):
        doc = json.loads(self.log_bytes.decode())
        direct = json.loads(self.record_out.decode())
        # 入口 results 仅含帧结果（链路/成员项不产出），与帧记录一一对应
        frame_outputs = [
            item["output"]
            for item in doc["records"]
            if "port" in item["event"]
        ]
        self.assertEqual(frame_outputs, direct["results"])
        # t=1/2/3/11 flood；t=10 准入拒绝 drop；t=12 迁移达限封锁 drop；
        # t=13 封锁期 drop；t=14 ACL 命中 drop；t=15 remark 目标拒绝 drop
        self.assertEqual(
            [(out["t"], out["action"], len(out["ports"]),
              len(out["mirrors"]))
             for out in direct["results"]],
            [(1, "flood", 2, 2), (2, "flood", 2, 2), (3, "flood", 2, 2),
             (10, "drop", 0, 0), (11, "flood", 2, 2), (12, "drop", 0, 0),
             (13, "drop", 0, 0), (14, "drop", 0, 0), (15, "drop", 0, 0)],
        )
        # t=1：入站副本（source=p2、ingress）先于 egress 副本（source=p3），
        # 均复制到 target p1，native VLAN 去标签
        first = direct["results"][0]
        self.assertEqual(
            first["mirrors"],
            [
                {"name": "p1", "vlan": None, "direction": "ingress",
                 "source": "p2"},
                {"name": "p1", "vlan": None, "direction": "egress",
                 "source": "p3"},
            ],
        )
        # flood 出口含边缘口与 LAG 经哈希选中的成员，native VLAN 去标签
        self.assertEqual(
            {p["name"] for p in first["ports"]},
            {"p3", "p4"},
        )
        for out_port in first["ports"]:
            self.assertIsNone(out_port["vlan"])
        # 各类拒绝帧：空 ports/mirrors，且 ACL 丢弃/remark 拒绝不镜像
        for index in (3, 5, 6, 7, 8):
            self.assertEqual(direct["results"][index]["ports"], [])
            self.assertEqual(direct["results"][index]["mirrors"], [])

    def test_replay_rebuilds_byte_identical_log(self):
        code, out, err = self._replay()
        self.assertEqual(code, 0, err)
        self.assertEqual(out, self.record_out)
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)


class AclBillingTest(unittest.TestCase):
    """acl 口径：初始 B+L+2U=2+1+2=5；事件先取老化前 K(FDB)/H(封锁)/
    Q(速率+迁移队列)：帧 K+H+Q+2P+M+R+1（P=5、M=2、R=2，即 2P+M+R=14）；
    成员事件 K+H+Q+1；链路先应用 up，改变计 K+H+Q+B+L+2U+2P+1，幂等
    计 K+H+Q+1。准入拒绝、ACL 丢弃、remark 目标拒绝、抑制帧及幂等事件
    均按全帧/事件计费。

    t=0  幂等链路 X=0：+1                  累计 6
    t=1  帧（学习、占速率）X=0：+15        累计 21
    t=2  帧 X=2：+17                       累计 38
    t=3  帧 X=4：+19                       累计 57
    t=4  成员改变 X=6：+7                  累计 64
    t=5  成员幂等 X=6：+7                  累计 71
    t=6  成员改变 X=6：+7                  累计 78
    t=7  断链改变(U=0) X=6：+20            累计 98
    t=8  幂等断链 X=6：+7                  累计 105
    t=9  恢复改变(U=1) X=6：+22            累计 127
    t=10 准入拒绝帧 X=6：+21               累计 148
    t=11 帧（迁移一）X=6：+21              累计 169
    t=12 帧（迁移二封锁，抑制）X=8：+23    累计 192
    t=13 封锁帧 X=10：+25                  累计 217
    t=14 ACL 丢弃帧 X=10：+25              累计 242
    t=15 remark 目标拒绝帧 X=10：+25       累计 267
    """

    TOTAL = 267

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
        # 等于上限合法，输出与 LOG 逐字节一致
        code, out, err = self._run(
            "record", self.cfg, self.evt, self.log, *HEAD, str(self.TOTAL)
        )
        self.assertEqual((code, out, err), (0, self.record_out, b""))
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)
        # 首次超过即报 record_work_limit，stdout 空、绝不创建 LOG
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

    def _single_frame_setup(self, events):
        d = self.tmp.name
        cfg = os.path.join(d, "single.json")
        evt = os.path.join(d, "single_events.json")
        log = os.path.join(d, "single.log")
        with open(cfg, "wb") as handle:
            handle.write(json.dumps(self.config).encode())
        with open(evt, "wb") as handle:
            handle.write(json.dumps(events).encode())
        return cfg, evt, log

    def _assert_single_frame_billed(self, events, action):
        # 单帧：初始 5 + 全帧 2P+M+R+1=15，累计 20；三种拒绝均按全帧
        # 计费。等于 20 合法，19 报 record_work_limit
        cfg, evt, log = self._single_frame_setup(events)
        code, out, err = self._run(
            "record", cfg, evt, log, *HEAD, "20"
        )
        self.assertEqual(code, 0, err)
        code, out, err = self._run("record", cfg, evt, log, *HEAD, "19")
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"record_work_limit"}\n')
        # 入口结果为空 drop（无出口、无镜像）
        code, direct, err = self._run("acl", cfg, evt)
        self.assertEqual(code, 0, err)
        result = json.loads(direct.decode())["results"][0]
        self.assertEqual(result["action"], action)
        self.assertEqual(result["ports"], [])
        self.assertEqual(result["mirrors"], [])

    def test_acl_drop_billed_like_frame(self):
        self._assert_single_frame_billed(
            [frame(0, "p2", "00:00:00:00:00:05")], "drop"
        )

    def test_remark_reject_billed_like_frame(self):
        # remark 到 vlan3，但 access p2 不允许 vlan3：按 drop 处理
        self._assert_single_frame_billed(
            [frame(0, "p2", "00:00:00:00:00:06")], "drop"
        )

    def test_admission_reject_billed_like_frame(self):
        # access 口携带 tagged vlan3：VLAN 准入拒绝
        self._assert_single_frame_billed(
            [frame(0, "p2", "00:00:00:00:00:07", vlan=3)], "drop"
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
        # drop/allow 规则的 to_vlan 必须为 null：acl 入口与 record 均拒绝
        bad = json.loads(json.dumps(self.config))
        bad["acl"][0]["to_vlan"] = 1
        with open(self.cfg, "wb") as handle:
            handle.write(json.dumps(bad).encode())
        code, _, err = self._run("acl", self.cfg, self.evt)
        self.assertEqual(code, 4, err)
        code, out, err = self._run("record", self.cfg, self.evt, self.log)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_bad_event_is_invalid_and_matches_entry(self):
        # 非法 VLAN id：acl 入口与 record 均按非法输入拒绝
        events = [frame(0, "p2", "00:00:00:00:00:01", vlan=4096)]
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
        events = [{"t": 0, "member": "p2", "up": True}]  # p2 非 LAG 成员
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
        events = [{"t": 0, "id": "NOPE", "up": True}]
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
