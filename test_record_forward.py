#!/usr/bin/env python3
"""record / replay 对 forward 配置形状的回归。

CONFIG 恰含 ports,age 且 ports 为非空对象数组时识别为 forward：覆盖旧式
access（端口 {name,vlan,up}、帧 {t,port,src,dst}）与新式 802.1Q（端口
{name,mode,pvid,allowed,untagged,up}、帧额外带 vlan）。端到端驱动：
record CONFIG FRAMES LOG、replay LOG、forward CONFIG FRAMES；校验 stdout
逐字节一致、LOG 契约、逐项记录与逐帧 K+P+1 工作量（拒绝帧与 down 口也
计费）。仅用标准库。
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


def old_port(name, vlan=1, up=True):
    return {"name": name, "vlan": vlan, "up": up}


def old_frame(t, port, src, dst=BCAST):
    return {"t": t, "port": port, "src": src, "dst": dst}


def v2_port(name, mode="access", pvid=1, allowed=None, untagged=None, up=True):
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


def v2_frame(t, port, src, dst=BCAST, vlan=None):
    return {"t": t, "port": port, "src": src, "dst": dst, "vlan": vlan}


def make_config(ports, age=100):
    return {"ports": ports, "age": age}


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


class _ForwardRecordBase:
    """共享 setUp/helper 混入：不继承 TestCase，故不被 discover 收集。"""

    config = None
    frames = None

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.cfg = os.path.join(d, "config.json")
        self.frm = os.path.join(d, "frames.json")
        self.log = os.path.join(d, "out.log")
        with open(self.cfg, "wb") as handle:
            handle.write(json.dumps(self.config).encode())
        with open(self.frm, "wb") as handle:
            handle.write(json.dumps(self.frames).encode())
        rec = subprocess.run(
            [sys.executable, SWITCH, "record", self.cfg, self.frm, self.log],
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

    def _assert_log_contract(self, event_sorted_keys):
        doc = json.loads(self.log_bytes.decode())
        self.assertEqual(list(doc), LOG_KEYS)
        self.assertEqual(doc["schema"], 1)
        self.assertTrue(self.log_bytes.endswith(b"}\n"))
        self.assertFalse(self.log_bytes.endswith(b"\n\n"))
        self.assertEqual(doc["config"], self.config)
        self.assertTrue(canonical_key_order(doc["config"]))
        self.assertEqual(doc["sha256"], prefix_digest(doc)[0])
        # records 与帧等长、同序；项键序 t,version,event,applied,output
        self.assertEqual(len(doc["records"]), len(self.frames))
        for frame, item in zip(self.frames, doc["records"]):
            self.assertEqual(list(item), RECORD_KEYS)
            self.assertEqual(item["t"], frame["t"])
            self.assertEqual(item["version"], 0)
            self.assertTrue(item["applied"])
            # event 为规范化原帧（键按码点升序）
            self.assertEqual(list(item["event"]), event_sorted_keys)
            self.assertEqual(
                item["event"],
                {key: frame[key] for key in event_sorted_keys},
            )
            # output 为对应结果项，键序 t,action,ports
            self.assertEqual(list(item["output"]), ["t", "action", "ports"])
        direct = json.loads(self.record_out.decode())
        self.assertEqual(
            [item["output"] for item in doc["records"]], direct["results"]
        )
        return doc

    def _assert_roundtrip(self):
        # record stdout 与直接执行 forward 入口逐字节一致
        code, direct, err = self._run("forward", self.cfg, self.frm)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.record_out, direct)
        self.assertTrue(self.record_out.endswith(b"\n"))
        # replay stdout 与 record 逐字节一致，且不改 LOG
        code, out, err = self._replay()
        self.assertEqual((code, out, err), (0, self.record_out, b""))
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)


class OldForwardRecordTest(_ForwardRecordBase, unittest.TestCase):
    """旧式 access：端口 {name,vlan,up}，帧 {t,port,src,dst}。"""

    config = make_config(
        [old_port("p1"), old_port("p2"), old_port("p3", vlan=2)]
    )
    frames = [
        old_frame(0, "p1", "00:00:00:00:00:01"),               # flood -> p2
        old_frame(1, "p2", "00:00:00:00:00:02",
                  "00:00:00:00:00:01"),                        # unicast -> p1
        old_frame(2, "p3", "00:00:00:00:00:03",
                  "00:00:00:00:00:09"),                        # 未知单播 drop
    ]

    def test_record_matches_entry_and_replay_matches_record(self):
        self._assert_roundtrip()

    def test_log_contract(self):
        doc = self._assert_log_contract(["dst", "port", "src", "t"])
        # 旧入口 results 的 ports 为纯名字字符串数组
        self.assertEqual(
            [r["ports"] for r in
             (item["output"] for item in doc["records"])],
            [["p2"], ["p1"], []],
        )
        self.assertEqual(
            [r["action"] for r in
             (item["output"] for item in doc["records"])],
            ["flood", "unicast", "drop"],
        )
        # 顶层聚合沿用旧 forward 版本：ports 与 vlans
        result = json.loads(self.record_out.decode())
        self.assertEqual(
            list(result), ["results", "ports", "vlans"]
        )
        self.assertEqual(
            result["ports"],
            [
                {"name": "p1", "rx": 1, "tx": 1, "drop": 0},
                {"name": "p2", "rx": 1, "tx": 1, "drop": 0},
                {"name": "p3", "rx": 1, "tx": 0, "drop": 1},
            ],
        )


class V2ForwardRecordTest(_ForwardRecordBase, unittest.TestCase):
    """新式 802.1Q：trunk/access 混配，含准入拒绝帧；下行口计帧但不学习。"""

    config = make_config(
        [
            v2_port("p1"),
            v2_port("t", mode="trunk", pvid=1, allowed=[1, 2]),
            v2_port("p3", pvid=2),
            v2_port("d", pvid=1, up=False),
        ]
    )
    frames = [
        v2_frame(0, "p1", "00:00:00:00:00:01"),                # 无标签 flood
        v2_frame(1, "t", "00:00:00:00:00:02",
                 "00:00:00:00:00:01", vlan=1),                 # 单播
        v2_frame(2, "t", "00:00:00:00:00:03", BCAST, vlan=2),  # 标签 flood
        v2_frame(3, "t", "00:00:00:00:00:04", BCAST, vlan=3),  # 准入拒绝
        v2_frame(4, "d", "00:00:00:00:00:05"),                 # down 口
    ]

    def test_record_matches_entry_and_replay_matches_record(self):
        self._assert_roundtrip()

    def test_log_contract(self):
        doc = self._assert_log_contract(["dst", "port", "src", "t", "vlan"])
        outputs = [item["output"] for item in doc["records"]]
        # t0 flood：trunk t 在 vlan1 允许且带标签外发；access p3(vlan2) 不在
        self.assertEqual(outputs[0]["action"], "flood")
        self.assertEqual(outputs[0]["ports"], [{"name": "t", "vlan": 1}])
        # t1 已知单播回 p1，access 口去标签（vlan=null）
        self.assertEqual(outputs[1]["action"], "unicast")
        self.assertEqual(outputs[1]["ports"], [{"name": "p1", "vlan": None}])
        # t2 vlan2 flood -> access p3 去标签
        self.assertEqual(outputs[2]["ports"], [{"name": "p3", "vlan": None}])
        # 准入拒绝与 down 口均 drop，仍逐帧记录、恒 applied、version 恒 0
        self.assertEqual(outputs[3]["action"], "drop")
        self.assertEqual(outputs[3]["ports"], [])
        self.assertEqual(outputs[4]["action"], "drop")
        self.assertEqual(outputs[4]["ports"], [])
        self.assertTrue(
            all(item["version"] == 0 for item in doc["records"])
        )
        result = json.loads(self.record_out.decode())
        self.assertEqual(list(result), ["results", "ports", "vlans"])


class _BillingBase(_ForwardRecordBase):
    """共享工作量边界测试混入：不继承 TestCase，故不被 discover 收集。"""

    TOTAL = None

    def test_record_work_boundary(self):
        head = ("100000", "16777216", "1048576", "16777216", "16777216")
        # 等于上限合法，输出与 LOG 逐字节一致
        code, out, err = self._run(
            "record", self.cfg, self.frm, self.log, *head, str(self.TOTAL)
        )
        self.assertEqual((code, out, err), (0, self.record_out, b""))
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)
        # 首次超过即报 record_work_limit，绝不触碰 LOG
        os.unlink(self.log)
        code, out, err = self._run(
            "record", self.cfg, self.frm, self.log, *head,
            str(self.TOTAL - 1),
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"record_work_limit"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_record_over_limit_keeps_existing_log(self):
        head = ("100000", "16777216", "1048576", "16777216", "16777216")
        code, out, err = self._run(
            "record", self.cfg, self.frm, self.log, *head,
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


class OldForwardBillingTest(_BillingBase, unittest.TestCase):
    """逐帧累计 K+P+1：K 为老化前表项数，P 为端口数，down 口也计费。

    4 个端口 -> width=5；age=10，p2 down。
    t0 good p1 src1：老化前 K=0，计费 5，学习 src1(vlan1)
    t3 down p2 src9：老化前 K=1，计费 6，down 口不学习
    t10 good p1 src2：老化前 K=1（src1 在 t-seen=10 恰老化），计费 6，
        随后老化 src1 并学习 src2，动态项仍为 1
    合计 17。
    """

    TOTAL = 17
    config = make_config(
        [
            old_port("p1"),
            old_port("p2", up=False),
            old_port("p3"),
            old_port("p4", vlan=2),
        ],
        age=10,
    )
    frames = [
        old_frame(0, "p1", "00:00:00:00:00:01"),
        old_frame(3, "p2", "00:00:00:00:00:09"),
        old_frame(10, "p1", "00:00:00:00:00:02"),
    ]

    def test_entry_matches_record_despite_down_port(self):
        # 工作量预演与正式转发同形：record stdout 与入口逐字节相同
        code, direct, err = self._run("forward", self.cfg, self.frm)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.record_out, direct)
        doc = json.loads(self.log_bytes.decode())
        self.assertTrue(all(r["applied"] for r in doc["records"]))
        self.assertTrue(all(r["version"] == 0 for r in doc["records"]))


class V2ForwardBillingTest(_BillingBase, unittest.TestCase):
    """新式逐帧累计 K+P+1：准入拒绝不学习但仍按当前 K 计费。

    3 个端口 -> width=4；age=10，p3 down。
    t0 无标签 p1 src1：老化前 K=0，计费 4，学习 src1(vlan1)
    t1 标签 vlan1 t src2：老化前 K=1，计费 5，学习 src2(vlan1)
    t2 标签 vlan3 t src3：老化前 K=2，计费 6，vlan3 不在 allowed ->
        准入拒绝、不学习
    合计 15。
    """

    TOTAL = 15
    config = make_config(
        [
            v2_port("p1"),
            v2_port("t", mode="trunk", pvid=1, allowed=[1, 2]),
            v2_port("p3", pvid=2, up=False),
        ],
        age=10,
    )
    frames = [
        v2_frame(0, "p1", "00:00:00:00:00:01"),
        v2_frame(1, "t", "00:00:00:00:00:02",
                 "00:00:00:00:00:01", vlan=1),
        v2_frame(2, "t", "00:00:00:00:00:03", BCAST, vlan=3),
    ]

    def test_rejected_frame_recorded_and_entry_matches(self):
        doc = json.loads(self.log_bytes.decode())
        # 准入拒绝帧 drop；三帧恒 applied 且 version 恒 0
        self.assertEqual(
            [r["output"]["action"] for r in doc["records"]],
            ["flood", "unicast", "drop"],
        )
        self.assertTrue(all(r["applied"] for r in doc["records"]))
        self.assertTrue(all(r["version"] == 0 for r in doc["records"]))
        code, direct, err = self._run("forward", self.cfg, self.frm)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.record_out, direct)


class ForwardFailureTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.cfg = os.path.join(d, "config.json")
        self.frm = os.path.join(d, "frames.json")
        self.log = os.path.join(d, "out.log")
        self.config = make_config([old_port("p1"), old_port("p2")])
        with open(self.cfg, "wb") as handle:
            handle.write(json.dumps(self.config).encode())
        with open(self.frm, "wb") as handle:
            handle.write(json.dumps(
                [old_frame(0, "p1", "00:00:00:00:00:01")]
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
        bad["age"] = 0  # 越界
        with open(self.cfg, "wb") as handle:
            handle.write(json.dumps(bad).encode())
        code, _, err = self._run("forward", self.cfg, self.frm)
        self.assertEqual(code, 4)
        code, out, err = self._run("record", self.cfg, self.frm, self.log)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_bad_frame_is_invalid_and_matches_entry(self):
        with open(self.frm, "wb") as handle:
            handle.write(json.dumps(
                [old_frame(0, "zz", "00:00:00:00:00:01")]
            ).encode())
        code, _, err = self._run("forward", self.cfg, self.frm)
        self.assertEqual(code, 4)
        code, out, err = self._run("record", self.cfg, self.frm, self.log)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_bad_v2_config_is_invalid(self):
        bad = make_config(
            [v2_port("p1", mode="trunk", pvid=1, allowed=[1, 2])]
        )  # trunk 不得带 untagged，但默认 untagged=[] 合法；改一条非法 allowed
        bad["ports"][0]["allowed"] = [2, 1]  # 非严格递增
        with open(self.cfg, "wb") as handle:
            handle.write(json.dumps(bad).encode())
        with open(self.frm, "wb") as handle:
            handle.write(json.dumps(
                [v2_frame(0, "p1", "00:00:00:00:00:01")]
            ).encode())
        code, _, _ = self._run("forward", self.cfg, self.frm)
        self.assertEqual(code, 4)
        code, out, err = self._run("record", self.cfg, self.frm, self.log)
        self.assertEqual(code, 4)
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_tampered_replay_invalid_and_untouched(self):
        code, _, err = self._run("record", self.cfg, self.frm, self.log)
        self.assertEqual(code, 0, err)
        with open(self.log, "rb") as handle:
            original = handle.read()
        doc = json.loads(original.decode())
        doc["records"][0]["applied"] = False
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
        # 重放失败不改文件
        with open(self.log, "rb") as handle:
            self.assertTrue(handle.read())

    def test_empty_ports_is_not_forward(self):
        # ports 为空数组不满足 forward 的“非空对象数组”要求；帧引用未知口，
        # 经入口校验 -> invalid_input，不写 LOG
        with open(self.cfg, "wb") as handle:
            handle.write(b'{"ports":[],"age":10}')
        code, out, err = self._run("record", self.cfg, self.frm, self.log)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertFalse(os.path.exists(self.log))


if __name__ == "__main__":
    unittest.main()
