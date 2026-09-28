#!/usr/bin/env python3
"""record / replay 对 forward-check 配置形状的回归。

端到端驱动：record CONFIG FRAMES LOG、replay LOG、forward-check CONFIG
FRAMES；校验 stdout 逐字节一致、LOG 契约、逐项记录与逐帧 K+P+1 工作量
（坏帧、VLAN 准入拒绝及 down 口也计费）。forward-check 与 forward-decode
共享 ports,age,max_frame 三键配置：非空帧数组含 src（八键）按
forward-check，含 data（原始帧）按 forward-decode，混用报
invalid_input/4，空数组仍按 forward-decode。仅用标准库。
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


def make_config(ports, age=100, max_frame=1518):
    return {"ports": ports, "age": age, "max_frame": max_frame}


def fc_frame(t, port, src, dst=BCAST, vlan=None, length=64, fcs=True,
             alignment=True):
    """构造 forward-check 八元组帧（默认 good：length>=64、fcs/alignment 真）。"""
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


def raw_frame(t, port, dst, src, vlan=None, payload_len=46):
    """构造单层 802.1Q 原始帧（forward-decode 形状，good FCS）。"""
    d = bytes(int(x, 16) for x in dst.split(":"))
    s = bytes(int(x, 16) for x in src.split(":"))
    if vlan is None:
        head = d + s + b"\x08\x00"
    else:
        head = d + s + b"\x81\x00" + vlan.to_bytes(2, "big") + b"\x08\x00"
    body = head + b"\x00" * payload_len
    fcs = (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little")
    return {"t": t, "port": port, "data": (body + fcs).hex()}


def canonical_key_order(value):
    if isinstance(value, dict):
        keys = list(value)
        return keys == sorted(keys) and all(
            canonical_key_order(value[k]) for k in keys
        )
    if isinstance(value, list):
        return all(canonical_key_order(item) for item in value)
    return True


def read_log(path):
    with open(path, "rb") as handle:
        return json.loads(handle.read().decode())


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


class ForwardCheckRecordTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.cfg = os.path.join(d, "config.json")
        self.frm = os.path.join(d, "frames.json")
        self.log = os.path.join(d, "out.log")
        self.config = make_config(
            [
                make_port("p1"),
                make_port("p2"),
                make_port("p3"),
                make_port("t", mode="trunk", pvid=1, allowed=[1, 2]),
            ]
        )
        self.frames = [
            fc_frame(0, "p1", "00:00:00:00:00:01"),
            fc_frame(1, "p1", "00:00:00:00:00:01",
                     dst="00:00:00:00:00:02", vlan=None),
            fc_frame(2, "t", "00:00:00:00:00:02",
                     dst="00:00:00:00:00:01", vlan=2),
        ]
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

    def test_record_matches_entry_and_replay_matches_record(self):
        # record stdout 与直接执行 forward-check 入口逐字节一致
        code, direct, err = self._run("forward-check", self.cfg, self.frm)
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
        # records 与帧等长、同序；项键序 t,version,event,applied,output
        self.assertEqual(len(doc["records"]), len(self.frames))
        for frame, item in zip(self.frames, doc["records"]):
            self.assertEqual(list(item), RECORD_KEYS)
            self.assertEqual(item["t"], frame["t"])
            self.assertEqual(item["version"], 0)
            self.assertTrue(item["applied"])
            # event 为规范化原八键帧（键按码点升序）
            self.assertEqual(item["event"], {
                "alignment": frame["alignment"],
                "dst": frame["dst"],
                "fcs": frame["fcs"],
                "length": frame["length"],
                "port": frame["port"],
                "src": frame["src"],
                "t": frame["t"],
                "vlan": frame["vlan"],
            })
            self.assertEqual(
                list(item["event"]),
                ["alignment", "dst", "fcs", "length", "port", "src", "t",
                 "vlan"],
            )
            # output 为对应结果项，键序 t,class,action,ports
            self.assertEqual(
                list(item["output"]), ["t", "class", "action", "ports"]
            )
        direct = json.loads(self.record_out.decode())
        self.assertEqual(
            [item["output"] for item in doc["records"]], direct["results"]
        )

    def test_replay_rebuilds_byte_identical_log(self):
        # 重放成功不重写文件；重建的 LOG 须与原文件逐字节一致（内部契约）
        code, out, err = self._replay()
        self.assertEqual(code, 0, err)
        self.assertEqual(out, self.record_out)
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), self.log_bytes)


class ForwardCheckBillingTest(unittest.TestCase):
    """逐帧累计 K+P+1：K 为本帧老化前动态 FDB 项数，P 为端口数。

    4 个端口 -> width=5；age=10，p2 down。
    t0  good p1 src1：老化前 K=0，计费 5，学习 src1(vlan1)
    t5  runt p2 src9（length<64）：老化前 K=1，计费 6，坏帧不学习
    t8  准入拒绝（access p1 收 vlan3 单标签）：K=1，计费 6，不学习
    t10 good p1 src2：老化前 K=1（src1 在 t-seen=10 恰老化），计费 6，
        随后老化 src1 并学习 src2，动态项仍为 1
    合计 23。
    """

    TOTAL = 23

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.cfg = os.path.join(d, "config.json")
        self.frm = os.path.join(d, "frames.json")
        self.log = os.path.join(d, "out.log")
        self.config = make_config(
            [
                make_port("p1"),
                make_port("p2", up=False),
                make_port("p3"),
                make_port("t", mode="trunk", pvid=1, allowed=[1, 2, 3]),
            ],
            age=10,
        )
        self.frames = [
            fc_frame(0, "p1", "00:00:00:00:00:01"),
            fc_frame(5, "p2", "00:00:00:00:00:09", length=10),
            fc_frame(8, "p1", "00:00:00:00:00:08", vlan=3),
            fc_frame(10, "p1", "00:00:00:00:00:02"),
        ]
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

    def test_bad_and_rejected_frames_recorded(self):
        doc = json.loads(self.log_bytes.decode())
        self.assertEqual(
            [r["output"]["class"] for r in doc["records"]],
            ["good", "runt", "good", "good"],
        )
        # 坏帧与准入拒绝均 drop；四帧恒 applied 且 version 恒 0
        self.assertTrue(all(r["applied"] for r in doc["records"]))
        self.assertTrue(all(r["version"] == 0 for r in doc["records"]))
        # 工作量预演与正式转发分类一致：record stdout 与入口逐字节相同
        code, direct, err = self._run("forward-check", self.cfg, self.frm)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.record_out, direct)

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


class ForwardCheckDownPortTest(unittest.TestCase):
    """good 帧到达 down 口：分类仍为 good、不学习不转发，但照常计 K+P+1。

    3 个端口（p1 up、p2 down、p3 up），age=100，width=4。
    t0 good p1 src1：K=0 计费 4，学习 src1
    t1 good p2 src9（入端口 down）：K=1 计费 5，不学习、drop
    t2 good p1 src1 查 dst src9 未命中：K=1 计费 5，flood（p2 不出口）
    合计 14。
    """

    TOTAL = 14

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.cfg = os.path.join(d, "config.json")
        self.frm = os.path.join(d, "frames.json")
        self.log = os.path.join(d, "out.log")
        self.config = make_config(
            [make_port("p1"), make_port("p2", up=False), make_port("p3")],
            age=100,
        )
        self.frames = [
            fc_frame(0, "p1", "00:00:00:00:00:01"),
            fc_frame(1, "p2", "00:00:00:00:00:09"),
            fc_frame(2, "p1", "00:00:00:00:00:01",
                     dst="00:00:00:00:00:09"),
        ]
        with open(self.cfg, "wb") as handle:
            handle.write(json.dumps(self.config).encode())
        with open(self.frm, "wb") as handle:
            handle.write(json.dumps(self.frames).encode())

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, *args):
        proc = subprocess.run(
            [sys.executable, SWITCH, *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        return proc.returncode, proc.stdout, proc.stderr

    def test_down_port_frame_matches_entry_and_billed(self):
        code, direct, err = self._run("forward-check", self.cfg, self.frm)
        self.assertEqual(code, 0, err)
        direct_doc = json.loads(direct.decode())
        self.assertEqual(
            [(r["class"], r["action"]) for r in direct_doc["results"]],
            [("good", "flood"), ("good", "drop"), ("good", "flood")],
        )
        # down 口帧不出口
        self.assertEqual(direct_doc["results"][1]["ports"], [])
        code, out, err = self._run(
            "record", self.cfg, self.frm, self.log
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(out, direct)
        # down 口帧同样超工作量上限：TOTAL-1 即拒，LOG 不生成
        code, out, err = self._run(
            "record", self.cfg, self.frm,
            os.path.join(self.tmp.name, "over.log"),
            "100000", "16777216", "1048576", "16777216", "16777216",
            str(self.TOTAL - 1),
        )
        self.assertEqual((code, out), (5, b""))
        self.assertEqual(err, b'{"error":"record_work_limit"}\n')


class ForwardCheckBadClassesTest(unittest.TestCase):
    """runt/giant/alignment/bad_fcs 四类坏帧均计费、drop、不学习。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.cfg = os.path.join(d, "config.json")
        self.frm = os.path.join(d, "frames.json")
        self.log = os.path.join(d, "out.log")
        self.config = make_config(
            [make_port("p1"), make_port("p2")], age=100, max_frame=1518
        )
        self.frames = [
            fc_frame(0, "p1", "00:00:00:00:00:01", length=63),  # runt
            fc_frame(1, "p1", "00:00:00:00:00:02", length=1519),  # giant
            fc_frame(2, "p1", "00:00:00:00:00:03",
                     alignment=False),  # alignment
            fc_frame(3, "p1", "00:00:00:00:00:04", fcs=False),  # bad_fcs
        ]
        with open(self.cfg, "wb") as handle:
            handle.write(json.dumps(self.config).encode())
        with open(self.frm, "wb") as handle:
            handle.write(json.dumps(self.frames).encode())

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, *args):
        proc = subprocess.run(
            [sys.executable, SWITCH, *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        return proc.returncode, proc.stdout, proc.stderr

    def test_bad_classes_match_entry(self):
        code, direct, err = self._run("forward-check", self.cfg, self.frm)
        self.assertEqual(code, 0, err)
        code, out, err = self._run(
            "record", self.cfg, self.frm, self.log
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(out, direct)
        doc = read_log(self.log)
        self.assertEqual(
            [r["output"]["class"] for r in doc["records"]],
            ["runt", "giant", "alignment", "bad_fcs"],
        )
        self.assertTrue(all(r["applied"] for r in doc["records"]))
        self.assertTrue(all(r["version"] == 0 for r in doc["records"]))
        # 无一帧学习：后续不存在任何单播命中（此处仅核对四帧全 drop）
        self.assertTrue(
            all(r["output"]["action"] == "drop" for r in doc["records"])
        )
        code, out, err = self._run("replay", self.log)
        self.assertEqual((code, out, err), (0, direct, b""))


class ForwardCheckShapeRoutingTest(unittest.TestCase):
    """共享配置形状下的模式路由：src 帧走 forward-check、data 帧走
    forward-decode，混用报 invalid_input/4，空数组仍走 forward-decode。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.cfg = os.path.join(d, "config.json")
        self.frm = os.path.join(d, "frames.json")
        self.log = os.path.join(d, "out.log")
        self.config = make_config([make_port("p1"), make_port("p2")])
        with open(self.cfg, "wb") as handle:
            handle.write(json.dumps(self.config).encode())

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, *args):
        proc = subprocess.run(
            [sys.executable, SWITCH, *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        return proc.returncode, proc.stdout, proc.stderr

    def _write_frames(self, frames):
        with open(self.frm, "wb") as handle:
            handle.write(json.dumps(frames).encode())

    def test_src_frames_route_forward_check(self):
        frames = [fc_frame(0, "p1", "00:00:00:00:00:01")]
        self._write_frames(frames)
        code, direct, err = self._run("forward-check", self.cfg, self.frm)
        self.assertEqual(code, 0, err)
        code, out, err = self._run(
            "record", self.cfg, self.frm, self.log
        )
        self.assertEqual((code, out, err), (0, direct, b""))
        # LOG 内 event 保留八键 src 帧（规范化），不解析为 data 原始帧
        doc = read_log(self.log)
        self.assertEqual(doc["records"][0]["event"]["src"],
                         "00:00:00:00:00:01")
        self.assertNotIn("data", doc["records"][0]["event"])
        code, out, err = self._run("replay", self.log)
        self.assertEqual((code, out, err), (0, direct, b""))

    def test_data_frames_route_forward_decode(self):
        frames = [raw_frame(0, "p1", BCAST, "00:00:00:00:00:01")]
        self._write_frames(frames)
        code, direct, err = self._run("forward-decode", self.cfg, self.frm)
        self.assertEqual(code, 0, err)
        code, out, err = self._run(
            "record", self.cfg, self.frm, self.log
        )
        self.assertEqual((code, out, err), (0, direct, b""))
        doc = read_log(self.log)
        self.assertEqual(doc["records"][0]["event"]["data"],
                         frames[0]["data"])
        self.assertNotIn("src", doc["records"][0]["event"])

    def test_mixed_shapes_are_invalid(self):
        src_frame = fc_frame(0, "p1", "00:00:00:00:00:01")
        data_frame = raw_frame(1, "p1", BCAST, "00:00:00:00:00:02")
        for frames in ([src_frame, data_frame], [data_frame, src_frame]):
            self._write_frames(frames)
            code, out, err = self._run(
                "record", self.cfg, self.frm, self.log
            )
            self.assertEqual(code, 4)
            self.assertEqual(out, b"")
            self.assertEqual(err, b'{"error":"invalid_input"}\n')
            self.assertFalse(os.path.exists(self.log))

    def test_empty_frames_still_route_forward_decode(self):
        self._write_frames([])
        code, decode_out, err = self._run(
            "forward-decode", self.cfg, self.frm
        )
        self.assertEqual(code, 0, err)
        code, check_out, err = self._run("forward-check", self.cfg, self.frm)
        self.assertEqual(code, 0, err)
        # 空序列两入口结果本身相同；record 路由沿用 forward-decode
        self.assertEqual(decode_out, check_out)
        code, out, err = self._run(
            "record", self.cfg, self.frm, self.log
        )
        self.assertEqual((code, out, err), (0, decode_out, b""))
        doc = read_log(self.log)
        self.assertEqual(doc["records"], [])
        self.assertEqual(doc["sha256"], prefix_digest(doc)[0])
        code, out, err = self._run("replay", self.log)
        self.assertEqual((code, out, err), (0, decode_out, b""))


class ForwardCheckFailureTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.cfg = os.path.join(d, "config.json")
        self.frm = os.path.join(d, "frames.json")
        self.log = os.path.join(d, "out.log")
        self.config = make_config([make_port("p1"), make_port("p2")])
        with open(self.cfg, "wb") as handle:
            handle.write(json.dumps(self.config).encode())
        with open(self.frm, "wb") as handle:
            handle.write(json.dumps(
                [fc_frame(0, "p1", "00:00:00:00:00:01")]
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
        code, _, err = self._run("forward-check", self.cfg, self.frm)
        self.assertEqual(code, 4)
        code, out, err = self._run("record", self.cfg, self.frm, self.log)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_bad_frame_is_invalid_and_matches_entry(self):
        # 未知端口：forward-check 入口与 record 均按非法输入拒绝
        with open(self.frm, "wb") as handle:
            handle.write(json.dumps(
                [fc_frame(0, "px", "00:00:00:00:00:01")]
            ).encode())
        code, _, err = self._run("forward-check", self.cfg, self.frm)
        self.assertEqual(code, 4)
        code, out, err = self._run("record", self.cfg, self.frm, self.log)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_extra_frame_key_is_invalid(self):
        bad = fc_frame(0, "p1", "00:00:00:00:00:01")
        bad["extra"] = 1
        with open(self.frm, "wb") as handle:
            handle.write(json.dumps([bad]).encode())
        code, out, err = self._run("record", self.cfg, self.frm, self.log)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
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
        with open(self.log, "rb") as handle:
            self.assertNotEqual(handle.read(), original)  # 重放不改文件


if __name__ == "__main__":
    unittest.main()
