#!/usr/bin/env python3
"""record / replay 对 forward-check 帧形状的回归。

端到端驱动：record CONFIG FRAMES LOG、replay LOG、forward-check CONFIG
FRAMES；校验 stdout 逐字节一致、LOG 契约、逐项记录与逐帧 K+P+1 工作量
（坏帧、VLAN 拒绝与 down 口也计费）。三键配置形状与 forward-decode 共享：
非空帧数组含 src 按 forward-check，含 data 按 forward-decode，混用报
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


def frame(t, port, src, dst=BCAST, vlan=None, length=100, fcs=True,
          alignment=True):
    """构造 forward-check 八键帧（默认 good：长度>=64、FCS/对齐正常）。"""
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


def raw_frame(t, port, dst, src, vlan=None, payload_len=46, bad_fcs=False):
    """构造单层 802.1Q 原始帧（forward-decode 形状，用于混用拒绝回归）。"""
    d = bytes(int(x, 16) for x in dst.split(":"))
    s = bytes(int(x, 16) for x in src.split(":"))
    if vlan is None:
        head = d + s + b"\x08\x00"
    else:
        head = d + s + b"\x81\x00" + vlan.to_bytes(2, "big") + b"\x08\x00"
    body = head + b"\x00" * payload_len
    fcs = (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little")
    if bad_fcs:
        fcs = b"\xff\xff\xff\xff"
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
            frame(0, "p1", "00:00:00:00:00:01"),
            frame(1, "p1", "00:00:00:00:00:01",
                  dst="00:00:00:00:00:02", vlan=None),
            frame(2, "t", "00:00:00:00:00:02",
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
        for src_frame, item in zip(self.frames, doc["records"]):
            self.assertEqual(list(item), RECORD_KEYS)
            self.assertEqual(item["t"], src_frame["t"])
            self.assertEqual(item["version"], 0)
            self.assertTrue(item["applied"])
            # event 为规范化原八键帧（键按码点升序）
            self.assertEqual(item["event"], {
                "alignment": src_frame["alignment"],
                "dst": src_frame["dst"],
                "fcs": src_frame["fcs"],
                "length": src_frame["length"],
                "port": src_frame["port"],
                "src": src_frame["src"],
                "t": src_frame["t"],
                "vlan": src_frame["vlan"],
            })
            self.assertEqual(
                list(item["event"]),
                ["alignment", "dst", "fcs", "length", "port", "src",
                 "t", "vlan"],
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
    t5  runt p2 src9（down 口）：老化前 K=1，计费 6，坏帧不学习
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
            frame(0, "p1", "00:00:00:00:00:01"),
            frame(5, "p2", "00:00:00:00:00:09", length=10),
            frame(8, "p1", "00:00:00:00:00:08", vlan=3),
            frame(10, "p1", "00:00:00:00:00:02"),
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
        self.assertEqual(
            [r["output"]["action"] for r in doc["records"]],
            ["flood", "drop", "drop", "flood"],
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
                [frame(0, "p1", "00:00:00:00:00:01")]
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
        code_entry = code
        code, out, err = self._run("record", self.cfg, self.frm, self.log)
        self.assertEqual(code, code_entry)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_bad_frame_is_invalid_and_matches_entry(self):
        # fcs 非布尔：forward-check 入口与 record 均按非法输入拒绝
        bad = frame(0, "p1", "00:00:00:00:00:01")
        bad["fcs"] = 1
        with open(self.frm, "wb") as handle:
            handle.write(json.dumps([bad]).encode())
        code, _, err = self._run("forward-check", self.cfg, self.frm)
        self.assertEqual(code, 4)
        code, out, err = self._run("record", self.cfg, self.frm, self.log)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_mixed_frame_shapes_invalid(self):
        # 含 src 的八键帧与含 data 的原始帧混用：record 报非法输入且不写 LOG
        mixed = [
            frame(0, "p1", "00:00:00:00:00:01"),
            raw_frame(1, "p1", BCAST, "00:00:00:00:00:02"),
        ]
        with open(self.frm, "wb") as handle:
            handle.write(json.dumps(mixed).encode())
        code, out, err = self._run("record", self.cfg, self.frm, self.log)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertFalse(os.path.exists(self.log))

    def test_empty_frames_still_forward_decode_route(self):
        # 空数组沿用 forward-decode 路由：record 成功且与 forward-check 入口
        # （空帧）逐字节一致
        with open(self.frm, "wb") as handle:
            handle.write(b"[]")
        code, out, err = self._run("record", self.cfg, self.frm, self.log)
        self.assertEqual(code, 0, err)
        code, direct, err = self._run("forward-check", self.cfg, self.frm)
        self.assertEqual(code, 0, err)
        self.assertEqual(out, direct)
        doc = json.loads(open(self.log).read())
        self.assertEqual(doc["records"], [])

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
            self.assertTrue(handle.read())  # 重放不改文件


if __name__ == "__main__":
    unittest.main()
