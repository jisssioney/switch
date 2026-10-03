#!/usr/bin/env python3
"""igmp-snoop-decode 子命令端到端回归。

在 stp-decode 配置上增加 igmp 子文档（membership_age 正整数、
router_ports 不重复端口名）；事件为链路项与 t/port/data 原始帧混合。
覆盖：IGMPv2 Report/Leave/Query 识别、成员建立/刷新/老化/链路清除、
Report/Leave 仅发往合格路由端口（无则泛洪）、Query 始终泛洪、其他
IPv4 组播命中成员表为 multicast、igmp_invalid 不改状态计丢弃、groups
键序与排序、record/replay 逐字节一致、工作量 stp-decode+N×(N+P+1)
边界与 igmp_work_limit、以及参数/文件/非法输入退出 2/3/4。仅标准库。
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


def make_port(name, mode="trunk", pvid=1, allowed=None, untagged=None,
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


def make_config(membership_age=100, router_ports=("p3",)):
    return {
        "bridges": ["b1"],
        "links": [],
        "delay": 2,
        "bridge": "b1",
        "ports": [
            make_port("p1", allowed=[1, 2]),
            make_port("p2", allowed=[1, 2]),
            make_port("p3", allowed=[1, 2]),
            make_port("p4", allowed=[1, 2]),
        ],
        "age": 1000,
        "max_frame": 1518,
        "igmp": {
            "membership_age": membership_age,
            "router_ports": list(router_ports),
        },
    }


def _checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) | data[index + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4(dst, proto, payload, fragment=0):
    total = 20 + len(payload)
    header = (
        bytes([0x45, 0]) + total.to_bytes(2, "big") + b"\x00\x00"
        + fragment.to_bytes(2, "big") + bytes([64, proto]) + b"\x00\x00"
        + b"\x0a\x00\x00\x01" + dst
    )
    header = header[:10] + _checksum(header).to_bytes(2, "big") + header[12:]
    return header + payload


def igmp(mtype, group, bad_checksum=False):
    message = bytes([mtype, 0, 0, 0]) + group
    checksum = 0 if bad_checksum else _checksum(message)
    return bytes([mtype, 0]) + checksum.to_bytes(2, "big") + group


def group_mac(group):
    value = 0x01005E000000 | (int.from_bytes(group, "big") & 0x7FFFFF)
    return ":".join("%02x" % b for b in value.to_bytes(6, "big"))


G1 = bytes([224, 1, 2, 3])
G2 = bytes([224, 5, 6, 7])
ALLHOSTS = bytes([224, 0, 0, 1])
ALLROUTERS = bytes([224, 0, 0, 2])


def raw_frame(t, port, dst, ip_packet, vlan=1):
    dst_octets = bytes(int(x, 16) for x in dst.split(":"))
    src = b"\x00\x00\x00\x00\x00\x01"
    head = (
        dst_octets + src + b"\x81\x00" + vlan.to_bytes(2, "big") + b"\x08\x00"
    )
    body = head + ip_packet
    if len(body) < 60:
        body += b"\x00" * (60 - len(body))
    fcs = (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little")
    return {"t": t, "port": port, "data": (body + fcs).hex()}


def data_frame(t, port, group, vlan=1, proto=17):
    return raw_frame(t, port, group_mac(group),
                     ipv4(group, proto, b"\x00" * 8), vlan)


def report(t, port, group, vlan=1):
    return raw_frame(t, port, group_mac(group),
                     ipv4(group, 2, igmp(0x16, group)), vlan)


def leave(t, port, group, vlan=1):
    return raw_frame(t, port, group_mac(ALLROUTERS),
                     ipv4(ALLROUTERS, 2, igmp(0x17, group)), vlan)


def query(t, port, vlan=1):
    return raw_frame(t, port, group_mac(ALLHOSTS),
                     ipv4(ALLHOSTS, 2, igmp(0x11, b"\x00\x00\x00\x00")), vlan)


class IgmpSnoopTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.cfg = os.path.join(d, "config.json")
        self.evt = os.path.join(d, "events.json")
        with open(self.cfg, "w") as handle:
            json.dump(make_config(), handle)

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, *args):
        proc = subprocess.run(
            [sys.executable, SWITCH, *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        return proc.returncode, proc.stdout, proc.stderr

    def _sim(self, events):
        with open(self.evt, "w") as handle:
            json.dump(events, handle)
        code, out, err = self._run("igmp-snoop-decode", self.cfg, self.evt)
        self.assertEqual(code, 0, err)
        return json.loads(out.decode())

    def test_result_key_order_and_groups(self):
        result = self._sim([report(1, "p1", G1)])
        self.assertEqual(list(result), ["results", "ports", "vlans", "groups"])
        self.assertEqual(
            list(result["results"][0]), ["t", "class", "action", "ports"]
        )
        self.assertEqual(result["groups"][0]["vlan"], 1)
        self.assertEqual(result["groups"][0]["group"], "224.1.2.3")
        self.assertEqual(
            result["groups"][0]["members"], [{"name": "p1", "expires": 101}]
        )

    def test_report_to_router_data_multicast_leave_query(self):
        result = self._sim([
            report(1, "p1", G1),
            data_frame(2, "p2", G1),
            query(3, "p1"),
            leave(4, "p1", G1),
            data_frame(5, "p2", G1),
        ])
        actions = [(r["t"], r["action"]) for r in result["results"]]
        self.assertEqual(actions, [
            (1, "igmp_report"),
            (2, "multicast"),
            (3, "igmp_query"),
            (4, "igmp_leave"),
            (5, "flood"),
        ])
        # Report/Leave 仅发往路由端口 p3，排除入端口
        self.assertEqual([p["name"] for p in result["results"][0]["ports"]],
                         ["p3"])
        self.assertEqual([p["name"] for p in result["results"][3]["ports"]],
                         ["p3"])
        # 数据帧命中成员表：成员 p1 + 路由 p3，排除入端口 p2
        self.assertEqual(
            sorted(p["name"] for p in result["results"][1]["ports"]),
            ["p1", "p3"],
        )
        # Query 始终泛洪（同 VLAN 其余 forwarding 端口）
        self.assertEqual(
            sorted(p["name"] for p in result["results"][2]["ports"]),
            ["p2", "p3", "p4"],
        )
        # Leave 后成员删除
        self.assertEqual(result["groups"], [])
        # 标签语义保留：trunk 出端口保留 vlan
        self.assertTrue(
            all(p["vlan"] == 1 for p in result["results"][1]["ports"])
        )

    def test_report_floods_when_no_qualified_router(self):
        with open(self.cfg, "w") as handle:
            # p3 不属于 VLAN 1：无合格路由端口
            config = make_config()
            for port in config["ports"]:
                if port["name"] == "p3":
                    port["mode"] = "hybrid"
                    port["pvid"] = 2
                    port["allowed"] = [2]
                    port["untagged"] = [2]
            json.dump(config, handle)
        result = self._sim([report(1, "p1", G1, vlan=1)])
        self.assertEqual(result["results"][0]["action"], "igmp_report")
        # 回退泛洪：VLAN 1 可转发且非入端口（p3 因 VLAN 不符被排除）
        self.assertEqual(
            sorted(p["name"] for p in result["results"][0]["ports"]),
            ["p2", "p4"],
        )

    def test_membership_refresh_expiry_and_groups_order(self):
        # G1@vlan1 p2(t2->102)、G2@vlan1 p2(t3->103)、G1@vlan2 p1(t1->101)
        seeded = self._sim([
            report(1, "p1", G1, vlan=2),
            report(2, "p2", G1, vlan=1),
            report(3, "p2", G2, vlan=1),
        ])
        self.assertEqual(
            [(g["vlan"], g["group"]) for g in seeded["groups"]],
            [(1, "224.1.2.3"), (1, "224.5.6.7"), (2, "224.1.2.3")],
        )
        # 刷新 G1@vlan1 至 t=50+100=150
        refreshed = self._sim([
            report(1, "p1", G1, vlan=2),
            report(2, "p2", G1, vlan=1),
            report(3, "p2", G2, vlan=1),
            report(50, "p2", G1, vlan=1),
        ])
        g1_v1 = [
            g for g in refreshed["groups"]
            if g["vlan"] == 1 and g["group"] == "224.1.2.3"
        ][0]
        self.assertEqual(g1_v1["members"], [{"name": "p2", "expires": 150}])
        # t=103：G2 到期(expires 103) 被删；G1@vlan1 仍在，数据命中
        aged = self._sim([
            report(1, "p1", G1, vlan=2),
            report(2, "p2", G1, vlan=1),
            report(3, "p2", G2, vlan=1),
            data_frame(103, "p1", G2, vlan=1),
        ])
        self.assertEqual(aged["results"][-1]["action"], "flood")
        self.assertNotIn(
            (1, "224.5.6.7"),
            [(g["vlan"], g["group"]) for g in aged["groups"]],
        )

    def test_invalid_igmp_does_not_change_state(self):
        result = self._sim([
            report(1, "p1", G1),
            # 类型非法（校验和正确）：igmp_invalid、空转发、计丢弃
            raw_frame(2, "p1", group_mac(G1),
                      ipv4(G1, 2, igmp(0x99, G1))),
            data_frame(3, "p2", G1),
        ])
        invalid = result["results"][1]
        self.assertEqual(invalid["action"], "igmp_invalid")
        self.assertEqual(invalid["ports"], [])
        # t=1 成员仍在：t=3 数据仍命中 multicast
        self.assertEqual(result["results"][2]["action"], "multicast")
        g1 = [g for g in result["groups"] if g["group"] == "224.1.2.3"][0]
        self.assertEqual(g1["members"], [{"name": "p1", "expires": 101}])
        # 丢弃计数：仅非法帧
        p1 = [p for p in result["ports"] if p["name"] == "p1"][0]
        self.assertEqual(p1["drop"], 1)

    def test_fragmented_proto2_is_not_igmp(self):
        result = self._sim([
            raw_frame(1, "p1", group_mac(G1),
                      ipv4(G1, 2, igmp(0x16, G1), fragment=0x2000)),
        ])
        self.assertEqual(result["results"][0]["action"], "flood")
        self.assertEqual(result["groups"], [])

    def test_bad_igmp_checksum_invalid_bad_ip_checksum_floods(self):
        result = self._sim([
            raw_frame(1, "p1", group_mac(G1),
                      ipv4(G1, 2, igmp(0x16, G1, bad_checksum=True))),
        ])
        self.assertEqual(result["results"][0]["action"], "igmp_invalid")
        bad_ip = bytearray(ipv4(G1, 2, igmp(0x16, G1)))
        bad_ip[10] ^= 0xFF
        result = self._sim([
            raw_frame(2, "p1", group_mac(G1), bytes(bad_ip)),
        ])
        self.assertEqual(result["results"][0]["action"], "flood")


class IgmpSnoopLinkTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.cfg = os.path.join(d, "config.json")
        self.evt = os.path.join(d, "events.json")
        self.config = {
            "bridges": ["b1", "b2"],
            "links": [
                {"id": "L1", "x": ["b1", "p1"], "y": ["b2", "p1"],
                 "cost": 1, "up": True},
            ],
            "delay": 2,
            "bridge": "b1",
            "ports": [
                make_port("p1", allowed=[1]),
                make_port("p2", allowed=[1]),
                make_port("p3", allowed=[1]),
            ],
            "age": 1000,
            "max_frame": 1518,
            "igmp": {"membership_age": 100, "router_ports": ["p3"]},
        }
        with open(self.cfg, "w") as handle:
            json.dump(self.config, handle)

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, *args):
        proc = subprocess.run(
            [sys.executable, SWITCH, *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        return proc.returncode, proc.stdout, proc.stderr

    def test_link_down_clears_members(self):
        events = [
            {"t": 0, "id": "L1", "up": True},
            report(10, "p1", G1),
            {"t": 20, "id": "L1", "up": False},
            data_frame(21, "p2", G1),
        ]
        with open(self.evt, "w") as handle:
            json.dump(events, handle)
        code, out, err = self._run("igmp-snoop-decode", self.cfg, self.evt)
        self.assertEqual(code, 0, err)
        result = json.loads(out.decode())
        self.assertEqual(result["results"][0]["action"], "igmp_report")
        # 链路断开后 p1 成员被清除：数据帧回退泛洪
        self.assertEqual(result["results"][-1]["action"], "flood")
        self.assertEqual(result["groups"], [])


class IgmpSnoopRecordTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.cfg = os.path.join(d, "config.json")
        self.evt = os.path.join(d, "events.json")
        self.log = os.path.join(d, "out.log")
        with open(self.cfg, "w") as handle:
            json.dump(make_config(), handle)
        self.events = [report(1, "p1", G1), data_frame(2, "p2", G1)]
        with open(self.evt, "w") as handle:
            json.dump(self.events, handle)

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, *args):
        proc = subprocess.run(
            [sys.executable, SWITCH, *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        return proc.returncode, proc.stdout, proc.stderr

    def test_record_matches_entry_and_replay_byte_identical(self):
        code, direct, err = self._run("igmp-snoop-decode", self.cfg, self.evt)
        self.assertEqual(code, 0, err)
        code, recorded, err = self._run("record", self.cfg, self.evt, self.log)
        self.assertEqual(code, 0, err)
        self.assertEqual(recorded, direct)
        code, replayed, err = self._run("replay", self.log)
        self.assertEqual(code, 0, err)
        self.assertEqual(replayed, recorded)
        # LOG 记录 output 为入口结果项
        doc = json.loads(open(self.log, "rb").read().decode())
        self.assertEqual(
            [r["output"] for r in doc["records"]],
            json.loads(direct.decode())["results"],
        )

    def test_work_boundary(self):
        # B=1、L=0、P=4、U=0、N=2：初始 1；每帧合并费用 (E+P+1)+(N+P+1)
        # 帧1：(0+4+1)+(2+4+1)=12；帧2：(1+4+1)+(2+4+1)=13；合计 26
        total = 1 + 12 + 13
        head = ("1048576", "16777216", "100000", "16777216")
        code, out, err = self._run(
            "igmp-snoop-decode", self.cfg, self.evt, *head, str(total)
        )
        self.assertEqual(code, 0, err)
        code, out, err = self._run(
            "igmp-snoop-decode", self.cfg, self.evt, *head, str(total - 1)
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"igmp_work_limit"}\n')
        # record 同一公式边界
        rec_head = (
            "100000", "16777216", "1048576", "16777216", "16777216",
        )
        code, out, err = self._run(
            "record", self.cfg, self.evt, self.log, *rec_head, str(total - 1)
        )
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"record_work_limit"}\n')
        # 先成功 record 产出 LOG，再测 replay 边界
        code, recorded, err = self._run("record", self.cfg, self.evt, self.log)
        self.assertEqual(code, 0, err)
        code, out, err = self._run(
            "replay", self.log, "100000", "16777216", "16777216",
            str(total - 1),
        )
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"replay_work_limit"}\n')
        code, out, err = self._run(
            "replay", self.log, "100000", "16777216", "16777216",
            str(total),
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(out, recorded)


class IgmpSnoopFailureTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.cfg = os.path.join(d, "config.json")
        self.evt = os.path.join(d, "events.json")
        with open(self.cfg, "w") as handle:
            json.dump(make_config(), handle)
        with open(self.evt, "w") as handle:
            json.dump([], handle)

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, *args):
        proc = subprocess.run(
            [sys.executable, SWITCH, *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        return proc.returncode, proc.stdout, proc.stderr

    def test_bad_config(self):
        for bad in (
            {**make_config(), "igmp": {"membership_age": 0,
                                       "router_ports": ["p3"]}},
            {**make_config(), "igmp": {"membership_age": -1,
                                       "router_ports": ["p3"]}},
            {**make_config(), "igmp": {"membership_age": 100,
                                       "router_ports": ["p2", "p2"]}},
            {**make_config(), "igmp": {"membership_age": 100,
                                       "router_ports": ["nope"]}},
        ):
            with open(self.cfg, "w") as handle:
                json.dump(bad, handle)
            code, _, err = self._run("igmp-snoop-decode", self.cfg, self.evt)
            self.assertEqual(code, 4, err)
        missing = make_config()
        del missing["igmp"]
        with open(self.cfg, "w") as handle:
            json.dump(missing, handle)
        self.assertEqual(
            self._run("igmp-snoop-decode", self.cfg, self.evt)[0], 4
        )

    def test_bad_event(self):
        with open(self.evt, "w") as handle:
            json.dump([{"t": 0, "port": "p1"}], handle)  # 缺 data
        code, _, err = self._run("igmp-snoop-decode", self.cfg, self.evt)
        self.assertEqual(code, 4, err)

    def test_usage_and_file_errors(self):
        code, _, _ = self._run(
            "igmp-snoop-decode", self.cfg, self.evt, "1", "2", "3"
        )
        self.assertEqual(code, 2)
        code, _, err = self._run(
            "igmp-snoop-decode", self.cfg, os.path.join(self.tmp.name, "no"),
        )
        self.assertEqual(code, 3)
        self.assertEqual(err, b'{"error":"file_not_found"}\n')


if __name__ == "__main__":
    unittest.main()
