#!/usr/bin/env python3
"""igmp-snoop-decode 端到端回归。

覆盖：IGMPv2 Report/Leave/Query 识别与动作、成员建立/刷新/老化/删除、
路由端口与无路由口泛洪、Query 始终泛洪、组成员数据按成员+路由端口
转发（排除入端口、保留标签语义）、其余组播泛洪、外层合法但 IGMP
非法固定 igmp_invalid（不改状态、计 drop）、分片/IPv4 头校验失败不
识别为 IGMP、链路断开清成员、groups 键序、record 自动识别与 replay
逐字节复现、igmp 工作量边界（stp-decode 工作量加 N*(N+P+1)）、退出
码 2/3/4/5 与错误名。仅用标准库。
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
SWITCH = os.path.join(HERE, "switch.py")


# ---------------------------------------------------------------------
# 字节构造
# ---------------------------------------------------------------------

def internet_checksum(data):
    if len(data) % 2:
        data = data + b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) | data[index + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ip_header(src, dst, protocol, payload_len, fragment_word=0, ihl=20,
              bad_checksum=False, total_length=None):
    if total_length is None:
        total_length = ihl + payload_len
    header = (
        bytes([0x40 | (ihl // 4), 0x00])
        + total_length.to_bytes(2, "big")
        + b"\x00\x00"
        + fragment_word.to_bytes(2, "big")
        + bytes([1, protocol])
        + b"\x00\x00"
        + bytes(src)
        + bytes(dst)
    )
    checksum = internet_checksum(header)
    if bad_checksum:
        checksum ^= 0xFFFF
    return header[:10] + checksum.to_bytes(2, "big") + header[12:]


def igmp_message(mtype, group, bad_checksum=False, length=8):
    """IGMPv2 8 字节消息；length!=8 时以零字节填充（长度非法场景）。"""
    msg = (
        bytes([mtype, 0x00]) + b"\x00\x00" + bytes(group)
    )
    checksum = internet_checksum(msg)
    if bad_checksum:
        checksum ^= 0xFFFF
    msg = msg[:2] + checksum.to_bytes(2, "big") + msg[4:]
    if length > 8:
        msg += b"\x00" * (length - 8)
    return msg


def ipv4_igmp(mtype, group, src=(10, 0, 0, 1), pad=18, fragment_word=0,
              ip_bad_checksum=False, igmp_bad_checksum=False,
              igmp_length=8, total_length=None):
    iphdr = ip_header(
        src, group, 2, igmp_length, fragment_word=fragment_word,
        bad_checksum=ip_bad_checksum, total_length=total_length,
    )
    return iphdr + igmp_message(
        mtype, group, bad_checksum=igmp_bad_checksum, length=igmp_length
    ) + b"\x00" * pad


def ipv4_udp_like(group, src=(10, 0, 0, 9), udp_len=8):
    payload = b"\x00" * udp_len
    # L2 载荷至少 46 字节：不足处以链路层填充补齐（IPv4 总长度字段不变）
    return ip_header(src, group, 17, len(payload)) + payload + b"\x00" * (
        46 - 20 - len(payload)
    )


def group_mac(group):
    return "01:00:5e:%02x:%02x:%02x" % (group[1] & 0x7F, group[2], group[3])


def raw_frame(t, port, dst, src, payload, vlan=None, ethertype=0x0800,
              bad_fcs=False):
    d = bytes(int(x, 16) for x in dst.split(":"))
    s = bytes(int(x, 16) for x in src.split(":"))
    if vlan is None:
        head = d + s + ethertype.to_bytes(2, "big")
    else:
        head = (
            d + s + b"\x81\x00" + vlan.to_bytes(2, "big")
            + ethertype.to_bytes(2, "big")
        )
    body = head + payload
    fcs = (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little")
    if bad_fcs:
        fcs = b"\xff\xff\xff\xff"
    return {"t": t, "port": port, "data": (body + fcs).hex()}


def link_event(t, lid, up):
    return {"t": t, "id": lid, "up": up}


# ---------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------

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


def make_config(ports=None, membership_age=50, router_ports=("p1",),
                bridges=("b1",), links=None, delay=2):
    if ports is None:
        ports = [
            make_port("p1", allowed=[1, 2]),
            make_port("p2", allowed=[1, 2]),
            make_port("p3", allowed=[1, 2]),
            make_port("p4", mode="hybrid", allowed=[1, 2], untagged=[1]),
        ]
    return {
        "bridges": list(bridges),
        "links": links or [],
        "delay": delay,
        "bridge": "b1",
        "ports": ports,
        "age": 100,
        "max_frame": 1518,
        "igmp": {
            "membership_age": membership_age,
            "router_ports": list(router_ports),
        },
    }


G1 = (224, 1, 2, 3)
G2 = (224, 1, 2, 2)
G3 = (224, 0, 0, 5)


class IgmpSnoopCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.cfg = os.path.join(d, "config.json")
        self.evt = os.path.join(d, "events.json")
        self.log = os.path.join(d, "out.log")

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, config, events):
        with open(self.cfg, "wb") as handle:
            handle.write(json.dumps(config).encode())
        with open(self.evt, "wb") as handle:
            handle.write(json.dumps(events).encode())

    def run_cmd(self, *args):
        proc = subprocess.run(
            [sys.executable, SWITCH, *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        return proc.returncode, proc.stdout, proc.stderr

    def simulate(self, config, events):
        self.write(config, events)
        code, out, err = self.run_cmd(
            "igmp-snoop-decode", self.cfg, self.evt
        )
        self.assertEqual(code, 0, err)
        return json.loads(out.decode())

    def report(self, t, port, group, vlan=1, bad_fcs=False, **kwargs):
        return raw_frame(
            t, port, group_mac(group), "02:00:00:00:00:01",
            ipv4_igmp(0x16, group, **kwargs), vlan=vlan, bad_fcs=bad_fcs,
        )

    def leave(self, t, port, group, vlan=1, **kwargs):
        return raw_frame(
            t, port, group_mac(group), "02:00:00:00:00:01",
            ipv4_igmp(0x17, group, **kwargs), vlan=vlan,
        )

    def query(self, t, port, group=(224, 0, 0, 1), vlan=1, **kwargs):
        return raw_frame(
            t, port, group_mac(group), "02:00:00:00:00:fe",
            ipv4_igmp(0x11, group, **kwargs), vlan=vlan,
        )

    def data_frame(self, t, port, group, src="02:00:00:00:00:09",
                   vlan=1, dst=None, payload=None):
        return raw_frame(
            t, port, dst if dst is not None else group_mac(group), src,
            payload if payload is not None else ipv4_udp_like(group),
            vlan=vlan,
        )


class IgmpControlTest(IgmpSnoopCase):
    def test_report_to_router_only_and_member_delivery(self):
        # Report 仅发往同 VLAN 可转发路由端口 p1（trunk，带标签）；
        # 随后组成员数据发往成员 p2 与路由 p1，排除入端口 p3
        config = make_config(router_ports=("p1",))
        events = [
            self.report(1, "p2", G1),
            self.data_frame(2, "p3", G1, src="02:00:00:00:00:09"),
        ]
        result = self.simulate(config, events)
        actions = [(r["t"], r["action"]) for r in result["results"]]
        self.assertEqual(actions, [(1, "igmp_report"), (2, "multicast")])
        self.assertEqual(
            result["results"][0]["ports"], [{"name": "p1", "vlan": 1}]
        )
        # trunk 端口均保留标签（vlan=1）
        self.assertEqual(
            result["results"][1]["ports"],
            [{"name": "p1", "vlan": 1}, {"name": "p2", "vlan": 1}],
        )

    def test_member_delivery_untagged_semantics(self):
        # 成员端口 p4 为 hybrid 且 vlan1 在 untagged：输出去标签（null）
        config = make_config(router_ports=("p1",))
        events = [
            self.report(1, "p4", G1),
            self.data_frame(2, "p3", G1, src="02:00:00:00:00:09"),
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            result["results"][1]["ports"],
            [{"name": "p1", "vlan": 1}, {"name": "p4", "vlan": None}],
        )

    def test_report_floods_without_eligible_router(self):
        # 无路由端口时 Report 泛洪（排除入端口），动作仍为 igmp_report
        config = make_config(router_ports=())
        events = [self.report(1, "p2", G1)]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][0]["action"], "igmp_report")
        self.assertEqual(
            [p["name"] for p in result["results"][0]["ports"]],
            ["p1", "p3", "p4"],
        )

    def test_ingress_router_excluded_then_floods(self):
        # 唯一路由端口即入端口：合格路由端口为空 -> 泛洪
        config = make_config(router_ports=("p2",))
        events = [self.report(1, "p2", G1)]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][0]["action"], "igmp_report")
        self.assertEqual(
            [p["name"] for p in result["results"][0]["ports"]],
            ["p1", "p3", "p4"],
        )

    def test_query_always_floods(self):
        # Query 始终泛洪，即使存在路由端口，也不建立成员
        config = make_config(router_ports=("p1",))
        events = [self.query(1, "p2", G1)]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][0]["action"], "igmp_query")
        self.assertEqual(
            [p["name"] for p in result["results"][0]["ports"]],
            ["p1", "p3", "p4"],
        )
        self.assertEqual(result["groups"], [])

    def test_leave_deletes_member_immediately(self):
        config = make_config(router_ports=("p1",))
        events = [
            self.report(1, "p2", G1),
            self.data_frame(2, "p3", G1, src="02:00:00:00:00:09"),
            self.leave(3, "p2", G1),
            self.data_frame(4, "p3", G1, src="02:00:00:00:00:09"),
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            [r["action"] for r in result["results"]],
            ["igmp_report", "multicast", "igmp_leave", "flood"],
        )
        # Leave 只发路由端口
        self.assertEqual(
            result["results"][2]["ports"], [{"name": "p1", "vlan": 1}]
        )
        self.assertEqual(result["groups"], [])

    def test_leave_for_one_member_keeps_others(self):
        config = make_config(router_ports=("p1",))
        events = [
            self.report(1, "p2", G1),
            self.report(2, "p3", G1),
            self.leave(3, "p2", G1),
            self.data_frame(4, "p4", G1, src="02:00:00:00:00:09"),
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][3]["action"], "multicast")
        self.assertEqual(
            [p["name"] for p in result["results"][3]["ports"]],
            ["p1", "p3"],
        )
        groups = result["groups"]
        self.assertEqual(len(groups), 1)
        self.assertEqual(
            [m["name"] for m in groups[0]["members"]], ["p3"]
        )

    def test_membership_refresh_extends_expiry(self):
        config = make_config(membership_age=50, router_ports=("p1",))
        events = [
            self.report(1, "p2", G1),
            self.report(10, "p2", G1),
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            result["groups"][0]["members"],
            [{"name": "p2", "expires": 60}],
        )

    def test_membership_expiry_before_event(self):
        config = make_config(membership_age=50, router_ports=("p1",))
        events = [
            self.report(1, "p2", G1),
            self.data_frame(50, "p3", G1, src="02:00:00:00:00:09"),
            self.data_frame(51, "p3", G1, src="02:00:00:00:00:09"),
        ]
        result = self.simulate(config, events)
        # t=50 时 expires=51 未到期；t=51 事件前清除 -> 泛洪
        self.assertEqual(
            [r["action"] for r in result["results"][1:]],
            ["multicast", "flood"],
        )
        self.assertEqual(result["groups"], [])

    def test_membership_scoped_by_vlan(self):
        config = make_config(router_ports=("p1",))
        events = [
            self.report(1, "p2", G1, vlan=1),
            self.data_frame(2, "p3", G1, vlan=2,
                            src="02:00:00:00:00:09"),
            self.data_frame(3, "p3", G1, vlan=1,
                            src="02:00:00:00:00:09"),
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            [r["action"] for r in result["results"]],
            ["igmp_report", "flood", "multicast"],
        )
        self.assertEqual(result["groups"][0]["vlan"], 1)

    def test_unknown_multicast_and_bad_mapping_flood(self):
        config = make_config(router_ports=("p1",))
        events = [
            self.report(1, "p2", G1),
            # 同组但目的 MAC 映射不一致：即使有成员也泛洪
            self.data_frame(
                2, "p3", G1, dst="01:00:5e:7f:02:03",
                src="02:00:00:00:00:09",
            ),
            # 其他组无成员：泛洪
            self.data_frame(3, "p3", G2, src="02:00:00:00:00:09"),
            # 非 IPv4 组播：泛洪
            raw_frame(
                4, "p3", "01:80:c2:00:00:00", "02:00:00:00:00:09",
                b"\x00" * 46, ethertype=0x0806,
            ),
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            [r["action"] for r in result["results"][1:]],
            ["flood", "flood", "flood"],
        )

    def test_groups_ordered_by_vlan_then_ipv4_members_by_port_order(self):
        config = make_config(router_ports=("p1",))
        events = [
            self.report(1, "p3", G1),
            self.report(2, "p2", G1),
            self.report(3, "p2", G2),
            self.report(4, "p2", G3, vlan=2),
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            [(g["vlan"], g["group"]) for g in result["groups"]],
            [(1, "224.1.2.2"), (1, "224.1.2.3"), (2, "224.0.0.5")],
        )
        # 成员按配置端口序（p2 在 p3 前），expires 为绝对时刻
        self.assertEqual(
            result["groups"][1]["members"],
            [
                {"name": "p2", "expires": 52},
                {"name": "p3", "expires": 51},
            ],
        )

    def test_output_key_order(self):
        config = make_config(router_ports=("p1",))
        events = [self.report(1, "p2", G1)]
        self.write(config, events)
        code, out, err = self.run_cmd(
            "igmp-snoop-decode", self.cfg, self.evt
        )
        self.assertEqual(code, 0, err)
        text = out.decode()
        self.assertIn(
            '"results":[{"t":1,"class":"good","action":"igmp_report",'
            '"ports":[{"name":"p1","vlan":1}]',
            text,
        )
        result = json.loads(text)
        self.assertEqual(list(result), ["results", "ports", "vlans", "groups"])
        self.assertEqual(
            list(result["groups"][0]), ["vlan", "group", "members"]
        )
        self.assertEqual(list(result["groups"][0]["members"][0]),
                         ["name", "expires"])
        self.assertEqual(list(result["ports"][0]),
                         ["name", "rx", "tx", "drop", "good", "runt",
                          "giant", "alignment", "bad_fcs"])
        self.assertEqual(list(result["vlans"][0]),
                         ["vlan", "rx", "tx", "drop"])


class IgmpInvalidTest(IgmpSnoopCase):
    def _invalid(self, events):
        config = make_config(router_ports=("p1",))
        result = self.simulate(config, events)
        return result

    def test_bad_igmp_checksum_is_invalid_and_no_state(self):
        events = [
            self.report(1, "p2", G1, igmp_bad_checksum=True),
            self.data_frame(2, "p3", G1, src="02:00:00:00:00:09"),
        ]
        result = self._invalid(events)
        self.assertEqual(result["results"][0]["action"], "igmp_invalid")
        self.assertEqual(result["results"][0]["ports"], [])
        self.assertEqual(result["results"][1]["action"], "flood")
        self.assertEqual(result["groups"], [])
        # 计入丢弃：入端口 drop=1、VLAN drop=1
        self.assertEqual(result["ports"][1]["drop"], 1)
        self.assertEqual(result["vlans"][0]["drop"], 1)

    def test_bad_igmp_type_is_invalid(self):
        events = [
            self.report(1, "p2", G1),
            raw_frame(
                2, "p3", group_mac(G1), "02:00:00:00:00:01",
                ipv4_igmp(0x22, G1), vlan=1,
            ),
        ]
        result = self._invalid(events)
        self.assertEqual(result["results"][1]["action"], "igmp_invalid")
        # 既有成员不受影响
        self.assertEqual(
            [g["group"] for g in result["groups"]], ["224.1.2.3"]
        )

    def test_report_non_class_d_group_is_invalid(self):
        events = [self.report(1, "p2", (240, 1, 2, 3))]
        result = self._invalid(events)
        self.assertEqual(result["results"][0]["action"], "igmp_invalid")
        self.assertEqual(result["groups"], [])

    def test_query_group_address_rules(self):
        # 组特定查询：D 类合法
        events = [self.query(1, "p2", G1)]
        result = self._invalid(events)
        self.assertEqual(result["results"][0]["action"], "igmp_query")
        # 非 D 类且非 0.0.0.0：非法
        events = [self.query(1, "p2", (1, 2, 3, 4))]
        result = self._invalid(events)
        self.assertEqual(result["results"][0]["action"], "igmp_invalid")
        # 通用查询 0.0.0.0 合法（始终泛洪）
        events = [
            raw_frame(
                1, "p2", "01:00:5e:00:00:01", "02:00:00:00:00:fe",
                ipv4_igmp(0x11, (0, 0, 0, 0)), vlan=1,
            ),
        ]
        result = self._invalid(events)
        self.assertEqual(result["results"][0]["action"], "igmp_query")

    def test_igmp_length_invalid(self):
        # IPv4 总长度仅 24 字节（20 头 + 4）：容纳不了 8 字节 IGMP
        events = [
            raw_frame(
                1, "p2", group_mac(G1), "02:00:00:00:00:01",
                ipv4_igmp(0x16, G1, total_length=24), vlan=1,
            ),
        ]
        result = self._invalid(events)
        self.assertEqual(result["results"][0]["action"], "igmp_invalid")
        # IGMP 消息 12 字节：长度非法
        events = [
            raw_frame(
                1, "p2", group_mac(G1), "02:00:00:00:00:01",
                ipv4_igmp(0x16, G1, igmp_length=12, pad=14), vlan=1,
            ),
        ]
        result = self._invalid(events)
        self.assertEqual(result["results"][0]["action"], "igmp_invalid")
        self.assertEqual(result["groups"], [])

    def test_fragmented_report_not_recognized(self):
        # MF=1 分片：不识别为 IGMP，不建成员；随后数据泛洪
        events = [
            self.report(1, "p2", G1, fragment_word=0x2000),
            self.data_frame(2, "p3", G1, src="02:00:00:00:00:09"),
        ]
        result = self._invalid(events)
        self.assertEqual(result["results"][0]["action"], "flood")
        self.assertEqual(result["results"][1]["action"], "flood")
        self.assertEqual(result["groups"], [])

    def test_bad_ipv4_header_checksum_not_recognized(self):
        events = [
            self.report(1, "p2", G1, ip_bad_checksum=True),
            self.data_frame(2, "p3", G1, src="02:00:00:00:00:09"),
        ]
        result = self._invalid(events)
        self.assertEqual(result["results"][0]["action"], "flood")
        self.assertEqual(result["groups"], [])


class IgmpAdmitTest(IgmpSnoopCase):
    def test_bad_fcs_and_vlan_reject_never_reach_igmp(self):
        config = make_config(router_ports=("p1",))
        bad = self.report(1, "p2", G1, bad_fcs=True)
        # p2 允许 1、2：vlan3 准入拒绝
        tagged = self.report(2, "p2", G1, vlan=3)
        events = [bad, tagged, self.report(3, "p2", G1)]
        result = self.simulate(config, events)
        self.assertEqual(
            [(r["class"], r["action"]) for r in result["results"]],
            [("bad_fcs", "drop"), ("good", "drop"),
             ("good", "igmp_report")],
        )

    def test_igmp_on_non_forwarding_port_ignored(self):
        # 两桥拓扑：p1 为桥链路口，delay=1，t=0 处于 discarding；
        # 其上 Report 不识别（动作 drop），成员不建立；t=2 已 forwarding
        links = [
            {"id": "L1", "x": ["b1", "p1"], "y": ["b2", "p1"],
             "cost": 1, "up": True},
        ]
        ports = [
            make_port("p1", allowed=[1, 2]),
            make_port("p2", allowed=[1, 2]),
            make_port("p3", allowed=[1, 2]),
        ]
        config = make_config(
            ports=ports, router_ports=("p2",), bridges=("b1", "b2"),
            links=links, delay=1,
        )
        events = [
            self.report(0, "p1", G1),
            self.data_frame(2, "p3", G1, src="02:00:00:00:00:09"),
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][0]["action"], "drop")
        self.assertEqual(result["results"][1]["action"], "flood")
        self.assertEqual(result["groups"], [])

    def test_link_down_clears_membership_on_port(self):
        # p1 在 t>=2 进入 forwarding；Report 建成员后链路断开，
        # 该端口成员立即清除
        links = [
            {"id": "L1", "x": ["b1", "p1"], "y": ["b2", "p1"],
             "cost": 1, "up": True},
        ]
        ports = [
            make_port("p1", allowed=[1, 2]),
            make_port("p2", allowed=[1, 2]),
            make_port("p3", allowed=[1, 2]),
        ]
        config = make_config(
            ports=ports, router_ports=("p2",), bridges=("b1", "b2"),
            links=links, delay=1,
        )
        events = [
            self.report(2, "p1", G1),
            self.data_frame(3, "p3", G1, src="02:00:00:00:00:09"),
            link_event(4, "L1", False),
            self.data_frame(5, "p3", G1, src="02:00:00:00:00:09"),
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][0]["action"], "igmp_report")
        self.assertEqual(result["results"][1]["action"], "multicast")
        self.assertEqual(result["results"][2]["action"], "flood")
        self.assertEqual(result["groups"], [])


class IgmpRecordTest(IgmpSnoopCase):
    def _config_events(self):
        config = make_config(router_ports=("p1",))
        events = [
            self.report(1, "p2", G1),
            self.data_frame(2, "p3", G1, src="02:00:00:00:00:09"),
            self.leave(3, "p2", G1),
            self.query(4, "p2", G1),
        ]
        return config, events

    def test_record_auto_detects_and_replay_byte_identical(self):
        config, events = self._config_events()
        self.write(config, events)
        code, direct, err = self.run_cmd(
            "igmp-snoop-decode", self.cfg, self.evt
        )
        self.assertEqual(code, 0, err)
        rec = subprocess.run(
            [sys.executable, SWITCH, "record", self.cfg, self.evt,
             self.log],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(rec.returncode, 0, rec.stderr)
        self.assertEqual(rec.stdout, direct)
        code, out, err = self.run_cmd("replay", self.log)
        self.assertEqual((code, out, err), (0, direct, b""))
        # LOG 契约：config 原样保留（含 igmp），output 为结果项，
        # 帧恒 applied；无链路项 version 恒 0
        with open(self.log, "rb") as handle:
            doc = json.loads(handle.read().decode())
        self.assertEqual(doc["config"], config)
        self.assertEqual(len(doc["records"]), 4)
        self.assertTrue(all(r["applied"] for r in doc["records"]))
        self.assertTrue(all(r["version"] == 0 for r in doc["records"]))
        self.assertEqual(
            [r["output"]["action"] for r in doc["records"]],
            ["igmp_report", "multicast", "igmp_leave", "igmp_query"],
        )

    def test_link_version_and_byte_rebuild(self):
        links = [
            {"id": "L1", "x": ["b1", "p1"], "y": ["b2", "p1"],
             "cost": 1, "up": True},
        ]
        ports = [
            make_port("p1", allowed=[1, 2]),
            make_port("p2", allowed=[1, 2]),
            make_port("p3", allowed=[1, 2]),
        ]
        config = make_config(
            ports=ports, router_ports=("p2",), bridges=("b1", "b2"),
            links=links, delay=1,
        )
        events = [
            link_event(0, "L1", True),   # 幂等：version 0
            self.report(3, "p1", G1),
            link_event(5, "L1", False),  # applied：version 1
        ]
        self.write(config, events)
        rec = subprocess.run(
            [sys.executable, SWITCH, "record", self.cfg, self.evt,
             self.log],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(rec.returncode, 0, rec.stderr)
        with open(self.log, "rb") as handle:
            original = handle.read()
        code, out, err = self.run_cmd("replay", self.log)
        self.assertEqual(code, 0, err)
        self.assertEqual(out, rec.stdout)
        with open(self.log, "rb") as handle:
            self.assertEqual(handle.read(), original)
        doc = json.loads(original.decode())
        self.assertEqual(
            [(r["applied"], r["version"]) for r in doc["records"]],
            [(False, 0), (True, 0), (True, 1)],
        )


class IgmpBillingTest(IgmpSnoopCase):
    # B=1、L=0、P=4：初始 1；三帧 E=0,1,2 计 5+6+7；stp 部分 19。
    # igmp 附加 N*(N+P+1)=3*8=24；总计 43。
    TOTAL = 43

    def _write_basic(self):
        config = make_config(router_ports=("p1",))
        events = [
            self.report(1, "p2", G1),
            self.data_frame(2, "p3", G1, src="02:00:00:00:00:09"),
            self.query(3, "p2", G1),
        ]
        self.write(config, events)

    def test_entry_work_boundary(self):
        self._write_basic()
        head = ("1048576", "16777216", "100000", "16777216")
        code, ok, err = self.run_cmd(
            "igmp-snoop-decode", self.cfg, self.evt, *head,
            str(self.TOTAL),
        )
        self.assertEqual(code, 0, err)
        code, out, err = self.run_cmd(
            "igmp-snoop-decode", self.cfg, self.evt, *head,
            str(self.TOTAL - 1),
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"igmp_work_limit"}\n')
        # 未给工作量上限时按默认值执行
        code, out, err = self.run_cmd(
            "igmp-snoop-decode", self.cfg, self.evt
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(out, ok)

    def test_record_replay_work_boundary(self):
        self._write_basic()
        head = ("100000", "16777216", "1048576", "16777216", "16777216")
        code, out, err = self.run_cmd(
            "record", self.cfg, self.evt, self.log, *head,
            str(self.TOTAL),
        )
        self.assertEqual(code, 0, err)
        record_out = out
        code, out, err = self.run_cmd(
            "record", self.cfg, self.evt, self.log, *head,
            str(self.TOTAL - 1),
        )
        self.assertEqual(
            (code, out, err),
            (5, b"", b'{"error":"record_work_limit"}\n'),
        )
        code, out, err = self.run_cmd(
            "replay", self.log, "100000", "16777216", "16777216",
            str(self.TOTAL),
        )
        self.assertEqual((code, out, err), (0, record_out, b""))
        code, out, err = self.run_cmd(
            "replay", self.log, "100000", "16777216", "16777216",
            str(self.TOTAL - 1),
        )
        self.assertEqual(
            (code, out, err),
            (5, b"", b'{"error":"replay_work_limit"}\n'),
        )


class IgmpFailureTest(IgmpSnoopCase):
    def base_config(self):
        return make_config(router_ports=("p1",))

    def test_usage_exit_2(self):
        self.write(self.base_config(), [])
        code, out, err = self.run_cmd(
            "igmp-snoop-decode", self.cfg, self.evt, "1048576",
        )
        self.assertEqual((code, out), (2, b""))
        code, out, err = self.run_cmd("igmp-snoop-decode")
        self.assertEqual((code, out), (2, b""))
        code, out, err = self.run_cmd(
            "igmp-snoop-decode", self.cfg, self.evt,
            "1048576", "16777216", "100000", "16777216", "zero",
        )
        self.assertEqual((code, out), (2, b""))

    def test_missing_file_exit_3(self):
        code, out, err = self.run_cmd(
            "igmp-snoop-decode",
            os.path.join(self.tmp.name, "nope.json"), self.evt,
        )
        self.assertEqual((code, out), (3, b""))
        self.assertEqual(err, b'{"error":"file_not_found"}\n')

    def test_bad_config_exit_4(self):
        cases = []
        bad_age = self.base_config()
        bad_age["igmp"] = {"membership_age": 0, "router_ports": ["p1"]}
        cases.append(bad_age)
        dup = self.base_config()
        dup["igmp"] = {"membership_age": 5, "router_ports": ["p1", "p1"]}
        cases.append(dup)
        unknown = self.base_config()
        unknown["igmp"] = {"membership_age": 5, "router_ports": ["px"]}
        cases.append(unknown)
        missing = {
            key: self.base_config()[key]
            for key in ("bridges", "links", "delay", "bridge", "ports",
                        "age", "max_frame")
        }
        cases.append(missing)
        extra = dict(self.base_config())
        extra["extra"] = 1
        cases.append(extra)
        bad_shape = dict(self.base_config())
        bad_shape["igmp"] = [5, ["p1"]]
        cases.append(bad_shape)
        for config in cases:
            self.write(config, [])
            code, out, err = self.run_cmd(
                "igmp-snoop-decode", self.cfg, self.evt
            )
            self.assertEqual((code, out), (4, b""), config)
            self.assertEqual(err, b'{"error":"invalid_input"}\n')

    def test_bad_events_exit_4(self):
        # 双标签帧为非法输入（沿用 stp-decode 外壳校验）
        double = self.report(0, "p2", G1) if False else None
        raw = bytes.fromhex(
            raw_frame(
                0, "p2", group_mac(G1), "02:00:00:00:00:01",
                ipv4_igmp(0x16, G1), vlan=1,
            )["data"]
        )
        double = raw[:16] + b"\x81\x00\x10\x00" + raw[16:]
        events = [{"t": 0, "port": "p2", "data": double.hex()}]
        self.write(self.base_config(), events)
        code, out, err = self.run_cmd(
            "igmp-snoop-decode", self.cfg, self.evt
        )
        self.assertEqual((code, out), (4, b""))

    def test_resource_limits_exit_5(self):
        config = make_config(router_ports=("p1",))
        events = [self.report(1, "p2", G1)]
        self.write(config, events)
        # item_limit：仅给 2、4、5 项上限时第三项为最大事件数
        code, out, err = self.run_cmd(
            "igmp-snoop-decode", self.cfg, self.evt,
            "1048576", "16777216", "0", "16777216",
        )
        # 0 不匹配 [1-9][0-9]* -> usage 2
        self.assertEqual(code, 2)
        code, out, err = self.run_cmd(
            "igmp-snoop-decode", self.cfg, self.evt,
            "1048576", "16777216",
        )
        self.assertEqual(code, 0, err)
        # config 字节上限：配置本身约数百字节
        code, out, err = self.run_cmd(
            "igmp-snoop-decode", self.cfg, self.evt,
            "50", "16777216",
        )
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"config_limit"}\n')

    def test_invalid_config_record_exit_4_no_log(self):
        bad = self.base_config()
        bad["igmp"] = {"membership_age": -1, "router_ports": ["p1"]}
        self.write(bad, [])
        code, out, err = self.run_cmd(
            "record", self.cfg, self.evt, self.log
        )
        self.assertEqual((code, out), (4, b""))
        self.assertFalse(os.path.exists(self.log))


if __name__ == "__main__":
    unittest.main()
