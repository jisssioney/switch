#!/usr/bin/env python3
"""igmp/mld-snoop-decode 增强模式 router_age 端到端回归。

覆盖：三键对象启用按 VLAN 动态发现组播路由端口（Query 登记/刷新、静态
端口不重复、VLAN 隔离、过期删除、出 forwarding/链路断开立即清除、坏帧/
非法查询/准入拒绝/discarding/learning 不登记），Report/Leave/Done/源
过滤组播数据按静态并动态路由端口转发，Query 仍泛洪；routers 键序与
排序（VLAN 升序、端口配置序、vlan/name/expires）；两键对象兼容模式
输出逐字节不变（无 routers 键）；router_age 全量校验（缺失/布尔/非正
整数/null/未知键 -> invalid_input 退出 4，无部分 stdout）；record/
replay/log 模式识别并逐字节复现。仅用标准库。
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

from test_igmp_snoop_decode import (  # noqa: E402
    G1,
    IgmpSnoopCase,
    make_config,
    make_port,
    link_event,
    group_mac,
    ipv4_igmp,
    raw_frame,
)


def internet_checksum(data):
    if len(data) % 2:
        data = data + b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) | data[index + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


# ---------------------------------------------------------------------
# MLD 字节构造
# ---------------------------------------------------------------------

MLD_SRC = bytes([0xFE, 0x80]) + b"\x00" * 13 + bytes([1])
MLD_DST = bytes([0xFF, 0x02]) + b"\x00" * 13 + bytes([1])
MLDV1_REPORT_GROUP = bytes([0xFF, 0x02]) + b"\x00" * 13 + bytes([5])


def icmpv6_checksum(src, dst, body):
    pseudo = (
        bytes(src) + bytes(dst)
        + len(body).to_bytes(4, "big")
        + b"\x00\x00\x00\x3a"
    )
    data = pseudo + body
    if len(data) % 2:
        data = data + b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) | data[index + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def mld_message(mtype, group, bad_checksum=False):
    """24 字节 MLDv1 报文：8 字节定长头 + 16 字节组地址。"""
    body = (
        bytes([mtype, 0x00]) + b"\x00\x00" + b"\x00\x00\x00\x00"
        + bytes(group)
    )
    checksum = icmpv6_checksum(MLD_SRC, MLD_DST, body)
    if bad_checksum:
        checksum ^= 0xFFFF
    return body[:2] + checksum.to_bytes(2, "big") + body[4:]


def ipv6_mld(body):
    """带 8 字节 Hop-by-Hop（Pad1 + Router Alert(0x0000) + Pad1）的 IPv6
    帧载荷；Hop Limit=1，下一首部 58(ICMPv6)。"""
    hbh = bytes([58, 0, 0, 5, 2, 0, 0, 0])
    header = (
        b"\x60\x00\x00\x00"
        + (len(hbh) + len(body)).to_bytes(2, "big")
        + bytes([0, 1])
        + MLD_SRC
        + MLD_DST
    )
    return header + hbh + body


def mld_frame(t, port, body, vlan=1, bad_fcs=False):
    dst_mac = b"\x33\x33" + MLD_DST[12:16]
    head = (
        dst_mac + b"\x02\x00\x00\x00\x00\x0f"
        + b"\x81\x00" + vlan.to_bytes(2, "big")
        + (0x86DD).to_bytes(2, "big")
        + ipv6_mld(body)
    )
    fcs = (zlib.crc32(head) & 0xFFFFFFFF).to_bytes(4, "little")
    if bad_fcs:
        fcs = b"\xff\xff\xff\xff"
    return {"t": t, "port": port, "data": (head + fcs).hex()}


class RouterAgeIgmpTest(IgmpSnoopCase):
    def enhanced_config(self, router_ports=("p1",), router_age=30, **kwargs):
        config = make_config(router_ports=router_ports, **kwargs)
        config["igmp"]["router_age"] = router_age
        return config

    def test_query_registers_dynamic_router_and_report_uses_union(self):
        config = self.enhanced_config()
        events = [
            self.query(1, "p2"),
            self.report(2, "p3", G1),
        ]
        result = self.simulate(config, events)
        # Report 发往静态 p1 与本 VLAN 动态 p2（配置序）
        self.assertEqual(
            [p["name"] for p in result["results"][1]["ports"]],
            ["p1", "p2"],
        )
        self.assertEqual(
            result["routers"], [{"vlan": 1, "name": "p2", "expires": 31}]
        )
        self.assertEqual(
            list(result),
            ["results", "ports", "vlans", "groups", "routers"],
        )

    def test_query_refresh_only_extends_same_vlan_entry(self):
        config = self.enhanced_config()
        events = [
            self.query(1, "p2"),
            self.query(10, "p2"),
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            result["routers"], [{"vlan": 1, "name": "p2", "expires": 40}]
        )

    def test_entries_scoped_by_vlan(self):
        config = self.enhanced_config()
        events = [
            self.query(1, "p2", vlan=2),
            self.query(2, "p2", vlan=1),
            self.report(3, "p3", G1, vlan=1),
            self.report(4, "p3", G1, vlan=2),
        ]
        result = self.simulate(config, events)
        # vlan1 的 Report 只去静态 p1 + 动态 p2；vlan2 同样含 p2
        self.assertEqual(
            [p["name"] for p in result["results"][2]["ports"]], ["p1", "p2"]
        )
        self.assertEqual(
            [p["name"] for p in result["results"][3]["ports"]], ["p1", "p2"]
        )
        # routers 按 VLAN 升序，过期时刻各自独立
        self.assertEqual(
            result["routers"],
            [
                {"vlan": 1, "name": "p2", "expires": 32},
                {"vlan": 2, "name": "p2", "expires": 31},
            ],
        )

    def test_static_router_query_creates_no_dynamic_entry(self):
        config = self.enhanced_config(router_ports=("p1",))
        result = self.simulate(config, [self.query(1, "p1")])
        self.assertEqual(result["routers"], [])

    def test_expiry_boundary_purge_before_event(self):
        config = self.enhanced_config(router_ports=())
        # expires=31：t=30 仍有效，Report 仅发往动态 p2；
        # t=31 事件前删除 -> 无合格路由端口 -> 泛洪
        events = [self.query(1, "p2"), self.report(30, "p3", G1)]
        result = self.simulate(config, events)
        self.assertEqual(
            [p["name"] for p in result["results"][1]["ports"]], ["p2"]
        )
        events = [self.query(1, "p2"), self.report(31, "p3", G1)]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][1]["action"], "igmp_report")
        self.assertEqual(
            [p["name"] for p in result["results"][1]["ports"]],
            ["p1", "p2", "p4"],
        )
        self.assertEqual(result["routers"], [])

    def test_multicast_data_uses_union_and_member_filter(self):
        config = self.enhanced_config()
        events = [
            self.query(1, "p2"),
            self.report(2, "p4", G1),
            self.data_frame(3, "p3", G1, src="02:00:00:00:00:09"),
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            [p["name"] for p in result["results"][2]["ports"]],
            ["p1", "p2", "p4"],
        )

    def test_query_still_floods_and_keeps_action(self):
        config = self.enhanced_config()
        result = self.simulate(config, [self.query(1, "p2")])
        self.assertEqual(result["results"][0]["action"], "igmp_query")
        self.assertEqual(
            [p["name"] for p in result["results"][0]["ports"]],
            ["p1", "p3", "p4"],
        )

    def test_routers_sorted_by_vlan_then_port_order(self):
        config = self.enhanced_config()
        events = [
            self.query(1, "p4", vlan=1),
            self.query(2, "p2", vlan=2),
            self.query(3, "p3", vlan=1),
            self.query(4, "p3", vlan=2),
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            [(r["vlan"], r["name"]) for r in result["routers"]],
            [(1, "p3"), (1, "p4"), (2, "p2"), (2, "p3")],
        )
        for entry in result["routers"]:
            self.assertEqual(list(entry), ["vlan", "name", "expires"])

    def test_empty_routers_is_empty_array(self):
        config = self.enhanced_config()
        self.write(config, [self.report(1, "p3", G1)])
        code, out, err = self.run_cmd(
            "igmp-snoop-decode", self.cfg, self.evt
        )
        self.assertEqual(code, 0, err)
        self.assertIn(b'"routers":[]', out)

    def test_bad_fcs_invalid_query_and_vlan_reject_never_register(self):
        config = self.enhanced_config()
        bad_query = raw_frame(
            1, "p2", group_mac((224, 0, 0, 1)), "02:00:00:00:00:fe",
            ipv4_igmp(0x11, (224, 0, 0, 1)), vlan=1, bad_fcs=True,
        )
        events = [
            bad_query,
            self.query(2, "p2", igmp_bad_checksum=True),
            self.query(3, "p2", vlan=3),  # p2 不允许 vlan3
            self.report(4, "p3", G1),
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][0]["action"], "drop")
        self.assertEqual(result["results"][1]["action"], "igmp_invalid")
        self.assertEqual(result["results"][2]["action"], "drop")
        # 无动态项：静态 p1 是唯一路由端口
        self.assertEqual(
            [p["name"] for p in result["results"][3]["ports"]], ["p1"]
        )
        self.assertEqual(result["routers"], [])

    def _bridge_config(self):
        links = [
            {"id": "L1", "x": ["b1", "p1"], "y": ["b2", "p1"],
             "cost": 1, "up": True},
        ]
        ports = [
            make_port("p1", allowed=[1, 2]),
            make_port("p2", allowed=[1, 2]),
            make_port("p3", allowed=[1, 2]),
        ]
        return self.enhanced_config(
            ports=ports, router_ports=("p2",), bridges=("b1", "b2"),
            links=links, delay=1, router_age=100,
        )

    def test_discarding_learning_ports_never_register(self):
        config = self._bridge_config()
        # delay=1：t=0 discarding（丢弃），t=1 learning（不解析），
        # t>=2 forwarding
        events = [
            self.query(0, "p1"),
            self.query(1, "p1"),
            self.report(2, "p3", G1),
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][0]["action"], "drop")
        self.assertEqual(result["results"][1]["action"], "drop")
        self.assertEqual(
            [p["name"] for p in result["results"][2]["ports"]], ["p2"]
        )
        self.assertEqual(result["routers"], [])

    def test_link_down_clears_dynamic_entries(self):
        config = self._bridge_config()
        events = [
            self.query(2, "p1"),
            link_event(3, "L1", False),
            self.report(4, "p3", G1),
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["routers"], [])
        self.assertEqual(
            [p["name"] for p in result["results"][1]["ports"]], ["p2"]
        )

    def test_leave_uses_union(self):
        config = self.enhanced_config()
        events = [
            self.report(1, "p3", G1),
            self.query(2, "p2"),
            self.leave(3, "p3", G1),
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            [p["name"] for p in result["results"][2]["ports"]], ["p1", "p2"]
        )

    def test_compat_config_output_byte_unchanged(self):
        # 两键对象：无 routers 键，stdout 与增强前逐字节一致
        config = make_config(router_ports=("p1",))
        self.write(config, [self.query(1, "p2"), self.report(2, "p3", G1)])
        code, out, err = self.run_cmd(
            "igmp-snoop-decode", self.cfg, self.evt
        )
        self.assertEqual(code, 0, err)
        result = json.loads(out)
        self.assertEqual(list(result), ["results", "ports", "vlans", "groups"])

    def test_bad_router_age_exit_4_no_stdout(self):
        for value in (True, False, 0, -1, "30", 1.5, None):
            config = self.enhanced_config()
            config["igmp"]["router_age"] = value
            self.write(config, [])
            code, out, err = self.run_cmd(
                "igmp-snoop-decode", self.cfg, self.evt
            )
            self.assertEqual((code, out), (4, b""), value)
            self.assertEqual(err, b'{"error":"invalid_input"}\n')
        # 未知键
        config = self.enhanced_config()
        config["igmp"]["extra"] = 1
        self.write(config, [])
        code, out, _ = self.run_cmd(
            "igmp-snoop-decode", self.cfg, self.evt
        )
        self.assertEqual((code, out), (4, b""))

    def test_record_replay_byte_identical(self):
        config = self.enhanced_config()
        events = [
            self.query(1, "p2"),
            self.report(2, "p3", G1),
            self.leave(3, "p3", G1),
        ]
        self.write(config, events)
        code, direct, err = self.run_cmd(
            "igmp-snoop-decode", self.cfg, self.evt
        )
        self.assertEqual(code, 0, err)
        rec = subprocess.run(
            [sys.executable, SWITCH, "record", self.cfg, self.evt, self.log],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(rec.returncode, 0, rec.stderr)
        self.assertEqual(rec.stdout, direct)
        code, out, err = self.run_cmd("replay", self.log)
        self.assertEqual((code, out, err), (0, direct, b""))
        with open(self.log, "rb") as handle:
            doc = json.loads(handle.read().decode())
        self.assertEqual(doc["config"], config)
        self.assertIn(b'"routers"', direct)


class RouterAgeMldTest(IgmpSnoopCase):
    def mld_config(self, router_ports=("p1",), router_age=30):
        return {
            "bridges": ["b1"],
            "links": [],
            "delay": 2,
            "bridge": "b1",
            "ports": [
                make_port("p1", allowed=[1, 2]),
                make_port("p2", allowed=[1, 2]),
                make_port("p3", allowed=[1, 2]),
                make_port("p4", mode="hybrid", allowed=[1, 2],
                          untagged=[1]),
            ],
            "age": 100,
            "max_frame": 1518,
            "mld": {
                "membership_age": 50,
                "router_ports": list(router_ports),
                "router_age": router_age,
            },
        }

    def mld_query(self, t, port="p2", vlan=1, **kwargs):
        return mld_frame(
            t, port, mld_message(130, b"\x00" * 16, **kwargs), vlan=vlan
        )

    def mld_report(self, t, port="p3", vlan=1):
        return mld_frame(
            t, port, mld_message(131, MLDV1_REPORT_GROUP), vlan=vlan
        )

    def simulate_mld(self, config, events):
        self.write(config, events)
        code, out, err = self.run_cmd(
            "mld-snoop-decode", self.cfg, self.evt
        )
        self.assertEqual(code, 0, err)
        return json.loads(out.decode())

    def test_query_registers_and_report_uses_union(self):
        result = self.simulate_mld(
            self.mld_config(),
            [self.mld_query(1), self.mld_report(2)],
        )
        self.assertEqual(result["results"][0]["action"], "mld_query")
        self.assertEqual(
            [p["name"] for p in result["results"][1]["ports"]], ["p1", "p2"]
        )
        self.assertEqual(
            result["routers"], [{"vlan": 1, "name": "p2", "expires": 31}]
        )
        self.assertEqual(
            list(result),
            ["results", "ports", "vlans", "groups", "routers"],
        )

    def test_bad_checksum_query_invalid_no_entry(self):
        result = self.simulate_mld(
            self.mld_config(), [self.mld_query(1, bad_checksum=True)]
        )
        self.assertEqual(result["results"][0]["action"], "mld_invalid")
        self.assertEqual(result["routers"], [])

    def test_expiry_and_compat_and_validation(self):
        # 过期边界
        result = self.simulate_mld(
            self.mld_config(router_ports=()),
            [self.mld_query(1), self.mld_report(31)],
        )
        self.assertEqual(result["routers"], [])
        self.assertEqual(
            [p["name"] for p in result["results"][1]["ports"]],
            ["p1", "p2", "p4"],
        )
        # 兼容模式无 routers 键
        compat = self.mld_config()
        compat["mld"] = {"membership_age": 50, "router_ports": ["p1"]}
        result = self.simulate_mld(compat, [self.mld_query(1)])
        self.assertNotIn("routers", result)
        # 非法 router_age
        for value in (True, 0, -3, "x", None, 2.0):
            bad = self.mld_config()
            bad["mld"]["router_age"] = value
            self.write(bad, [])
            code, out, err = self.run_cmd(
                "mld-snoop-decode", self.cfg, self.evt
            )
            self.assertEqual((code, out), (4, b""), value)

    def test_record_replay_byte_identical(self):
        config = self.mld_config()
        events = [self.mld_query(1), self.mld_report(2)]
        self.write(config, events)
        code, direct, err = self.run_cmd(
            "mld-snoop-decode", self.cfg, self.evt
        )
        self.assertEqual(code, 0, err)
        rec = subprocess.run(
            [sys.executable, SWITCH, "record", self.cfg, self.evt, self.log],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(rec.returncode, 0, rec.stderr)
        self.assertEqual(rec.stdout, direct)
        code, out, err = self.run_cmd("replay", self.log)
        self.assertEqual((code, out, err), (0, direct, b""))


if __name__ == "__main__":
    unittest.main()
