#!/usr/bin/env python3
"""router_age 动态组播路由端口端到端回归（igmp-snoop-decode / mld-snoop-decode）。

两键对象为兼容模式（校验与输出不变）；三键对象（新增 router_age，仅
接受非布尔正整数）启用按 VLAN 的动态路由端口：合法 Query 登记入端口、
同 VLAN 同端口刷新、每事件前老化、链路断开/退出 forwarding 立即清除；
坏帧、非法查询、准入拒绝、discarding/learning 端口均不改状态；静态
router_ports 不产生重复动态项；Report/Leave/Done/源过滤组播数据取静态
与当前 VLAN 动态并集；Query 仍泛洪；结果在 groups 后追加 routers，
record/replay 逐字节复现。
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


def internet_checksum(data):
    if len(data) % 2:
        data = data + b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) | data[index + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def pad(body, minimum=64):
    return body + b"\x00" * max(0, minimum - len(body))


def with_fcs(body, bad=False):
    fcs = b"\xff\xff\xff\xff" if bad else (
        zlib.crc32(body) & 0xFFFFFFFF
    ).to_bytes(4, "little")
    return body + fcs


# ---------------------------------------------------------------------
# IGMP 字节
# ---------------------------------------------------------------------

def igmp_ipv4(src, dst, mtype, group, payload_len=8, bad_igmp=False):
    igmp = bytes([mtype, 0, 0, 0]) + bytes(group)
    checksum = internet_checksum(igmp)
    if bad_igmp:
        checksum ^= 0xFFFF
    igmp = igmp[:2] + checksum.to_bytes(2, "big") + igmp[4:]
    total = 20 + len(igmp)
    header = (
        bytes([0x45, 0x00]) + total.to_bytes(2, "big") + b"\x00\x00\x00\x00"
        + bytes([1, 2]) + b"\x00\x00" + bytes(src) + bytes(dst)
    )
    header = (
        header[:10] + internet_checksum(header).to_bytes(2, "big")
        + header[12:]
    )
    return header + igmp + b"\x00" * (payload_len - len(igmp))


def igmp_v4_data(src, dst):
    payload = b"\x00" * 8
    total = 20 + len(payload)
    header = (
        bytes([0x45, 0x00]) + total.to_bytes(2, "big") + b"\x00\x00\x00\x00"
        + bytes([1, 17]) + b"\x00\x00" + bytes(src) + bytes(dst)
    )
    header = (
        header[:10] + internet_checksum(header).to_bytes(2, "big")
        + header[12:]
    )
    return header + payload + b"\x00" * 18


def igmp_frame(t, port, dst_mac, src_mac, payload, vlan, bad_fcs=False):
    d = bytes(int(x, 16) for x in dst_mac.split(":"))
    s = bytes(int(x, 16) for x in src_mac.split(":"))
    head = d + s + b"\x81\x00" + vlan.to_bytes(2, "big") + b"\x08\x00"
    return {
        "t": t, "port": port,
        "data": with_fcs(pad(head + payload), bad_fcs).hex(),
    }


# ---------------------------------------------------------------------
# MLD 字节
# ---------------------------------------------------------------------

def icmpv6_checksum(src, dst, body):
    pseudo = (
        src + dst + len(body).to_bytes(4, "big") + b"\x00\x00\x00"
        + bytes([58])
    )
    return internet_checksum(pseudo + body)


def mld_packet(src, dst, mtype, group, bad_checksum=False, code=0):
    body = (
        bytes([mtype, code]) + b"\x00\x00" + b"\x00\x00" + b"\x00\x00"
        + bytes(group)
    )
    checksum = icmpv6_checksum(src, dst, body)
    if bad_checksum:
        checksum ^= 0xFFFF
    return body[:2] + checksum.to_bytes(2, "big") + body[4:]


HOPOPT_RA = bytes([58, 0, 5, 2, 0, 0, 0, 0])  # 8 字节 Hop-by-Hop Router Alert


def mld_ipv6(src, dst, body):
    payload = HOPOPT_RA + body
    return (
        (0x60000000).to_bytes(4, "big")
        + len(payload).to_bytes(2, "big") + bytes([0, 1]) + src + dst
        + payload
    )


def mld_v6_data(src, dst):
    payload = b"\x00" * 8
    return (
        (0x60000000).to_bytes(4, "big")
        + len(payload).to_bytes(2, "big") + bytes([17, 1]) + src + dst
        + payload
    )


def mld_frame(t, port, dst_mac, payload, vlan, bad_fcs=False):
    d = bytes(int(x, 16) for x in dst_mac.split(":"))
    s = bytes(int(x, 16) for x in "02:00:00:00:00:fe".split(":"))
    head = d + s + b"\x81\x00" + vlan.to_bytes(2, "big") + b"\x86\xdd"
    return {
        "t": t, "port": port,
        "data": with_fcs(pad(head + payload), bad_fcs).hex(),
    }


def make_port(name, mode="trunk", pvid=1, allowed=None, up=True):
    if allowed is None:
        allowed = [pvid]
    return {
        "name": name,
        "mode": mode,
        "pvid": pvid,
        "allowed": allowed,
        "untagged": [] if mode == "trunk" else [pvid],
        "up": up,
    }


def make_ports():
    return [
        make_port("p1", allowed=[1, 2]),
        make_port("p2", allowed=[1, 2]),
        make_port("p3", allowed=[1, 2]),
        make_port("p4", allowed=[1, 2]),
    ]


def make_config(proto, router_ports=("p1",), router_age=10, ports=None,
                bridges=("b1",), links=None, delay=2, enhanced=True):
    obj = {
        "membership_age": 50,
        "router_ports": list(router_ports),
    }
    if enhanced:
        obj["router_age"] = router_age
    config = {
        "bridges": list(bridges),
        "links": links or [],
        "delay": delay,
        "bridge": "b1",
        "ports": ports or make_ports(),
        "age": 100,
        "max_frame": 1518,
        proto: obj,
    }
    return config


class RouterAgeCase(unittest.TestCase):
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

    def simulate_raw(self, mode, config, events):
        self.write(config, events)
        code, out, err = self.run_cmd(mode, self.cfg, self.evt)
        self.assertEqual(code, 0, err)
        return json.loads(out.decode())


class CommonDynamicRouterMixin(object):
    """与协议无关的动态路由端口语义；子类提供 mode 与帧构造。"""

    MODE = None

    def config(self, **kwargs):
        return make_config(self.PROTO, **kwargs)

    def simulate(self, config, events):
        return self.simulate_raw(self.MODE, config, events)

    # 以下工厂由子类实现
    def query(self, t, port, vlan):
        raise NotImplementedError

    def report(self, t, port, vlan):
        raise NotImplementedError

    def leave(self, t, port, vlan):
        raise NotImplementedError

    def data(self, t, port, vlan):
        raise NotImplementedError

    def query_bad_fcs(self, t, port, vlan):
        raise NotImplementedError

    def query_bad_proto(self, t, port, vlan):
        raise NotImplementedError

    # -------------------------------------------------------------
    def test_query_registers_dynamic_router_and_report_uses_union(self):
        config = self.config(router_ports=("p1",))
        events = [
            self.query(1, "p2", 1),
            self.report(2, "p3", 1),
            self.data(3, "p4", 1),
        ]
        result = self.simulate(config, events)
        # Query 仍泛洪全部合格端口
        self.assertEqual(result["results"][0]["action"], self.QUERY_ACTION)
        self.assertEqual(
            [p["name"] for p in result["results"][0]["ports"]],
            ["p1", "p3", "p4"],
        )
        # Report 路由目标 = 静态 p1 ∪ 动态 p2（p3 为入端口排除）
        self.assertEqual(
            [p["name"] for p in result["results"][1]["ports"]],
            ["p1", "p2"],
        )
        # 组成员数据：静态 p1、动态 p2 加成员 p3（入端口 p4 排除）
        self.assertEqual(result["results"][2]["action"], "multicast")
        self.assertEqual(
            [p["name"] for p in result["results"][2]["ports"]],
            ["p1", "p2", "p3"],
        )
        self.assertEqual(
            result["routers"], [{"vlan": 1, "name": "p2", "expires": 11}]
        )
        self.assertEqual(
            list(result), ["results", "ports", "vlans", "groups", "routers"]
        )

    def test_refresh_same_vlan_same_port(self):
        config = self.config(router_ports=())
        result = self.simulate(
            config, [self.query(1, "p2", 1), self.query(5, "p2", 1)]
        )
        self.assertEqual(
            result["routers"], [{"vlan": 1, "name": "p2", "expires": 15}]
        )

    def test_dynamic_router_expires_before_event(self):
        # expires=11：t=11 事件前清除，Report 不再发往 p2
        config = self.config(router_ports=("p1",))
        result = self.simulate(
            config, [self.query(1, "p2", 1), self.report(11, "p3", 1)]
        )
        self.assertEqual(
            [p["name"] for p in result["results"][1]["ports"]], ["p1"]
        )
        self.assertEqual(result["routers"], [])

    def test_dynamic_router_alive_at_expiry_minus_one(self):
        config = self.config(router_ports=("p1",), router_age=10)
        result = self.simulate(
            config, [self.query(1, "p2", 1), self.report(10, "p3", 1)]
        )
        self.assertEqual(
            [p["name"] for p in result["results"][1]["ports"]], ["p1", "p2"]
        )
        self.assertEqual(
            result["routers"], [{"vlan": 1, "name": "p2", "expires": 11}]
        )

    def test_router_state_scoped_by_vlan(self):
        # p2 仅在 VLAN2 是动态路由端口；VLAN1 的 Report 不发给它
        config = self.config(router_ports=("p1",))
        result = self.simulate(
            config, [self.query(1, "p2", 2), self.report(2, "p3", 1)]
        )
        self.assertEqual(
            [p["name"] for p in result["results"][1]["ports"]], ["p1"]
        )
        self.assertEqual(
            result["routers"], [{"vlan": 2, "name": "p2", "expires": 11}]
        )

    def test_routers_sorted_vlan_then_port_config_order(self):
        config = self.config(router_ports=())
        events = [
            self.query(1, "p3", 2),
            self.query(2, "p3", 1),
            self.query(3, "p2", 1),
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            [(r["vlan"], r["name"]) for r in result["routers"]],
            [(1, "p2"), (1, "p3"), (2, "p3")],
        )
        # 键序固定
        self.assertEqual(
            [list(r) for r in result["routers"]],
            [["vlan", "name", "expires"]] * 3,
        )

    def test_static_port_query_creates_no_dynamic_entry(self):
        config = self.config(router_ports=("p1",))
        result = self.simulate(config, [self.query(1, "p1", 1)])
        self.assertEqual(result["routers"], [])
        # 静态端口本身永不过期：超 router_age 后仍收到 Report
        result = self.simulate(
            config, [self.query(1, "p1", 1), self.report(50, "p3", 1)]
        )
        self.assertEqual(
            [p["name"] for p in result["results"][1]["ports"]], ["p1"]
        )
        self.assertEqual(result["routers"], [])

    def test_bad_fcs_query_does_not_register(self):
        config = self.config(router_ports=("p1",))
        result = self.simulate(
            config, [self.query_bad_fcs(1, "p2", 1), self.report(2, "p3", 1)]
        )
        self.assertEqual(result["results"][0]["action"], "drop")
        self.assertEqual(result["routers"], [])
        self.assertEqual(
            [p["name"] for p in result["results"][1]["ports"]], ["p1"]
        )

    def test_invalid_protocol_query_does_not_register(self):
        config = self.config(router_ports=("p1",))
        result = self.simulate(
            config, [self.query_bad_proto(1, "p2", 1), self.report(2, "p3", 1)]
        )
        self.assertEqual(result["results"][0]["action"], self.INVALID_ACTION)
        self.assertEqual(result["results"][0]["ports"], [])
        self.assertEqual(result["routers"], [])
        self.assertEqual(
            [p["name"] for p in result["results"][1]["ports"]], ["p1"]
        )

    def test_vlan_admission_reject_does_not_register(self):
        # p2 仅允许 VLAN1、2：带 VLAN3 标签的 Query 被准入拒绝
        ports = make_ports()
        config = self.config(router_ports=("p1",), ports=ports)
        result = self.simulate(
            config, [self.query(1, "p2", 3), self.report(2, "p3", 1)]
        )
        self.assertEqual(result["results"][0]["action"], "drop")
        self.assertEqual(result["routers"], [])

    def test_query_on_discarding_port_does_not_register(self):
        # p1 为桥链路口：t=0 处于 discarding，Query 不登记；t>=2 后有效
        links = [
            {"id": "L1", "x": ["b1", "p1"], "y": ["b2", "p1"],
             "cost": 1, "up": True},
        ]
        ports = make_ports()[:3]
        config = self.config(
            router_ports=("p2",), ports=ports, bridges=("b1", "b2"),
            links=links, delay=1,
        )
        result = self.simulate(
            config,
            [
                self.query(0, "p1", 1),       # discarding
                self.report(1, "p3", 1),
                self.query(1, "p1", 1),       # learning
                self.report(2, "p3", 1),
                self.query(2, "p1", 1),       # forwarding
                self.report(3, "p3", 1),
            ],
        )
        self.assertEqual(result["results"][0]["action"], "drop")
        self.assertEqual(result["results"][2]["action"], "drop")
        # discarding/learning 的 Query 均未登记：Report 仅静态 p2
        self.assertEqual(
            [p["name"] for p in result["results"][1]["ports"]], ["p2"]
        )
        self.assertEqual(
            [p["name"] for p in result["results"][3]["ports"]], ["p2"]
        )
        # forwarding 的 Query 登记 p1：路由目标 p1+p2
        self.assertEqual(
            [p["name"] for p in result["results"][5]["ports"]], ["p1", "p2"]
        )
        self.assertEqual(
            result["routers"], [{"vlan": 1, "name": "p1", "expires": 12}]
        )

    def test_link_down_clears_dynamic_entries_immediately(self):
        links = [
            {"id": "L1", "x": ["b1", "p1"], "y": ["b2", "p1"],
             "cost": 1, "up": True},
        ]
        ports = make_ports()[:3]
        config = self.config(
            router_ports=("p2",), ports=ports, bridges=("b1", "b2"),
            links=links, delay=1,
        )
        events = [
            self.query(2, "p1", 1),       # p1 forwarding，登记动态
            self.query(3, "p1", 2),       # 同端口再登记 VLAN2 动态
            self.report(4, "p3", 1),      # 发往 p2 静态 + p1 动态
            {"t": 5, "id": "L1", "up": False},
            self.report(6, "p3", 1),      # 两个 VLAN 的动态项均立即清除
            self.report(7, "p3", 2),
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            [p["name"] for p in result["results"][2]["ports"]], ["p1", "p2"]
        )
        self.assertEqual(
            [p["name"] for p in result["results"][3]["ports"]], ["p2"]
        )
        self.assertEqual(
            [p["name"] for p in result["results"][4]["ports"]], ["p2"]
        )
        self.assertEqual(result["routers"], [])

    def test_leave_targets_static_and_dynamic(self):
        config = self.config(router_ports=("p1",))
        result = self.simulate(
            config, [self.query(1, "p2", 1), self.leave(2, "p3", 1)]
        )
        self.assertEqual(
            [p["name"] for p in result["results"][1]["ports"]], ["p1", "p2"]
        )

    def test_dynamic_router_without_static_floods_only_when_expired(self):
        # 无静态端口、无动态项时 Report 回退泛洪
        config = self.config(router_ports=())
        result = self.simulate(config, [self.report(1, "p3", 1)])
        self.assertEqual(
            [p["name"] for p in result["results"][0]["ports"]],
            ["p1", "p2", "p4"],
        )
        self.assertEqual(result["routers"], [])

    def test_compat_mode_output_unchanged(self):
        # 两键对象：结果不含 routers，行为与旧基线一致
        config = self.config(router_ports=("p1",), enhanced=False)
        result = self.simulate(
            config, [self.query(1, "p2", 1), self.report(2, "p3", 1)]
        )
        self.assertEqual(
            list(result), ["results", "ports", "vlans", "groups"]
        )
        # Query 不产生动态路由：Report 仅发往静态 p1
        self.assertEqual(
            [p["name"] for p in result["results"][1]["ports"]], ["p1"]
        )

    def test_record_replay_byte_identical(self):
        config = self.config(router_ports=("p1",))
        events = [
            self.query(1, "p2", 1),
            self.report(2, "p3", 1),
            self.data(3, "p4", 1),
        ]
        self.write(config, events)
        code, direct, err = self.run_cmd(self.MODE, self.cfg, self.evt)
        self.assertEqual(code, 0, err)
        doc = json.loads(direct.decode())
        self.assertIn("routers", doc)
        rec = subprocess.run(
            [sys.executable, SWITCH, "record", self.cfg, self.evt, self.log],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(rec.returncode, 0, rec.stderr)
        self.assertEqual(rec.stdout, direct)
        code, out, err = self.run_cmd("replay", self.log)
        self.assertEqual((code, out, err), (0, direct, b""))

    def test_invalid_router_age_exits_4_with_empty_stdout(self):
        for bad in (True, False, 0, -3, 1.5, "10", None, [10]):
            config = self.config(router_ports=("p1",))
            config[self.PROTO]["router_age"] = bad
            self.write(config, [])
            code, out, err = self.run_cmd(self.MODE, self.cfg, self.evt)
            self.assertEqual((code, out), (4, b""), bad)
            self.assertIn(b"invalid_input", err)

    def test_unknown_key_exits_4(self):
        config = self.config(router_ports=("p1",))
        config[self.PROTO]["extra"] = 1
        self.write(config, [])
        code, out, err = self.run_cmd(self.MODE, self.cfg, self.evt)
        self.assertEqual((code, out), (4, b""))
        self.assertIn(b"invalid_input", err)


IGMP_GQ = (224, 0, 0, 1)
IGMP_G1 = (224, 1, 2, 3)
IGMP_QMAC = "01:00:5e:00:00:01"
IGMP_G1MAC = "01:00:5e:01:02:03"


class IgmpDynamicRouterTest(CommonDynamicRouterMixin, RouterAgeCase):
    MODE = "igmp-snoop-decode"
    PROTO = "igmp"
    QUERY_ACTION = "igmp_query"
    INVALID_ACTION = "igmp_invalid"

    def query(self, t, port, vlan, bad_fcs=False, bad_proto=False):
        return igmp_frame(
            t, port, IGMP_QMAC, "02:00:00:00:00:fe",
            igmp_ipv4((10, 0, 0, 1), IGMP_GQ, 0x99 if bad_proto else 0x11,
                      IGMP_GQ, bad_igmp=bad_proto),
            vlan, bad_fcs=bad_fcs,
        )

    def query_bad_fcs(self, t, port, vlan):
        return self.query(t, port, vlan, bad_fcs=True)

    def query_bad_proto(self, t, port, vlan):
        return self.query(t, port, vlan, bad_proto=True)

    def report(self, t, port, vlan):
        return igmp_frame(
            t, port, IGMP_G1MAC, "02:00:00:00:00:01",
            igmp_ipv4((10, 0, 0, 1), IGMP_G1, 0x16, IGMP_G1), vlan,
        )

    def leave(self, t, port, vlan):
        return igmp_frame(
            t, port, IGMP_G1MAC, "02:00:00:00:00:01",
            igmp_ipv4((10, 0, 0, 1), IGMP_G1, 0x17, IGMP_G1), vlan,
        )

    def data(self, t, port, vlan):
        return igmp_frame(
            t, port, IGMP_G1MAC, "02:00:00:00:00:09",
            igmp_v4_data((10, 0, 0, 9), IGMP_G1), vlan,
        )


MLD_SRC = b"\xfe\x80" + b"\x00" * 13 + b"\x01"
MLD_QDST = bytes.fromhex("ff020000000000000000000000000001")
MLD_G1 = bytes.fromhex("ff1e0000000000000000000000001234")
MLD_QMAC = "33:33:00:00:00:01"
MLD_G1MAC = "33:33:00:00:12:34"


class MldDynamicRouterTest(CommonDynamicRouterMixin, RouterAgeCase):
    MODE = "mld-snoop-decode"
    PROTO = "mld"
    QUERY_ACTION = "mld_query"
    INVALID_ACTION = "mld_invalid"

    def query(self, t, port, vlan, bad_fcs=False, bad_proto=False):
        body = mld_packet(
            MLD_SRC, MLD_QDST, 0x99 if bad_proto else 130, MLD_QDST,
            bad_checksum=bad_proto,
        )
        return mld_frame(
            t, port, MLD_QMAC, mld_ipv6(MLD_SRC, MLD_QDST, body), vlan,
            bad_fcs=bad_fcs,
        )

    def query_bad_fcs(self, t, port, vlan):
        return self.query(t, port, vlan, bad_fcs=True)

    def query_bad_proto(self, t, port, vlan):
        return self.query(t, port, vlan, bad_proto=True)

    def report(self, t, port, vlan):
        body = mld_packet(MLD_SRC, MLD_G1, 131, MLD_G1)
        return mld_frame(t, port, MLD_G1MAC, mld_ipv6(MLD_SRC, MLD_G1, body),
                         vlan)

    def leave(self, t, port, vlan):
        body = mld_packet(MLD_SRC, MLD_G1, 132, MLD_G1)
        return mld_frame(t, port, MLD_G1MAC, mld_ipv6(MLD_SRC, MLD_G1, body),
                         vlan)

    def data(self, t, port, vlan):
        return mld_frame(
            t, port, MLD_G1MAC, mld_v6_data(MLD_SRC, MLD_G1), vlan
        )


if __name__ == "__main__":
    unittest.main()
