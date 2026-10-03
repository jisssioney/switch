#!/usr/bin/env python3
"""mld-snoop-decode 端到端回归。

覆盖：MLDv1 Query/Report/Done 与 MLDv2 Report 识别（Router Alert 逐跳
选项、IPv6 外层边界、Hop Limit=1、ICMPv6 伪首部校验和）、六类组记录与
INCLUDE/EXCLUDE 源地址过滤、成员建立/刷新/老化/Done 删除、路由端口与无
路由口泛洪、Query 始终泛洪、IPv6 组播数据按 33:33 MAC 映射与成员+路由
端口转发（排除入端口、保留标签语义、分片不重组按普通 IPv6 帧处理）、
其余组播/映射不符/无成员泛洪、外层合法但 MLD 语义非法固定 mld_invalid
（不学习 MAC、不改状态、计 drop）、缺 Router Alert/分片 MLD/Hop Limit
非 1/外层边界破损不识别或非法、链路断开清成员、groups 按 VLAN 与 128 位
地址排序、IPv6 确定小写压缩形式、record 自动识别与 replay 逐字节复现、
mld 工作量边界（stp-decode 工作量加 N*(N+P+1)）、退出码 2/3/4/5 与错误
名。仅用标准库。
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


# 常用 IPv6 地址（全部 16 字节）
SRC = bytes.fromhex("fe800000000000000200000000000001")
ALL_MLD_ROUTERS = bytes.fromhex("ff020000000000000000000000000001")
ALL_MLD_ROUTERS_V2 = bytes.fromhex("ff020000000000000000000000000016")
ALL_ROUTERS = bytes.fromhex("ff020000000000000000000000000002")
UNSPECIFIED = b"\x00" * 16
LOOPBACK = b"\x00" * 15 + b"\x01"

G1 = bytes.fromhex("ff150000000000000000000000000003")
G2 = bytes.fromhex("ff150000000000000000000000000002")
G3 = bytes.fromhex("ff020000000000000000000000000005")

S1 = bytes.fromhex("20010db8000000000000000000000009")
S2 = bytes.fromhex("20010db800000000000000000000000a")
S3 = bytes.fromhex("20010db8000100000000000000000001")  # 2001:db8:1::1

# MLDv2 组记录类型
V2_MODE_IS_INCLUDE = 1
V2_MODE_IS_EXCLUDE = 2
V2_CHANGE_TO_INCLUDE = 3
V2_CHANGE_TO_EXCLUDE = 4
V2_ALLOW_NEW_SOURCES = 5
V2_BLOCK_OLD_SOURCES = 6

MLD_TYPE_QUERY_V1 = 130
MLD_TYPE_REPORT_V1 = 131
MLD_TYPE_DONE_V1 = 132
MLD_TYPE_REPORT_V2 = 143


def hbh_header(next_header=58, options=b"\x05\x02\x00\x00\x00\x00",
               ext_len=0):
    """逐跳选项扩展头：8*(ext_len+1) 字节，前两字节为下一报头/长度。"""
    total = 8 * (ext_len + 1)
    body = bytes([next_header, ext_len]) + options
    return body + b"\x00" * (total - len(body))


def fragment_header(next_header=58, more_fragments=True):
    flags_offset = 0x0001 if more_fragments else 0x0000
    return (
        bytes([next_header, 0]) + flags_offset.to_bytes(2, "big")
        + b"\x00\x00\x00\x01"
    )


def ipv6_packet(src, dst, extension_and_payload, hop_limit=1, next_header=0,
                payload_length=None, first_byte=0x60):
    if payload_length is None:
        payload_length = len(extension_and_payload)
    head = (
        bytes([first_byte, 0x00, 0x00, 0x00])
        + payload_length.to_bytes(2, "big")
        + bytes([next_header, hop_limit])
        + src
        + dst
    )
    assert len(head) == 40
    return head + extension_and_payload


def mld_v1_dst(mtype, group):
    if mtype == MLD_TYPE_QUERY_V1:
        return ALL_MLD_ROUTERS
    return group


def mld_v1_message(mtype, group, src=SRC, bad_checksum=False, length=24):
    """MLDv1 24 字节定长报文：type/code/cksum/MRT/reserved/group。"""
    dst = mld_v1_dst(mtype, group)
    msg = bytes([mtype, 0x00]) + b"\x00" * 6 + bytes(group)
    pseudo = (
        src + dst + len(msg).to_bytes(4, "big")
        + b"\x00\x00\x00\x3a"
    )
    checksum = internet_checksum(pseudo + msg)
    if bad_checksum:
        checksum ^= 0xFFFF
    msg = msg[:2] + checksum.to_bytes(2, "big") + msg[4:]
    if length > 24:  # 长度非法场景：校验后补零（长度先判失败）
        msg += b"\x00" * (length - 24)
    return msg


def mld_v2_message(records, src=SRC, bad_checksum=False, count=None,
                   truncate=0, append=b"", aux_words=0):
    """MLDv2 Membership Report 报文。

    records 为 (rtype, group, sources) 列表；count/truncate/append 用于
    记录数不符、长度不闭合等非法场景。
    """
    body = b""
    for rtype, group, sources in records:
        body += (
            bytes([rtype, aux_words])
            + len(sources).to_bytes(2, "big")
            + bytes(group)
            + b"".join(bytes(source) for source in sources)
            + b"\x00" * (4 * aux_words)
        )
    number = len(records) if count is None else count
    msg = (
        bytes([MLD_TYPE_REPORT_V2, 0x00]) + b"\x00" * 4
        + number.to_bytes(2, "big") + body
    )
    pseudo = (
        src + ALL_MLD_ROUTERS_V2 + len(msg).to_bytes(4, "big")
        + b"\x00\x00\x00\x3a"
    )
    checksum = internet_checksum(pseudo + msg)
    if bad_checksum:
        checksum ^= 0xFFFF
    msg = msg[:2] + checksum.to_bytes(2, "big") + msg[4:]
    msg += append
    return msg if not truncate else msg[:-truncate]


def ipv6_mld_v1(mtype, group, src=SRC, hop_limit=1, bad_checksum=False,
                length=24, payload_length=None, extension=None,
                next_header=0, first_byte=0x60):
    msg = mld_v1_message(
        mtype, group, src=src, bad_checksum=bad_checksum, length=length
    )
    ext = extension if extension is not None else hbh_header()
    return ipv6_packet(
        src, mld_v1_dst(mtype, group), ext + msg,
        hop_limit=hop_limit, next_header=next_header,
        payload_length=payload_length, first_byte=first_byte,
    )


def ipv6_mld_v2(records, src=SRC, hop_limit=1, extension=None,
                payload_length=None, **kwargs):
    msg = mld_v2_message(records, src=src, **kwargs)
    ext = extension if extension is not None else hbh_header()
    return ipv6_packet(
        src, ALL_MLD_ROUTERS_V2, ext + msg,
        hop_limit=hop_limit, next_header=0, payload_length=payload_length,
    )


def ipv6_data(group, src=S1, payload_len=8):
    """普通 IPv6 组播数据（无扩展头，下一报头 17）。"""
    payload = b"\x00" * payload_len
    return ipv6_packet(
        src, group, payload, hop_limit=64, next_header=17
    )


def group_mac(group):
    return "33:33:%02x:%02x:%02x:%02x" % tuple(group[-4:])


def raw_frame(t, port, dst, src, payload, vlan=None, ethertype=0x86DD,
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
    body += b"\x00" * max(0, 60 - len(body))  # L2 载荷最短 46 字节
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
        "mld": {
            "membership_age": membership_age,
            "router_ports": list(router_ports),
        },
    }


class MldSnoopCase(unittest.TestCase):
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
            "mld-snoop-decode", self.cfg, self.evt
        )
        self.assertEqual(code, 0, err)
        return json.loads(out.decode())

    def report(self, t, port, group, vlan=1, bad_fcs=False, **kwargs):
        kwargs.setdefault("bad_checksum", bad_fcs)
        return raw_frame(
            t, port, group_mac(group), "02:00:00:00:00:01",
            ipv6_mld_v1(MLD_TYPE_REPORT_V1, group, **kwargs),
            vlan=vlan, bad_fcs=bad_fcs,
        )

    def done(self, t, port, group, vlan=1, **kwargs):
        return raw_frame(
            t, port, group_mac(group), "02:00:00:00:00:01",
            ipv6_mld_v1(MLD_TYPE_DONE_V1, group, **kwargs), vlan=vlan,
        )

    def query(self, t, port, group=UNSPECIFIED, vlan=1, **kwargs):
        return raw_frame(
            t, port, group_mac(ALL_MLD_ROUTERS), "02:00:00:00:00:fe",
            ipv6_mld_v1(MLD_TYPE_QUERY_V1, group, **kwargs), vlan=vlan,
        )

    def data_frame(self, t, port, group, src=S1, src_mac="02:00:00:00:00:09",
                   vlan=1, dst=None, packet=None):
        return raw_frame(
            t, port, dst if dst is not None else group_mac(group), src_mac,
            packet if packet is not None else ipv6_data(group, src),
            vlan=vlan,
        )

    def v2_report(self, t, port, records, vlan=1, **kwargs):
        return raw_frame(
            t, port, group_mac(ALL_MLD_ROUTERS_V2), "02:00:00:00:00:02",
            ipv6_mld_v2(records, **kwargs), vlan=vlan,
        )


class MldControlTest(MldSnoopCase):
    def test_report_to_router_only_and_member_delivery(self):
        # Report 仅发往同 VLAN 可转发路由端口 p1（trunk，带标签）；
        # 随后组成员数据发往成员 p2 与路由 p1，排除入端口 p3
        config = make_config(router_ports=("p1",))
        events = [
            self.report(1, "p2", G1),
            self.data_frame(2, "p3", G1),
        ]
        result = self.simulate(config, events)
        actions = [(r["t"], r["action"]) for r in result["results"]]
        self.assertEqual(actions, [(1, "mld_report"), (2, "multicast")])
        self.assertEqual(
            result["results"][0]["ports"], [{"name": "p1", "vlan": 1}]
        )
        self.assertEqual(
            result["results"][1]["ports"],
            [{"name": "p1", "vlan": 1}, {"name": "p2", "vlan": 1}],
        )

    def test_member_delivery_untagged_semantics(self):
        # 成员端口 p4 为 hybrid 且 vlan1 在 untagged：输出去标签（null）
        config = make_config(router_ports=("p1",))
        events = [
            self.report(1, "p4", G1),
            self.data_frame(2, "p3", G1),
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            result["results"][1]["ports"],
            [{"name": "p1", "vlan": 1}, {"name": "p4", "vlan": None}],
        )

    def test_report_floods_without_eligible_router(self):
        # 无路由端口时 Report 泛洪（排除入端口），动作仍为 mld_report
        config = make_config(router_ports=())
        events = [self.report(1, "p2", G1)]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][0]["action"], "mld_report")
        self.assertEqual(
            [p["name"] for p in result["results"][0]["ports"]],
            ["p1", "p3", "p4"],
        )

    def test_ingress_router_excluded_then_floods(self):
        # 唯一路由端口即入端口：合格路由端口为空 -> 泛洪
        config = make_config(router_ports=("p2",))
        events = [self.report(1, "p2", G1)]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][0]["action"], "mld_report")
        self.assertEqual(
            [p["name"] for p in result["results"][0]["ports"]],
            ["p1", "p3", "p4"],
        )

    def test_query_always_floods(self):
        # Query 始终泛洪，即使存在路由端口，也不建立成员
        config = make_config(router_ports=("p1",))
        events = [self.query(1, "p2", G1)]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][0]["action"], "mld_query")
        self.assertEqual(
            [p["name"] for p in result["results"][0]["ports"]],
            ["p1", "p3", "p4"],
        )
        self.assertEqual(result["groups"], [])

    def test_general_query_unspecified_group(self):
        # 通用查询组地址 :: 合法（始终泛洪，不建成员）
        config = make_config(router_ports=("p1",))
        events = [self.query(1, "p2", UNSPECIFIED)]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][0]["action"], "mld_query")
        self.assertEqual(result["groups"], [])

    def test_done_deletes_member_immediately(self):
        config = make_config(router_ports=("p1",))
        events = [
            self.report(1, "p2", G1),
            self.data_frame(2, "p3", G1),
            self.done(3, "p2", G1),
            self.data_frame(4, "p3", G1),
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            [r["action"] for r in result["results"]],
            ["mld_report", "multicast", "mld_done", "flood"],
        )
        # Done 只发路由端口
        self.assertEqual(
            result["results"][2]["ports"], [{"name": "p1", "vlan": 1}]
        )
        self.assertEqual(result["groups"], [])

    def test_done_for_one_member_keeps_others(self):
        config = make_config(router_ports=("p1",))
        events = [
            self.report(1, "p2", G1),
            self.report(2, "p3", G1),
            self.done(3, "p2", G1),
            self.data_frame(4, "p4", G1),
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
            self.data_frame(50, "p3", G1),
            self.data_frame(51, "p3", G1),
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
            self.data_frame(2, "p3", G1, vlan=2),
            self.data_frame(3, "p3", G1, vlan=1),
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            [r["action"] for r in result["results"]],
            ["mld_report", "flood", "multicast"],
        )
        self.assertEqual(result["groups"][0]["vlan"], 1)

    def test_wrong_mac_mapping_floods(self):
        # 目的 MAC 的 33:33 映射与 IPv6 目的组不一致：沿用泛洪
        config = make_config(router_ports=("p1",))
        events = [
            self.report(1, "p2", G1),
            self.data_frame(
                2, "p3", G1, dst=group_mac(G2)
            ),
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            [r["action"] for r in result["results"]],
            ["mld_report", "flood"],
        )

    def test_non_ipv6_multicast_floods_and_learns(self):
        # 非 IPv6 的组播帧沿用泛洪（不因成员表裁剪）
        config = make_config(router_ports=("p1",))
        events = [
            self.report(1, "p2", G1),
            raw_frame(
                2, "p3", group_mac(G1), "02:00:00:00:00:09",
                b"\x00" * 46, vlan=1, ethertype=0x1234,
            ),
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][1]["action"], "flood")
        self.assertEqual(
            [p["name"] for p in result["results"][1]["ports"]],
            ["p1", "p2", "p4"],
        )

    def test_fragmented_data_delivered_like_plain_ipv6(self):
        # 分片不重组：组播数据分片的外层组地址仍可读取，33:33 映射一致时
        # 按普通 IPv6 帧投递给匹配成员与路由端口
        config = make_config(router_ports=("p1",))
        frag = fragment_header(next_header=17) + b"\x00" * 8
        packet = ipv6_packet(
            S1, G1, frag, hop_limit=64, next_header=44
        )
        events = [
            self.report(1, "p2", G1),
            self.data_frame(2, "p3", G1, packet=packet),
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][1]["action"], "multicast")
        self.assertEqual(
            [p["name"] for p in result["results"][1]["ports"]],
            ["p1", "p2"],
        )

    def test_groups_ordered_by_vlan_then_128bit_members_by_port_order(self):
        config = make_config(router_ports=("p1",))
        events = [
            self.report(1, "p3", G1),  # ff15::3
            self.report(2, "p2", G1),
            self.report(3, "p2", G2),  # ff15::2（数值更小）
            self.report(4, "p2", G3, vlan=2),  # ff02::5 在 vlan2
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            [(g["vlan"], g["group"]) for g in result["groups"]],
            [(1, "ff15::2"), (1, "ff15::3"), (2, "ff02::5")],
        )
        # 成员按配置端口序（p2 在 p3 前），expires 为绝对时刻
        self.assertEqual(
            result["groups"][1]["members"],
            [
                {"name": "p2", "expires": 52},
                {"name": "p3", "expires": 51},
            ],
        )

    def test_ipv6_compressed_form_deterministic(self):
        # 零段折叠取最长、并列取首个；全部小写
        g_tie = bytes.fromhex("ff010000000000020000000000030000")
        g_long = bytes.fromhex("ff150000000000010000000000000005")
        g_simple = bytes.fromhex("ff050000000000000000000000000001")
        config = make_config(router_ports=("p1",))
        events = [
            self.report(1, "p2", g_tie),
            self.report(2, "p2", g_long),
            self.report(3, "p3", g_simple),
        ]
        result = self.simulate(config, events)
        groups = {g["group"] for g in result["groups"]}
        self.assertIn("ff01::2:0:0:3:0", groups)  # 并列取首个零串
        self.assertIn("ff15:0:0:1::5", groups)    # 最长三零段
        self.assertIn("ff05::1", groups)

    def test_output_key_order(self):
        config = make_config(router_ports=("p1",))
        events = [self.report(1, "p2", G1)]
        self.write(config, events)
        code, out, err = self.run_cmd(
            "mld-snoop-decode", self.cfg, self.evt
        )
        self.assertEqual(code, 0, err)
        text = out.decode()
        self.assertIn(
            '"results":[{"t":1,"class":"good","action":"mld_report",'
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

    def test_empty_events_empty_groups(self):
        result = self.simulate(make_config(router_ports=("p1",)), [])
        self.assertEqual(result["results"], [])
        self.assertEqual(result["groups"], [])


class MldInvalidTest(MldSnoopCase):
    def _invalid(self, events):
        config = make_config(router_ports=("p1",))
        return self.simulate(config, events)

    def test_bad_mld_checksum_is_invalid_and_no_state(self):
        events = [
            self.report(1, "p2", G1, bad_checksum=True),
            self.data_frame(2, "p3", G1),
        ]
        result = self._invalid(events)
        self.assertEqual(result["results"][0]["action"], "mld_invalid")
        self.assertEqual(result["results"][0]["ports"], [])
        self.assertEqual(result["results"][1]["action"], "flood")
        self.assertEqual(result["groups"], [])
        # 计入丢弃：入端口 drop=1、VLAN drop=1；不学习 MAC
        self.assertEqual(result["ports"][1]["drop"], 1)
        self.assertEqual(result["vlans"][0]["drop"], 1)

    def test_v2_shaped_type_143_v1_body_is_invalid(self):
        # 类型 143 但报文为 24 字节 v1 形状（记录数巨大且无内容）：
        # 交 v2 解析器判定非法
        events = [
            self.report(1, "p2", G1),
            raw_frame(
                2, "p3", group_mac(G1), "02:00:00:00:00:01",
                ipv6_mld_v1(MLD_TYPE_REPORT_V2, G1), vlan=1,
            ),
        ]
        result = self._invalid(events)
        self.assertEqual(result["results"][1]["action"], "mld_invalid")
        self.assertEqual(
            [g["group"] for g in result["groups"]], ["ff15::3"]
        )

    def test_report_non_multicast_group_is_invalid(self):
        events = [self.report(1, "p2", S1)]
        result = self._invalid(events)
        self.assertEqual(result["results"][0]["action"], "mld_invalid")
        self.assertEqual(result["groups"], [])

    def test_query_group_address_rules(self):
        # 组特定查询：组播合法
        events = [self.query(1, "p2", G1)]
        result = self._invalid(events)
        self.assertEqual(result["results"][0]["action"], "mld_query")
        # 非组播且非 ::：非法
        events = [self.query(1, "p2", S1)]
        result = self._invalid(events)
        self.assertEqual(result["results"][0]["action"], "mld_invalid")
        # 通用查询 :: 合法
        events = [self.query(1, "p2", UNSPECIFIED)]
        result = self._invalid(events)
        self.assertEqual(result["results"][0]["action"], "mld_query")

    def test_v1_message_length_invalid(self):
        # v1 报文 28 字节：长度非法
        events = [self.report(1, "p2", G1, length=28)]
        result = self._invalid(events)
        self.assertEqual(result["results"][0]["action"], "mld_invalid")
        self.assertEqual(result["groups"], [])

    def test_outer_payload_too_short_for_icmpv6(self):
        # IPv6 Payload Length 仅 12（逐跳 8 + 4）：容纳不了最短 ICMPv6
        events = [self.report(1, "p2", G1, payload_length=12)]
        result = self._invalid(events)
        self.assertEqual(result["results"][0]["action"], "mld_invalid")

    def test_hop_limit_not_one_is_invalid(self):
        events = [self.report(1, "p2", G1, hop_limit=64)]
        result = self._invalid(events)
        self.assertEqual(result["results"][0]["action"], "mld_invalid")
        self.assertEqual(result["groups"], [])

    def test_fragmented_report_not_recognized(self):
        # HBH 后继分片扩展（下一报头 44）：不识别为 MLD，不建成员
        frag = fragment_header(next_header=58)
        ext = hbh_header(next_header=44) + frag
        events = [
            raw_frame(
                1, "p2", group_mac(G1), "02:00:00:00:00:01",
                ipv6_mld_v1(
                    MLD_TYPE_REPORT_V1, G1, extension=ext
                ),
                vlan=1,
            ),
            self.data_frame(2, "p3", G1),
        ]
        result = self._invalid(events)
        self.assertEqual(result["results"][0]["action"], "flood")
        self.assertEqual(result["results"][1]["action"], "flood")
        self.assertEqual(result["groups"], [])

    def test_missing_router_alert_not_recognized(self):
        # 逐跳选项中无 Router Alert：按普通 IPv6 帧处理
        pad_only = bytes([1, 4, 0, 0, 0, 0])
        ext = hbh_header(next_header=58, options=pad_only)
        events = [
            raw_frame(
                1, "p2", group_mac(G1), "02:00:00:00:00:01",
                ipv6_mld_v1(
                    MLD_TYPE_REPORT_V1, G1, extension=ext
                ),
                vlan=1,
            ),
        ]
        result = self._invalid(events)
        self.assertEqual(result["results"][0]["action"], "flood")
        self.assertEqual(result["groups"], [])

    def test_router_alert_value_ignored(self):
        # Router Alert 选项长度恰为 2 即识别，值内容不检查
        ra_nonzero = bytes([5, 2, 0x00, 0x01, 0, 0])
        ext = hbh_header(next_header=58, options=ra_nonzero)
        events = [
            raw_frame(
                1, "p2", group_mac(G1), "02:00:00:00:00:01",
                ipv6_mld_v1(
                    MLD_TYPE_REPORT_V1, G1, extension=ext
                ),
                vlan=1,
            ),
        ]
        result = self._invalid(events)
        self.assertEqual(result["results"][0]["action"], "mld_report")

    def test_options_not_closed_not_recognized(self):
        # 选项 TLV 超出逐跳头边界：外层不识别
        bad = bytes([5, 4, 0, 0])  # 声明长度 4 但选项区只剩 4 字节
        ext = hbh_header(next_header=58, options=bad)
        events = [
            raw_frame(
                1, "p2", group_mac(G1), "02:00:00:00:00:01",
                ipv6_mld_v1(
                    MLD_TYPE_REPORT_V1, G1, extension=ext
                ),
                vlan=1,
            ),
        ]
        result = self._invalid(events)
        self.assertEqual(result["results"][0]["action"], "flood")

    def test_unknown_icmpv6_type_with_ra_is_invalid(self):
        # 带 RA 的 ICMPv6 Echo Request（128）：RA+ICMPv6 链路成立但类型
        # 非 MLD，固定 mld_invalid（对齐 IGMP 对协议 2 未知类型的处理）
        msg0 = bytes([128, 0]) + b"\x00" * 6
        pseudo = (
            SRC + ALL_MLD_ROUTERS + len(msg0).to_bytes(4, "big")
            + b"\x00\x00\x00\x3a"
        )
        cs = internet_checksum(pseudo + msg0)
        msg = msg0[:2] + cs.to_bytes(2, "big") + msg0[4:]
        packet = ipv6_packet(SRC, ALL_MLD_ROUTERS, hbh_header() + msg)
        events = [
            raw_frame(
                1, "p2", group_mac(ALL_MLD_ROUTERS), "02:00:00:00:00:01",
                packet, vlan=1,
            ),
        ]
        result = self._invalid(events)
        self.assertEqual(result["results"][0]["action"], "mld_invalid")
        self.assertEqual(result["results"][0]["ports"], [])
        self.assertEqual(result["groups"], [])

    def test_payload_length_exceeds_frame_is_invalid(self):
        # IPv6 Payload Length 超过实际载荷：RA+ICMPv6 链路成立但外层边界
        # 破损，固定 mld_invalid（对齐 IGMP 总长度越界处理）
        events = [self.report(1, "p2", G1, payload_length=1000)]
        result = self._invalid(events)
        self.assertEqual(result["results"][0]["action"], "mld_invalid")
        self.assertEqual(result["groups"], [])

    def test_wrong_ip_version_not_recognized(self):
        events = [
            raw_frame(
                1, "p2", group_mac(G1), "02:00:00:00:00:01",
                ipv6_mld_v1(MLD_TYPE_REPORT_V1, G1, first_byte=0x40),
                vlan=1,
            ),
        ]
        result = self._invalid(events)
        self.assertEqual(result["results"][0]["action"], "flood")

    def test_no_hop_by_hop_not_recognized(self):
        # 首扩展非逐跳选项（直接 ICMPv6，无 RA）：不识别
        msg = mld_v1_message(MLD_TYPE_REPORT_V1, G1)
        packet = ipv6_packet(
            SRC, G1, msg, hop_limit=1, next_header=58
        )
        events = [
            raw_frame(
                1, "p2", group_mac(G1), "02:00:00:00:00:01",
                packet, vlan=1,
            ),
        ]
        result = self._invalid(events)
        self.assertEqual(result["results"][0]["action"], "flood")


class MldAdmitTest(MldSnoopCase):
    def test_bad_fcs_and_vlan_reject_never_reach_mld(self):
        config = make_config(router_ports=("p1",))
        bad = self.report(1, "p2", G1, bad_fcs=True)
        # p2 允许 1、2：vlan3 准入拒绝
        tagged = self.report(2, "p2", G1, vlan=3)
        events = [bad, tagged, self.report(3, "p2", G1)]
        result = self.simulate(config, events)
        self.assertEqual(
            [(r["class"], r["action"]) for r in result["results"]],
            [("bad_fcs", "drop"), ("good", "drop"),
             ("good", "mld_report")],
        )

    def test_mld_on_non_forwarding_port_ignored(self):
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
            self.data_frame(2, "p3", G1),
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
            self.data_frame(3, "p3", G1),
            link_event(4, "L1", False),
            self.data_frame(5, "p3", G1),
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][0]["action"], "mld_report")
        self.assertEqual(result["results"][1]["action"], "multicast")
        self.assertEqual(result["results"][2]["action"], "flood")
        self.assertEqual(result["groups"], [])


class MldV2ControlTest(MldSnoopCase):
    def test_action_and_router_delivery(self):
        config = make_config(router_ports=("p1",))
        events = [
            self.v2_report(1, "p2", [(V2_MODE_IS_INCLUDE, G1, [S1])]),
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][0]["action"], "mldv2_report")
        self.assertEqual(
            result["results"][0]["ports"], [{"name": "p1", "vlan": 1}]
        )

    def test_report_floods_without_eligible_router(self):
        config = make_config(router_ports=())
        events = [
            self.v2_report(1, "p2", [(V2_MODE_IS_INCLUDE, G1, [])])
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][0]["action"], "mldv2_report")
        self.assertEqual(
            [p["name"] for p in result["results"][0]["ports"]],
            ["p1", "p3", "p4"],
        )

    def test_include_filter(self):
        config = make_config(router_ports=("p1",))
        events = [
            self.v2_report(1, "p2", [(V2_MODE_IS_INCLUDE, G1, [S1])]),
            self.data_frame(2, "p3", G1, src=S1),
            self.data_frame(3, "p3", G1, src=S2),
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            [r["action"] for r in result["results"]],
            ["mldv2_report", "multicast", "multicast"],
        )
        # S1 命中 INCLUDE：成员 p2 + 路由 p1；S2 不命中：仅路由 p1
        self.assertEqual(
            [p["name"] for p in result["results"][1]["ports"]], ["p1", "p2"]
        )
        self.assertEqual(
            [p["name"] for p in result["results"][2]["ports"]], ["p1"]
        )

    def test_empty_include_deletes_member(self):
        config = make_config(router_ports=("p1",))
        events = [
            self.v2_report(1, "p2", [(V2_MODE_IS_INCLUDE, G1, [S1])]),
            self.v2_report(2, "p2", [(V2_MODE_IS_INCLUDE, G1, [])]),
            self.data_frame(3, "p3", G1, src=S1),
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][2]["action"], "flood")
        self.assertEqual(result["groups"], [])

    def test_exclude_filter_and_empty_means_all(self):
        config = make_config(router_ports=("p1",))
        events = [
            self.v2_report(1, "p2", [(V2_MODE_IS_EXCLUDE, G1, [S1])]),
            self.data_frame(2, "p3", G1, src=S1),  # 被排除
            self.data_frame(3, "p3", G1, src=S2),  # 接收
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            [p["name"] for p in result["results"][1]["ports"]], ["p1"]
        )
        self.assertEqual(
            [p["name"] for p in result["results"][2]["ports"]], ["p1", "p2"]
        )
        # 空集合 EXCLUDE：接收全部源
        events = [
            self.v2_report(1, "p2", [(V2_MODE_IS_EXCLUDE, G1, [])]),
            self.data_frame(2, "p3", G1, src=S2),
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            [p["name"] for p in result["results"][1]["ports"]], ["p1", "p2"]
        )

    def test_allow_block_semantics(self):
        config = make_config(router_ports=("p1",))
        events = [
            self.v2_report(1, "p2", [(V2_MODE_IS_INCLUDE, G1, [S1])]),
            # ALLOW_NEW_SOURCES 对 INCLUDE 取并集
            self.v2_report(2, "p2", [(V2_ALLOW_NEW_SOURCES, G1, [S2])]),
            self.data_frame(3, "p3", G1, src=S2),
            # 切到 EXCLUDE {S1}
            self.v2_report(4, "p2", [(V2_CHANGE_TO_EXCLUDE, G1, [S1])]),
            # BLOCK_OLD_SOURCES 对 EXCLUDE 取并集
            self.v2_report(5, "p2", [(V2_BLOCK_OLD_SOURCES, G1, [S2])]),
            self.data_frame(6, "p3", G1, src=S2),
            # ALLOW_NEW_SOURCES 对 EXCLUDE 做差集：解除 S1 封锁
            self.v2_report(7, "p2", [(V2_ALLOW_NEW_SOURCES, G1, [S1])]),
            self.data_frame(8, "p3", G1, src=S1),
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            [p["name"] for p in result["results"][2]["ports"]], ["p1", "p2"]
        )
        # S2 此时被 EXCLUDE：仅路由 p1
        self.assertEqual(
            [p["name"] for p in result["results"][5]["ports"]], ["p1"]
        )
        self.assertEqual(
            [p["name"] for p in result["results"][7]["ports"]], ["p1", "p2"]
        )
        member = result["groups"][0]["members"][0]
        self.assertEqual(member["mode"], "exclude")
        # EXCLUDE {S1,S2} 再 ALLOW S1（差集）-> EXCLUDE {S2}
        self.assertEqual(member["sources"], ["2001:db8::a"])

    def test_block_on_include_difference_deletes_when_empty(self):
        config = make_config(router_ports=("p1",))
        events = [
            self.v2_report(1, "p2", [(V2_MODE_IS_INCLUDE, G1, [S1])]),
            # BLOCK_OLD_SOURCES 对 INCLUDE 做差集：集合变空 -> 删除成员
            self.v2_report(2, "p2", [(V2_BLOCK_OLD_SOURCES, G1, [S1])]),
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["groups"], [])

    def test_records_apply_in_order_unified_expiry(self):
        config = make_config(membership_age=50, router_ports=("p1",))
        events = [
            # 先 INCLUDE {S1}，再 CHANGE_TO_INCLUDE {S2}：后者覆盖
            self.v2_report(
                10, "p2",
                [(V2_MODE_IS_INCLUDE, G1, [S1]),
                 (V2_CHANGE_TO_INCLUDE, G1, [S2])],
            ),
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            result["groups"][0]["members"],
            [{"name": "p2", "expires": 60, "mode": "include",
              "sources": ["2001:db8::a"]}],
        )

    def test_multiple_records_multiple_groups(self):
        config = make_config(router_ports=("p1",))
        events = [
            self.v2_report(
                1, "p2",
                [(V2_MODE_IS_INCLUDE, G1, [S1]),
                 (V2_MODE_IS_EXCLUDE, G2, [S1])],
            ),
            self.data_frame(2, "p3", G1, src=S1),
            self.data_frame(3, "p3", G2, src=S2),
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            [g["group"] for g in result["groups"]],
            ["ff15::2", "ff15::3"],
        )
        self.assertEqual(result["results"][1]["action"], "multicast")
        self.assertEqual(result["results"][2]["action"], "multicast")

    def test_two_members_independent_filters(self):
        config = make_config(router_ports=("p1",))
        events = [
            self.v2_report(1, "p2", [(V2_MODE_IS_INCLUDE, G1, [S1])]),
            self.v2_report(2, "p3", [(V2_MODE_IS_INCLUDE, G1, [S2])]),
            self.data_frame(3, "p4", G1, src=S1),
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            [p["name"] for p in result["results"][2]["ports"]], ["p1", "p2"]
        )

    def test_v1_and_v2_coexist_key_shapes(self):
        config = make_config(membership_age=50, router_ports=("p1",))
        events = [
            self.report(1, "p3", G1),
            self.v2_report(2, "p2", [(V2_MODE_IS_EXCLUDE, G1, [S1])]),
        ]
        result = self.simulate(config, events)
        members = result["groups"][0]["members"]
        # 配置端口序：p2 在 p3 前；p2 为 v2 四键，p3 保持 v1 两键
        self.assertEqual(list(members[0]), ["name", "expires", "mode",
                                            "sources"])
        self.assertEqual(members[0], {
            "name": "p2", "expires": 52, "mode": "exclude",
            "sources": ["2001:db8::9"],
        })
        self.assertEqual(list(members[1]), ["name", "expires"])
        self.assertEqual(members[1], {"name": "p3", "expires": 51})

    def test_v2_sources_numeric_sorted(self):
        config = make_config(router_ports=("p1",))
        events = [
            self.v2_report(
                1, "p2",
                [(V2_MODE_IS_INCLUDE, G1, [S2, S1, S3])],
            ),
        ]
        result = self.simulate(config, events)
        # 数值序而非字典序：::9 < ::a < 1::1
        self.assertEqual(
            result["groups"][0]["members"][0]["sources"],
            ["2001:db8::9", "2001:db8::a", "2001:db8:1::1"],
        )

    def test_v2_aging(self):
        config = make_config(membership_age=50, router_ports=("p1",))
        events = [
            self.v2_report(1, "p2", [(V2_MODE_IS_INCLUDE, G1, [S1])]),
            self.data_frame(50, "p3", G1, src=S1),
            self.data_frame(51, "p3", G1, src=S1),
        ]
        result = self.simulate(config, events)
        # expires=51：t=50 仍成员，t=51 事件前清除 -> 泛洪
        self.assertEqual(
            [r["action"] for r in result["results"][1:]],
            ["multicast", "flood"],
        )
        self.assertEqual(result["groups"], [])


class MldV2InvalidTest(MldSnoopCase):
    def _invalid_v2(self, **kwargs):
        config = make_config(router_ports=("p1",))
        events = [
            self.v2_report(1, "p2", [(V2_MODE_IS_INCLUDE, G1, [S1])]),
            self.v2_report(2, "p2", **kwargs),
        ]
        return self.simulate(config, events)

    def test_auxiliary_data_skipped_but_must_close(self):
        config = make_config(router_ports=("p1",))
        # 记录带 1 字辅助数据：忽略内容，成员正常建立
        events = [
            self.v2_report(
                1, "p2",
                [(V2_MODE_IS_INCLUDE, G1, [S1])], aux_words=1,
            ),
            self.data_frame(2, "p3", G1, src=S1),
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][0]["action"], "mldv2_report")
        self.assertEqual(
            [p["name"] for p in result["results"][1]["ports"]], ["p1", "p2"]
        )

    def test_bad_checksum_invalid_no_state(self):
        result = self._invalid_v2(
            records=[(V2_MODE_IS_INCLUDE, G1, [S1])],
            bad_checksum=True,
        )
        self.assertEqual(result["results"][1]["action"], "mld_invalid")
        self.assertEqual(result["results"][1]["ports"], [])
        # 首帧成员保持不变
        self.assertEqual(len(result["groups"][0]["members"]), 1)
        self.assertEqual(result["ports"][1]["drop"], 1)
        self.assertEqual(result["vlans"][0]["drop"], 1)

    def test_bad_record_type_invalid(self):
        result = self._invalid_v2(records=[(7, G1, [S1])])
        self.assertEqual(result["results"][1]["action"], "mld_invalid")

    def test_non_multicast_group_invalid(self):
        result = self._invalid_v2(
            records=[(V2_MODE_IS_INCLUDE, S1, [S1])]
        )
        self.assertEqual(result["results"][1]["action"], "mld_invalid")

    def test_bad_source_address_invalid(self):
        # 未指定 ::、环回 ::1、组播 ff02::1 均非有效源地址；链路本地
        # fe80::1 合法
        for source in (UNSPECIFIED, LOOPBACK, ALL_MLD_ROUTERS, G1):
            result = self._invalid_v2(
                records=[(V2_MODE_IS_INCLUDE, G1, [source])]
            )
            self.assertEqual(
                result["results"][1]["action"], "mld_invalid", source.hex()
            )
        result = self._invalid_v2(
            records=[(
                V2_MODE_IS_INCLUDE, G1,
                [bytes.fromhex("fe800000000000000000000000000009")],
            )]
        )
        self.assertEqual(result["results"][1]["action"], "mldv2_report")

    def test_length_not_closed_invalid(self):
        result = self._invalid_v2(
            records=[(V2_MODE_IS_INCLUDE, G1, [S1])], truncate=2
        )
        self.assertEqual(result["results"][1]["action"], "mld_invalid")

    def test_record_count_mismatch_invalid(self):
        result = self._invalid_v2(
            records=[(V2_MODE_IS_INCLUDE, G1, [S1])], count=2
        )
        self.assertEqual(result["results"][1]["action"], "mld_invalid")
        result = self._invalid_v2(
            records=[(V2_MODE_IS_INCLUDE, G1, [S1])], append=b"\x00"
        )
        self.assertEqual(result["results"][1]["action"], "mld_invalid")

    def test_frame_validated_before_commit(self):
        # 两条记录中第二条源地址非法：整帧丢弃，第一条也不得生效
        config = make_config(router_ports=("p1",))
        events = [
            self.v2_report(1, "p2", [(V2_MODE_IS_INCLUDE, G2, [S1])]),
            self.v2_report(
                2, "p2",
                [(V2_MODE_IS_INCLUDE, G1, [S1]),
                 (V2_MODE_IS_INCLUDE, G1, [UNSPECIFIED])],
            ),
            self.data_frame(3, "p3", G1, src=S1),
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][1]["action"], "mld_invalid")
        # G1 无成员（未提交），数据泛洪；G2 成员保持
        self.assertEqual(result["results"][2]["action"], "flood")
        self.assertEqual(
            [g["group"] for g in result["groups"]], ["ff15::2"]
        )

    def test_hop_limit_v2_invalid(self):
        result = self._invalid_v2(
            records=[(V2_MODE_IS_INCLUDE, G1, [S1])], hop_limit=2
        )
        self.assertEqual(result["results"][1]["action"], "mld_invalid")


class MldRecordTest(MldSnoopCase):
    def _config_events(self):
        config = make_config(router_ports=("p1",))
        events = [
            self.report(1, "p2", G1),
            self.data_frame(2, "p3", G1),
            self.done(3, "p2", G1),
            self.query(4, "p2", G1),
        ]
        return config, events

    def test_record_auto_detects_and_replay_byte_identical(self):
        config, events = self._config_events()
        self.write(config, events)
        code, direct, err = self.run_cmd(
            "mld-snoop-decode", self.cfg, self.evt
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
        # LOG 契约：config 原样保留（含 mld），output 为结果项，
        # 帧恒 applied；无链路项 version 恒 0
        with open(self.log, "rb") as handle:
            doc = json.loads(handle.read().decode())
        self.assertEqual(doc["config"], config)
        self.assertEqual(len(doc["records"]), 4)
        self.assertTrue(all(r["applied"] for r in doc["records"]))
        self.assertTrue(all(r["version"] == 0 for r in doc["records"]))
        self.assertEqual(
            [r["output"]["action"] for r in doc["records"]],
            ["mld_report", "multicast", "mld_done", "mld_query"],
        )

    def test_v2_record_replay_byte_identical(self):
        config = make_config(router_ports=("p1",))
        events = [
            self.v2_report(
                1, "p2",
                [(V2_MODE_IS_INCLUDE, G1, [S1, S2])],
            ),
            self.data_frame(2, "p3", G1, src=S1),
        ]
        self.write(config, events)
        code, direct, err = self.run_cmd(
            "mld-snoop-decode", self.cfg, self.evt
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
        with open(self.log, "rb") as handle:
            doc = json.loads(handle.read().decode())
        self.assertEqual(
            doc["records"][0]["output"]["action"], "mldv2_report"
        )

    def test_abstract_frame_shape_rejected(self):
        # mld 配置的 record 不接受含 src 的抽象帧（九键）：invalid_input
        config = make_config(router_ports=("p1",))
        events = [
            {"t": 1, "port": "p2", "src": "02:00:00:00:00:01",
             "dst": group_mac(G1), "vlan": 1, "length": 100,
             "fcs": True, "alignment": True,
             "ethertype": 34525, "priority": 0},
        ]
        self.write(config, events)
        proc = subprocess.run(
            [sys.executable, SWITCH, "record", self.cfg, self.evt,
             self.log],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(proc.returncode, 4)
        self.assertFalse(os.path.exists(self.log))

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


class MldBillingTest(MldSnoopCase):
    # B=1、L=0、P=4：初始 1；三帧 E=0,1,2 计 5+6+7；stp 部分 19。
    # mld 附加 N*(N+P+1)=3*8=24；总计 43。
    TOTAL = 43

    def _write_basic(self):
        config = make_config(router_ports=("p1",))
        events = [
            self.report(1, "p2", G1),
            self.data_frame(2, "p3", G1),
            self.query(3, "p2", G1),
        ]
        self.write(config, events)

    def test_entry_work_boundary(self):
        self._write_basic()
        head = ("1048576", "16777216", "100000", "16777216")
        code, ok, err = self.run_cmd(
            "mld-snoop-decode", self.cfg, self.evt, *head,
            str(self.TOTAL),
        )
        self.assertEqual(code, 0, err)
        code, out, err = self.run_cmd(
            "mld-snoop-decode", self.cfg, self.evt, *head,
            str(self.TOTAL - 1),
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"mld_work_limit"}\n')
        # 未给工作量上限时按默认值执行
        code, out, err = self.run_cmd(
            "mld-snoop-decode", self.cfg, self.evt
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


class MldV2BillingTest(MldSnoopCase):
    # B=1、L=0、P=4：初始 1；两帧 E=0,1 计 5+6；stp 小计 12。
    # N*(N+P+1)=2*7=14；v2 帧含 1 组记录 2 源地址：再加 1+2=3。总计 29。
    TOTAL = 29

    def _write(self):
        config = make_config(router_ports=("p1",))
        events = [
            self.v2_report(
                1, "p2",
                [(V2_MODE_IS_INCLUDE, G1, [S1, S2])],
            ),
            self.data_frame(2, "p3", G1, src=S1),
        ]
        self.write(config, events)

    def test_v2_work_boundary(self):
        self._write()
        head = ("1048576", "16777216", "100000", "16777216")
        code, ok, err = self.run_cmd(
            "mld-snoop-decode", self.cfg, self.evt, *head, str(self.TOTAL)
        )
        self.assertEqual(code, 0, err)
        code, out, err = self.run_cmd(
            "mld-snoop-decode", self.cfg, self.evt, *head,
            str(self.TOTAL - 1),
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"mld_work_limit"}\n')

    def test_v2_record_replay_work_boundary(self):
        self._write()
        head = ("100000", "16777216", "1048576", "16777216", "16777216")
        code, record_out, err = self.run_cmd(
            "record", self.cfg, self.evt, self.log, *head, str(self.TOTAL)
        )
        self.assertEqual(code, 0, err)
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


class MldFailureTest(MldSnoopCase):
    def base_config(self):
        return make_config(router_ports=("p1",))

    def test_usage_exit_2(self):
        self.write(self.base_config(), [])
        code, out, err = self.run_cmd(
            "mld-snoop-decode", self.cfg, self.evt, "1048576",
        )
        self.assertEqual((code, out), (2, b""))
        code, out, err = self.run_cmd("mld-snoop-decode")
        self.assertEqual((code, out), (2, b""))
        code, out, err = self.run_cmd(
            "mld-snoop-decode", self.cfg, self.evt,
            "1048576", "16777216", "100000", "16777216", "zero",
        )
        self.assertEqual((code, out), (2, b""))

    def test_missing_file_exit_3(self):
        code, out, err = self.run_cmd(
            "mld-snoop-decode",
            os.path.join(self.tmp.name, "nope.json"), self.evt,
        )
        self.assertEqual((code, out), (3, b""))
        self.assertEqual(err, b'{"error":"file_not_found"}\n')

    def test_bad_config_exit_4(self):
        cases = []
        bad_age = self.base_config()
        bad_age["mld"] = {"membership_age": 0, "router_ports": ["p1"]}
        cases.append(bad_age)
        dup = self.base_config()
        dup["mld"] = {"membership_age": 5, "router_ports": ["p1", "p1"]}
        cases.append(dup)
        unknown = self.base_config()
        unknown["mld"] = {"membership_age": 5, "router_ports": ["px"]}
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
        bad_shape["mld"] = [5, ["p1"]]
        cases.append(bad_shape)
        bad_neg = self.base_config()
        bad_neg["mld"] = {"membership_age": -1, "router_ports": ["p1"]}
        cases.append(bad_neg)
        for config in cases:
            self.write(config, [])
            code, out, err = self.run_cmd(
                "mld-snoop-decode", self.cfg, self.evt
            )
            self.assertEqual((code, out), (4, b""), config)
            self.assertEqual(err, b'{"error":"invalid_input"}\n')

    def test_bad_events_exit_4(self):
        # 双标签帧为非法输入（沿用 stp-decode 外壳校验）
        raw = bytes.fromhex(
            raw_frame(
                0, "p2", group_mac(G1), "02:00:00:00:00:01",
                ipv6_mld_v1(MLD_TYPE_REPORT_V1, G1), vlan=1,
            )["data"]
        )
        double = raw[:16] + b"\x81\x00\x10\x00" + raw[16:]
        events = [{"t": 0, "port": "p2", "data": double.hex()}]
        self.write(self.base_config(), events)
        code, out, err = self.run_cmd(
            "mld-snoop-decode", self.cfg, self.evt
        )
        self.assertEqual((code, out), (4, b""))

    def test_resource_limits_exit_5(self):
        config = make_config(router_ports=("p1",))
        events = [self.report(1, "p2", G1)]
        self.write(config, events)
        # item_limit：0 不匹配 [1-9][0-9]* -> usage 2
        code, out, err = self.run_cmd(
            "mld-snoop-decode", self.cfg, self.evt,
            "1048576", "16777216", "0", "16777216",
        )
        self.assertEqual(code, 2)
        code, out, err = self.run_cmd(
            "mld-snoop-decode", self.cfg, self.evt,
            "1048576", "16777216",
        )
        self.assertEqual(code, 0, err)
        # config 字节上限：配置本身约数百字节
        code, out, err = self.run_cmd(
            "mld-snoop-decode", self.cfg, self.evt,
            "50", "16777216",
        )
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"config_limit"}\n')

    def test_invalid_config_record_exit_4_no_log(self):
        bad = self.base_config()
        bad["mld"] = {"membership_age": -1, "router_ports": ["p1"]}
        self.write(bad, [])
        code, out, err = self.run_cmd(
            "record", self.cfg, self.evt, self.log
        )
        self.assertEqual((code, out), (4, b""))
        self.assertFalse(os.path.exists(self.log))

    def test_mld_config_does_not_route_to_igmp(self):
        # mld 配置必须走独立模式：IGMPv2 帧在本入口按普通 IPv4 帧泛洪，
        # 不产生 igmp_* 动作与成员
        def ipv4_igmp_report():
            group = bytes([224, 1, 2, 3])
            msg = bytes([0x16, 0x00]) + b"\x00\x00" + group
            cs = internet_checksum(msg)
            msg = msg[:2] + cs.to_bytes(2, "big") + msg[4:]
            iphdr = (
                bytes([0x45, 0x00]) + (20 + 8).to_bytes(2, "big")
                + b"\x00\x00\x00\x00\x01\x02" + b"\x00\x00"
                + bytes([10, 0, 0, 1]) + group
            )
            csum = internet_checksum(iphdr)
            iphdr = iphdr[:10] + csum.to_bytes(2, "big") + iphdr[12:]
            return iphdr + msg + b"\x00" * 18

        events = [
            raw_frame(
                1, "p2", "01:00:5e:01:02:03", "02:00:00:00:00:01",
                ipv4_igmp_report(), vlan=1, ethertype=0x0800,
            ),
        ]
        result = self.simulate(self.base_config(), events)
        self.assertEqual(result["results"][0]["action"], "flood")
        self.assertEqual(result["groups"], [])


if __name__ == "__main__":
    unittest.main()
