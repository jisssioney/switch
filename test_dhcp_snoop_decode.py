#!/usr/bin/env python3
"""dhcp-snoop-decode 端到端回归。

覆盖：单层 802.1Q 上 IPv4/UDP/BOOTP/DHCP 识别（协议长度、IPv4 首部校验
和、magic cookie、关键选项）；非 DHCP 帧沿用既有 VLAN/STP/帧合法性/转发
语义；malformed_dhcp 丢弃且不学习 FDB/请求/绑定；非受信任端口
OFFER/ACK/NAK 输出 untrusted_server 丢弃；DISCOVER/REQUEST 按
xid/chaddr/VLAN 记录接入口；受信任端口匹配 ACK 建立/刷新绑定（租期截断、
先老化）；NAK 清除匹配请求；RELEASE 端口/MAC/VLAN 全匹配才删除；
binding_conflict 丢弃；binding_full 时 ACK 仍转发但不建绑定；末态绑定排序
与每端口分类计数；逐事件 t/action/ports/snoop 固定键序；record 自动识别
与 replay 逐字节复现；工作量逐事件 1+P+处理前活动绑定数（边界等于合法）；
退出码 2/3/4/5 与错误名；相同输入逐字节一致。仅用标准库。
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


def ip_header(src, dst, protocol, payload_len, fragment_word=0,
              total_length=None):
    if total_length is None:
        total_length = 20 + payload_len
    header = (
        bytes([0x45, 0x00])
        + total_length.to_bytes(2, "big")
        + b"\x00\x00"
        + fragment_word.to_bytes(2, "big")
        + bytes([64, protocol])
        + b"\x00\x00"
        + bytes(src)
        + bytes(dst)
    )
    checksum = internet_checksum(header)
    return header[:10] + checksum.to_bytes(2, "big") + header[12:]


def udp_segment(sport, dport, payload, udp_len=None):
    if udp_len is None:
        udp_len = 8 + len(payload)
    return (
        sport.to_bytes(2, "big")
        + dport.to_bytes(2, "big")
        + udp_len.to_bytes(2, "big")
        + b"\x00\x00"
        + payload
    )


def opt(code, value):
    return bytes([code, len(value)]) + bytes(value)


OPT_END = bytes([255])
OPT_PAD = bytes([0])


def msg_type_option(mtype):
    return bytes([53, 1, mtype])


def lease_option(lease):
    return bytes([51, 4]) + lease.to_bytes(4, "big")


def bootp_message(op, chaddr, xid, options, ciaddr=(0, 0, 0, 0),
                  yiaddr=(0, 0, 0, 0), siaddr=(0, 0, 0, 0),
                  hlen=6, hops=0, tail_pad=True):
    """构造 300 字节 BOOTP 请求/应答（236 定长 + cookie + 选项 + 零填充）。"""
    msg = (
        bytes([op, 1, hlen, hops])
        + xid.to_bytes(4, "big")
        + b"\x00\x00"  # secs
        + b"\x00\x00"  # flags
        + bytes(ciaddr)
        + bytes(yiaddr)
        + bytes(siaddr)
        + b"\x00" * 4  # giaddr
        + bytes(chaddr)
        + b"\x00" * 10  # chaddr 余 10 字节
        + b"\x00" * 64  # sname
        + b"\x00" * 128  # file
        + b"\x63\x82\x53\x63"
        + options
    )
    if tail_pad and len(msg) < 300:
        msg += b"\x00" * (300 - len(msg))
    return msg


DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK, RELEASE, INFORM = range(1, 9)

BCAST_MAC = "ff:ff:ff:ff:ff:ff"
CLI_MAC = "02:00:00:00:00:01"
CLI2_MAC = "02:00:00:00:00:02"
SVR_MAC = "02:00:00:00:00:09"
BCAST_IP = (255, 255, 255, 255)
SVR_IP = (10, 0, 0, 9)
IP1 = (10, 0, 0, 5)
IP2 = (10, 0, 0, 6)


def _mac(mac_text):
    return bytes(int(x, 16) for x in mac_text.split(":"))


def client_packet(mtype, chaddr=CLI_MAC, xid=0x1234, lease=None,
                  ciaddr=(0, 0, 0, 0), extra_options=b"", options=None,
                  **bootp_kwargs):
    if options is None:
        body = msg_type_option(mtype)
        if lease is not None:
            body += lease_option(lease)
        body += extra_options + OPT_END
        options = body
    bp = bootp_message(
        1, _mac(chaddr), xid, options, ciaddr=ciaddr, **bootp_kwargs
    )
    return ip_header((0, 0, 0, 0), BCAST_IP, 17, 8 + len(bp)) + (
        udp_segment(68, 67, bp)
    )


def server_packet(mtype, yiaddr=(0, 0, 0, 0), chaddr=CLI_MAC, xid=0x1234,
                  lease=None, src_ip=SVR_IP, dst_ip=BCAST_IP,
                  extra_options=b"", options=None, **bootp_kwargs):
    if options is None:
        body = msg_type_option(mtype)
        if lease is not None:
            body += lease_option(lease)
        body += extra_options + OPT_END
        options = body
    bp = bootp_message(
        2, _mac(chaddr), xid, options, yiaddr=yiaddr, **bootp_kwargs
    )
    return ip_header(src_ip, dst_ip, 17, 8 + len(bp)) + (
        udp_segment(67, 68, bp)
    )


def raw_frame(t, port, dst, src, payload, vlan=None, ethertype=0x0800,
              bad_fcs=False):
    d = _mac(dst)
    s = _mac(src)
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


def with_recomputed_fcs(event, mutate_body):
    """对原始帧 body（去掉 4 字节 FCS）做变异并重新计算 FCS。"""
    raw = bytes.fromhex(event["data"])
    body = mutate_body(raw[:-4])
    fcs = (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little")
    new_event = dict(event)
    new_event["data"] = (body + fcs).hex()
    return new_event


def discover(t, port="p2", chaddr=CLI_MAC, xid=0x1234, vlan=None,
             dst=BCAST_MAC, bad_fcs=False):
    return raw_frame(
        t, port, dst, chaddr, client_packet(DISCOVER, chaddr, xid),
        vlan=vlan, bad_fcs=bad_fcs,
    )


def request(t, port="p2", chaddr=CLI_MAC, xid=0x1234, ciaddr=(0, 0, 0, 0),
            vlan=None, dst=BCAST_MAC, lease=None):
    return raw_frame(
        t, port, dst, chaddr,
        client_packet(REQUEST, chaddr, xid, ciaddr=ciaddr, lease=lease),
        vlan=vlan,
    )


def offer(t, yiaddr=IP1, port="p1", chaddr=CLI_MAC, xid=0x1234, vlan=None,
          dst=BCAST_MAC):
    return raw_frame(
        t, port, dst, SVR_MAC,
        server_packet(OFFER, yiaddr, chaddr, xid), vlan=vlan,
    )


def ack(t, yiaddr=IP1, lease=500, port="p1", chaddr=CLI_MAC, xid=0x1234,
        vlan=None, dst=BCAST_MAC, src_ip=SVR_IP):
    return raw_frame(
        t, port, dst, SVR_MAC,
        server_packet(ACK, yiaddr, chaddr, xid, lease=lease, src_ip=src_ip),
        vlan=vlan,
    )


def nak(t, port="p1", chaddr=CLI_MAC, xid=0x1234, vlan=None, dst=BCAST_MAC):
    return raw_frame(
        t, port, dst, SVR_MAC,
        server_packet(NAK, (0, 0, 0, 0), chaddr, xid), vlan=vlan,
    )


def release(t, ciaddr, port="p2", chaddr=CLI_MAC, xid=0x1234, vlan=None):
    return raw_frame(
        t, port, BCAST_MAC, chaddr,
        client_packet(RELEASE, chaddr, xid, ciaddr=ciaddr), vlan=vlan,
    )


def inform(t, port="p2", chaddr=CLI_MAC, xid=0x1234, ciaddr=IP1, vlan=None):
    return raw_frame(
        t, port, BCAST_MAC, chaddr,
        client_packet(INFORM, chaddr, xid, ciaddr=ciaddr), vlan=vlan,
    )


def decline(t, ciaddr, port="p2", chaddr=CLI_MAC, xid=0x1234, vlan=None):
    return raw_frame(
        t, port, BCAST_MAC, chaddr,
        client_packet(DECLINE, chaddr, xid, ciaddr=ciaddr), vlan=vlan,
    )


def link_event(t, lid, up):
    return {"t": t, "id": lid, "up": up}


def plain_frame(t, port="p2", dst=SVR_MAC, src=CLI_MAC, protocol=17,
                dport=None, payload_len=40, vlan=None, fragment=0,
                src_ip=(10, 0, 0, 1), dst_ip=(10, 0, 0, 9)):
    """非 DHCP 的 IPv4 UDP（或指定协议）帧。"""
    payload = b"\x00" * payload_len
    if dport is None:
        dport = 1000
    if protocol == 17:
        l3 = ip_header(src_ip, dst_ip, 17, 8 + len(payload),
                       fragment_word=fragment) + udp_segment(
            2000, dport, payload
        )
    else:
        l3 = ip_header(src_ip, dst_ip, protocol, len(payload),
                       fragment_word=fragment) + payload
    return raw_frame(t, port, dst, src, l3, vlan=vlan)


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


def make_config(ports=None, trusted=("p1",), capacities=((1, 8),),
                max_lease=1000, bridges=("b1",), links=None, delay=2):
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
        "dhcp": {
            "trusted_ports": list(trusted),
            "binding_capacity": [
                {"vlan": vlan, "limit": limit}
                for vlan, limit in capacities
            ],
            "max_lease": max_lease,
        },
    }


def bind_sequence(xid=0x1234, chaddr=CLI_MAC, access="p2", trusted="p1",
                  ip=IP1, lease=500, start=1, vlan=None):
    """DISCOVER/REQUEST/ACK 三帧完整绑定序列。"""
    return [
        discover(start, access, chaddr, xid, vlan=vlan),
        request(start + 1, access, chaddr, xid, vlan=vlan),
        ack(start + 2, ip, lease, trusted, chaddr, xid, vlan=vlan),
    ]


class DhcpCase(unittest.TestCase):
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
            "dhcp-snoop-decode", self.cfg, self.evt
        )
        self.assertEqual(code, 0, err)
        return json.loads(out.decode())

    def actions(self, result):
        return [(r["t"], r["action"]) for r in result["results"]]


# ---------------------------------------------------------------------
# 控制面：识别、动作、接入口记录
# ---------------------------------------------------------------------

class DhcpControlTest(DhcpCase):
    def test_discover_offer_request_ack_actions_and_flood(self):
        result = self.simulate(
            make_config(),
            [
                discover(1),
                offer(2),
                request(3),
                ack(4, lease=500),
            ],
        )
        self.assertEqual(
            self.actions(result),
            [(1, "discover"), (2, "offer"), (3, "request"), (4, "ack")],
        )
        # 广播帧泛洪到同 VLAN 其余 forwarding 端口（排除入端口，带标签）
        self.assertEqual(
            [p["name"] for p in result["results"][0]["ports"]],
            ["p1", "p3", "p4"],
        )
        self.assertEqual(
            [p["name"] for p in result["results"][3]["ports"]],
            ["p2", "p3", "p4"],
        )
        # 每帧固定键序 t/action/ports/snoop
        for record in result["results"]:
            self.assertEqual(
                list(record), ["t", "action", "ports", "snoop"]
            )
        self.assertEqual(
            result["results"][0]["snoop"]["verdict"], "discover"
        )

    def test_untagged_ingress_uses_pvid_and_output_tag_semantics(self):
        # 客户端从 hybrid p4（vlan1 在 untagged）发无标签帧：pvid=1；
        # 服务器广播输出到 p4 时去标签（null）
        result = self.simulate(
            make_config(),
            [discover(1, "p4"), offer(2)],
        )
        self.assertEqual(result["results"][0]["action"], "discover")
        offer_ports = {
            p["name"]: p["vlan"] for p in result["results"][1]["ports"]
        }
        self.assertEqual(offer_ports["p4"], None)
        self.assertEqual(offer_ports["p2"], 1)

    def test_tagged_vlan_binding_is_per_vlan(self):
        config = make_config(capacities=((1, 8), (2, 8)))
        # 同一 xid/chaddr 在 vlan1 与 vlan2 各请求一次，分别绑定
        events = bind_sequence(vlan=1) + bind_sequence(
            start=4, ip=IP2, vlan=2
        )
        result = self.simulate(config, events)
        self.assertEqual(
            [(b["vlan"], b["ip"]) for b in result["bindings"]],
            [(1, "10.0.0.5"), (2, "10.0.0.6")],
        )

    def test_ack_binds_to_access_port_not_trusted_port(self):
        result = self.simulate(make_config(), bind_sequence())
        binding = result["bindings"][0]
        self.assertEqual(binding["port"], "p2")  # 接入口，非受信任口 p1
        self.assertEqual(binding["mac"], CLI_MAC)
        self.assertEqual(binding["ip"], "10.0.0.5")
        self.assertEqual(binding["vlan"], 1)
        self.assertEqual(binding["expires"], 3 + 500)

    def test_ack_lease_above_cap_is_truncated(self):
        events = bind_sequence(lease=5000)
        result = self.simulate(make_config(max_lease=1000), events)
        snoop = result["results"][2]["snoop"]
        self.assertTrue(snoop["truncated"])
        self.assertEqual(snoop["lease"], 1000)
        self.assertEqual(result["bindings"][0]["expires"], 3 + 1000)

    def test_ack_lease_within_cap_unchanged(self):
        events = bind_sequence(lease=300)
        result = self.simulate(make_config(max_lease=1000), events)
        snoop = result["results"][2]["snoop"]
        self.assertFalse(snoop["truncated"])
        self.assertEqual(snoop["lease"], 300)

    def test_ack_without_request_is_forwarded_but_not_bound(self):
        result = self.simulate(make_config(), [ack(1, lease=500)])
        snoop = result["results"][0]["snoop"]
        self.assertEqual(snoop["verdict"], "ack")
        self.assertFalse(snoop["bound"])
        self.assertEqual(result["bindings"], [])
        # 数据面仍泛洪
        self.assertTrue(result["results"][0]["ports"])

    def test_ack_wrong_vlan_does_not_match_request(self):
        config = make_config(capacities=((1, 8), (2, 8)))
        events = [
            discover(1, "p2", vlan=1),
            request(2, "p2", vlan=1),
            ack(3, lease=500, vlan=2),  # 受信任口但 VLAN 不匹配
        ]
        result = self.simulate(config, events)
        self.assertFalse(result["results"][2]["snoop"]["bound"])
        self.assertEqual(result["bindings"], [])

    def test_offer_creates_no_binding_or_request_state(self):
        result = self.simulate(make_config(), [offer(1)])
        self.assertEqual(result["results"][0]["action"], "offer")
        self.assertEqual(result["bindings"], [])

    def test_decline_and_inform_do_not_change_bindings(self):
        events = bind_sequence() + [
            decline(5, IP1),
            inform(6, ciaddr=IP1),
        ]
        result = self.simulate(make_config(), events)
        self.assertEqual(
            [r["action"] for r in result["results"][3:]],
            ["decline", "inform"],
        )
        self.assertEqual(len(result["bindings"]), 1)

    def test_refresh_existing_binding_updates_expiry(self):
        events = bind_sequence(lease=500)
        # 同 MAC 同 IP 续约：REQUEST 在 t=10，ACK t=11
        events += [
            request(10, "p2", xid=0x1234),
            ack(11, IP1, lease=500, xid=0x1234),
        ]
        result = self.simulate(make_config(), events)
        self.assertEqual(len(result["bindings"]), 1)
        self.assertEqual(result["bindings"][0]["expires"], 11 + 500)
        self.assertTrue(result["results"][4]["snoop"]["refreshed"])


# ---------------------------------------------------------------------
# NAK / RELEASE / 老化
# ---------------------------------------------------------------------

class DhcpLifecycleTest(DhcpCase):
    def test_nak_clears_matching_request(self):
        events = [
            discover(1),
            nak(2),
            ack(3, IP1, lease=500),  # 请求已被 NAK 清除，ACK 不建绑定
        ]
        result = self.simulate(make_config(), events)
        self.assertTrue(result["results"][1]["snoop"]["matched"])
        self.assertFalse(result["results"][2]["snoop"]["bound"])
        self.assertEqual(result["bindings"], [])

    def test_nak_without_request_reports_unmatched(self):
        result = self.simulate(make_config(), [nak(1)])
        self.assertFalse(result["results"][0]["snoop"]["matched"])

    def test_renew_after_nak_requires_new_request(self):
        events = [
            discover(1),
            nak(2),
            request(3),  # 客户端重新请求
            ack(4, IP1, lease=500),
        ]
        result = self.simulate(make_config(), events)
        self.assertTrue(result["results"][3]["snoop"]["bound"])
        self.assertEqual(len(result["bindings"]), 1)

    def test_release_matching_port_mac_vlan_removes_binding(self):
        events = bind_sequence() + [release(4, IP1, port="p2")]
        result = self.simulate(make_config(), events)
        self.assertTrue(result["results"][3]["snoop"]["removed"])
        self.assertEqual(result["bindings"], [])

    def test_release_wrong_port_keeps_binding(self):
        events = bind_sequence() + [release(4, IP1, port="p3")]
        result = self.simulate(make_config(), events)
        self.assertFalse(result["results"][3]["snoop"]["removed"])
        self.assertEqual(len(result["bindings"]), 1)

    def test_release_wrong_mac_keeps_binding(self):
        events = bind_sequence() + [
            release(4, IP1, port="p3", chaddr=CLI2_MAC)
        ]
        result = self.simulate(make_config(), events)
        self.assertFalse(result["results"][3]["snoop"]["removed"])
        self.assertEqual(len(result["bindings"]), 1)

    def test_release_unknown_ip_is_noop(self):
        events = bind_sequence() + [release(4, IP2, port="p2")]
        result = self.simulate(make_config(), events)
        self.assertFalse(result["results"][3]["snoop"]["removed"])
        self.assertEqual(len(result["bindings"]), 1)

    def test_binding_aged_at_expiry_boundary(self):
        config = make_config()
        events = bind_sequence(lease=50)  # expires = 3+50 = 53
        result = self.simulate(config, events)
        self.assertEqual(result["bindings"][0]["expires"], 53)
        # t=52 仍在期内（先老化 expires<=52 不命中）
        result = self.simulate(
            config, events + [plain_frame(52, "p3", dst=SVR_MAC)]
        )
        self.assertEqual(len(result["bindings"]), 1)
        # t 到达截止值 53：先老化 expires<=53，绑定消失
        result = self.simulate(
            config, events + [plain_frame(53, "p3", dst=SVR_MAC)]
        )
        self.assertEqual(result["bindings"], [])

    def test_aging_runs_before_request_and_binding_count(self):
        config = make_config()
        events = bind_sequence(lease=10)  # expires 13
        events += [
            discover(13),  # 处理前绑定恰好老化
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["bindings"], [])


# ---------------------------------------------------------------------
# 冲突与容量
# ---------------------------------------------------------------------

class DhcpConflictCapacityTest(DhcpCase):
    def test_active_ip_other_mac_is_conflict_and_dropped(self):
        events = bind_sequence(chaddr=CLI_MAC, ip=IP1)
        # 第二客户端从 p3 请求，服务器 ACK 同一 IP
        events += [
            discover(4, "p3", CLI2_MAC, xid=0xABCD),
            request(5, "p3", CLI2_MAC, xid=0xABCD),
            ack(6, IP1, lease=500, port="p1", chaddr=CLI2_MAC,
                xid=0xABCD),
        ]
        result = self.simulate(make_config(), events)
        conflict = result["results"][5]
        self.assertEqual(conflict["action"], "binding_conflict")
        self.assertEqual(conflict["ports"], [])
        self.assertEqual(conflict["snoop"]["owner_mac"], CLI_MAC)
        # 原绑定不变，未建立第二绑定
        self.assertEqual(len(result["bindings"]), 1)
        self.assertEqual(result["bindings"][0]["mac"], CLI_MAC)

    def test_same_mac_renew_same_ip_is_not_conflict(self):
        events = bind_sequence(ip=IP1) + [
            request(10, "p2", xid=0x9999),
            ack(11, IP1, lease=500, xid=0x9999),
        ]
        result = self.simulate(make_config(), events)
        self.assertEqual(result["results"][4]["action"], "ack")
        self.assertEqual(len(result["bindings"]), 1)

    def test_new_binding_over_capacity_is_full_but_ack_forwarded(self):
        config = make_config(capacities=((1, 1),))
        events = bind_sequence(chaddr=CLI_MAC, ip=IP1)
        events += [
            discover(4, "p3", CLI2_MAC, xid=0xABCD),
            request(5, "p3", CLI2_MAC, xid=0xABCD),
            ack(6, IP2, lease=500, chaddr=CLI2_MAC, xid=0xABCD),
        ]
        result = self.simulate(config, events)
        full = result["results"][5]
        self.assertEqual(full["action"], "binding_full")
        # ACK 仍按既有数据面转发（广播泛洪），但不建绑定
        self.assertTrue(full["ports"])
        self.assertEqual([b["ip"] for b in result["bindings"]], ["10.0.0.5"])

    def test_capacity_zero_rejects_first_binding(self):
        config = make_config(capacities=((1, 0),))
        result = self.simulate(config, bind_sequence())
        self.assertEqual(result["results"][2]["action"], "binding_full")
        self.assertEqual(result["bindings"], [])

    def test_capacity_refresh_does_not_consume_new_slot(self):
        config = make_config(capacities=((1, 1),))
        events = bind_sequence(lease=100) + [
            request(10, "p2", xid=0x77),
            ack(11, IP1, lease=100, xid=0x77),
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][4]["action"], "ack")
        self.assertEqual(len(result["bindings"]), 1)

    def test_vlan_without_capacity_entry_is_unlimited(self):
        config = make_config(capacities=((2, 1),))  # vlan1 无项：不限
        events = bind_sequence(vlan=1, ip=IP1)
        result = self.simulate(config, events)
        self.assertEqual(result["results"][2]["action"], "ack")
        self.assertEqual(len(result["bindings"]), 1)

    def test_bindings_sorted_by_vlan_ip_mac_port(self):
        config = make_config(capacities=((1, 8), (2, 8)))
        events = [
            # vlan2 上 IP2（CLI2，p3）
            discover(1, "p3", CLI2_MAC, 0x2, vlan=2),
            request(2, "p3", CLI2_MAC, 0x2, vlan=2),
            ack(3, IP2, lease=9, chaddr=CLI2_MAC, xid=0x2, vlan=2),
            # vlan1 上 IP1（CLI，p2）
            discover(4, "p2", CLI_MAC, 0x1, vlan=1),
            request(5, "p2", CLI_MAC, 0x1, vlan=1),
            ack(6, IP1, lease=9, chaddr=CLI_MAC, xid=0x1, vlan=1),
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            [(b["vlan"], b["ip"]) for b in result["bindings"]],
            [(1, "10.0.0.5"), (2, "10.0.0.6")],
        )


# ---------------------------------------------------------------------
# malformed_dhcp
# ---------------------------------------------------------------------

class DhcpMalformedTest(DhcpCase):
    def _one(self, event):
        return self.simulate(make_config(), [event])["results"][0]

    def test_bad_ip_header_checksum(self):
        event = with_recomputed_fcs(
            discover(1),
            lambda body: body[:14 + 10] + b"\x00\x00" + body[14 + 12:],
        )
        record = self._one(event)
        self.assertEqual(record["action"], "malformed_dhcp")
        self.assertEqual(record["ports"], [])

    def test_bad_magic_cookie(self):
        # 无标签：14 以太 + 20 IP + 8 UDP = 42；cookie 在 BOOTP 偏移 236
        event = with_recomputed_fcs(
            discover(1),
            lambda body: (
                body[:42 + 236] + b"\x00\x00\x00\x00"
                + body[42 + 240:]
            ),
        )
        self.assertEqual(self._one(event)["action"], "malformed_dhcp")

    def test_missing_message_type_option(self):
        packet = client_packet(DISCOVER, options=OPT_END)
        event = raw_frame(1, "p2", BCAST_MAC, CLI_MAC, packet)
        self.assertEqual(self._one(event)["action"], "malformed_dhcp")

    def test_duplicate_message_type_option(self):
        packet = client_packet(
            DISCOVER,
            options=msg_type_option(DISCOVER)
            + msg_type_option(DISCOVER) + OPT_END,
        )
        event = raw_frame(1, "p2", BCAST_MAC, CLI_MAC, packet)
        self.assertEqual(self._one(event)["action"], "malformed_dhcp")

    def test_unknown_message_type(self):
        packet = client_packet(99)
        event = raw_frame(1, "p2", BCAST_MAC, CLI_MAC, packet)
        self.assertEqual(self._one(event)["action"], "malformed_dhcp")

    def test_option_not_closed_with_end(self):
        packet = client_packet(DISCOVER, options=msg_type_option(DISCOVER))
        event = raw_frame(1, "p2", BCAST_MAC, CLI_MAC, packet)
        self.assertEqual(self._one(event)["action"], "malformed_dhcp")

    def test_garbage_after_end(self):
        packet = client_packet(
            DISCOVER, options=msg_type_option(DISCOVER) + OPT_END + b"\x01"
        )
        event = raw_frame(1, "p2", BCAST_MAC, CLI_MAC, packet)
        self.assertEqual(self._one(event)["action"], "malformed_dhcp")

    def test_pad_before_end_is_accepted(self):
        packet = client_packet(
            DISCOVER,
            options=msg_type_option(DISCOVER) + OPT_PAD * 3 + OPT_END,
        )
        event = raw_frame(1, "p2", BCAST_MAC, CLI_MAC, packet)
        self.assertEqual(self._one(event)["action"], "discover")

    def test_unknown_options_are_ignored(self):
        packet = client_packet(
            DISCOVER, extra_options=opt(54, bytes(SVR_IP)) + opt(60, b"x")
        )
        event = raw_frame(1, "p2", BCAST_MAC, CLI_MAC, packet)
        self.assertEqual(self._one(event)["action"], "discover")

    def test_zero_lease_is_malformed(self):
        packet = server_packet(ACK, IP1, lease=None,
                               options=msg_type_option(ACK)
                               + lease_option(0) + OPT_END)
        event = raw_frame(1, "p1", BCAST_MAC, SVR_MAC, packet)
        self.assertEqual(self._one(event)["action"], "malformed_dhcp")

    def test_short_bootp_is_malformed(self):
        bp = bootp_message(1, _mac(CLI_MAC), 0x1234,
                           msg_type_option(DISCOVER) + OPT_END)[:200]
        packet = ip_header((0, 0, 0, 0), BCAST_IP, 17, 8 + len(bp)) + (
            udp_segment(68, 67, bp)
        )
        event = raw_frame(1, "p2", BCAST_MAC, CLI_MAC, packet)
        self.assertEqual(self._one(event)["action"], "malformed_dhcp")

    def test_bad_udp_length_is_malformed(self):
        bp = bootp_message(1, _mac(CLI_MAC), 0x1234,
                           msg_type_option(DISCOVER) + OPT_END)
        packet = ip_header((0, 0, 0, 0), BCAST_IP, 17, 8 + len(bp)) + (
            udp_segment(68, 67, bp, udp_len=8 + len(bp) + 40)
        )
        event = raw_frame(1, "p2", BCAST_MAC, CLI_MAC, packet)
        self.assertEqual(self._one(event)["action"], "malformed_dhcp")

    def test_hlen_not_six_is_malformed(self):
        packet = client_packet(DISCOVER, hlen=5)
        event = raw_frame(1, "p2", BCAST_MAC, CLI_MAC, packet)
        self.assertEqual(self._one(event)["action"], "malformed_dhcp")

    def test_nonzero_hops_is_malformed(self):
        packet = client_packet(DISCOVER, hops=1)
        event = raw_frame(1, "p2", BCAST_MAC, CLI_MAC, packet)
        self.assertEqual(self._one(event)["action"], "malformed_dhcp")

    def test_multicast_chaddr_is_malformed(self):
        # 帧源 MAC 合法（外壳通过），但 BOOTP chaddr 为组播地址：非法
        packet = client_packet(DISCOVER, chaddr="03:00:00:00:00:01")
        event = raw_frame(1, "p2", BCAST_MAC, CLI_MAC, packet)
        self.assertEqual(self._one(event)["action"], "malformed_dhcp")

    def test_client_request_to_client_port_is_malformed(self):
        # op=REQUEST 但 UDP 目的端口为 68（方向不符）
        bp = bootp_message(
            1, _mac(CLI_MAC), 0x1234, msg_type_option(DISCOVER) + OPT_END
        )
        packet = ip_header((0, 0, 0, 0), BCAST_IP, 17, 8 + len(bp)) + (
            udp_segment(68, 68, bp)
        )
        event = raw_frame(1, "p2", BCAST_MAC, CLI_MAC, packet)
        self.assertEqual(self._one(event)["action"], "malformed_dhcp")

    def test_reply_op_with_client_type_is_malformed(self):
        packet = server_packet(DISCOVER)  # op=2 但类型为客户端 DISCOVER
        event = raw_frame(1, "p1", BCAST_MAC, SVR_MAC, packet)
        self.assertEqual(self._one(event)["action"], "malformed_dhcp")

    def test_malformed_learns_no_fdb_request_or_binding(self):
        event = with_recomputed_fcs(
            discover(1),
            lambda body: body[:14 + 10] + b"\x00\x00" + body[14 + 12:],
        )
        result = self.simulate(make_config(), [event])
        self.assertEqual(result["bindings"], [])
        # 坏 DHCP 计 drop，rx 仍计
        p2 = result["ports"][1]
        self.assertEqual(p2["rx"], 1)
        self.assertEqual(p2["drop"], 1)
        # 随后到同一客户端 MAC 的单播不因前帧学习而命中
        follow = self.simulate(
            make_config(),
            [event, plain_frame(2, "p3", dst=CLI_MAC, src=SVR_MAC,
                                dport=1000)],
        )
        # 第二帧为普通 IPv4，目的 MAC 未学习 -> 泛洪
        self.assertEqual(follow["results"][1]["action"], "flood")

    def test_fragmented_udp_to_bootp_port_is_not_shaped(self):
        # MF 分片：不识别为 DHCP，按普通帧泛洪，snoop 为 null
        event = plain_frame(1, "p2", dport=67, fragment=0x2000)
        record = self._one(event)
        self.assertEqual(record["action"], "flood")
        self.assertIsNone(record["snoop"])

    def test_non_udp_protocol_is_not_shaped(self):
        event = plain_frame(1, "p2", protocol=6, payload_len=40)
        record = self._one(event)
        self.assertEqual(record["action"], "flood")
        self.assertIsNone(record["snoop"])

    def test_udp_other_port_is_not_shaped(self):
        event = plain_frame(1, "p2", dport=53)
        record = self._one(event)
        self.assertEqual(record["action"], "flood")
        self.assertIsNone(record["snoop"])


# ---------------------------------------------------------------------
# 非受信任服务器
# ---------------------------------------------------------------------

class DhcpUntrustedTest(DhcpCase):
    def test_offer_from_untrusted_port_dropped(self):
        result = self.simulate(
            make_config(trusted=("p1",)),
            [offer(1, port="p2")],
        )
        record = result["results"][0]
        self.assertEqual(record["action"], "untrusted_server")
        self.assertEqual(record["ports"], [])

    def test_ack_nak_from_untrusted_port_dropped(self):
        for builder, mtype in (
            (lambda: ack(1, lease=500, port="p2"), "untrusted_server"),
            (lambda: nak(1, port="p2"), "untrusted_server"),
        ):
            result = self.simulate(make_config(), [builder()])
            self.assertEqual(result["results"][0]["action"], mtype)
            self.assertEqual(result["results"][0]["ports"], [])

    def test_untrusted_server_creates_no_state(self):
        # 客户端从 p3 发 DISCOVER，冒充服务器从 p2 发 ACK：丢弃，无绑定
        events = [
            discover(1, "p3", CLI2_MAC, 0x55),
            ack(2, IP1, lease=500, port="p2", chaddr=CLI2_MAC, xid=0x55),
        ]
        result = self.simulate(make_config(), events)
        self.assertEqual(result["results"][1]["action"], "untrusted_server")
        self.assertEqual(result["bindings"], [])

    def test_trusted_port_configuration_takes_effect(self):
        result = self.simulate(
            make_config(trusted=("p2",)),
            [
                discover(1, "p3", CLI2_MAC, 0x1),
                request(2, "p3", CLI2_MAC, 0x1),
                ack(3, IP1, lease=500, port="p2", chaddr=CLI2_MAC, xid=0x1),
            ],
        )
        self.assertEqual(result["results"][2]["action"], "ack")
        self.assertEqual(result["bindings"][0]["port"], "p3")

    def test_untrusted_frame_is_valid_so_still_learns_source_mac(self):
        # untrusted_server 是合法帧的策略拒绝：源 MAC 仍学习，后续单播直达
        result = self.simulate(
            make_config(),
            [
                offer(1, port="p2"),  # SVR_MAC 从 p2 进入，被拒但学习
                plain_frame(
                    2, "p3", dst=SVR_MAC, src=CLI2_MAC,
                    src_ip=(10, 0, 0, 2), dst_ip=SVR_IP,
                ),
            ],
        )
        self.assertEqual(result["results"][0]["action"], "untrusted_server")
        self.assertEqual(result["results"][1]["action"], "unicast")
        self.assertEqual(
            [p["name"] for p in result["results"][1]["ports"]], ["p2"]
        )

    def test_conflict_frame_is_valid_so_still_learns_source_mac(self):
        events = bind_sequence(chaddr=CLI_MAC, ip=IP1)
        events += [
            discover(4, "p3", CLI2_MAC, 0xAB),
            request(5, "p3", CLI2_MAC, 0xAB),
            ack(6, IP1, chaddr=CLI2_MAC, xid=0xAB),  # SVR_MAC@p1 冲突
            plain_frame(
                7, "p2", dst=SVR_MAC, src=CLI_MAC,
                src_ip=(10, 0, 0, 1), dst_ip=SVR_IP,
            ),
        ]
        result = self.simulate(make_config(), events)
        self.assertEqual(result["results"][5]["action"], "binding_conflict")
        self.assertEqual(result["results"][6]["action"], "unicast")
        self.assertEqual(
            [p["name"] for p in result["results"][6]["ports"]], ["p1"]
        )


# ---------------------------------------------------------------------
# 数据面与帧合法性、VLAN、STP 语义沿用
# ---------------------------------------------------------------------

class DhcpDataplaneTest(DhcpCase):
    def test_runt_dropped_without_dhcp_classification(self):
        # 构造合法 FCS 的超短帧（<64 字节）：runt 丢弃
        head = _mac(BCAST_MAC) + _mac(CLI_MAC) + (0x0800).to_bytes(2, "big")
        body = head + b"\x00" * 10
        fcs = (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little")
        event = {"t": 1, "port": "p2", "data": (body + fcs).hex()}
        result = self.simulate(make_config(), [event])
        record = result["results"][0]
        self.assertEqual(record["action"], "drop")
        self.assertIsNone(record["snoop"])
        self.assertEqual(result["ports"][1]["runt"], 1)

    def test_bad_fcs_dropped(self):
        result = self.simulate(make_config(), [discover(1, bad_fcs=True)])
        record = result["results"][0]
        self.assertEqual(record["action"], "drop")
        self.assertIsNone(record["snoop"])
        self.assertEqual(result["ports"][1]["bad_fcs"], 1)

    def test_tag_on_access_port_rejected(self):
        ports = [
            make_port("p1", allowed=[1]),
            make_port("p2", mode="access", pvid=1, allowed=[1]),
        ]
        result = self.simulate(
            make_config(ports=ports), [discover(1, "p2", vlan=1)]
        )
        self.assertEqual(result["results"][0]["action"], "drop")
        self.assertIsNone(result["results"][0]["snoop"])
        self.assertEqual(result["bindings"], [])

    def test_tag_not_allowed_on_trunk_rejected(self):
        ports = [
            make_port("p1", allowed=[1]),
            make_port("p2", allowed=[1]),
        ]
        result = self.simulate(
            make_config(ports=ports, capacities=((1, 8), (2, 8))),
            [discover(1, "p2", vlan=2)],
        )
        self.assertEqual(result["results"][0]["action"], "drop")
        self.assertEqual(result["bindings"], [])

    def test_non_dhcp_unicast_uses_fdb(self):
        # 客户端先以普通帧让交换机学习 CLI_MAC@(1,p2)，再从 p1 发单播
        result = self.simulate(
            make_config(),
            [
                plain_frame(1, "p2", dst=SVR_MAC, src=CLI_MAC),
                plain_frame(2, "p1", dst=CLI_MAC, src=SVR_MAC,
                            src_ip=SVR_IP, dst_ip=(10, 0, 0, 1)),
            ],
        )
        self.assertEqual(result["results"][0]["action"], "flood")
        self.assertEqual(result["results"][1]["action"], "unicast")
        self.assertEqual(
            [p["name"] for p in result["results"][1]["ports"]], ["p2"]
        )

    def test_ack_server_frames_learn_fdb(self):
        # 合法 ACK 从受信任口进入：服务器 MAC 被学习，后续单播直达 p1
        events = bind_sequence() + [
            plain_frame(
                10, "p2", dst=SVR_MAC, src=CLI_MAC,
                src_ip=(10, 0, 0, 1), dst_ip=SVR_IP,
            )
        ]
        result = self.simulate(make_config(), events)
        self.assertEqual(result["results"][3]["action"], "unicast")
        self.assertEqual(
            [p["name"] for p in result["results"][3]["ports"]], ["p1"]
        )

    def test_dhcp_discarded_frame_counts_drop_and_vlan_drop(self):
        result = self.simulate(make_config(), [offer(1, port="p2")])
        self.assertEqual(result["ports"][1]["drop"], 1)
        self.assertEqual(result["vlans"][0]["drop"], 1)

    def test_stp_discarding_port_does_not_classify_dhcp(self):
        # p1 为 b1-b2 链路口，delay=10：t=1 仍处 discarding，DISCOVER 丢弃，
        # 不产生 discover 动作与请求；t>=20 进入 forwarding 后正常
        links = [
            {"id": "L1", "x": ["b1", "p1"], "y": ["b2", "p1"],
             "cost": 1, "up": True},
        ]
        ports = [
            make_port("p1", allowed=[1]),
            make_port("p2", allowed=[1]),
        ]
        config = make_config(
            ports=ports, bridges=("b1", "b2"), links=links, delay=10,
            trusted=("p2",),
        )
        result = self.simulate(
            config,
            [discover(1, "p1"), discover(25, "p1")],
        )
        self.assertEqual(result["results"][0]["action"], "drop")
        self.assertIsNone(result["results"][0]["snoop"])
        self.assertEqual(result["results"][1]["action"], "discover")


# ---------------------------------------------------------------------
# 每端口分类计数
# ---------------------------------------------------------------------

class DhcpCountersTest(DhcpCase):
    def test_per_port_classification_counts(self):
        events = [
            discover(1, "p2"),
            request(2, "p2"),
            offer(3),
            ack(4, lease=500),
            nak(10, port="p2"),  # 非受信任：untrusted_server
            release(11, IP1, port="p3"),  # 端口不匹配：仍分类 release
        ]
        result = self.simulate(make_config(), events)
        counters = {c["name"]: c for c in result["counters"]}
        self.assertEqual(counters["p2"]["discover"], 1)
        self.assertEqual(counters["p2"]["request"], 1)
        self.assertEqual(counters["p2"]["untrusted_server"], 1)
        self.assertEqual(counters["p1"]["offer"], 1)
        self.assertEqual(counters["p1"]["ack"], 1)
        self.assertEqual(counters["p3"]["release"], 1)
        # 计数对象固定键序 name + 12 个分类键
        self.assertEqual(
            list(counters["p1"]),
            ["name"] + [
                "malformed_dhcp", "untrusted_server", "discover", "request",
                "offer", "ack", "nak", "release", "decline", "inform",
                "binding_conflict", "binding_full",
            ],
        )

    def test_malformed_and_conflict_counts(self):
        events = bind_sequence(chaddr=CLI_MAC, ip=IP1) + [
            discover(4, "p3", CLI2_MAC, 0xAB),
            request(5, "p3", CLI2_MAC, 0xAB),
            ack(6, IP1, chaddr=CLI2_MAC, xid=0xAB),
        ]
        bad = with_recomputed_fcs(
            discover(7, "p4"),
            lambda body: body[:14 + 10] + b"\x00\x00" + body[14 + 12:],
        )
        events.append(bad)
        result = self.simulate(make_config(), events)
        counters = {c["name"]: c for c in result["counters"]}
        self.assertEqual(counters["p1"]["binding_conflict"], 1)
        self.assertEqual(counters["p4"]["malformed_dhcp"], 1)


# ---------------------------------------------------------------------
# record / replay
# ---------------------------------------------------------------------

class DhcpRecordTest(DhcpCase):
    def _config_events(self):
        config = make_config()
        events = [
            discover(1, "p2"),
            offer(2),
            request(3, "p2"),
            ack(4, lease=2000),
            release(20, IP1, port="p2"),
        ]
        return config, events

    def test_record_auto_detects_and_replay_byte_identical(self):
        config, events = self._config_events()
        self.write(config, events)
        code, direct, err = self.run_cmd(
            "dhcp-snoop-decode", self.cfg, self.evt
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
        self.assertTrue(all(r["applied"] for r in doc["records"]))
        self.assertTrue(all(r["version"] == 0 for r in doc["records"]))
        self.assertEqual(
            [r["output"]["action"] for r in doc["records"]],
            ["discover", "offer", "request", "ack", "release"],
        )

    def test_link_version_and_byte_rebuild(self):
        links = [
            {"id": "L1", "x": ["b1", "p1"], "y": ["b2", "p1"],
             "cost": 1, "up": True},
        ]
        ports = [
            make_port("p1", allowed=[1]),
            make_port("p2", allowed=[1]),
            make_port("p3", allowed=[1]),
        ]
        config = make_config(
            ports=ports, bridges=("b1", "b2"), links=links, delay=1,
            trusted=("p2",),
        )
        events = [
            link_event(0, "L1", True),  # 幂等：version 0
            discover(3, "p3"),
            link_event(5, "L1", False),  # applied：version 1
        ]
        self.write(config, events)
        rec = subprocess.run(
            [sys.executable, SWITCH, "record", self.cfg, self.evt, self.log],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(rec.returncode, 0, rec.stderr)
        with open(self.log, "rb") as handle:
            original = handle.read()
        code, out, err = self.run_cmd("replay", self.log)
        self.assertEqual(code, 0, err)
        self.assertEqual(out, rec.stdout)
        doc = json.loads(original.decode())
        self.assertEqual(
            [(r["applied"], r["version"]) for r in doc["records"]],
            [(False, 0), (True, 0), (True, 1)],
        )

    def test_link_down_does_not_remove_lease_bindings(self):
        # 绑定在租期内不因链路断开而删除
        links = [
            {"id": "L1", "x": ["b1", "p1"], "y": ["b2", "p1"],
             "cost": 1, "up": True},
        ]
        ports = [
            make_port("p1", allowed=[1]),
            make_port("p2", allowed=[1]),
        ]
        config = make_config(
            ports=ports, bridges=("b1", "b2"), links=links, delay=1,
            trusted=("p2",),
        )
        events = [
            discover(30, "p1"),
            request(31, "p1"),
            ack(32, IP1, lease=1000, port="p2"),
            link_event(40, "L1", False),
        ]
        result = self.simulate(config, events)
        self.assertEqual(len(result["bindings"]), 1)
        self.assertEqual(result["bindings"][0]["port"], "p1")


# ---------------------------------------------------------------------
# 工作量：逐事件 1 + P + 处理前活动绑定数
# ---------------------------------------------------------------------

class DhcpBillingTest(DhcpCase):
    # P=4，无绑定事件每个 1+4=5。DISCOVER/REQUEST/ACK 三帧后绑定建立；
    # 第四个事件处理前 B=1，计 1+4+1=6。合计 5+5+5+6=21。
    TOTAL = 21

    def _write(self):
        config = make_config()
        events = bind_sequence(lease=1000) + [
            plain_frame(10, "p3", dst=SVR_MAC)
        ]
        self.write(config, events)

    def test_entry_work_boundary(self):
        self._write()
        head = ("1048576", "16777216", "100000", "16777216")
        code, ok, err = self.run_cmd(
            "dhcp-snoop-decode", self.cfg, self.evt, *head, str(self.TOTAL)
        )
        self.assertEqual(code, 0, err)
        code, out, err = self.run_cmd(
            "dhcp-snoop-decode", self.cfg, self.evt, *head,
            str(self.TOTAL - 1),
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"dhcp_work_limit"}\n')

    def test_link_events_billed_with_active_bindings(self):
        # 绑定后两个链路事件：处理前 B=1，每个 1+4+1=6
        links = [
            {"id": "L1", "x": ["b1", "p1"], "y": ["b2", "p1"],
             "cost": 1, "up": True},
        ]
        ports = [make_port("p%d" % n, allowed=[1]) for n in (1, 2, 3, 4)]
        config = make_config(
            ports=ports, bridges=("b1", "b2"), links=links, delay=1,
            trusted=("p2",),
        )
        # t=30 转发已收敛；三帧 3*5=15，绑定建立；两链路事件 2*6=12；总 27
        events = [
            discover(30, "p3"),
            request(31, "p3"),
            ack(32, IP1, lease=1000, port="p2"),
            link_event(40, "L1", False),
            link_event(50, "L1", True),
        ]
        self.write(config, events)
        head = ("1048576", "16777216", "100000", "16777216")
        code, _, err = self.run_cmd(
            "dhcp-snoop-decode", self.cfg, self.evt, *head, "27"
        )
        self.assertEqual(code, 0, err)
        code, out, err = self.run_cmd(
            "dhcp-snoop-decode", self.cfg, self.evt, *head, "26"
        )
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"dhcp_work_limit"}\n')

    def test_record_replay_work_boundary(self):
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

    def test_preview_has_no_side_effect_on_input(self):
        # 超限预演不得修改配置中的 links.up；再次以大限额执行应成功，
        # 且链路版本行为与正常一致
        links = [
            {"id": "L1", "x": ["b1", "p1"], "y": ["b2", "p1"],
             "cost": 1, "up": True},
        ]
        ports = [make_port("p%d" % n, allowed=[1]) for n in (1, 2)]
        config = make_config(
            ports=ports, bridges=("b1", "b2"), links=links, delay=1,
            trusted=("p2",),
        )
        events = [
            link_event(40, "L1", False),
            discover(41, "p1"),
        ]
        self.write(config, events)
        head = ("1048576", "16777216", "100000", "16777216")
        code, _, err = self.run_cmd(
            "dhcp-snoop-decode", self.cfg, self.evt, *head, "1"
        )
        self.assertEqual(code, 5)
        self.assertEqual(links[0]["up"], True)  # 原始配置未被预演改写
        code, out, err = self.run_cmd(
            "dhcp-snoop-decode", self.cfg, self.evt, *head, "10000000"
        )
        self.assertEqual(code, 0, err)


# ---------------------------------------------------------------------
# 确定性
# ---------------------------------------------------------------------

class DhcpDeterminismTest(DhcpCase):
    def test_identical_input_byte_identical_output(self):
        config = make_config(capacities=((1, 8), (2, 8)))
        events = [
            discover(1, "p2"),
            offer(2),
            request(3, "p2"),
            ack(4, IP1, lease=2000),
            discover(5, "p3", CLI2_MAC, 0x9, vlan=2),
            request(6, "p3", CLI2_MAC, 0x9, vlan=2),
            ack(7, IP2, lease=10, chaddr=CLI2_MAC, xid=0x9, vlan=2),
            plain_frame(30, "p4", dst=SVR_MAC),
        ]
        self.write(config, events)
        runs = [
            self.run_cmd("dhcp-snoop-decode", self.cfg, self.evt)[1]
            for _ in range(3)
        ]
        self.assertTrue(all(r == runs[0] for r in runs))


# ---------------------------------------------------------------------
# 失败契约：usage 2 / file 3 / invalid_input 4 / 资源与工作量 5
# ---------------------------------------------------------------------

class DhcpFailureTest(DhcpCase):
    def base_config(self):
        return make_config()

    def test_usage_exit_2(self):
        self.write(self.base_config(), [])
        code, out, _ = self.run_cmd("dhcp-snoop-decode", self.cfg)
        self.assertEqual((code, out), (2, b""))
        code, out, _ = self.run_cmd("dhcp-snoop-decode")
        self.assertEqual((code, out), (2, b""))
        code, out, _ = self.run_cmd(
            "dhcp-snoop-decode", self.cfg, self.evt,
            "1048576", "16777216", "100000", "16777216", "zero",
        )
        self.assertEqual((code, out), (2, b""))
        code, out, _ = self.run_cmd(
            "dhcp-snoop-decode", self.cfg, self.evt, "1048576"
        )
        self.assertEqual((code, out), (2, b""))

    def test_missing_file_exit_3(self):
        code, out, err = self.run_cmd(
            "dhcp-snoop-decode",
            os.path.join(self.tmp.name, "nope.json"), self.evt,
        )
        self.assertEqual((code, out), (3, b""))
        self.assertEqual(err, b'{"error":"file_not_found"}\n')

    def test_bad_config_exit_4(self):
        cases = []
        # 缺 dhcp
        cases.append({
            key: self.base_config()[key]
            for key in (
                "bridges", "links", "delay", "bridge", "ports", "age",
                "max_frame",
            )
        })
        # 多余顶层键
        extra = dict(self.base_config())
        extra["nope"] = 1
        cases.append(extra)
        # dhcp 缺键 / 多键
        for keys in (
            ("trusted_ports", "binding_capacity"),
            ("trusted_ports", "binding_capacity", "max_lease", "x"),
        ):
            bad = self.base_config()
            bad["dhcp"] = {
                key: bad["dhcp"][key] if key in bad["dhcp"] else 1
                for key in keys
            }
            cases.append(bad)
        # 未知受信任端口 / 重复
        bad = self.base_config()
        bad["dhcp"]["trusted_ports"] = ["px"]
        cases.append(bad)
        bad = self.base_config()
        bad["dhcp"]["trusted_ports"] = ["p1", "p1"]
        cases.append(bad)
        # 容量形状错误
        bad = self.base_config()
        bad["dhcp"]["binding_capacity"] = {"vlan": 1, "limit": 8}
        cases.append(bad)
        bad = self.base_config()
        bad["dhcp"]["binding_capacity"] = [{"vlan": 1}]
        cases.append(bad)
        bad = self.base_config()
        bad["dhcp"]["binding_capacity"] = [{"vlan": 0, "limit": 8}]
        cases.append(bad)
        bad = self.base_config()
        bad["dhcp"]["binding_capacity"] = [{"vlan": 1, "limit": -1}]
        cases.append(bad)
        bad = self.base_config()
        bad["dhcp"]["binding_capacity"] = [
            {"vlan": 1, "limit": 8}, {"vlan": 1, "limit": 2}
        ]
        cases.append(bad)
        # max_lease 非正/布尔
        bad = self.base_config()
        bad["dhcp"]["max_lease"] = 0
        cases.append(bad)
        bad = self.base_config()
        bad["dhcp"]["max_lease"] = True
        cases.append(bad)
        for config in cases:
            self.write(config, [])
            code, out, err = self.run_cmd(
                "dhcp-snoop-decode", self.cfg, self.evt
            )
            self.assertEqual((code, out), (4, b""), config)
            self.assertEqual(err, b'{"error":"invalid_input"}\n')

    def test_bad_events_exit_4(self):
        tagged = discover(0, "p2", vlan=1)
        raw = bytes.fromhex(tagged["data"])
        # 在既有单层标签后再插一层 8100：双标签为外壳非法
        double = raw[:16] + b"\x81\x00\x10\x00" + raw[16:]
        good = discover(0, "p2")
        for events, event in (
            ([{"t": 0, "port": "p2", "data": double.hex()}], "double tag"),
            ([{"t": 0, "port": "px", "data": good["data"]}], "bad port"),
            ([{"t": -1, "port": "p2", "data": good["data"]}], "bad t"),
            ([{"t": 2, "port": "p2", "data": good["data"]},
              {"t": 1, "port": "p2", "data": good["data"]}], "nonmono"),
            ("notalist", None),
        ):
            self.write(self.base_config(), events)
            code, out, err = self.run_cmd(
                "dhcp-snoop-decode", self.cfg, self.evt
            )
            self.assertEqual((code, out), (4, b""), event)

    def test_item_limit_exit_5(self):
        self.write(self.base_config(), [discover(1), request(2, "p2")])
        code, out, err = self.run_cmd(
            "dhcp-snoop-decode", self.cfg, self.evt,
            "1048576", "16777216", "1", "16777216",
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"item_limit"}\n')
        # 等于上限合法
        code, _, err = self.run_cmd(
            "dhcp-snoop-decode", self.cfg, self.evt,
            "1048576", "16777216", "2", "16777216",
        )
        self.assertEqual(code, 0, err)

    def test_config_and_data_byte_limits(self):
        self.write(self.base_config(), [discover(1)])
        code, out, err = self.run_cmd(
            "dhcp-snoop-decode", self.cfg, self.evt, "50", "16777216"
        )
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"config_limit"}\n')
        code, out, err = self.run_cmd(
            "dhcp-snoop-decode", self.cfg, self.evt,
            "1048576", "50",
        )
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"data_limit"}\n')

    def test_failure_stdout_is_empty(self):
        self.write(self.base_config(), [discover(1)])
        head = ("1048576", "16777216", "100000", "16777216")
        code, out, _ = self.run_cmd(
            "dhcp-snoop-decode", self.cfg, self.evt, *head, "1"
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")


if __name__ == "__main__":
    unittest.main()
