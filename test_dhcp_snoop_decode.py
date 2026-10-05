#!/usr/bin/env python3
"""dhcp-snoop-decode 端到端回归。

覆盖：单层 802.1Q 上 IPv4/UDP/BOOTP/DHCP 识别与长度、IPv4 首部校验和、
magic cookie、关键选项校验；DISCOVER/REQUEST 接入口记录与受信 ACK 匹配
（xid/chaddr/VLAN）建立/刷新绑定；租期截断与显式 t 老化；NAK 清除请求、
RELEASE 按端口/MAC/VLAN 匹配删除；malformed_dhcp、untrusted_server、
binding_conflict、binding_full 四类处置与计数；非 DHCP 帧沿用 VLAN/STP/
转发语义；末态绑定排序与每端口分类计数；record 自动识别与 replay 逐字节
复现；工作量边界（每事件 1+P+处理前活动绑定数）；退出码 2/3/4/5 与错误
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


def ip_header(src, dst, payload_len, protocol=17, fragment_word=0,
              bad_checksum=False, total_length=None, ihl=20):
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


def udp_segment(sport, dport, payload, length=None):
    if length is None:
        length = 8 + len(payload)
    return (
        sport.to_bytes(2, "big")
        + dport.to_bytes(2, "big")
        + length.to_bytes(2, "big")
        + b"\x00\x00"
        + payload
    )


BOOTP_FIXED_ZERO = b"\x00" * (236 - 44)  # sname(64)+file(128)
MAGIC = b"\x63\x82\x53\x63"


def bootp_message(
    op=1, htype=1, hlen=6, xid=1, chaddr=b"\x02\x00\x00\x00\x00\x01",
    ciaddr=(0, 0, 0, 0), yiaddr=(0, 0, 0, 0), options=b"\xff",
    cookie=MAGIC, pad=300, chaddr_tail_zero=True, flags=None,
):
    """构造 BOOTP 报文；pad 为最终长度（不足补零），None 不补齐。"""
    chaddr_field = bytes(chaddr)
    if len(chaddr_field) < 16:
        tail = b"\x00" * (16 - len(chaddr_field))
        chaddr_field = chaddr_field + (tail if chaddr_tail_zero else b"\xff" * (16 - len(chaddr_field)))
    msg = (
        bytes([op, htype, hlen, 0])
        + xid.to_bytes(4, "big")
        + b"\x00\x00"  # secs
        + (b"\x00\x00" if flags is None else flags.to_bytes(2, "big"))
        + bytes(ciaddr)
        + bytes(yiaddr)
        + b"\x00" * 4  # siaddr
        + b"\x00" * 4  # giaddr
        + chaddr_field
        + BOOTP_FIXED_ZERO
        + cookie
        + options
    )
    if pad is not None and len(msg) < pad:
        msg += b"\x00" * (pad - len(msg))
    return msg


def dhcp_options(msg_type=None, lease=None, extra=b"", end=True,
                 duplicate_type=False, bad_type_len=False):
    body = b""
    if msg_type is not None:
        length = 2 if bad_type_len else 1
        body += bytes([53, length, msg_type]) + (b"\x00" if bad_type_len else b"")
        if duplicate_type:
            body += bytes([53, 1, msg_type])
    if lease is not None:
        body += bytes([51, 4]) + lease.to_bytes(4, "big")
    body += extra
    if end:
        body += b"\xff"
    return body


def client_packet(mac, xid, msg_type, ciaddr=(0, 0, 0, 0), yiaddr=(0, 0, 0, 0),
                  lease=None, options=None, src=None, dst=(255, 255, 255, 255),
                  **bootp_kwargs):
    """68→67 客户端报文（BOOTREQUEST）。"""
    if options is None:
        options = dhcp_options(msg_type, lease=lease)
    bp = bootp_message(
        op=1, xid=xid, chaddr=bytes(mac), ciaddr=ciaddr, yiaddr=yiaddr,
        options=options, **bootp_kwargs
    )
    udp = udp_segment(68, 67, bp)
    src = src or (ciaddr if any(ciaddr) else (0, 0, 0, 0))
    return ip_header(src, dst, len(udp)) + udp


def server_packet(mac, xid, msg_type, yiaddr=(0, 0, 0, 0), lease=None,
                  options=None, src=(192, 168, 0, 1), dst=(255, 255, 255, 255),
                  ciaddr=(0, 0, 0, 0), **bootp_kwargs):
    """67→68 服务器报文（BOOTREPLY）。"""
    if options is None:
        options = dhcp_options(msg_type, lease=lease)
    bp = bootp_message(
        op=2, xid=xid, chaddr=bytes(mac), ciaddr=ciaddr, yiaddr=yiaddr,
        options=options, **bootp_kwargs
    )
    udp = udp_segment(67, 68, bp)
    return ip_header(src, dst, len(udp)) + udp


MAC1 = b"\x02\x00\x00\x00\x00\x01"
MAC2 = b"\x02\x00\x00\x00\x00\x02"
MAC3 = b"\x02\x00\x00\x00\x00\x03"
MAC4 = b"\x02\x00\x00\x00\x00\x04"
M1 = "02:00:00:00:00:01"
M2 = "02:00:00:00:00:02"
M3 = "02:00:00:00:00:03"
M4 = "02:00:00:00:00:04"
IP10 = (192, 168, 0, 10)
IP11 = (192, 168, 0, 11)
IP12 = (192, 168, 0, 12)


def raw_frame(t, port, payload, vlan=None, dst_mac=b"\xff" * 6,
              src_mac=MAC1, bad_fcs=False, ethertype=0x0800):
    d = bytes(dst_mac)
    s = bytes(src_mac)
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


def make_port(name, mode="trunk", pvid=1, allowed=None, up=True,
              untagged=None):
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


def make_config(ports=None, trusted_ports=("p1",), binding_capacity=10,
                max_lease=1000, bridges=("b1",), links=None, delay=2):
    if ports is None:
        ports = [
            make_port("p1", allowed=[1, 2]),
            make_port("p2", allowed=[1, 2]),
            make_port("p3", allowed=[1, 2]),
            make_port("p4", mode="hybrid", allowed=[1, 2],
                      untagged=[1]),
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
            "trusted_ports": list(trusted_ports),
            "binding_capacity": binding_capacity,
            "max_lease": max_lease,
        },
    }


# 简单非 DHCP 的 IPv4 UDP 载荷（源/目的端口无关）
def plain_ipv4_udp(src=(10, 0, 0, 9), dst=(10, 0, 0, 10), pad=18):
    payload = b"\x00" * 8
    return ip_header(src, dst, len(payload)) + udp_segment(
        1000, 2000, payload
    ) + b"\x00" * pad


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

    # 常用四步序列：DISCOVER@ingress、OFFER@trusted、REQUEST@ingress、
    # ACK@trusted
    def handshake(self, mac=MAC1, xid=0x11111111, ip=IP10, lease=5000,
                  client_port="p2", server_port="p1", vlan=None,
                  discover=True, offer=True, request=True, ack=True,
                  t0=1):
        events = []
        t = t0
        if discover:
            events.append(raw_frame(
                t, client_port,
                client_packet(mac, xid, 1), vlan=vlan,
            ))
            t += 1
        if offer:
            events.append(raw_frame(
                t, server_port,
                server_packet(mac, xid, 2, yiaddr=ip), vlan=vlan,
            ))
            t += 1
        if request:
            events.append(raw_frame(
                t, client_port,
                client_packet(mac, xid, 3), vlan=vlan,
            ))
            t += 1
        if ack:
            events.append(raw_frame(
                t, server_port,
                server_packet(mac, xid, 5, yiaddr=ip, lease=lease),
                vlan=vlan,
            ))
            t += 1
        return events, t


class DhcpLifecycleTest(DhcpCase):
    def test_discover_offer_request_ack_binds(self):
        config = make_config(max_lease=100)
        events, t = self.handshake(lease=5000)
        result = self.simulate(config, events)
        actions = [(r["t"], r["action"]) for r in result["results"]]
        self.assertEqual(
            actions, [(1, "flood"), (2, "flood"), (3, "flood"), (4, "flood")]
        )
        effects = [
            r["snoop"]["effect"] for r in result["results"]
        ]
        self.assertEqual(
            effects, ["record", "forward", "record", "bind"]
        )
        ack_snoop = result["results"][3]["snoop"]
        self.assertEqual(ack_snoop["message"], "ack")
        self.assertEqual(ack_snoop["ip"], "192.168.0.10")
        self.assertEqual(ack_snoop["port"], "p2")
        self.assertEqual(ack_snoop["expires"], 104)  # 4 + min(5000,100)
        # 绑定接入口取 REQUEST 所在端口 p2，租期截断到 max_lease
        self.assertEqual(result["bindings"], [
            {"vlan": 1, "ip": "192.168.0.10", "mac": M1,
             "port": "p2", "expires": 104}
        ])

    def test_lease_not_truncated_when_within_cap(self):
        config = make_config(max_lease=1000)
        events, _ = self.handshake(lease=500)
        result = self.simulate(config, events)
        self.assertEqual(result["bindings"][0]["expires"], 504)

    def test_renewal_refreshes_binding(self):
        config = make_config(max_lease=1000)
        events, t = self.handshake(lease=500)
        # 续租：新 xid 的 REQUEST 从同口进入，ACK 同 IP/MAC，刷新过期时刻
        events += [
            raw_frame(t, "p2", client_packet(MAC1, 0x22222222, 3)),
            raw_frame(t + 1, "p1",
                      server_packet(MAC1, 0x22222222, 5, yiaddr=IP10,
                                    lease=500)),
        ]
        result = self.simulate(config, events)
        self.assertEqual(len(result["bindings"]), 1)
        self.assertEqual(result["bindings"][0]["expires"], t + 1 + 500)

    def test_binding_ages_at_expiry(self):
        config = make_config(max_lease=100)
        events, t = self.handshake(lease=100)  # expires = t_ack + 100
        ack_t = t - 1
        # 截止时刻前一事件仍存在
        events.append(raw_frame(
            ack_t + 99, "p3", plain_ipv4_udp()
        ))
        result = self.simulate(config, events)
        self.assertEqual(len(result["bindings"]), 1)
        # t 到达截止值：先老化，绑定消失（事件本身只是普通数据帧）
        events.append(raw_frame(
            ack_t + 100, "p3", plain_ipv4_udp()
        ))
        result = self.simulate(config, events)
        self.assertEqual(result["bindings"], [])

    def test_offer_does_not_bind(self):
        config = make_config()
        events = [
            raw_frame(1, "p2", client_packet(MAC1, 1, 1)),
            raw_frame(2, "p1", server_packet(MAC1, 1, 2, yiaddr=IP10)),
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["bindings"], [])
        self.assertEqual(
            result["results"][1]["snoop"]["effect"], "forward"
        )

    def test_discover_only_request_ingress_recorded(self):
        # DISCOVER 与 REQUEST 均按 xid/chaddr/VLAN 记录接入口：仅有
        # DISCOVER 时，匹配其 xid/chaddr/VLAN 的受信 ACK 同样建绑定
        config = make_config()
        events = [
            raw_frame(1, "p2", client_packet(MAC1, 1, 1)),
            raw_frame(2, "p1",
                      server_packet(MAC1, 1, 5, yiaddr=IP10, lease=100)),
        ]
        result = self.simulate(config, events)
        self.assertEqual(len(result["bindings"]), 1)
        self.assertEqual(
            result["results"][1]["snoop"]["effect"], "bind"
        )
        self.assertEqual(result["bindings"][0]["port"], "p2")


class DhcpRequestMatchTest(DhcpCase):
    def _setup_request(self, xid=0xabcdef01, port="p2", vlan=None):
        return raw_frame(
            1, port, client_packet(MAC1, xid, 3), vlan=vlan
        )

    def test_ack_wrong_xid_no_bind(self):
        config = make_config()
        events = [
            self._setup_request(xid=111),
            raw_frame(2, "p1",
                      server_packet(MAC1, 222, 5, yiaddr=IP10, lease=100)),
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["bindings"], [])
        self.assertEqual(result["results"][1]["snoop"]["effect"], "forward")

    def test_ack_wrong_chaddr_no_bind(self):
        config = make_config()
        events = [
            raw_frame(1, "p2", client_packet(MAC1, 111, 3)),
            raw_frame(2, "p1",
                      server_packet(MAC2, 111, 5, yiaddr=IP10, lease=100)),
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["bindings"], [])

    def test_ack_vlan_must_match(self):
        config = make_config()
        events = [
            # REQUEST 在 VLAN 2
            self._setup_request(xid=111, vlan=2),
            # ACK 仅带 VLAN 1 标签：VLAN 不同，不匹配，不建绑定
            raw_frame(2, "p1",
                      server_packet(MAC1, 111, 5, yiaddr=IP10, lease=100),
                      vlan=1),
            # ACK 带 VLAN 2：匹配，建绑定
            raw_frame(3, "p1",
                      server_packet(MAC1, 111, 5, yiaddr=IP10, lease=100),
                      vlan=2),
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            result["results"][1]["snoop"]["effect"], "forward"
        )
        self.assertEqual(result["bindings"], [
            {"vlan": 2, "ip": "192.168.0.10", "mac": M1,
             "port": "p2", "expires": 103}
        ])

    def test_ack_port_is_request_ingress(self):
        config = make_config()
        events = [
            raw_frame(1, "p3", client_packet(MAC1, 111, 3)),
            raw_frame(2, "p1",
                      server_packet(MAC1, 111, 5, yiaddr=IP10, lease=100)),
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["bindings"][0]["port"], "p3")

    def test_nak_clears_matching_request(self):
        config = make_config()
        events = [
            raw_frame(1, "p2", client_packet(MAC1, 111, 3)),
            raw_frame(2, "p1", server_packet(MAC1, 111, 6)),
            # NAK 后 ACK 无匹配请求，不建绑定
            raw_frame(3, "p1",
                      server_packet(MAC1, 111, 5, yiaddr=IP10, lease=100)),
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][1]["snoop"]["effect"], "clear")
        self.assertEqual(result["results"][2]["snoop"]["effect"], "forward")
        self.assertEqual(result["bindings"], [])

    def test_nak_non_matching_is_forward(self):
        config = make_config()
        events = [
            raw_frame(1, "p2", client_packet(MAC1, 111, 3)),
            raw_frame(2, "p1", server_packet(MAC2, 111, 6)),
            # 原请求仍在，ACK 可建绑定
            raw_frame(3, "p1",
                      server_packet(MAC1, 111, 5, yiaddr=IP10, lease=100)),
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][1]["snoop"]["effect"], "forward")
        self.assertEqual(len(result["bindings"]), 1)

    def test_request_refresh_keeps_latest_ingress(self):
        config = make_config()
        events = [
            raw_frame(1, "p2", client_packet(MAC1, 111, 3)),
            raw_frame(2, "p3", client_packet(MAC1, 111, 3)),  # 同键刷新
            raw_frame(3, "p1",
                      server_packet(MAC1, 111, 5, yiaddr=IP10, lease=100)),
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["bindings"][0]["port"], "p3")


class UntrustedServerTest(DhcpCase):
    def test_offer_ack_nak_on_untrusted_dropped(self):
        config = make_config(trusted_ports=("p1",))
        for mtype, name in ((2, "offer"), (5, "ack"), (6, "nak")):
            events = [
                raw_frame(1, "p2",
                          server_packet(
                              MAC1, 111, mtype, yiaddr=IP10, lease=100
                          )),
            ]
            result = self.simulate(config, events)
            entry = result["results"][0]
            self.assertEqual(entry["action"], "untrusted_server", name)
            self.assertEqual(entry["ports"], [])
            self.assertEqual(entry["snoop"]["effect"], "untrusted_server")
            self.assertEqual(result["bindings"], [])

    def test_untrusted_server_does_not_learn_or_count_message(self):
        config = make_config(trusted_ports=("p1",))
        events = [
            raw_frame(1, "p2",
                      server_packet(MAC1, 111, 5, yiaddr=IP10, lease=100)),
            # 后续目的 MAC1 的单播：若未学习则泛洪
            raw_frame(2, "p3", plain_ipv4_udp(dst=(10, 0, 0, 10)),
                      dst_mac=MAC1, src_mac=MAC3),
        ]
        result = self.simulate(config, events)
        # 第二帧因 p2 未学习 MAC1 而泛洪
        self.assertEqual(result["results"][1]["action"], "flood")
        p2 = next(p for p in result["ports"] if p["name"] == "p2")
        self.assertEqual(p2["snoop"]["ack"], 0)
        self.assertEqual(p2["snoop"]["untrusted_server"], 1)

    def test_trusted_server_accepted(self):
        config = make_config(trusted_ports=("p1",))
        events = [
            raw_frame(1, "p2", client_packet(MAC1, 111, 3)),
            raw_frame(2, "p1",
                      server_packet(MAC1, 111, 5, yiaddr=IP10, lease=100)),
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][1]["action"], "flood")
        self.assertEqual(len(result["bindings"]), 1)


class MalformedDhcpTest(DhcpCase):
    def _expect_malformed(self, payload, vlan=None, port="p2"):
        config = make_config()
        events = [raw_frame(1, port, payload, vlan=vlan)]
        result = self.simulate(config, events)
        entry = result["results"][0]
        self.assertEqual(entry["action"], "malformed_dhcp")
        self.assertEqual(entry["ports"], [])
        self.assertIsNone(entry["snoop"])
        port_stat = next(p for p in result["ports"] if p["name"] == port)
        self.assertEqual(port_stat["snoop"]["malformed_dhcp"], 1)
        return result

    def test_bad_magic_cookie(self):
        bp = bootp_message(
            op=1, xid=1, options=dhcp_options(1), cookie=b"\x00\x00\x00\x00"
        )
        udp = udp_segment(68, 67, bp)
        self._expect_malformed(ip_header((0, 0, 0, 0), (255, 255, 255, 255),
                                         len(udp)) + udp)

    def test_missing_message_type(self):
        bp = bootp_message(op=1, xid=1, options=b"\xff")
        udp = udp_segment(68, 67, bp)
        self._expect_malformed(ip_header((0, 0, 0, 0), (255, 255, 255, 255),
                                         len(udp)) + udp)

    def test_unknown_message_type(self):
        bp = bootp_message(op=1, xid=1, options=dhcp_options(9))
        udp = udp_segment(68, 67, bp)
        self._expect_malformed(ip_header((0, 0, 0, 0), (255, 255, 255, 255),
                                         len(udp)) + udp)

    def test_message_type_wrong_direction(self):
        # 客户端口 68→67 不允许 ACK(5)；服务器口 67→68 不允许 DISCOVER(1)
        client_ack = client_packet(MAC1, 1, 5, yiaddr=IP10, lease=100)
        self._expect_malformed(client_ack)
        server_disc = server_packet(MAC1, 1, 1)
        self._expect_malformed(server_disc, port="p1")

    def test_op_direction_mismatch(self):
        bp = bootp_message(op=2, xid=1, options=dhcp_options(1))  # REPLY 上行
        udp = udp_segment(68, 67, bp)
        self._expect_malformed(
            ip_header((0, 0, 0, 0), (255, 255, 255, 255), len(udp)) + udp
        )
        bp = bootp_message(op=1, xid=1, options=dhcp_options(2))  # REQUEST 下行
        udp = udp_segment(67, 68, bp)
        self._expect_malformed(
            ip_header((192, 168, 0, 1), (255, 255, 255, 255), len(udp)) + udp,
            port="p1",
        )

    def test_hlen_not_six(self):
        bp = bootp_message(op=1, hlen=8, options=dhcp_options(1))
        udp = udp_segment(68, 67, bp)
        self._expect_malformed(
            ip_header((0, 0, 0, 0), (255, 255, 255, 255), len(udp)) + udp
        )

    def test_htype_not_ethernet(self):
        bp = bootp_message(op=1, htype=6, options=dhcp_options(1))
        udp = udp_segment(68, 67, bp)
        self._expect_malformed(
            ip_header((0, 0, 0, 0), (255, 255, 255, 255), len(udp)) + udp
        )

    def test_chaddr_multicast_or_nonzero_tail(self):
        bp = bootp_message(
            op=1, chaddr=b"\x03\x00\x00\x00\x00\x01",
            options=dhcp_options(1),
        )
        udp = udp_segment(68, 67, bp)
        self._expect_malformed(
            ip_header((0, 0, 0, 0), (255, 255, 255, 255), len(udp)) + udp
        )
        bp = bootp_message(
            op=1, chaddr=MAC1, chaddr_tail_zero=False,
            options=dhcp_options(1),
        )
        udp = udp_segment(68, 67, bp)
        self._expect_malformed(
            ip_header((0, 0, 0, 0), (255, 255, 255, 255), len(udp)) + udp
        )

    def test_duplicate_message_type(self):
        bp = bootp_message(
            op=1, options=dhcp_options(1, duplicate_type=True)
        )
        udp = udp_segment(68, 67, bp)
        self._expect_malformed(
            ip_header((0, 0, 0, 0), (255, 255, 255, 255), len(udp)) + udp
        )

    def test_message_type_bad_length(self):
        bp = bootp_message(
            op=1, options=dhcp_options(1, bad_type_len=True)
        )
        udp = udp_segment(68, 67, bp)
        self._expect_malformed(
            ip_header((0, 0, 0, 0), (255, 255, 255, 255), len(udp)) + udp
        )

    def test_options_not_closed(self):
        bp = bootp_message(op=1, options=dhcp_options(1, end=False))
        udp = udp_segment(68, 67, bp)
        self._expect_malformed(
            ip_header((0, 0, 0, 0), (255, 255, 255, 255), len(udp)) + udp
        )

    def test_options_length_overrun(self):
        bp = bootp_message(
            op=1, options=bytes([53, 8, 1]) + b"\xff"
        )
        udp = udp_segment(68, 67, bp)
        self._expect_malformed(
            ip_header((0, 0, 0, 0), (255, 255, 255, 255), len(udp)) + udp
        )

    def test_ack_without_lease(self):
        bp = bootp_message(op=2, options=dhcp_options(5))
        udp = udp_segment(67, 68, bp)
        self._expect_malformed(
            ip_header((192, 168, 0, 1), (255, 255, 255, 255), len(udp)) + udp,
            port="p1",
        )

    def test_ack_zero_lease(self):
        bp = bootp_message(op=2, options=dhcp_options(5, lease=0))
        udp = udp_segment(67, 68, bp)
        self._expect_malformed(
            ip_header((192, 168, 0, 1), (255, 255, 255, 255), len(udp)) + udp,
            port="p1",
        )

    def test_ack_broadcast_or_loopback_yiaddr(self):
        for yi in ((255, 255, 255, 255), (127, 0, 0, 1), (224, 0, 0, 1),
                   (0, 0, 0, 0)):
            bp = bootp_message(
                op=2, yiaddr=yi, options=dhcp_options(5, lease=100)
            )
            udp = udp_segment(67, 68, bp)
            self._expect_malformed(
                ip_header((192, 168, 0, 1), (255, 255, 255, 255), len(udp))
                + udp,
                port="p1",
            )

    def test_truncated_bootp(self):
        bp = bootp_message(op=1, options=dhcp_options(1), pad=None)
        bp = bp[:200]  # 短于 300
        udp = udp_segment(68, 67, bp)
        self._expect_malformed(
            ip_header((0, 0, 0, 0), (255, 255, 255, 255), len(udp)) + udp
        )

    def test_udp_length_exceeds_ip(self):
        bp = bootp_message(op=1, options=dhcp_options(1))
        udp = udp_segment(68, 67, bp, length=8 + len(bp) + 50)
        self._expect_malformed(
            ip_header((0, 0, 0, 0), (255, 255, 255, 255), len(udp)) + udp
        )

    def test_padding_and_pad_options_allowed(self):
        # END 前 pad(0)、END 后零填充均合法
        bp = bootp_message(
            op=1,
            options=b"\x00\x00" + dhcp_options(1) + b"\x00\x00",
            pad=320,
        )
        udp = udp_segment(68, 67, bp)
        config = make_config()
        events = [raw_frame(
            1, "p2",
            ip_header((0, 0, 0, 0), (255, 255, 255, 255), len(udp)) + udp,
        )]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][0]["action"], "flood")
        self.assertEqual(
            result["results"][0]["snoop"]["message"], "discover"
        )


class MalformedNotCommittedTest(DhcpCase):
    """外层不提交为 DHCP 形状：按普通帧沿用转发语义，snoop 为 null。"""

    def _expect_plain(self, payload, ethertype=0x0800, expect="flood"):
        config = make_config()
        events = [raw_frame(1, "p2", payload, ethertype=ethertype)]
        result = self.simulate(config, events)
        entry = result["results"][0]
        self.assertEqual(entry["action"], expect)
        self.assertIsNone(entry["snoop"])
        return result

    def test_bad_ipv4_checksum_is_plain_frame(self):
        bp = bootp_message(op=1, options=dhcp_options(1))
        udp = udp_segment(68, 67, bp)
        pkt = ip_header(
            (0, 0, 0, 0), (255, 255, 255, 255), len(udp), bad_checksum=True
        ) + udp
        self._expect_plain(pkt)

    def test_fragmented_is_plain_frame(self):
        bp = bootp_message(op=1, options=dhcp_options(1))
        udp = udp_segment(68, 67, bp)
        pkt = ip_header(
            (0, 0, 0, 0), (255, 255, 255, 255), len(udp), fragment_word=0x2000
        ) + udp
        self._expect_plain(pkt)

    def test_non_udp_protocol_is_plain_frame(self):
        bp = bootp_message(op=1, options=dhcp_options(1))
        # 协议号 6（TCP），但端口字节恰为 68/67
        pkt = ip_header(
            (0, 0, 0, 0), (255, 255, 255, 255), len(bp), protocol=6
        ) + bp
        self._expect_plain(pkt)

    def test_ports_not_67_68_is_plain_frame(self):
        bp = bootp_message(op=1, options=dhcp_options(1))
        udp = udp_segment(1068, 1067, bp)
        pkt = ip_header((0, 0, 0, 0), (255, 255, 255, 255), len(udp)) + udp
        self._expect_plain(pkt)

    def test_non_ipv4_ethertype_is_plain_frame(self):
        self._expect_plain(b"\x00" * 46, ethertype=0x0806)


class BindingConflictTest(DhcpCase):
    def test_same_ip_other_mac_conflict(self):
        config = make_config(max_lease=1000)
        events, t = self.handshake(mac=MAC1, ip=IP10, lease=500)
        # MAC2 请求同 IP，ACK 冲突丢弃
        events += [
            raw_frame(t, "p3", client_packet(MAC2, 0x99999999, 3)),
            raw_frame(t + 1, "p1",
                      server_packet(MAC2, 0x99999999, 5, yiaddr=IP10,
                                    lease=500)),
        ]
        result = self.simulate(config, events)
        conflict = result["results"][-1]
        self.assertEqual(conflict["action"], "binding_conflict")
        self.assertEqual(conflict["ports"], [])
        self.assertEqual(conflict["snoop"]["effect"], "binding_conflict")
        self.assertEqual(conflict["snoop"]["owner"], M1)
        # 原绑定不变
        self.assertEqual(len(result["bindings"]), 1)
        self.assertEqual(result["bindings"][0]["mac"], M1)
        p1 = next(p for p in result["ports"] if p["name"] == "p1")
        self.assertEqual(p1["snoop"]["binding_conflict"], 1)
        self.assertEqual(p1["snoop"]["ack"], 1)  # 仅前一个成功 ACK

    def test_same_ip_same_mac_refreshes(self):
        config = make_config(max_lease=1000)
        events, t = self.handshake(mac=MAC1, ip=IP10, lease=500)
        events += [
            raw_frame(t, "p2", client_packet(MAC1, 0xaaaa, 3)),
            raw_frame(t + 1, "p1",
                      server_packet(MAC1, 0xaaaa, 5, yiaddr=IP10,
                                    lease=500)),
        ]
        result = self.simulate(config, events)
        self.assertEqual(len(result["bindings"]), 1)
        self.assertEqual(
            result["results"][-1]["snoop"]["effect"], "bind"
        )

    def test_conflict_scoped_per_vlan(self):
        config = make_config()
        events, t = self.handshake(mac=MAC1, ip=IP10, lease=500, vlan=1)
        # 同 IP 在 VLAN 2 被 MAC2 绑定：不同 VLAN 不冲突
        events += [
            raw_frame(t, "p3", client_packet(MAC2, 0xaaaa, 3), vlan=2),
            raw_frame(t + 1, "p1",
                      server_packet(MAC2, 0xaaaa, 5, yiaddr=IP10, lease=500),
                      vlan=2),
        ]
        result = self.simulate(config, events)
        self.assertEqual(len(result["bindings"]), 2)
        vlans = {b["vlan"] for b in result["bindings"]}
        self.assertEqual(vlans, {1, 2})

    def test_rebind_after_release_or_expiry(self):
        config = make_config(max_lease=100)
        events, t = self.handshake(mac=MAC1, ip=IP10, lease=100)
        # MAC1 在 p2 释放
        events.append(raw_frame(
            t, "p2",
            client_packet(MAC1, 0xbbbb, 7, ciaddr=IP10),
        ))
        # MAC2 取得同 IP：不再冲突
        events += [
            raw_frame(t + 1, "p3", client_packet(MAC2, 0xcccc, 3)),
            raw_frame(t + 2, "p1",
                      server_packet(MAC2, 0xcccc, 5, yiaddr=IP10,
                                    lease=100)),
        ]
        result = self.simulate(config, events)
        self.assertEqual(len(result["bindings"]), 1)
        self.assertEqual(result["bindings"][0]["mac"], M2)
        self.assertEqual(result["bindings"][0]["port"], "p3")


class BindingCapacityTest(DhcpCase):
    def test_new_binding_over_capacity_full(self):
        config = make_config(binding_capacity=1, max_lease=1000)
        events, t = self.handshake(mac=MAC1, ip=IP10, lease=500)
        events += [
            raw_frame(t, "p3", client_packet(MAC2, 0xaaaa, 3)),
            raw_frame(t + 1, "p1",
                      server_packet(MAC2, 0xaaaa, 5, yiaddr=IP11,
                                    lease=500)),
        ]
        result = self.simulate(config, events)
        full = result["results"][-1]
        self.assertEqual(full["action"], "flood")  # ACK 仍按数据面转发
        self.assertEqual(full["snoop"]["effect"], "binding_full")
        self.assertEqual(full["snoop"]["ingress_port"], "p3")
        self.assertEqual(len(result["bindings"]), 1)
        self.assertEqual(result["bindings"][0]["mac"], M1)
        p1 = next(p for p in result["ports"] if p["name"] == "p1")
        self.assertEqual(p1["snoop"]["binding_full"], 1)
        # 超容量 ACK 不计入 ack 分类
        self.assertEqual(p1["snoop"]["ack"], 1)

    def test_refresh_does_not_consume_capacity(self):
        config = make_config(binding_capacity=1, max_lease=1000)
        events, t = self.handshake(mac=MAC1, ip=IP10, lease=500)
        events += [
            raw_frame(t, "p2", client_packet(MAC1, 0xaaaa, 3)),
            raw_frame(t + 1, "p1",
                      server_packet(MAC1, 0xaaaa, 5, yiaddr=IP10,
                                    lease=500)),
        ]
        result = self.simulate(config, events)
        self.assertEqual(len(result["bindings"]), 1)
        p1 = next(p for p in result["ports"] if p["name"] == "p1")
        self.assertEqual(p1["snoop"]["binding_full"], 0)
        self.assertEqual(p1["snoop"]["ack"], 2)

    def test_capacity_per_vlan_independent(self):
        config = make_config(binding_capacity=1)
        events, t = self.handshake(mac=MAC1, ip=IP10, lease=500, vlan=1)
        events += [
            raw_frame(t, "p3", client_packet(MAC2, 0xaaaa, 3), vlan=2),
            raw_frame(t + 1, "p1",
                      server_packet(MAC2, 0xaaaa, 5, yiaddr=IP11, lease=500),
                      vlan=2),
        ]
        result = self.simulate(config, events)
        self.assertEqual(len(result["bindings"]), 2)

    def test_exactly_at_capacity_allowed(self):
        config = make_config(binding_capacity=2, max_lease=1000)
        events, t = self.handshake(mac=MAC1, ip=IP10, lease=500)
        events += [
            raw_frame(t, "p3", client_packet(MAC2, 0xaaaa, 3)),
            raw_frame(t + 1, "p1",
                      server_packet(MAC2, 0xaaaa, 5, yiaddr=IP11,
                                    lease=500)),
        ]
        result = self.simulate(config, events)
        self.assertEqual(len(result["bindings"]), 2)
        p1 = next(p for p in result["ports"] if p["name"] == "p1")
        self.assertEqual(p1["snoop"]["binding_full"], 0)


class ReleaseTest(DhcpCase):
    def _bound(self, mac=MAC2, ip=IP11, port="p3", xid=0xaaaa, t=5):
        return [
            raw_frame(t, port, client_packet(mac, xid, 3)),
            raw_frame(t + 1, "p1",
                      server_packet(mac, xid, 5, yiaddr=ip, lease=1000)),
        ]

    def test_release_matching_deletes(self):
        config = make_config()
        events, t = self.handshake()
        events += self._bound(t=t)
        rel_t = t + 2
        events.append(raw_frame(
            rel_t, "p3",
            client_packet(MAC2, 0xbbbb, 7, ciaddr=IP11),
        ))
        result = self.simulate(config, events)
        self.assertEqual(
            result["results"][-1]["snoop"]["effect"], "release"
        )
        macs = {b["mac"] for b in result["bindings"]}
        self.assertEqual(macs, {M1})

    def test_release_wrong_port_keeps(self):
        config = make_config()
        events, t = self.handshake()
        events += self._bound(t=t)
        events.append(raw_frame(
            t + 2, "p2",  # 绑定在 p3，从 p2 释放
            client_packet(MAC2, 0xbbbb, 7, ciaddr=IP11),
        ))
        result = self.simulate(config, events)
        self.assertEqual(
            result["results"][-1]["snoop"]["effect"], "forward"
        )
        self.assertEqual(len(result["bindings"]), 2)

    def test_release_wrong_mac_keeps(self):
        config = make_config()
        events, t = self.handshake()
        events += self._bound(t=t)
        events.append(raw_frame(
            t + 2, "p3",
            client_packet(MAC3, 0xbbbb, 7, ciaddr=IP11),
        ))
        result = self.simulate(config, events)
        self.assertEqual(
            result["results"][-1]["snoop"]["effect"], "forward"
        )
        self.assertEqual(len(result["bindings"]), 2)

    def test_release_wrong_vlan_keeps(self):
        config = make_config()
        events, t = self.handshake()  # VLAN 1 上 MAC1/IP10 绑定
        events += [
            raw_frame(t, "p3", client_packet(MAC2, 0xaaaa, 3), vlan=2),
            raw_frame(t + 1, "p1",
                      server_packet(MAC2, 0xaaaa, 5, yiaddr=IP11, lease=500),
                      vlan=2),
        ]
        # 从 VLAN 1 发 RELEASE：VLAN 不匹配，不删除 VLAN 2 绑定
        events.append(raw_frame(
            t + 2, "p3",
            client_packet(MAC2, 0xbbbb, 7, ciaddr=IP11), vlan=1,
        ))
        result = self.simulate(config, events)
        self.assertEqual(
            result["results"][-1]["snoop"]["effect"], "forward"
        )
        self.assertEqual(len(result["bindings"]), 2)


class ForwardingSemanticsTest(DhcpCase):
    def test_client_frame_learns_fdb_for_unicast(self):
        config = make_config()
        events = [
            raw_frame(1, "p2", client_packet(MAC1, 1, 1)),
            # p3 发往 MAC1 的普通单播：应只从 p2 出
            raw_frame(2, "p3", plain_ipv4_udp(dst=(10, 0, 0, 10)),
                      dst_mac=MAC1, src_mac=MAC3),
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][1]["action"], "unicast")
        self.assertEqual(
            [p["name"] for p in result["results"][1]["ports"]], ["p2"]
        )

    def test_non_dhcp_frame_snoop_null(self):
        config = make_config()
        events = [raw_frame(1, "p3", plain_ipv4_udp())]
        result = self.simulate(config, events)
        self.assertIsNone(result["results"][0]["snoop"])
        self.assertEqual(result["results"][0]["action"], "flood")

    def test_bad_fcs_dropped_before_snoop(self):
        config = make_config()
        events = [
            raw_frame(1, "p2", client_packet(MAC1, 1, 1), bad_fcs=True),
        ]
        result = self.simulate(config, events)
        entry = result["results"][0]
        self.assertEqual(entry["action"], "drop")
        self.assertIsNone(entry["snoop"])
        p2 = next(p for p in result["ports"] if p["name"] == "p2")
        self.assertEqual(p2["bad_fcs"], 1)
        self.assertEqual(p2["snoop"]["discover"], 0)

    def test_tagged_on_access_port_rejected(self):
        ports = [
            make_port("p1", allowed=[1, 2]),
            make_port("p2", mode="access", pvid=1, allowed=[1]),
        ]
        config = make_config(ports=ports)
        events = [
            raw_frame(1, "p2", client_packet(MAC1, 1, 1), vlan=1),
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][0]["action"], "drop")
        self.assertIsNone(result["results"][0]["snoop"])

    def test_tag_not_allowed_rejected(self):
        config = make_config()
        events = [
            raw_frame(1, "p2", client_packet(MAC1, 1, 1), vlan=999),
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][0]["action"], "drop")

    def test_dhcp_broadcast_floods_eligible_except_ingress(self):
        config = make_config()
        events = [raw_frame(1, "p2", client_packet(MAC1, 1, 1))]
        result = self.simulate(config, events)
        self.assertEqual(
            [p["name"] for p in result["results"][0]["ports"]],
            ["p1", "p3", "p4"],
        )

    def test_untagged_egress_on_hybrid_port(self):
        config = make_config()
        events = [raw_frame(1, "p2", client_packet(MAC1, 1, 1))]
        result = self.simulate(config, events)
        ports = {p["name"]: p["vlan"]
                 for p in result["results"][0]["ports"]}
        self.assertIsNone(ports["p4"])  # hybrid untagged VLAN 1
        self.assertEqual(ports["p1"], 1)

    def test_decline_inform_forward_no_state(self):
        config = make_config()
        events = [
            raw_frame(1, "p2", client_packet(MAC1, 1, 4,
                                             ciaddr=IP10)),  # DECLINE
            raw_frame(2, "p2", client_packet(MAC1, 1, 8,
                                             ciaddr=IP10)),  # INFORM
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            [r["snoop"]["message"] for r in result["results"]],
            ["decline", "inform"],
        )
        self.assertTrue(all(
            r["snoop"]["effect"] == "forward" for r in result["results"]
        ))
        self.assertEqual(result["bindings"], [])


class StpIntegrationTest(DhcpCase):
    def _two_bridge_config(self):
        # b1 边缘口 p2/p3；p1 经链路 L1 连 b2；STP 收敛后 p1 forwarding
        links = [{"id": "L1", "x": ["b1", "p1"], "y": ["b2", "p1"],
                  "cost": 1, "up": True}]
        ports = [
            make_port("p1", allowed=[1]),
            make_port("p2", allowed=[1]),
            make_port("p3", allowed=[1]),
        ]
        return make_config(
            ports=ports, bridges=("b1", "b2"), links=links, delay=2
        )

    def test_dhcp_on_forwarding_link_port(self):
        config = self._two_bridge_config()
        # delay=2：2*delay=4 后 p1 forwarding；t>=4 可信 ACK 生效
        events = [
            raw_frame(5, "p2", client_packet(MAC1, 111, 3)),
            raw_frame(6, "p1",
                      server_packet(MAC1, 111, 5, yiaddr=IP10, lease=100)),
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            result["results"][1]["snoop"]["effect"], "bind"
        )
        self.assertEqual(len(result["bindings"]), 1)

    def test_link_down_does_not_remove_binding(self):
        config = self._two_bridge_config()
        events = [
            raw_frame(5, "p2", client_packet(MAC1, 111, 3)),
            raw_frame(6, "p1",
                      server_packet(MAC1, 111, 5, yiaddr=IP10, lease=1000)),
            link_event(7, "L1", False),
            link_event(8, "L1", True),
        ]
        result = self.simulate(config, events)
        # 绑定只由显式 t 老化，不随链路清除
        self.assertEqual(len(result["bindings"]), 1)

    def test_dhcp_state_machine_independent_of_stp_state(self):
        config = self._two_bridge_config()
        config["dhcp"]["max_lease"] = 5
        events = [
            raw_frame(1, "p2", client_packet(MAC1, 111, 3)),
            # p1 在 t=1 仍 discarding：ACK 不转发（drop），但受信 ACK 的
            # snooping 状态机独立于 STP，仍按匹配请求建绑定
            raw_frame(2, "p1",
                      server_packet(MAC1, 111, 5, yiaddr=IP10, lease=5)),
        ]
        result = self.simulate(config, events)
        ack = result["results"][1]
        self.assertEqual(ack["action"], "drop")
        self.assertEqual(ack["ports"], [])
        self.assertEqual(ack["snoop"]["effect"], "bind")
        self.assertEqual(len(result["bindings"]), 1)
        # 分类仍计入 p1 的 ack
        p1 = next(p for p in result["ports"] if p["name"] == "p1")
        self.assertEqual(p1["snoop"]["ack"], 1)

    def test_malformed_dhcp_classified_on_non_forwarding_port(self):
        config = self._two_bridge_config()
        # p1 在 t=1 discarding：其上的非法 DHCP 仍按 malformed_dhcp 分类，
        # 而非普通 STP 丢弃
        bad = server_packet(MAC1, 1, 1)  # 方向非法的 BOOTREPLY 上行
        events = [raw_frame(1, "p1", bad)]
        result = self.simulate(config, events)
        self.assertEqual(
            result["results"][0]["action"], "malformed_dhcp"
        )
        p1 = next(p for p in result["ports"] if p["name"] == "p1")
        self.assertEqual(p1["snoop"]["malformed_dhcp"], 1)


class BindingsOutputTest(DhcpCase):
    def test_bindings_sorted_vlan_ip_mac_port(self):
        config = make_config(max_lease=1000)
        seq = [
            (MAC3, 0x3333, IP12, "p3", 2),
            (MAC1, 0x1111, IP10, "p2", 1),
            (MAC2, 0x2222, IP11, "p2", 2),
            (MAC4, 0x4444, IP10, "p3", 2),  # 同 VLAN2 同 IP 不同 MAC
        ]
        events = []
        t = 1
        for mac, xid, ip, prt, vlan in seq:
            events.append(raw_frame(
                t, prt, client_packet(mac, xid, 3), vlan=vlan
            ))
            events.append(raw_frame(
                t + 1, "p1",
                server_packet(mac, xid, 5, yiaddr=ip, lease=1000),
                vlan=vlan,
            ))
            t += 2
        result = self.simulate(config, events)
        ordered = [
            (b["vlan"], b["ip"], b["mac"]) for b in result["bindings"]
        ]
        self.assertEqual(ordered, [
            (1, "192.168.0.10", M1),
            (2, "192.168.0.10", M4),
            (2, "192.168.0.11", M2),
            (2, "192.168.0.12", M3),
        ])
        # 固定键序
        self.assertEqual(
            list(result["bindings"][0]),
            ["vlan", "ip", "mac", "port", "expires"],
        )

    def test_results_fixed_key_order(self):
        config = make_config()
        events, _ = self.handshake()
        self.write(config, events)
        code, out, err = self.run_cmd(
            "dhcp-snoop-decode", self.cfg, self.evt
        )
        self.assertEqual(code, 0, err)
        text = out.decode()
        # 每帧结果对象以 t/action/ports/snoop 固定顺序出现
        self.assertIn(
            '{"t":1,"action":"flood","ports":[', text
        )
        self.assertIn('"snoop":{"message":"discover","xid":', text)


class CountersTest(DhcpCase):
    def test_per_port_snoop_categories(self):
        config = make_config(binding_capacity=1, max_lease=1000)
        events, t = self.handshake()  # discover/offer/request/ack
        # 一个非法报文（p2 malformed）与一个非可信服务器（p3 untrusted）
        bad = client_packet(MAC1, 1, 5, yiaddr=IP10, lease=100)
        events.append(raw_frame(t, "p2", bad))
        events.append(raw_frame(
            t + 1, "p3",
            server_packet(MAC1, 1, 5, yiaddr=IP11, lease=100),
        ))
        result = self.simulate(config, events)
        p1 = next(p for p in result["ports"] if p["name"] == "p1")
        p2 = next(p for p in result["ports"] if p["name"] == "p2")
        p3 = next(p for p in result["ports"] if p["name"] == "p3")
        self.assertEqual(p1["snoop"]["offer"], 1)
        self.assertEqual(p1["snoop"]["ack"], 1)
        self.assertEqual(p2["snoop"]["discover"], 1)
        self.assertEqual(p2["snoop"]["request"], 1)
        self.assertEqual(p2["snoop"]["malformed_dhcp"], 1)
        self.assertEqual(p3["snoop"]["untrusted_server"], 1)
        # 无事件端口全零且类别齐全
        p4 = next(p for p in result["ports"] if p["name"] == "p4")
        self.assertEqual(
            list(p4["snoop"]),
            ["discover", "request", "offer", "ack", "nak", "release",
             "decline", "inform", "malformed_dhcp", "untrusted_server",
             "binding_conflict", "binding_full"],
        )
        self.assertTrue(all(v == 0 for v in p4["snoop"].values()))


class DeterminismTest(DhcpCase):
    def test_byte_identical_outputs(self):
        config = make_config(binding_capacity=2, max_lease=100)
        events, t = self.handshake(lease=50)
        events += [
            raw_frame(t, "p3", client_packet(MAC2, 0x1, 3)),
            raw_frame(t + 1, "p1",
                      server_packet(MAC2, 0x1, 5, yiaddr=IP11, lease=50)),
        ]
        self.write(config, events)
        code, out1, err = self.run_cmd(
            "dhcp-snoop-decode", self.cfg, self.evt
        )
        self.assertEqual(code, 0, err)
        code, out2, err = self.run_cmd(
            "dhcp-snoop-decode", self.cfg, self.evt
        )
        self.assertEqual(out1, out2)


class RecordReplayTest(DhcpCase):
    def test_record_auto_detect_and_replay_identical(self):
        config = make_config(binding_capacity=2, max_lease=100)
        events, t = self.handshake(lease=50)
        events += [
            raw_frame(t, "p3", client_packet(MAC2, 0x1, 3)),
            raw_frame(t + 1, "p3",
                      server_packet(MAC2, 0x1, 5, yiaddr=IP11, lease=50)),
        ]
        self.write(config, events)
        code, out, err = self.run_cmd(
            "record", self.cfg, self.evt, self.log
        )
        self.assertEqual(code, 0, err)
        record_out = out
        code, out, err = self.run_cmd("replay", self.log)
        self.assertEqual(code, 0, err)
        self.assertEqual(out, record_out)
        with open(self.log, "rb") as handle:
            doc = json.loads(handle.read().decode())
        # 仅链路项 applied 才计 version；全帧项 version 恒 0
        self.assertTrue(all(r["version"] == 0 for r in doc["records"]))

    def test_record_with_links_replay_identical(self):
        links = [{"id": "L1", "x": ["b1", "p1"], "y": ["b2", "p1"],
                  "cost": 1, "up": True}]
        ports = [
            make_port("p1", allowed=[1]),
            make_port("p2", allowed=[1]),
            make_port("p3", allowed=[1]),
        ]
        config = make_config(
            ports=ports, bridges=("b1", "b2"), links=links, max_lease=1000
        )
        events = [
            link_event(1, "L1", False),
            raw_frame(5, "p2", client_packet(MAC1, 111, 3)),
            raw_frame(6, "p2", client_packet(MAC1, 111, 1)),
            link_event(7, "L1", True),
        ]
        self.write(config, events)
        code, out, err = self.run_cmd(
            "record", self.cfg, self.evt, self.log
        )
        self.assertEqual(code, 0, err)
        record_out = out
        code, out, err = self.run_cmd("replay", self.log)
        self.assertEqual(code, 0, err)
        self.assertEqual(out, record_out)
        with open(self.log, "rb") as handle:
            doc = json.loads(handle.read().decode())
        versions = [(r["t"], r["version"], r["applied"])
                    for r in doc["records"]]
        self.assertEqual(versions, [
            (1, 1, True), (5, 1, True), (6, 1, True), (7, 2, True)
        ])


class WorkLimitTest(DhcpCase):
    def test_work_formula_and_boundary(self):
        config = make_config(max_lease=100)
        events, t = self.handshake(lease=50)  # 4 帧，P=4
        # ACK 在 t=4 绑定，expires=54；再放一个 t=54 的帧先老化
        events.append(raw_frame(54, "p3", plain_ipv4_udp()))
        self.write(config, events)
        # 前 4 个事件处理前绑定数恒 0：各 1+4=5；第 5 个事件先老化（绑定
        # expires=54），处理前活动绑定数仍 0，计 5。总计 25。
        total = 25
        head = ("1048576", "16777216", "100000", "16777216")
        code, ok, err = self.run_cmd(
            "dhcp-snoop-decode", self.cfg, self.evt, *head, str(total)
        )
        self.assertEqual(code, 0, err)
        code, out, err = self.run_cmd(
            "dhcp-snoop-decode", self.cfg, self.evt, *head, str(total - 1)
        )
        self.assertEqual((code, out), (5, b""))
        self.assertEqual(err, b'{"error":"dhcp_work_limit"}\n')

    def test_work_counts_active_bindings(self):
        config = make_config(max_lease=1000)
        events, t = self.handshake(lease=500)  # 1 个绑定
        events.append(raw_frame(t, "p3", plain_ipv4_udp()))
        self.write(config, events)
        # 前 4 事件各 5；第 5 事件处理前有 1 个活动绑定：1+4+1=6；总 26
        total = 26
        head = ("1048576", "16777216", "100000", "16777216")
        code, _, err = self.run_cmd(
            "dhcp-snoop-decode", self.cfg, self.evt, *head, str(total)
        )
        self.assertEqual(code, 0, err)
        code, out, err = self.run_cmd(
            "dhcp-snoop-decode", self.cfg, self.evt, *head, str(total - 1)
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")

    def test_record_replay_work_boundary(self):
        config = make_config()
        events, _ = self.handshake()
        self.write(config, events)
        total = 4 * (1 + 4)  # 无活动绑定进入任何事件
        head = ("100000", "16777216", "1048576", "16777216", "16777216")
        code, record_out, err = self.run_cmd(
            "record", self.cfg, self.evt, self.log, *head, str(total)
        )
        self.assertEqual(code, 0, err)
        code, out, err = self.run_cmd(
            "record", self.cfg, self.evt, self.log, *head, str(total - 1)
        )
        self.assertEqual(
            (code, out), (5, b"")
        )
        self.assertEqual(err, b'{"error":"record_work_limit"}\n')
        code, out, err = self.run_cmd(
            "replay", self.log, "100000", "16777216", "16777216",
            str(total),
        )
        self.assertEqual((code, out), (0, record_out))
        code, out, err = self.run_cmd(
            "replay", self.log, "100000", "16777216", "16777216",
            str(total - 1),
        )
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"replay_work_limit"}\n')


class FailureContractTest(DhcpCase):
    def base_config(self):
        return make_config()

    def test_usage_exit_2(self):
        self.write(self.base_config(), [])
        code, out, _ = self.run_cmd(
            "dhcp-snoop-decode", self.cfg, self.evt, "1048576"
        )
        self.assertEqual((code, out), (2, b""))
        code, out, _ = self.run_cmd("dhcp-snoop-decode")
        self.assertEqual((code, out), (2, b""))
        code, out, _ = self.run_cmd(
            "dhcp-snoop-decode", self.cfg, self.evt,
            "1048576", "16777216", "100000", "16777216", "zero",
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
        bad_cap = self.base_config()
        bad_cap["dhcp"] = {
            "trusted_ports": ["p1"], "binding_capacity": 0, "max_lease": 10,
        }
        cases.append(bad_cap)
        bad_lease = self.base_config()
        bad_lease["dhcp"] = {
            "trusted_ports": [], "binding_capacity": 10, "max_lease": -1,
        }
        cases.append(bad_lease)
        dup = self.base_config()
        dup["dhcp"] = {
            "trusted_ports": ["p1", "p1"], "binding_capacity": 10,
            "max_lease": 10,
        }
        cases.append(dup)
        unknown = self.base_config()
        unknown["dhcp"] = {
            "trusted_ports": ["px"], "binding_capacity": 10, "max_lease": 10,
        }
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
        for config in cases:
            self.write(config, [])
            code, out, err = self.run_cmd(
                "dhcp-snoop-decode", self.cfg, self.evt
            )
            self.assertEqual((code, out), (4, b""), config)
            self.assertEqual(err, b'{"error":"invalid_input"}\n')

    def test_bad_events_exit_4(self):
        # t 下降
        config = self.base_config()
        events = [
            raw_frame(2, "p2", client_packet(MAC1, 1, 1)),
            raw_frame(1, "p2", client_packet(MAC1, 1, 1)),
        ]
        self.write(config, events)
        code, out, _ = self.run_cmd(
            "dhcp-snoop-decode", self.cfg, self.evt
        )
        self.assertEqual((code, out), (4, b""))
        # 双标签帧（外壳非法）：以单层 802.1Q 帧为基在标签后再插 8100
        raw = bytes.fromhex(raw_frame(
            1, "p2", client_packet(MAC1, 1, 1), vlan=1
        )["data"])
        double = raw[:16] + b"\x81\x00\x10\x00" + raw[16:]
        self.write(config, [{"t": 1, "port": "p2", "data": double.hex()}])
        code, out, _ = self.run_cmd(
            "dhcp-snoop-decode", self.cfg, self.evt
        )
        self.assertEqual((code, out), (4, b""))

    def test_resource_limits_exit_5(self):
        config = self.base_config()
        events = [raw_frame(1, "p2", client_packet(MAC1, 1, 1))]
        self.write(config, events)
        code, _, err = self.run_cmd(
            "dhcp-snoop-decode", self.cfg, self.evt, "50", "16777216"
        )
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"config_limit"}\n')

    def test_invalid_config_record_exit_4_no_log(self):
        bad = self.base_config()
        bad["dhcp"] = {
            "trusted_ports": [], "binding_capacity": 0, "max_lease": 10,
        }
        self.write(bad, [])
        code, out, _ = self.run_cmd(
            "record", self.cfg, self.evt, self.log
        )
        self.assertEqual((code, out), (4, b""))
        self.assertFalse(os.path.exists(self.log))


if __name__ == "__main__":
    unittest.main()
