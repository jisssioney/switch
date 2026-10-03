#!/usr/bin/env python3
"""igmp-snoop-decode 的 IGMPv3 Membership Report 与源地址过滤端到端测试。

覆盖：六类组记录状态机（MODE_IS_INCLUDE/EXCLUDE、CHANGE_TO_*、
ALLOW_NEW_SOURCES、BLOCK_OLD_SOURCES）、空 INCLUDE 删除、空 EXCLUDE
接收全部源、多记录按序一次提交（整帧非法不改状态）、组播数据按 IPv4
源做 INCLUDE/EXCLUDE 过滤、无成员组仍泛洪、igmpv3_report 优先路由端口
否则泛洪、groups 固定键序与源地址数值升序、v2 成员保持原键形、record/
replay 逐字节复现、v3 工作量（每记录与每源各加 1）边界。仅用标准库。
"""

import json
import os
import subprocess
import sys
import unittest

import switch
from test_igmp_snoop_decode import (
    G1,
    G2,
    IgmpSnoopCase,
    group_mac,
    internet_checksum,
    ip_header,
    ipv4_udp_like,
    make_config,
    raw_frame,
)

S1 = (10, 0, 0, 1)
S2 = (10, 0, 0, 2)
S9 = (10, 0, 0, 9)
S20 = (10, 0, 0, 20)
OUTER = (224, 0, 0, 22)


def igmpv3_message(records, bad_checksum=False, ngroups=None,
                   trailing=b""):
    """records：(rtype, group 4 元组, 源 4 元组列表, aux 字节) 列表。"""
    body = b""
    for rtype, group, sources, aux in records:
        body += (
            bytes([rtype, len(aux) // 4])
            + len(sources).to_bytes(2, "big")
            + bytes(group)
            + b"".join(bytes(src) for src in sources)
            + aux
        )
    count = len(records) if ngroups is None else ngroups
    # 8 字节报告头：Type、Reserved、Checksum(2)、Reserved(2)、N(2)
    msg = (
        bytes([0x22, 0x00]) + b"\x00\x00" + b"\x00\x00"
        + count.to_bytes(2, "big") + body + trailing
    )
    checksum = internet_checksum(msg)
    if bad_checksum:
        checksum ^= 0xFFFF
    return msg[:2] + checksum.to_bytes(2, "big") + msg[4:]


def v3_frame(t, port, records, vlan=1, outer=OUTER, src=(10, 0, 0, 1),
             bad_fcs=False, **message_kwargs):
    payload = igmpv3_message(records, **message_kwargs)
    iphdr = ip_header(src, outer, 2, len(payload))
    body = iphdr + payload
    if len(body) < 46:  # L2 最小载荷 46 字节，填充不改变 IPv4 总长度
        body += b"\x00" * (46 - len(body))
    return raw_frame(
        t, port, group_mac(outer), "02:00:00:00:00:01", body,
        vlan=vlan, bad_fcs=bad_fcs,
    )


def rec(rtype, group, sources=(), aux=b""):
    return (rtype, group, list(sources), aux)


def data_frame(t, port, group, source=S9, vlan=1):
    return raw_frame(
        t, port, group_mac(group), "02:00:00:00:00:09",
        ipv4_udp_like(group, src=source), vlan=vlan,
    )


class IgmpV3ReportTest(IgmpSnoopCase):
    def report_include(self, t=1, port="p2", group=G1, sources=(S1,),
                       **kwargs):
        return v3_frame(
            t, port, [rec(1, group, sources)], **kwargs
        )

    def test_action_and_router_delivery(self):
        config = make_config(router_ports=("p1",))
        result = self.simulate(config, [self.report_include()])
        self.assertEqual(result["results"][0]["action"], "igmpv3_report")
        self.assertEqual(
            result["results"][0]["ports"], [{"name": "p1", "vlan": 1}]
        )

    def test_flood_without_router(self):
        config = make_config(router_ports=())
        result = self.simulate(config, [self.report_include()])
        self.assertEqual(result["results"][0]["action"], "igmpv3_report")
        self.assertEqual(
            [p["name"] for p in result["results"][0]["ports"]],
            ["p1", "p3", "p4"],
        )

    def test_include_member_shape_and_sources_sorted_numerically(self):
        # 源地址按数值升序：10.0.0.9 排在 10.0.0.20 前（非字典序）
        config = make_config(router_ports=("p1",))
        events = [self.report_include(sources=(S20, S9))]
        result = self.simulate(config, events)
        group = result["groups"][0]
        self.assertEqual(group["vlan"], 1)
        self.assertEqual(group["group"], "224.1.2.3")
        self.assertEqual(
            group["members"],
            [
                {
                    "name": "p2", "expires": 51, "mode": "include",
                    "sources": ["10.0.0.9", "10.0.0.20"],
                }
            ],
        )

    def run_switch(self, config, events, *extra):
        self.write(config, events)
        return self.run_cmd(
            "igmp-snoop-decode", self.cfg, self.evt, *extra
        )

    def test_member_key_order(self):
        config = make_config(router_ports=("p1",))
        code, out, err = self.run_switch(config, [self.report_include()])
        self.assertEqual(code, 0, err)
        text = out.decode()
        self.assertIn(
            '"members":[{"name":"p2","expires":51,"mode":"include",'
            '"sources":["10.0.0.1"]}]',
            text,
        )

    def test_empty_include_deletes_member(self):
        config = make_config(router_ports=("p1",))
        events = [
            self.report_include(1, sources=(S1,)),
            v3_frame(2, "p2", [rec(3, G1, [])]),  # CHANGE_TO_INCLUDE 空
            data_frame(3, "p3", G1, S1),
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["groups"], [])
        self.assertEqual(
            [r["action"] for r in result["results"]],
            ["igmpv3_report", "igmpv3_report", "flood"],
        )

    def test_exclude_empty_receives_all_sources(self):
        config = make_config(router_ports=("p1",))
        events = [
            v3_frame(1, "p2", [rec(2, G1, [])]),  # MODE_IS_EXCLUDE 空
            data_frame(2, "p3", G1, S1),
            data_frame(3, "p3", G1, S20),
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            result["groups"][0]["members"][0]["mode"], "exclude"
        )
        self.assertEqual(result["groups"][0]["members"][0]["sources"], [])
        self.assertEqual(
            [r["action"] for r in result["results"][1:]],
            ["multicast", "multicast"],
        )
        # 成员 p2 与路由 p1 均收到
        for entry in result["results"][1:]:
            self.assertEqual(
                [p["name"] for p in entry["ports"]], ["p1", "p2"]
            )

    def test_exclude_blocks_listed_source(self):
        config = make_config(router_ports=("p1",))
        events = [
            v3_frame(1, "p2", [rec(2, G1, [S1])]),
            data_frame(2, "p3", G1, S1),   # 被排除：成员不收
            data_frame(3, "p3", G1, S2),   # 其他源：成员收
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            [p["name"] for p in result["results"][1]["ports"]], ["p1"]
        )
        self.assertEqual(
            [p["name"] for p in result["results"][2]["ports"]],
            ["p1", "p2"],
        )

    def test_include_delivers_only_listed_source(self):
        config = make_config(router_ports=("p1",))
        events = [
            v3_frame(1, "p2", [rec(1, G1, [S1])]),
            data_frame(2, "p3", G1, S1),
            data_frame(3, "p3", G1, S2),
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            [p["name"] for p in result["results"][1]["ports"]],
            ["p1", "p2"],
        )
        self.assertEqual(
            [p["name"] for p in result["results"][2]["ports"]], ["p1"]
        )


class IgmpV3DeltaTest(IgmpSnoopCase):
    def sim_delta(self, records_sequence, data=None, router_ports=("p1",)):
        config = make_config(router_ports=router_ports)
        events = [
            v3_frame(t, "p2", records)
            for t, records in enumerate(records_sequence, start=1)
        ]
        if data is not None:
            t0 = len(events) + 1
            for offset, source in enumerate(data):
                events.append(
                    data_frame(t0 + offset, "p3", G1, source)
                )
        return super().simulate(config, events)

    def member(self, result):
        return result["groups"][0]["members"][0]

    def test_change_to_include_replaces(self):
        result = self.sim_delta(
            [
                [rec(2, G1, [S1, S2])],
                [rec(3, G1, [S20])],  # CHANGE_TO_INCLUDE 覆盖
            ]
        )
        self.assertEqual(
            self.member(result),
            {
                "name": "p2", "expires": 52, "mode": "include",
                "sources": ["10.0.0.20"],
            },
        )

    def test_change_to_exclude_empty_means_all(self):
        result = self.sim_delta(
            [
                [rec(1, G1, [S1])],
                [rec(4, G1, [])],  # CHANGE_TO_EXCLUDE 空：接收全部
            ],
            data=[S1, S2],
        )
        # 两次数据均投递给成员（之前 INCLUDE 不收 S2）
        self.assertEqual(
            [r["action"] for r in result["results"][2:]],
            ["multicast", "multicast"],
        )

    def test_allow_new_sources_include_union(self):
        result = self.sim_delta(
            [
                [rec(1, G1, [S1])],
                [rec(5, G1, [S2])],  # ALLOW_NEW_SOURCES 并集
            ]
        )
        self.assertEqual(self.member(result)["mode"], "include")
        self.assertEqual(
            self.member(result)["sources"], ["10.0.0.1", "10.0.0.2"]
        )
        self.assertEqual(self.member(result)["expires"], 52)

    def test_allow_new_sources_exclude_difference(self):
        result = self.sim_delta(
            [
                [rec(2, G1, [S1, S2])],
                [rec(5, G1, [S1])],  # EXCLUDE 差集：仅排除 S2
            ],
            data=[S1, S2],
        )
        member = self.member(result)
        self.assertEqual(member["mode"], "exclude")
        self.assertEqual(member["sources"], ["10.0.0.2"])
        # S1 已从排除集移除 -> 成员收；S2 仍排除 -> 成员不收
        self.assertEqual(
            [p["name"] for p in result["results"][2]["ports"]],
            ["p1", "p2"],
        )
        self.assertEqual(
            [p["name"] for p in result["results"][3]["ports"]], ["p1"]
        )

    def test_allow_new_sources_exclude_to_empty_stays_exclude(self):
        # EXCLUDE 差集为空仍为 EXCLUDE {}（接收全部源），成员不删除
        result = self.sim_delta(
            [
                [rec(2, G1, [S1])],
                [rec(5, G1, [S1])],
            ],
            data=[S1],
        )
        member = self.member(result)
        self.assertEqual(member["mode"], "exclude")
        self.assertEqual(member["sources"], [])
        self.assertEqual(
            [p["name"] for p in result["results"][2]["ports"]],
            ["p1", "p2"],
        )

    def test_block_old_sources_include_difference_deletes_when_empty(self):
        result = self.sim_delta(
            [
                [rec(1, G1, [S1, S2])],
                [rec(6, G1, [S1, S2])],  # INCLUDE 差空：删除成员
            ],
            data=[S1],
        )
        self.assertEqual(result["groups"], [])
        self.assertEqual(result["results"][2]["action"], "flood")

    def test_block_old_sources_include_partial(self):
        result = self.sim_delta(
            [
                [rec(1, G1, [S1, S2])],
                [rec(6, G1, [S1])],  # INCLUDE 差集：仅剩 S2
            ],
            data=[S1, S2],
        )
        self.assertEqual(
            [p["name"] for p in result["results"][2]["ports"]], ["p1"]
        )
        self.assertEqual(
            [p["name"] for p in result["results"][3]["ports"]],
            ["p1", "p2"],
        )

    def test_block_old_sources_exclude_union(self):
        result = self.sim_delta(
            [
                [rec(2, G1, [S1])],
                [rec(6, G1, [S2])],  # EXCLUDE 并集：排除 S1、S2
            ],
            data=[S1, S2, S20],
        )
        member = self.member(result)
        self.assertEqual(member["mode"], "exclude")
        self.assertEqual(
            member["sources"], ["10.0.0.1", "10.0.0.2"]
        )
        self.assertEqual(
            [p["name"] for p in result["results"][2]["ports"]], ["p1"]
        )
        self.assertEqual(
            [p["name"] for p in result["results"][3]["ports"]], ["p1"]
        )
        self.assertEqual(
            [p["name"] for p in result["results"][4]["ports"]],
            ["p1", "p2"],
        )

    def test_delta_on_absent_member_uses_include_baseline(self):
        # 无成员时 ALLOW/BLOCK 以 INCLUDE 空集为基线
        allow = self.sim_delta([[rec(5, G1, [S1])]], data=[S1])
        self.assertEqual(
            self.member(allow),
            {
                "name": "p2", "expires": 51, "mode": "include",
                "sources": ["10.0.0.1"],
            },
        )
        block = self.sim_delta([[rec(6, G1, [S1])]])
        self.assertEqual(block["groups"], [])

    def test_delta_on_v2_member_treated_as_exclude_empty(self):
        # v2 成员（等价 EXCLUDE {}）：BLOCK 并集排除 S1，升级为 EXCLUDE
        # {S1}，expires 刷新
        config = make_config(router_ports=("p1",))
        events = [
            self.report(1, "p2", G1),
            v3_frame(2, "p2", [rec(6, G1, [S1])]),
        ]
        result = self.simulate(config, events)
        member = result["groups"][0]["members"][0]
        self.assertEqual(member["mode"], "exclude")
        self.assertEqual(member["sources"], ["10.0.0.1"])
        self.assertEqual(member["expires"], 52)


class IgmpV3MultiRecordTest(IgmpSnoopCase):
    def test_multiple_records_applied_in_order_uniform_expiry(self):
        config = make_config(router_ports=("p1",))
        events = [
            v3_frame(
                10, "p2",
                [
                    rec(1, G1, [S1]),
                    rec(1, G2, [S2]),
                    rec(5, G1, [S20]),  # 同帧再改 G1：并集
                ],
            ),
        ]
        result = self.simulate(config, events)
        groups = result["groups"]
        self.assertEqual(
            [(g["group"], g["members"][0]["expires"]) for g in groups],
            [("224.1.2.2", 60), ("224.1.2.3", 60)],
        )
        g1 = next(g for g in groups if g["group"] == "224.1.2.3")
        self.assertEqual(
            g1["members"][0]["sources"], ["10.0.0.1", "10.0.0.20"]
        )

    def test_multiple_members_ports_ordered(self):
        config = make_config(router_ports=("p1",))
        events = [
            v3_frame(1, "p3", [rec(1, G1, [S1])]),
            v3_frame(2, "p2", [rec(2, G1, [])]),
        ]
        result = self.simulate(config, events)
        members = result["groups"][0]["members"]
        self.assertEqual(
            [(m["name"], m["mode"]) for m in members],
            [("p2", "exclude"), ("p3", "include")],
        )

    def test_group_absent_still_floods(self):
        config = make_config(router_ports=("p1",))
        events = [
            v3_frame(1, "p2", [rec(1, G1, [S1])]),
            data_frame(2, "p3", G2, S1),  # 另一个组无成员
        ]
        result = self.simulate(config, events)
        self.assertEqual(
            [r["action"] for r in result["results"]],
            ["igmpv3_report", "flood"],
        )


class IgmpV3InvalidTest(IgmpSnoopCase):
    def _bad(self, message_kwargs=None, records=None):
        config = make_config(router_ports=("p1",))
        if records is None:
            records = [rec(1, G1, [S1])]
        frame = v3_frame(1, "p2", records, **(message_kwargs or {}))
        follow = data_frame(2, "p3", G1, S1)
        result = self.simulate(config, [frame, follow])
        return result

    def test_bad_checksum_invalid_no_state(self):
        result = self._bad({"bad_checksum": True})
        self.assertEqual(result["results"][0]["action"], "igmp_invalid")
        self.assertEqual(result["results"][0]["ports"], [])
        self.assertEqual(result["results"][1]["action"], "flood")
        self.assertEqual(result["groups"], [])
        self.assertEqual(result["ports"][1]["drop"], 1)
        self.assertEqual(result["vlans"][0]["drop"], 1)

    def test_bad_record_type_invalid(self):
        result = self._bad(records=[rec(7, G1, [S1])])
        self.assertEqual(result["results"][0]["action"], "igmp_invalid")
        self.assertEqual(result["groups"], [])

    def test_non_class_d_group_invalid(self):
        result = self._bad(records=[rec(1, (240, 1, 2, 3), [S1])])
        self.assertEqual(result["results"][0]["action"], "igmp_invalid")
        self.assertEqual(result["groups"], [])

    def test_non_unicast_source_invalid(self):
        result = self._bad(records=[rec(1, G1, [(224, 0, 0, 1)])])
        self.assertEqual(result["results"][0]["action"], "igmp_invalid")
        self.assertEqual(result["groups"], [])
        result = self._bad(records=[rec(1, G1, [(0, 0, 0, 1)])])
        self.assertEqual(result["results"][0]["action"], "igmp_invalid")

    def test_record_count_mismatch_invalid(self):
        # ngroups 声明 2 但只有一条记录：长度不闭合
        result = self._bad({"ngroups": 2})
        self.assertEqual(result["results"][0]["action"], "igmp_invalid")
        self.assertEqual(result["groups"], [])
        # 记录闭合后多出 4 字节：记录数与内容不符
        result = self._bad({"trailing": b"\x00\x00\x00\x00"})
        self.assertEqual(result["results"][0]["action"], "igmp_invalid")
        self.assertEqual(result["groups"], [])

    def test_sources_array_not_closed_invalid(self):
        # 记录声明 2 个源但仅给出 1 个：源地址数组不闭合
        record_bytes = (
            bytes([1, 0]) + (2).to_bytes(2, "big") + bytes(G1) + bytes(S1)
        )
        msg = (
            bytes([0x22, 0]) + b"\x00\x00" + b"\x00\x00"
            + (1).to_bytes(2, "big") + record_bytes
        )
        csum = internet_checksum(msg)
        msg = msg[:2] + csum.to_bytes(2, "big") + msg[4:]
        iphdr = ip_header((10, 0, 0, 1), OUTER, 2, len(msg))
        body = iphdr + msg + b"\x00" * max(
            0, 46 - 20 - len(msg)
        )
        frame = raw_frame(
            1, "p2", group_mac(OUTER), "02:00:00:00:00:01", body, vlan=1
        )
        config = make_config(router_ports=("p1",))
        events = [
            frame,
            data_frame(2, "p3", G1, S1),
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][0]["action"], "igmp_invalid")
        self.assertEqual(result["groups"], [])

    def test_invalid_frame_is_atomic(self):
        # 首条记录合法、次条记录非法：整帧 igmp_invalid，两组都不建成员
        config = make_config(router_ports=("p1",))
        frame = v3_frame(
            1, "p2",
            [rec(1, G1, [S1]), rec(7, G2, [S2])],
        )
        result = self.simulate(config, [frame, data_frame(2, "p3", G1, S1)])
        self.assertEqual(result["results"][0]["action"], "igmp_invalid")
        self.assertEqual(result["groups"], [])
        self.assertEqual(result["results"][1]["action"], "flood")

    def test_fragmented_v3_not_recognized(self):
        # MF=1 分片不识别为 IGMP：按普通帧泛洪，不建成员
        config = make_config(router_ports=("p1",))
        payload = igmpv3_message([rec(1, G1, [S1])])
        from test_igmp_snoop_decode import ip_header as _iph
        iphdr = _iph(
            (10, 0, 0, 1), OUTER, 2, len(payload), fragment_word=0x2000
        )
        l2 = iphdr + payload
        l2 += b"\x00" * max(0, 46 - len(l2))
        frame = raw_frame(
            1, "p2", group_mac(OUTER), "02:00:00:00:00:01", l2, vlan=1
        )
        result = self.simulate(config, [frame, data_frame(2, "p3", G1, S1)])
        self.assertEqual(result["results"][0]["action"], "flood")
        self.assertEqual(result["results"][1]["action"], "flood")
        self.assertEqual(result["groups"], [])


class IgmpV2InteropTest(IgmpSnoopCase):
    def test_v2_member_keeps_key_shape_and_receives_all(self):
        config = make_config(router_ports=("p1",))
        events = [
            self.report(1, "p2", G1),
            data_frame(2, "p3", G1, S1),
            data_frame(3, "p3", G1, S20),
        ]
        self.write(config, events)
        code, out, err = self.run_cmd(
            "igmp-snoop-decode", self.cfg, self.evt
        )
        self.assertEqual(code, 0, err)
        self.assertIn(
            '"members":[{"name":"p2","expires":51}]', out.decode()
        )
        result = json.loads(out.decode())
        self.assertEqual(
            list(result["groups"][0]["members"][0]), ["name", "expires"]
        )
        self.assertEqual(
            [r["action"] for r in result["results"][1:]],
            ["multicast", "multicast"],
        )

    def test_v2_then_v3_upgrades_shape(self):
        config = make_config(router_ports=("p1",))
        events = [
            self.report(1, "p2", G1),
            v3_frame(2, "p2", [rec(3, G1, [S1])]),
        ]
        result = self.simulate(config, events)
        member = result["groups"][0]["members"][0]
        self.assertEqual(
            member,
            {
                "name": "p2", "expires": 52, "mode": "include",
                "sources": ["10.0.0.1"],
            },
        )

    def test_v2_leave_still_removes_v3_member(self):
        config = make_config(router_ports=("p1",))
        events = [
            v3_frame(1, "p2", [rec(1, G1, [S1])]),
            self.leave(2, "p2", G1),
            data_frame(3, "p3", G1, S1),
        ]
        result = self.simulate(config, events)
        self.assertEqual(result["results"][1]["action"], "igmp_leave")
        self.assertEqual(result["groups"], [])
        self.assertEqual(result["results"][2]["action"], "flood")


class IgmpV3RecordReplayTest(IgmpSnoopCase):
    def test_record_replay_byte_identical(self):
        config = make_config(router_ports=("p1",))
        events = [
            v3_frame(
                1, "p2",
                [rec(1, G1, [S1, S9]), rec(2, G2, [])],
            ),
            data_frame(2, "p3", G1, S1),
            v3_frame(3, "p2", [rec(5, G1, [S20])]),
        ]
        self.write(config, events)
        code, direct, err = self.run_cmd(
            "igmp-snoop-decode", self.cfg, self.evt
        )
        self.assertEqual(code, 0, err)
        proc = subprocess.run(
            [sys.executable,
             os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "switch.py"),
             "record", self.cfg, self.evt, self.log],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, direct)
        code, out, err = self.run_cmd("replay", self.log)
        self.assertEqual((code, out, err), (0, direct, b""))
        with open(self.log, "rb") as handle:
            doc = json.loads(handle.read().decode())
        self.assertEqual(doc["config"], config)
        self.assertEqual(
            [r["output"]["action"] for r in doc["records"]],
            ["igmpv3_report", "multicast", "igmpv3_report"],
        )


class IgmpV3WorkTest(IgmpSnoopCase):
    def _total(self, config, raw_events, validated, v3_units):
        bridges = ["b1"]
        links = []
        ports = config["ports"]
        base = switch._forward_stp_work_total(bridges, links, ports, validated)
        N = len(validated)
        P = len(ports)
        return base + N * (N + P + 1) + v3_units

    def test_v3_work_boundary(self):
        # 两帧：一条 v3 报告（2 记录、共 3 源 -> 5 单位）+ 一条数据帧
        config = make_config(router_ports=("p1",))
        events = [
            v3_frame(1, "p2", [rec(1, G1, [S1, S2]), rec(1, G2, [S9])]),
            data_frame(2, "p3", G1, S1),
        ]
        validated = [
            ("frame", e["t"], e["port"], bytes.fromhex(e["data"]))
            for e in events
        ]
        total = self._total(config, events, validated, 5)
        # 手工核对：初始收敛 1；帧 (0+4+1)+(1+4+1)=5+6=11；
        # N*(N+P+1)=2*7=14；v3 记录与源共 5 -> 31
        self.assertEqual(total, 31)
        code, ok, err = self._boundary(config, events, total)
        self.assertEqual(code, 0, err)
        code, out, err = self._boundary(config, events, total - 1)
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"igmp_work_limit"}\n')

    def _boundary(self, config, events, limit):
        self.write(config, events)
        head = ("1048576", "16777216", "100000", "16777216")
        return self.run_cmd(
            "igmp-snoop-decode", self.cfg, self.evt, *head, str(limit)
        )


if __name__ == "__main__":
    unittest.main()
