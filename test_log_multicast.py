#!/usr/bin/env python3
"""log-multicast 子命令回归：按日志游标查询 igmp/mld-snoop-decode LOG 在前
offset 条记录重放后的组播控制面状态。

仅用标准库；端到端驱动 `python switch.py log-multicast LOG CURSOR
[MAX_WORK]`。成功产物键序固定为
schema,source_sha256,offset,family,groups,routers,sha256，末项为前六键
紧凑 UTF-8 加 LF 的 sha256；family 取 ipv4（igmp-snoop-decode 日志）或
ipv6（mld-snoop-decode 日志）；groups 与对应 snooping 入口处理同一前缀
后的最终 groups 逐字节一致，routers 只列未过期动态路由端口，未配置
router_age 时恒为空数组。CURSOR 沿用 log-page（* 或
<sha256>:<offset>），但 * 表示 records 长度（重演全部）；其他日志模式、
坏摘要/记录/游标均 invalid_input/4；前缀重放按所选 snooping 模式同一
计费口径，等于上限合法，首次超过 stderr 仅
{"error":"multicast_work_limit"} 加 LF 并退出 5；查询绝不写回 LOG。
"""

import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SWITCH = os.path.join(HERE, "switch.py")
sys.path.insert(0, HERE)

import switch as switch_mod  # noqa: E402
from test_igmp_snoop_decode import (  # noqa: E402
    G1,
    G2,
    make_config,
    make_port,
    link_event,
    group_mac,
    ipv4_igmp,
    raw_frame,
)
from test_snoop_router_age import (  # noqa: E402
    MLDV1_REPORT_GROUP,
    mld_frame,
    mld_message,
)

MULTICAST_KEYS = [
    "schema", "source_sha256", "offset", "family", "groups", "routers",
    "sha256",
]


# ---------------------------------------------------------------------
# 事件构造
# ---------------------------------------------------------------------

def igmp_report(t, port, group, vlan=1):
    return raw_frame(
        t, port, group_mac(group), "02:00:00:00:00:01",
        ipv4_igmp(0x16, group), vlan=vlan,
    )


def igmp_leave(t, port, group, vlan=1):
    return raw_frame(
        t, port, group_mac(group), "02:00:00:00:00:01",
        ipv4_igmp(0x17, group), vlan=vlan,
    )


def igmp_query(t, port, group=(224, 0, 0, 1), vlan=1):
    return raw_frame(
        t, port, group_mac(group), "02:00:00:00:00:fe",
        ipv4_igmp(0x11, group), vlan=vlan,
    )


def igmp_v3_report(t, port, records, vlan=1):
    """records 为 (rtype, group_tuple, [src_tuple, ...]) 的 IGMPv3 报文帧。"""
    from test_igmp_snoop_decode import ipv4_igmp_v3
    return raw_frame(
        t, port, group_mac((224, 0, 0, 22)), "02:00:00:00:00:01",
        ipv4_igmp_v3(records), vlan=vlan,
    )


def mld_report(t, port="p3", vlan=1):
    return mld_frame(
        t, port, mld_message(131, MLDV1_REPORT_GROUP), vlan=vlan
    )


def mld_query(t, port="p2", vlan=1):
    return mld_frame(t, port, mld_message(130, b"\x00" * 16), vlan=vlan)


def enhanced_config(router_ports=("p1",), router_age=30, **kwargs):
    config = make_config(router_ports=router_ports, **kwargs)
    config["igmp"]["router_age"] = router_age
    return config


def mld_config(router_ports=("p1",), router_age=30):
    return {
        "bridges": ["b1"],
        "links": [],
        "delay": 2,
        "bridge": "b1",
        "ports": [
            make_port("p1", allowed=[1, 2]),
            make_port("p2", allowed=[1, 2]),
            make_port("p3", allowed=[1, 2]),
            make_port("p4", mode="hybrid", allowed=[1, 2], untagged=[1]),
        ],
        "age": 100,
        "max_frame": 1518,
        "mld": {
            "membership_age": 50,
            "router_ports": list(router_ports),
            "router_age": router_age,
        },
    }


# ---------------------------------------------------------------------
# record / 调用辅助
# ---------------------------------------------------------------------

def record(cfg, events, *limits):
    """record CONFIG EVENTS → LOG 字节（断言成功）。"""
    with tempfile.TemporaryDirectory() as tmp:
        cp = os.path.join(tmp, "config.json")
        ep = os.path.join(tmp, "events.json")
        lp = os.path.join(tmp, "out.log")
        with open(cp, "w", encoding="utf-8") as handle:
            json.dump(cfg, handle)
        with open(ep, "w", encoding="utf-8") as handle:
            json.dump(events, handle)
        proc = subprocess.run(
            [sys.executable, SWITCH, "record", cp, ep, lp, *limits],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        assert proc.returncode == 0, proc.stderr.decode()
        with open(lp, "rb") as handle:
            return handle.read()


def run_multicast(log_bytes, cursor, *extra):
    with tempfile.TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "in.log")
        with open(log_path, "wb") as handle:
            handle.write(log_bytes)
        proc = subprocess.run(
            [sys.executable, SWITCH, "log-multicast", log_path, cursor, *extra],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        with open(log_path, "rb") as handle:
            after = handle.read()
    return proc.returncode, proc.stdout, proc.stderr, after


def run_decode(cfg, events):
    """直接驱动 igmp-snoop-decode 入口处理给定（前缀）事件。"""
    with tempfile.TemporaryDirectory() as tmp:
        cp = os.path.join(tmp, "config.json")
        ep = os.path.join(tmp, "events.json")
        with open(cp, "w", encoding="utf-8") as handle:
            json.dump(cfg, handle)
        with open(ep, "w", encoding="utf-8") as handle:
            json.dump(events, handle)
        proc = subprocess.run(
            [sys.executable, SWITCH, "igmp-snoop-decode", cp, ep],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        assert proc.returncode == 0, proc.stderr.decode()
        return json.loads(proc.stdout.decode("utf-8"))


def digest_of(doc):
    prefix = {key: doc[key] for key in MULTICAST_KEYS[:-1]}
    raw = (
        json.dumps(prefix, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def igmp_work_value(cfg, events):
    """按 igmp-snoop-decode 入口公式计算给定事件序的工作量总值。"""
    (
        bridges, links, _delay, _bridge, ports, _age, _max_frame,
        _membership_age, _router_ports, _router_age,
    ) = switch_mod.validate_igmp_snoop_config(cfg)
    checked = switch_mod.validate_stp_decode_events(
        events, ports, {link["id"] for link in links}
    )
    N, P = len(checked), len(ports)
    return (
        switch_mod._forward_stp_work_total(bridges, links, ports, checked)
        + N * (N + P + 1)
        + switch_mod._igmp_v3_work_units(checked)
    )


class IgmpHappyPathTests(unittest.TestCase):
    def setUp(self):
        self.config = enhanced_config()

    def test_star_full_prefix_key_order_family_digest_and_routers(self):
        events = [igmp_query(1, "p2"), igmp_report(2, "p3", G1)]
        log_bytes = record(self.config, events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_multicast(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertTrue(out.endswith(b"\n"))
        self.assertEqual(after, log_bytes)  # 查询不写回
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(list(doc), MULTICAST_KEYS)
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["source_sha256"], source)
        self.assertEqual(doc["offset"], 2)
        self.assertEqual(doc["family"], "ipv4")
        self.assertEqual(
            doc["groups"],
            [
                {
                    "vlan": 1,
                    "group": "224.1.2.3",
                    "members": [{"name": "p3", "expires": 52}],
                }
            ],
        )
        self.assertEqual(
            doc["routers"],
            [{"vlan": 1, "name": "p2", "expires": 31}],
        )
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_star_equals_sha_cursor_at_record_count_byte_for_byte(self):
        events = [igmp_query(1, "p2"), igmp_report(2, "p3", G1)]
        log_bytes = record(self.config, events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        _, star_out, _, _ = run_multicast(log_bytes, "*")
        code, cur_out, err, _ = run_multicast(log_bytes, source + ":2")
        self.assertEqual(code, 0, err)
        self.assertEqual(cur_out, star_out)

    def test_offset_zero_is_empty_state(self):
        events = [igmp_query(1, "p2"), igmp_report(2, "p3", G1)]
        log_bytes = record(self.config, events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_multicast(log_bytes, source + ":0")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["offset"], 0)
        self.assertEqual(doc["groups"], [])
        self.assertEqual(doc["routers"], [])
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_groups_match_entry_processing_same_prefix(self):
        # 含链路项与多个组：各 offset 的 groups 必须与 igmp-snoop-decode
        # 入口仅处理同前缀事件后的最终 groups 完全一致
        ports = [
            make_port("p1", allowed=[1, 2]),
            make_port("p2", allowed=[1, 2]),
            make_port("p3", allowed=[1, 2]),
            make_port("p4", mode="hybrid", allowed=[1, 2], untagged=[1]),
        ]
        config = enhanced_config(ports=ports)
        events = [
            igmp_report(1, "p3", G1, vlan=1),
            igmp_report(2, "p4", G2, vlan=2),
            igmp_leave(3, "p3", G1, vlan=1),
            igmp_report(4, "p2", G1, vlan=1),
        ]
        log_bytes = record(config, events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for offset in range(len(events) + 1):
            code, out, err, _ = run_multicast(
                log_bytes, source + ":%d" % offset
            )
            self.assertEqual(code, 0, (offset, err))
            doc = json.loads(out.decode("utf-8"))
            expected = run_decode(config, events[:offset])
            self.assertEqual(
                doc["groups"], expected["groups"], offset
            )
            self.assertEqual(doc["offset"], offset)
            self.assertEqual(doc["sha256"], digest_of(doc))

    def test_groups_sorted_by_vlan_then_group_numeric(self):
        events = [
            igmp_report(1, "p3", G1, vlan=2),
            igmp_report(2, "p3", G2, vlan=1),
            igmp_report(3, "p3", G2, vlan=2),
        ]
        log_bytes = record(self.config, events)
        _, out, err, _ = run_multicast(log_bytes, "*")
        self.assertEqual(err, b"")
        groups = json.loads(out.decode("utf-8"))["groups"]
        self.assertEqual(
            [(g["vlan"], g["group"]) for g in groups],
            [(1, "224.1.2.2"), (2, "224.1.2.2"), (2, "224.1.2.3")],
        )

    def test_v3_filter_mode_and_sources_carried_through(self):
        # CHANGE_TO_EXCLUDE 两个源：成员键序 name/expires/mode/sources，
        # 源地址按 IPv4 数值升序
        events = [
            igmp_v3_report(
                1, "p3",
                [(4, G1, [(10, 0, 0, 9), (10, 0, 0, 2)])],
            ),
        ]
        log_bytes = record(self.config, events)
        _, out, err, _ = run_multicast(log_bytes, "*")
        self.assertEqual(err, b"")
        doc = json.loads(out.decode("utf-8"))
        member = doc["groups"][0]["members"][0]
        self.assertEqual(
            member,
            {
                "name": "p3",
                "expires": 51,
                "mode": "exclude",
                "sources": ["10.0.0.2", "10.0.0.9"],
            },
        )
        self.assertEqual(
            list(member), ["name", "expires", "mode", "sources"]
        )

    def test_member_expiry_boundary_uses_absolute_event_time(self):
        # membership_age=50：t=1 建成员 expires=51；t=50 仍在，t=51
        # 事件前清除
        events = [igmp_report(1, "p3", G1), igmp_report(50, "p3", G2)]
        log_bytes = record(self.config, events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        _, out, _, _ = run_multicast(log_bytes, source + ":2")
        groups = {g["group"] for g in json.loads(out.decode("utf-8"))["groups"]}
        self.assertEqual(groups, {"224.1.2.3", "224.1.2.2"})
        events = [igmp_report(1, "p3", G1), igmp_report(51, "p3", G2)]
        log_bytes = record(self.config, events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        _, out, _, _ = run_multicast(log_bytes, source + ":2")
        groups = {g["group"] for g in json.loads(out.decode("utf-8"))["groups"]}
        self.assertEqual(groups, {"224.1.2.2"})

    def test_compat_config_without_router_age_has_empty_routers(self):
        config = make_config(router_ports=("p1",))
        events = [igmp_query(1, "p2"), igmp_report(2, "p3", G1)]
        log_bytes = record(config, events)
        code, out, err, after = run_multicast(log_bytes, "*")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["routers"], [])
        self.assertEqual(after, log_bytes)

    def test_dynamic_router_expiry_purge_before_event(self):
        # router_age=30：t=1 登记 expires=31；t=31 再收 Report 前动态项
        # 已删除，routers 为空（无静态端口场景 Report 走泛洪）
        config = enhanced_config(router_ports=())
        events = [igmp_query(1, "p2"), igmp_report(31, "p3", G1)]
        log_bytes = record(config, events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        _, out, _, _ = run_multicast(log_bytes, source + ":1")
        self.assertEqual(
            json.loads(out.decode("utf-8"))["routers"],
            [{"vlan": 1, "name": "p2", "expires": 31}],
        )
        _, out, _, _ = run_multicast(log_bytes, "*")
        self.assertEqual(json.loads(out.decode("utf-8"))["routers"], [])

    def test_empty_log_star_and_zero(self):
        log_bytes = record(self.config, [])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for cursor in ("*", source + ":0"):
            code, out, err, _ = run_multicast(log_bytes, cursor)
            self.assertEqual(code, 0, err)
            doc = json.loads(out.decode("utf-8"))
            self.assertEqual(doc["offset"], 0)
            self.assertEqual(doc["groups"], [])
            self.assertEqual(doc["routers"], [])

    def test_repeated_queries_are_byte_identical(self):
        events = [igmp_query(1, "p2"), igmp_report(2, "p3", G1)]
        log_bytes = record(self.config, events)
        outputs = {run_multicast(log_bytes, "*")[1] for _ in range(3)}
        self.assertEqual(len(outputs), 1)


class MldHappyPathTests(unittest.TestCase):
    def test_ipv6_family_groups_and_routers(self):
        config = mld_config()
        events = [mld_query(1, "p2"), mld_report(2, "p3")]
        log_bytes = record(config, events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_multicast(log_bytes, "*")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(list(doc), MULTICAST_KEYS)
        self.assertEqual(doc["family"], "ipv6")
        self.assertEqual(doc["offset"], 2)
        self.assertEqual(doc["source_sha256"], source)
        self.assertEqual(
            doc["groups"],
            [
                {
                    "vlan": 1,
                    "group": "ff02::5",
                    "members": [{"name": "p3", "expires": 52}],
                }
            ],
        )
        self.assertEqual(
            doc["routers"],
            [{"vlan": 1, "name": "p2", "expires": 31}],
        )
        self.assertEqual(doc["sha256"], digest_of(doc))
        self.assertEqual(after, log_bytes)

    def test_ipv6_offset_zero(self):
        config = mld_config()
        events = [mld_query(1), mld_report(2)]
        log_bytes = record(config, events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_multicast(log_bytes, source + ":0")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["family"], "ipv6")
        self.assertEqual(doc["groups"], [])
        self.assertEqual(doc["routers"], [])


class UsageTests(unittest.TestCase):
    def setUp(self):
        self.log_bytes = record(enhanced_config(), [igmp_report(1, "p3", G1)])
        self.source = json.loads(self.log_bytes.decode("utf-8"))["sha256"]

    def test_arg_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "in.log")
            with open(path, "wb") as handle:
                handle.write(self.log_bytes)
            for tokens in ([], [path], [path, "*", "1", "2"]):
                proc = subprocess.run(
                    [sys.executable, SWITCH, "log-multicast", *tokens],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                self.assertEqual(proc.returncode, 2, tokens)
                self.assertEqual(proc.stdout, b"")

    def test_bad_cursor_tokens(self):
        for cursor in (
            "",
            "x",
            "* ",
            self.source[:63],
            self.source + "x:0",
            "G" * 64 + ":0",
            self.source.upper() + ":0",
            self.source + ":",
            self.source + ":01",
            self.source + ":-0",
            self.source + ":+1",
            self.source + ":1.0",
            self.source + ":0:0",
        ):
            code, out, _, _ = run_multicast(self.log_bytes, cursor)
            self.assertEqual(code, 2, cursor)
            self.assertEqual(out, b"")

    def test_bad_max_work_tokens(self):
        for token in ("", "0", "-1", "01", "1.0", "1 ", "x", "1e3"):
            code, out, _, _ = run_multicast(
                self.log_bytes, self.source + ":0", token
            )
            self.assertEqual(code, 2, token)
            self.assertEqual(out, b"")
            code, _, _, _ = run_multicast(self.log_bytes, "*", token)
            self.assertEqual(code, 2, token)

    def test_arbitrary_length_decimal_max_work_accepted(self):
        code, _, err, _ = run_multicast(self.log_bytes, "*", "9" * 60)
        self.assertEqual(code, 0, err)


class ErrorPrecedenceTests(unittest.TestCase):
    def setUp(self):
        self.config = enhanced_config()
        self.events = [igmp_query(1, "p2"), igmp_report(2, "p3", G1)]
        self.log_bytes = record(self.config, self.events)
        self.source = json.loads(self.log_bytes.decode("utf-8"))["sha256"]

    def test_file_not_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "nope.log")
            proc = subprocess.run(
                [sys.executable, SWITCH, "log-multicast", missing, "*"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(proc.stderr, b'{"error":"file_not_found"}\n')
        self.assertEqual(proc.stdout, b"")

    def test_log_limit_before_invalid_input(self):
        oversized = b"{" + b" " * (16 * 1024 * 1024)
        code, out, err, after = run_multicast(oversized, "*")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"log_limit"}\n')
        self.assertEqual(out, b"")
        self.assertEqual(after, oversized)

    def test_bad_json_invalid_input(self):
        code, out, err, _ = run_multicast(b"{not json\n", "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_bad_encoding_invalid_input(self):
        code, out, err, _ = run_multicast(b'{"a":\xff}\n', "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_bad_internal_sha_invalid_input(self):
        doc = json.loads(self.log_bytes.decode("utf-8"))
        doc["sha256"] = "0" * 64
        bad = (json.dumps(doc, separators=(",", ":")) + "\n").encode()
        code, out, err, _ = run_multicast(bad, "*")
        self.assertEqual(code, 4)
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertEqual(out, b"")

    def test_cursor_sha_mismatch_invalid_input(self):
        code, out, err, _ = run_multicast(
            self.log_bytes, "0" * 64 + ":0"
        )
        self.assertEqual(code, 4)
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertEqual(out, b"")

    def test_cursor_offset_beyond_record_count_invalid_input(self):
        code, out, err, _ = run_multicast(
            self.log_bytes, self.source + ":3"
        )
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_fdb_mode_rejected(self):
        fdb_cfg = {"ports": ["p1", "p2"], "age": 100}
        fdb_events = [{"t": 0, "port": "p1", "mac": "00:00:00:00:00:01",
                       "vlan": 1}]
        log_bytes = record(fdb_cfg, fdb_events)
        code, out, err, after = run_multicast(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_stp_decode_mode_rejected(self):
        # 七键 stp-check 配置 + t/port/data 原始帧为 stp-decode 模式，
        # 静态合法 LOG 但非 snooping 模式，须拒绝
        stp_cfg = {
            "bridges": ["b1"], "links": [], "delay": 2, "bridge": "b1",
            "ports": [make_port("p1"), make_port("p2")],
            "age": 100, "max_frame": 1518,
        }
        stp_events = [raw_frame(0, "p1", "ff:ff:ff:ff:ff:ff",
                                "02:00:00:00:00:01", b"\x00" * 46)]
        log_bytes = record(stp_cfg, stp_events)
        code, out, err, after = run_multicast(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_tampered_record_output_fails_replay_verification(self):
        doc = json.loads(self.log_bytes.decode("utf-8"))
        # 篡改首帧结果动作并重算内部摘要：静态自洽但重放不符
        doc["records"][0]["output"]["action"] = "flood"
        prefix = {
            "schema": doc["schema"],
            "config": doc["config"],
            "records": doc["records"],
        }
        doc["sha256"] = hashlib.sha256(
            (json.dumps(prefix, separators=(",", ":")) + "\n").encode("utf-8")
        ).hexdigest()
        bad = (json.dumps(doc, separators=(",", ":")) + "\n").encode()
        code, out, err, _ = run_multicast(bad, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_invalid_input_before_work_limit(self):
        doc = json.loads(self.log_bytes.decode("utf-8"))
        doc["sha256"] = "0" * 64
        bad = (json.dumps(doc, separators=(",", ":")) + "\n").encode()
        code, out, err, _ = run_multicast(bad, "*", "1")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertNotIn(b"multicast_work_limit", err)
        self.assertEqual(out, b"")


class WorkLimitTests(unittest.TestCase):
    def test_equal_limit_legal_first_over_fails(self):
        config = enhanced_config()
        events = [igmp_report(i + 1, "p3", G1) for i in range(3)]
        log_bytes = record(config, events)
        total = igmp_work_value(config, events)
        code, _, err, _ = run_multicast(log_bytes, "*", str(total))
        self.assertEqual(code, 0, err)
        code, out, err, after = run_multicast(
            log_bytes, "*", str(total - 1)
        )
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"multicast_work_limit"}\n')
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_work_charged_only_for_prefix_events(self):
        config = enhanced_config()
        events = [igmp_report(i + 1, "p%d" % ((i % 3) + 1), G1)
                  for i in range(4)]
        log_bytes = record(config, events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for offset in (1, 2, 3, 4):
            prefix_work = igmp_work_value(config, events[:offset])
            code, _, err, _ = run_multicast(
                log_bytes, source + ":%d" % offset, str(prefix_work)
            )
            self.assertEqual(code, 0, (offset, err))
            code, _, err, _ = run_multicast(
                log_bytes, source + ":%d" % offset, str(prefix_work - 1)
            )
            self.assertEqual(code, 5, offset)
            self.assertEqual(
                err, b'{"error":"multicast_work_limit"}\n', offset
            )

    def test_offset_zero_never_hits_work_limit(self):
        config = enhanced_config()
        events = [igmp_report(1, "p3", G1)]
        log_bytes = record(config, events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, _, err, _ = run_multicast(log_bytes, source + ":0", "1")
        self.assertEqual(code, 0, err)

    def test_link_events_are_charged(self):
        ports = [
            make_port("p1"), make_port("p2"), make_port("p3"),
            make_port("p4"),
        ]
        links = [
            {
                "id": "l1",
                "x": ["b1", "p2"],
                "y": ["b2", "p1"],
                "cost": 1,
                "up": True,
            },
        ]
        config = enhanced_config(
            ports=ports, links=links, bridges=("b1", "b2")
        )
        events = [link_event(1, "l1", False), igmp_report(2, "p3", G1)]
        log_bytes = record(config, events)
        total = igmp_work_value(config, events)
        code, _, err, _ = run_multicast(log_bytes, "*", str(total))
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_multicast(log_bytes, "*", str(total - 1))
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"multicast_work_limit"}\n')

    def test_default_max_work_is_ten_million(self):
        config = enhanced_config()
        code, _, err, _ = run_multicast(record(config, []), "*")
        self.assertEqual(code, 0, err)


class OutputLimitTests(unittest.TestCase):
    """输出上限固定 16777216 字节：进程内补丁 DEFAULT_MAX_OUTPUT_BYTES
    驱动 main，验证判定顺序与等大合法。"""

    def run_inproc(self, log_path, cursor, output_limit):
        old = switch_mod.DEFAULT_MAX_OUTPUT_BYTES
        switch_mod.DEFAULT_MAX_OUTPUT_BYTES = output_limit
        out_buffer, err_buffer = io.BytesIO(), io.BytesIO()
        out_text = io.TextIOWrapper(out_buffer)
        err_text = io.TextIOWrapper(err_buffer)
        try:
            with contextlib.redirect_stdout(
                out_text
            ), contextlib.redirect_stderr(err_text):
                code = switch_mod.main(
                    ["log-multicast", log_path, cursor]
                )
        finally:
            switch_mod.DEFAULT_MAX_OUTPUT_BYTES = old
        out_text.flush()
        err_text.flush()
        # detach 防止 TextIOWrapper 关闭底层 BytesIO
        out_text.detach()
        err_text.detach()
        return code, out_buffer.getvalue(), err_buffer.getvalue()

    def test_output_limit_exceeded(self):
        config = enhanced_config()
        events = [igmp_query(1, "p2"), igmp_report(2, "p3", G1)]
        with tempfile.TemporaryDirectory() as tmp:
            cp = os.path.join(tmp, "config.json")
            ep = os.path.join(tmp, "events.json")
            lp = os.path.join(tmp, "out.log")
            with open(cp, "w") as handle:
                json.dump(config, handle)
            with open(ep, "w") as handle:
                json.dump(events, handle)
            subprocess.run(
                [sys.executable, SWITCH, "record", cp, ep, lp],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            code, out, err = self.run_inproc(lp, "*", 1)
            self.assertEqual(code, 5)
            self.assertEqual(out, b"")
            self.assertEqual(err, b'{"error":"output_limit"}\n')

    def test_output_equal_size_legal(self):
        config = enhanced_config()
        events = [igmp_report(1, "p3", G1)]
        log_bytes = record(config, events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_multicast(log_bytes, "*")
        self.assertEqual(code, 0, err)
        size = len(out)
        with tempfile.TemporaryDirectory() as tmp:
            lp = os.path.join(tmp, "out.log")
            with open(lp, "wb") as handle:
                handle.write(log_bytes)
            code, out2, err2 = self.run_inproc(lp, source + ":1", size)
            self.assertEqual(code, 0, err2)
            self.assertEqual(out2, out)


if __name__ == "__main__":
    unittest.main()
