#!/usr/bin/env python3
"""log-multicast 子命令回归：按游标重演 igmp/mld-snoop-decode LOG 的前
offset 条记录并查询当时的组播控制面状态（groups、动态路由端口）。

仅用标准库；端到端驱动 `python switch.py log-multicast LOG CURSOR
[MAX_WORK]`。成功产物键序固定为
schema,source_sha256,offset,family,groups,routers,sha256，末项为前六键
紧凑 UTF-8 加 LF 的 sha256；CURSOR 沿用 log-page（* 或
<sha256>:<offset>），* 表示全部记录；family 为 ipv4/ipv6；groups 与
对应 snooping 入口处理同一前缀后的最终 groups 一致；routers 只列当前
未过期动态路由端口，兼容模式恒为空数组。LOG 须通过 record 结构、内部
摘要与全部记录重放核对且仅接受两种 snooping 模式，否则
invalid_input/4；前缀重放沿用所选模式计费口径，等于上限合法，首次超过
stderr 仅 {"error":"multicast_work_limit"} 加 LF 并退出 5；查询不写回
LOG。
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SWITCH = os.path.join(HERE, "switch.py")
sys.path.insert(0, HERE)

from test_igmp_snoop_decode import (  # noqa: E402
    G1,
    G2,
    V3_MODE_IS_INCLUDE,
    make_config,
    raw_frame,
    group_mac,
    ipv4_igmp,
    ipv4_igmp_v3,
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


def write_and_record(cfg, events, name="out.log"):
    with tempfile.TemporaryDirectory() as tmp:
        cp = os.path.join(tmp, "config.json")
        ep = os.path.join(tmp, "events.json")
        lp = os.path.join(tmp, name)
        with open(cp, "w", encoding="utf-8") as handle:
            json.dump(cfg, handle)
        with open(ep, "w", encoding="utf-8") as handle:
            json.dump(events, handle)
        proc = subprocess.run(
            [sys.executable, SWITCH, "record", cp, ep, lp],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        assert proc.returncode == 0, proc.stderr.decode()
        with open(lp, "rb") as handle:
            log_bytes = handle.read()
    return log_bytes


def run_multicast(log_bytes, cursor, *extra):
    with tempfile.TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "in.log")
        with open(log_path, "wb") as handle:
            handle.write(log_bytes)
        proc = subprocess.run(
            [sys.executable, SWITCH, "log-multicast", log_path, cursor,
             *extra],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        with open(log_path, "rb") as handle:
            after = handle.read()
    return proc.returncode, proc.stdout, proc.stderr, after


def digest_of(doc):
    prefix = {key: doc[key] for key in MULTICAST_KEYS[:6]}
    raw = (
        json.dumps(prefix, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def igmp_report(t, port, group, vlan=1, **kwargs):
    return raw_frame(
        t, port, group_mac(group), "02:00:00:00:00:01",
        ipv4_igmp(0x16, group, **kwargs), vlan=vlan,
    )


def igmp_query(t, port, group=(224, 0, 0, 1), vlan=1, **kwargs):
    return raw_frame(
        t, port, group_mac(group), "02:00:00:00:00:fe",
        ipv4_igmp(0x11, group, **kwargs), vlan=vlan,
    )


def igmp_v3_report(t, port, records, vlan=1):
    return raw_frame(
        t, port, "01:00:5e:00:00:16", "02:00:00:00:00:02",
        ipv4_igmp_v3(records), vlan=vlan,
    )


def enhanced_config(**kwargs):
    config = make_config(**kwargs)
    config["igmp"]["router_age"] = kwargs.get("router_age", 30)
    return config


def mld_config(router_ports=("p1",), router_age=30):
    config = make_config(router_ports=router_ports)
    del config["igmp"]
    config["mld"] = {
        "membership_age": 50,
        "router_ports": list(router_ports),
        "router_age": router_age,
    }
    return config


def mld_v1_report(t, port, group=MLDV1_REPORT_GROUP, vlan=1):
    return mld_frame(t, port, mld_message(131, group), vlan=vlan)


def mld_v1_query(t, port, group=b"\x00" * 16, vlan=1):
    return mld_frame(t, port, mld_message(130, group), vlan=vlan)


def snoop_decode(config, events):
    """直接驱动对应 snooping 入口，返回结果 dict。"""
    mode = "mld-snoop-decode" if "mld" in config else "igmp-snoop-decode"
    with tempfile.TemporaryDirectory() as tmp:
        cp = os.path.join(tmp, "config.json")
        ep = os.path.join(tmp, "events.json")
        with open(cp, "w", encoding="utf-8") as handle:
            json.dump(config, handle)
        with open(ep, "w", encoding="utf-8") as handle:
            json.dump(events, handle)
        proc = subprocess.run(
            [sys.executable, SWITCH, mode, cp, ep],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    assert proc.returncode == 0, proc.stderr.decode()
    return json.loads(proc.stdout.decode("utf-8"))


class HappyPathTests(unittest.TestCase):
    def test_star_full_prefix_igmp_ipv4_with_groups_and_routers(self):
        config = enhanced_config()
        events = [
            igmp_query(1, "p2"),
            igmp_report(2, "p3", G1),
            igmp_report(3, "p4", G2),
        ]
        log_bytes = write_and_record(config, events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_multicast(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertTrue(out.endswith(b"\n"))
        self.assertEqual(after, log_bytes)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(list(doc), MULTICAST_KEYS)
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["source_sha256"], source)
        self.assertEqual(doc["offset"], 3)
        self.assertEqual(doc["family"], "ipv4")
        direct = snoop_decode(config, events)
        self.assertEqual(doc["groups"], direct["groups"])
        self.assertEqual(doc["routers"], direct["routers"])
        self.assertEqual(
            doc["routers"],
            [{"vlan": 1, "name": "p2", "expires": 31}],
        )
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_star_equals_sha_cursor_at_record_count(self):
        config = enhanced_config()
        events = [igmp_report(1, "p2", G1), igmp_report(2, "p3", G2)]
        log_bytes = write_and_record(config, events)
        _, star_out, _, _ = run_multicast(log_bytes, "*")
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, cur_out, err, _ = run_multicast(log_bytes, source + ":2")
        self.assertEqual(code, 0, err)
        self.assertEqual(cur_out, star_out)

    def test_offset_zero_is_empty_state(self):
        config = enhanced_config()
        events = [igmp_query(1, "p2"), igmp_report(2, "p3", G1)]
        log_bytes = write_and_record(config, events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_multicast(log_bytes, source + ":0")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["offset"], 0)
        self.assertEqual(doc["groups"], [])
        self.assertEqual(doc["routers"], [])
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_partial_prefix_matches_decode_entry_on_same_prefix(self):
        config = enhanced_config()
        events = [
            igmp_query(1, "p2"),
            igmp_report(2, "p3", G1),
            igmp_report(60, "p4", G2),  # t=60：动态路由项 31 已过期
        ]
        log_bytes = write_and_record(config, events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for offset in (1, 2, 3):
            code, out, err, _ = run_multicast(
                log_bytes, "%s:%d" % (source, offset)
            )
            self.assertEqual(code, 0, (offset, err))
            doc = json.loads(out.decode("utf-8"))
            direct = snoop_decode(config, events[:offset])
            self.assertEqual(doc["groups"], direct["groups"], offset)
            self.assertEqual(doc["routers"], direct["routers"], offset)
            self.assertEqual(doc["sha256"], digest_of(doc), offset)
        # offset=2 动态路由仍有效；offset=3 时 expires=31<=60 已过期
        _, out2, _, _ = run_multicast(log_bytes, source + ":2")
        _, out3, _, _ = run_multicast(log_bytes, source + ":3")
        self.assertEqual(
            json.loads(out2.decode())["routers"],
            [{"vlan": 1, "name": "p2", "expires": 31}],
        )
        self.assertEqual(json.loads(out3.decode())["routers"], [])

    def test_v3_member_keeps_mode_and_sources(self):
        config = enhanced_config(router_ports=())
        records = [
            (V3_MODE_IS_INCLUDE, G1, [(10, 0, 0, 1), (10, 0, 0, 2)]),
        ]
        events = [igmp_v3_report(5, "p3", records)]
        log_bytes = write_and_record(config, events)
        code, out, err, _ = run_multicast(log_bytes, "*")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        direct = snoop_decode(config, events)
        self.assertEqual(doc["groups"], direct["groups"])
        member = doc["groups"][0]["members"][0]
        self.assertEqual(
            member,
            {
                "name": "p3",
                "expires": 55,
                "mode": "include",
                "sources": ["10.0.0.1", "10.0.0.2"],
            },
        )
        self.assertEqual(
            list(member), ["name", "expires", "mode", "sources"]
        )

    def test_compat_mode_routers_always_empty(self):
        config = make_config()
        self.assertNotIn("router_age", config["igmp"])
        events = [igmp_query(1, "p2"), igmp_report(2, "p3", G1)]
        log_bytes = write_and_record(config, events)
        code, out, err, _ = run_multicast(log_bytes, "*")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["family"], "ipv4")
        self.assertEqual(doc["routers"], [])
        direct = snoop_decode(config, events)
        self.assertEqual(doc["groups"], direct["groups"])

    def test_mld_family_ipv6(self):
        config = mld_config()
        events = [mld_v1_query(1, "p2"), mld_v1_report(2, "p3")]
        log_bytes = write_and_record(config, events)
        code, out, err, after = run_multicast(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(after, log_bytes)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["family"], "ipv6")
        self.assertEqual(doc["offset"], 2)
        direct = snoop_decode(config, events)
        self.assertEqual(doc["groups"], direct["groups"])
        self.assertEqual(doc["routers"], direct["routers"])
        self.assertEqual(
            doc["groups"][0]["group"], "ff02::5"
        )
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_empty_log_star_and_zero(self):
        log_bytes = write_and_record(enhanced_config(), [])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for cursor in ("*", source + ":0"):
            code, out, err, _ = run_multicast(log_bytes, cursor)
            self.assertEqual(code, 0, err)
            doc = json.loads(out.decode("utf-8"))
            self.assertEqual(doc["offset"], 0)
            self.assertEqual(doc["groups"], [])
            self.assertEqual(doc["routers"], [])


class UsageTests(unittest.TestCase):
    def _log(self):
        return write_and_record(enhanced_config(), [igmp_report(1, "p2", G1)])

    def test_arg_counts(self):
        log_bytes = self._log()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "in.log")
            with open(path, "wb") as handle:
                handle.write(log_bytes)
            for tokens in ([], [path], [path, "*", "1", "2"]):
                proc = subprocess.run(
                    [sys.executable, SWITCH, "log-multicast", *tokens],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                self.assertEqual(proc.returncode, 2, tokens)

    def test_bad_cursor_tokens(self):
        log_bytes = self._log()
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for cursor in (
            "",
            "x",
            "* ",
            source[:63],
            source + "x:0",
            "G" * 64 + ":0",
            source.upper() + ":0",
            source + ":",
            source + ":01",
            source + ":-0",
            source + ":+1",
            source + ":1.0",
            source + ":0:0",
        ):
            code, out, err, _ = run_multicast(log_bytes, cursor)
            self.assertEqual(code, 2, cursor)
            self.assertEqual(out, b"", cursor)

    def test_bad_max_work_tokens(self):
        log_bytes = self._log()
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for token in ("", "0", "-1", "01", "1.0", "1 ", "x", "1e3"):
            code, _, _, _ = run_multicast(log_bytes, source + ":0", token)
            self.assertEqual(code, 2, token)
            code, _, _, _ = run_multicast(log_bytes, "*", token)
            self.assertEqual(code, 2, token)

    def test_arbitrary_length_decimal_max_work_accepted(self):
        log_bytes = self._log()
        code, _, err, _ = run_multicast(log_bytes, "*", "9" * 60)
        self.assertEqual(code, 0, err)


class ErrorPrecedenceTests(unittest.TestCase):
    def test_file_not_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "nope.log")
            proc = subprocess.run(
                [sys.executable, SWITCH, "log-multicast", missing, "*"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(proc.returncode, 3)
        self.assertIn(b"file_not_found", proc.stderr)
        self.assertEqual(proc.stdout, b"")

    def test_log_limit_before_invalid_input(self):
        oversized = b"{" + b" " * (16 * 1024 * 1024)
        code, out, err, after = run_multicast(oversized, "*")
        self.assertEqual(code, 5)
        self.assertIn(b"log_limit", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, oversized)

    def test_bad_internal_sha_invalid_input(self):
        log_bytes = write_and_record(
            enhanced_config(), [igmp_report(1, "p2", G1)]
        )
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_multicast(bad, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_bad_encoding_invalid_input(self):
        code, out, err, _ = run_multicast(b"\xff\xfe", "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_sha_mismatch_invalid_input(self):
        log_bytes = write_and_record(
            enhanced_config(), [igmp_report(1, "p2", G1)]
        )
        code, out, err, _ = run_multicast(log_bytes, "0" * 64 + ":0")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_cursor_offset_beyond_record_count_invalid_input(self):
        log_bytes = write_and_record(
            enhanced_config(), [igmp_report(1, "p2", G1)]
        )
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_multicast(log_bytes, source + ":2")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_non_snoop_mode_rejected(self):
        cfg = {"ports": ["p1", "p2", "p3"], "age": 100}
        events = [
            {"t": 0, "port": "p1", "mac": "00:00:00:00:00:01", "vlan": 1}
        ]
        log_bytes = write_and_record(cfg, events)
        code, out, err, after = run_multicast(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_tampered_records_fail_replay_verification(self):
        config = enhanced_config()
        events = [igmp_query(1, "p2"), igmp_report(2, "p3", G1)]
        log_bytes = write_and_record(config, events)
        doc = json.loads(log_bytes.decode("utf-8"))
        # 篡改首条记录的 t 并重算内部摘要：静态校验通过、重放核对失败
        doc["records"][0]["t"] = 42
        prefix = {
            "schema": doc["schema"],
            "config": doc["config"],
            "records": doc["records"],
        }
        doc["sha256"] = hashlib.sha256(
            (json.dumps(prefix, separators=(",", ":")) + "\n").encode("utf-8")
        ).hexdigest()
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_multicast(bad, "*")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")

    def test_invalid_input_before_work_limit(self):
        log_bytes = write_and_record(
            enhanced_config(), [igmp_report(1, "p2", G1)]
        )
        doc = json.loads(log_bytes.decode("utf-8"))
        doc["sha256"] = "0" * 64
        bad = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        code, out, err, _ = run_multicast(bad, "*", "1")
        self.assertEqual(code, 4)
        self.assertIn(b"invalid_input", err)
        self.assertEqual(out, b"")


class WorkLimitTests(unittest.TestCase):
    def _prefix_work(self, config, events, count):
        import switch

        if "mld" in config:
            (
                bridges, links, delay, bridge, ports, age, max_frame,
                membership_age, router_ports, router_age,
            ) = switch.validate_mld_snoop_config(config)
        else:
            (
                bridges, links, delay, bridge, ports, age, max_frame,
                membership_age, router_ports, router_age,
            ) = switch.validate_igmp_snoop_config(config)
        link_ids = {link["id"] for link in links}
        parsed = switch.validate_stp_decode_events(events, ports, link_ids)
        prefix = parsed[:count]
        work = switch._forward_stp_work_total(bridges, links, ports, prefix)
        work += count * (count + len(ports) + 1)
        return work

    def test_equal_limit_legal_first_exceed_fails_igmp(self):
        config = enhanced_config()
        events = [
            igmp_query(1, "p2"),
            igmp_report(2, "p3", G1),
            igmp_report(3, "p4", G2),
        ]
        log_bytes = write_and_record(config, events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        limit = self._prefix_work(config, events, 3)
        code, _, err, _ = run_multicast(log_bytes, "*", str(limit))
        self.assertEqual(code, 0, err)
        code, out, err, after = run_multicast(
            log_bytes, "*", str(limit - 1)
        )
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"multicast_work_limit"}\n')
        self.assertEqual(out, b"")
        self.assertEqual(after, log_bytes)

    def test_work_charged_only_for_prefix_offset_zero_free(self):
        config = enhanced_config()
        events = [
            igmp_query(1, "p2"),
            igmp_report(2, "p3", G1),
            igmp_report(3, "p4", G2),
        ]
        log_bytes = write_and_record(config, events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        limit2 = self._prefix_work(config, events, 2)
        code, _, err, _ = run_multicast(
            log_bytes, source + ":2", str(limit2)
        )
        self.assertEqual(code, 0, err)
        code, _, err, _ = run_multicast(
            log_bytes, source + ":2", str(limit2 - 1)
        )
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"multicast_work_limit"}\n')
        # offset=0：不重演任何事件，上限再小（正整数）也合法
        code, out, err, _ = run_multicast(log_bytes, source + ":0", "1")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out.decode())["groups"], [])

    def test_mld_uses_same_error_name(self):
        config = mld_config()
        events = [mld_v1_query(1, "p2"), mld_v1_report(2, "p3")]
        log_bytes = write_and_record(config, events)
        code, out, err, _ = run_multicast(log_bytes, "*", "1")
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"multicast_work_limit"}\n')
        self.assertEqual(out, b"")

    def test_default_max_work_is_ten_million(self):
        config = enhanced_config()
        events = [igmp_report(i, "p2", G1) for i in range(20)]
        log_bytes = write_and_record(config, events)
        code, _, err, _ = run_multicast(log_bytes, "*")
        self.assertEqual(code, 0, err)


if __name__ == "__main__":
    unittest.main()
