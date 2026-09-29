#!/usr/bin/env python3
"""log-acl 子命令回归：按游标重演 acl-check 模式 LOG 的前 offset 条事件
并给出 ACL 命中计数。

仅用标准库；端到端驱动 `python switch.py log-acl LOG CURSOR [MAX_WORK]`。
参数、资源、CURSOR 及错误顺序完全沿用 log-qos；成功产物键序固定为
schema,source_sha256,offset,rules,default,sha256，末项为前五键紧凑非
ASCII 转义 UTF-8 加 LF 的 sha256；CURSOR 的 * 表示 records 长度（重演
全部），否则 <sha256>:<offset>，offset=0 为零命中。rules 按配置序，项
键序 index,action,hits（零基整数、原 action、非负整数）；default 键序
action,hits，action 恒 allow。仅 good 帧通过入端 VLAN 准入后计数：首条
匹配规则 hits 加 1，未命中加 default；坏帧、VLAN 拒绝、链路和成员事件
不计，drop 或 remark 后续拒绝仍计命中。LOG 须通过摘要核对、acl-check
语义、全部记录核对与重建日志逐字节一致，其他模式 invalid_input/4；重演
前 offset 项按 acl-check 工作量公式（与 acl 同口径）计费，等于上限
合法，首次超过 stderr 仅 {"error":"acl_work_limit"} 加 LF 并退出 5。
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

# 5000 位游标 offset/MAX_WORK 须按不限长十进制处理；测试自身解析产物时
# 同样需关闭 3.11+ 的 int↔str 位数上限
if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(0)

import switch as switch_mod  # noqa: E402
from test_log_fdb import record  # noqa: E402
from test_record_acl import make_config as plain_acl_config  # noqa: E402
from test_record_acl_check import make_config  # noqa: E402

ACL_KEYS = ["schema", "source_sha256", "offset", "rules", "default",
            "sha256"]
RULE_KEYS = ["index", "action", "hits"]
DEFAULT_KEYS = ["action", "hits"]
BCAST = "ff:ff:ff:ff:ff:ff"


def rule(src=None, dst=None, vlan=None, ethertype=None, priority=None,
         action="allow", to_vlan=None):
    return {
        "src": src, "dst": dst, "vlan": vlan, "ethertype": ethertype,
        "priority": priority, "action": action, "to_vlan": to_vlan,
    }


def acl_config(acl=None, **kwargs):
    cfg = make_config(**kwargs)
    if acl is not None:
        cfg["acl"] = acl
    return cfg


def frame(t, port, src, dst=BCAST, vlan=None, ethertype=0x0800,
          priority=0, length=100, fcs=True, alignment=True):
    return {
        "t": t, "port": port, "src": src, "dst": dst, "vlan": vlan,
        "ethertype": ethertype, "priority": priority, "length": length,
        "fcs": fcs, "alignment": alignment,
    }


def link_event(t, lid, up):
    return {"t": t, "id": lid, "up": up}


def member_event(t, member, up):
    return {"t": t, "member": member, "up": up}


def acl_log(cfg, events):
    return record(cfg, events)


def digest_of(doc):
    prefix = {key: doc[key] for key in ACL_KEYS[:5]}
    raw = (
        json.dumps(prefix, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def run_acl(log_bytes, cursor, *extra):
    with tempfile.TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "in.log")
        with open(log_path, "wb") as handle:
            handle.write(log_bytes)
        proc = subprocess.run(
            [sys.executable, SWITCH, "log-acl", log_path, cursor, *extra],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        with open(log_path, "rb") as handle:
            after = handle.read()
    return proc.returncode, proc.stdout, proc.stderr, after


def simulate(cfg, events):
    """直接调用 forward_acl_check 求前 events 的 ACL 命中快照。"""
    cfg = json.loads(json.dumps(cfg))  # 防 forward 改写链路状态
    (
        bridges, links, delay, bridge, ports, age, storm, lags, mirror,
        acl, max_frame,
    ) = switch_mod.validate_acl_check_config(cfg)
    link_ids = {link["id"] for link in links}
    check_events = switch_mod.validate_acl_check_events(
        events, ports, link_ids, lags
    )
    state = {}
    switch_mod.forward_acl_check(
        bridges, links, delay, bridge, ports, age, storm, lags, mirror,
        acl, max_frame, check_events, state_out=state,
    )
    return state["rules"], state["default"]


# 三条规则：src=...:01 -> drop；ethertype=0x0800 -> remark vlan1（access
# p1 允许 vlan1，即正常 remark）；priority=5 -> allow。其余字段组合走
# default（例如非 0x0800 且 priority!=5 的帧）
THREE_RULES = [
    rule(src="00:00:00:00:00:01", action="drop"),
    rule(ethertype=0x0800, action="remark", to_vlan=1),
    rule(priority=5, action="allow"),
]


class HappyPathTests(unittest.TestCase):
    def test_star_is_records_length_with_fixed_key_order_and_digest(self):
        cfg = acl_config(THREE_RULES)
        events = [
            frame(1, "p1", "00:00:00:00:00:01"),       # 规则 0 drop
            frame(2, "p2", "00:00:00:00:00:02", ethertype=0x86DD),  # default
            frame(3, "p2", "00:00:00:00:00:03"),       # 规则 1 remark
            frame(4, "p3", "00:00:00:00:00:01"),       # 规则 0 drop
        ]
        log_bytes = acl_log(cfg, events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, after = run_acl(log_bytes, "*")
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertTrue(out.endswith(b"\n"))
        self.assertNotIn(b", ", out)
        self.assertNotIn(b": ", out)
        self.assertEqual(after, log_bytes)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(list(doc), ACL_KEYS)
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["source_sha256"], source)
        self.assertEqual(doc["offset"], 4)
        self.assertEqual(len(doc["rules"]), 3)
        for idx, entry in enumerate(doc["rules"]):
            self.assertEqual(list(entry), RULE_KEYS)
            self.assertEqual(entry["index"], idx)
        self.assertEqual(
            [entry["action"] for entry in doc["rules"]],
            ["drop", "remark", "allow"],
        )
        self.assertEqual([entry["hits"] for entry in doc["rules"]],
                         [2, 1, 0])
        self.assertEqual(list(doc["default"]), DEFAULT_KEYS)
        self.assertEqual(doc["default"], {"action": "allow", "hits": 1})
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_star_equals_sha_cursor_at_record_count(self):
        cfg = acl_config(THREE_RULES)
        events = [frame(1, "p1", "00:00:00:00:00:01")]
        log_bytes = acl_log(cfg, events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code_a, out_a, err_a, _ = run_acl(log_bytes, "*")
        code_b, out_b, err_b, _ = run_acl(log_bytes, "%s:1" % source)
        self.assertEqual((code_a, err_a), (0, b""))
        self.assertEqual((code_b, err_b), (0, b""))
        self.assertEqual(out_a, out_b)

    def test_offset_zero_is_zero_hits(self):
        cfg = acl_config(THREE_RULES)
        events = [frame(1, "p1", "00:00:00:00:00:01")]
        log_bytes = acl_log(cfg, events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_acl(log_bytes, "%s:0" % source)
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["offset"], 0)
        self.assertEqual([entry["hits"] for entry in doc["rules"]],
                         [0, 0, 0])
        self.assertEqual(doc["default"], {"action": "allow", "hits": 0})
        self.assertEqual(doc["sha256"], digest_of(doc))

    def test_partial_offset_replays_only_prefix(self):
        cfg = acl_config(THREE_RULES)
        events = [
            frame(1, "p1", "00:00:00:00:00:01"),
            frame(2, "p2", "00:00:00:00:00:02"),
            frame(3, "p2", "00:00:00:00:00:03"),
        ]
        log_bytes = acl_log(cfg, events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        expected = [
            [0, 0, 0],
            [1, 0, 0],
            [1, 1, 0],
            [1, 2, 0],
        ]
        for offset, hits in enumerate(expected):
            code, out, err, _ = run_acl(log_bytes, "%s:%d" % (source, offset))
            self.assertEqual(code, 0, err)
            doc = json.loads(out.decode("utf-8"))
            self.assertEqual(doc["offset"], offset)
            self.assertEqual(
                [entry["hits"] for entry in doc["rules"]], hits
            )
            self.assertEqual(doc["default"]["hits"], 0)
            self.assertEqual(doc["sha256"], digest_of(doc))

    def test_first_matching_rule_wins(self):
        # 两条规则都匹配 ...:01：只计首条
        cfg = acl_config([
            rule(src="00:00:00:00:00:01", action="drop"),
            rule(src="00:00:00:00:00:01", action="allow"),
        ])
        events = [frame(1, "p1", "00:00:00:00:00:01")]
        log_bytes = acl_log(cfg, events)
        code, out, err, _ = run_acl(log_bytes, "*")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual([entry["hits"] for entry in doc["rules"]], [1, 0])
        self.assertEqual(doc["default"]["hits"], 0)

    def test_bad_frames_vlan_reject_link_member_not_counted(self):
        cfg = acl_config(THREE_RULES)
        events = [
            link_event(0, "L2", True),                       # 幂等链路
            frame(1, "p1", "00:00:00:00:00:01", length=10),  # runt 坏帧
            frame(2, "p1", "00:00:00:00:00:02", fcs=False),  # bad_fcs
            frame(3, "p1", "00:00:00:00:00:03",
                  alignment=False),                          # alignment
            frame(4, "p1", "00:00:00:00:00:04", length=9000),   # giant
            # access 口带 tag：VLAN 准入拒绝（即使 vlan 等于 pvid）
            frame(5, "p1", "00:00:00:00:00:05", vlan=1),
            member_event(6, "p5", True),                     # 幂等成员
            member_event(7, "p5", False),                    # 成员下线
            link_event(8, "L2", False),                      # 链路断开
        ]
        log_bytes = acl_log(cfg, events)
        code, out, err, _ = run_acl(log_bytes, "*")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual([entry["hits"] for entry in doc["rules"]],
                         [0, 0, 0])
        self.assertEqual(doc["default"]["hits"], 0)

    def test_untagged_uses_pvid_and_tagged_allowed_counts(self):
        # p4 为 access vlan2：无 tag 帧以 vlan2 匹配；带 tag vlan2 拒绝
        cfg = acl_config([rule(vlan=2, action="drop")])
        events = [
            frame(1, "p4", "00:00:00:00:00:01"),  # pvid=2 命中规则 0
            frame(2, "p4", "00:00:00:00:00:02", vlan=2),  # access 带 tag 拒绝
        ]
        log_bytes = acl_log(cfg, events)
        code, out, err, _ = run_acl(log_bytes, "*")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["rules"][0]["hits"], 1)
        self.assertEqual(doc["default"]["hits"], 0)

    def test_drop_and_remark_denied_still_count_as_hit(self):
        # remark 到 p1 不允许的 vlan2：后续按 drop，但仍计规则命中
        cfg = acl_config([rule(action="remark", to_vlan=2)])
        events = [
            frame(1, "p1", "00:00:00:00:00:01"),
            frame(2, "p1", "00:00:00:00:00:02"),
        ]
        log_bytes = acl_log(cfg, events)
        code, out, err, _ = run_acl(log_bytes, "*")
        self.assertEqual(code, 0, err)
        doc = json.loads(out.decode("utf-8"))
        self.assertEqual(doc["rules"],
                         [{"index": 0, "action": "remark", "hits": 2}])
        self.assertEqual(doc["default"]["hits"], 0)

    def test_prefix_matches_direct_simulation_for_every_offset(self):
        cfg = acl_config(THREE_RULES)
        events = [
            link_event(0, "L2", True),
            frame(1, "p1", "00:00:00:00:00:01", length=10),
            frame(2, "p1", "00:00:00:00:00:02"),
            frame(3, "p2", "00:00:00:00:00:03", ethertype=0x86DD),
            member_event(4, "p5", False),
            frame(5, "p4", "00:00:00:00:00:04"),
            frame(6, "p1", "00:00:00:00:00:01"),
        ]
        log_bytes = acl_log(cfg, events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        for offset in range(len(events) + 1):
            rules, default = simulate(cfg, events[:offset])
            code, out, err, _ = run_acl(log_bytes, "%s:%d" % (source, offset))
            self.assertEqual(code, 0, err)
            doc = json.loads(out.decode("utf-8"))
            self.assertEqual(doc["rules"], rules)
            self.assertEqual(doc["default"], default)

    def test_empty_log_star_and_zero_identical(self):
        cfg = acl_config(THREE_RULES)
        log_bytes = acl_log(cfg, [])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code_a, out_a, _, _ = run_acl(log_bytes, "*")
        code_b, out_b, _, _ = run_acl(log_bytes, "%s:0" % source)
        self.assertEqual(code_a, 0)
        self.assertEqual(code_b, 0)
        self.assertEqual(out_a, out_b)
        doc = json.loads(out_a.decode("utf-8"))
        self.assertEqual(doc["offset"], 0)
        self.assertEqual([entry["hits"] for entry in doc["rules"]],
                         [0, 0, 0])
        self.assertEqual(doc["default"]["hits"], 0)


class UsageTests(unittest.TestCase):
    def test_arg_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "in.log")
            open(log_path, "wb").close()
            for argv in (
                ["log-acl"],
                ["log-acl", log_path],
                ["log-acl", log_path, "*", "1", "2"],
            ):
                proc = subprocess.run(
                    [sys.executable, SWITCH, *argv],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(proc.stdout, b"")
                self.assertEqual(proc.stderr,
                                 b'{"error":"usage"}\n')

    def test_bad_cursor_tokens(self):
        log_bytes = acl_log(acl_config(), [frame(1, "p1",
                                                 "00:00:00:00:00:01")])
        for token in ("", "abc", "00", "*:0",
                      "z" * 64 + ":0", "0" * 64,
                      "0" * 64 + ":-1", "0" * 64 + ":01"):
            code, out, err, _ = run_acl(log_bytes, token)
            self.assertEqual(code, 2, token)
            self.assertEqual(out, b"")
            self.assertEqual(err, b'{"error":"usage"}\n')

    def test_bad_max_work_tokens(self):
        log_bytes = acl_log(acl_config(), [])
        for token in ("0", "-1", "abc", "01", "1.0", "1 "):
            code, out, err, _ = run_acl(log_bytes, "*", token)
            self.assertEqual(code, 2, token)
            self.assertEqual(out, b"")
            self.assertEqual(err, b'{"error":"usage"}\n')

    def test_arbitrary_length_decimal_max_work_accepted(self):
        log_bytes = acl_log(acl_config(), [])
        code, out, err, _ = run_acl(log_bytes, "*", "9" * 5000)
        self.assertEqual(code, 0, err)
        self.assertEqual(out.count(b"\n"), 1)

    def test_five_thousand_digit_cursor_offset_unbounded(self):
        log_bytes = acl_log(acl_config(), [])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        # 5000 位 offset 须按不限长十进制解析；超过记录数 -> invalid_input
        # （解析本身不按 usage 拒绝）
        token = "%s:%s" % (source, "1" + "0" * 4999)
        code, out, err, _ = run_acl(log_bytes, token)
        self.assertEqual(code, 4, err)
        self.assertEqual(out, b"")


class ErrorPrecedenceTests(unittest.TestCase):
    def test_file_not_found(self):
        proc = subprocess.run(
            [sys.executable, SWITCH, "log-acl",
             os.path.join(tempfile.gettempdir(), "no-such-log-acl.log"),
             "*"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b'{"error":"file_not_found"}\n')

    def test_bad_internal_sha_invalid_input(self):
        cfg = acl_config()
        log_bytes = acl_log(cfg, [])
        log = json.loads(log_bytes.decode("utf-8"))
        log["sha256"] = "0" * 64
        tampered = (
            json.dumps(log, ensure_ascii=False, separators=(",", ":"))
        ).encode("utf-8")
        code, out, err, _ = run_acl(tampered, "*")
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')

    def test_cursor_sha_mismatch_invalid_input(self):
        log_bytes = acl_log(acl_config(), [])
        code, out, err, _ = run_acl(log_bytes, "%s:0" % ("1" * 64))
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')

    def test_cursor_offset_beyond_record_count_invalid_input(self):
        log_bytes = acl_log(acl_config(), [])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_acl(log_bytes, "%s:1" % source)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')

    def test_plain_acl_mode_rejected(self):
        # 无 max_frame 的 acl 配置形状：log-acl 仅接受 acl-check
        cfg = plain_acl_config()
        events = [
            {"t": 1, "port": "p2", "src": "00:00:00:00:00:05",
             "dst": BCAST, "vlan": None, "ethertype": 0x0800,
             "priority": 0},
        ]
        log_bytes = record(cfg, events)
        code, out, err, _ = run_acl(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')

    def test_qos_check_mode_rejected(self):
        from test_log_qos import qos_log, good_frame
        log_bytes = qos_log([good_frame(1, "p1", "00:00:00:00:00:01")])
        code, out, err, _ = run_acl(log_bytes, "*")
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')

    def test_tampered_records_fail_verification(self):
        cfg = acl_config(THREE_RULES)
        events = [frame(1, "p1", "00:00:00:00:00:01")]
        log_bytes = acl_log(cfg, events)
        log = json.loads(log_bytes.decode("utf-8"))
        # 篡改记录 output 但不重算顶层 sha：内部 sha 先失败
        log["records"][0]["output"]["action"] = "flood"
        tampered = (
            json.dumps(log, ensure_ascii=False, separators=(",", ":"))
        ).encode("utf-8")
        code, out, err, _ = run_acl(tampered, "*")
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')

    def test_invalid_input_before_work_limit(self):
        # 游标 offset 越界（invalid_input）优先于 MAX_WORK=1
        log_bytes = acl_log(acl_config(), [])
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, out, err, _ = run_acl(log_bytes, "%s:1" % source, "1")
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')


class WorkLimitTests(unittest.TestCase):
    def test_frame_charge_uses_acl_check_formula(self):
        # B=2、L=1、初始 U=1 -> 初始 work=5；P=6、M=2、R=1，
        # 每帧 K+H+Q+1+2P+M+R = 16。坏帧不计 VLAN/ACL 也不改 K/H/Q，
        # 故每条 runt 固定 +16。offset=1 仅初始收敛加一条坏帧
        cfg = acl_config()  # 默认 R=1
        events = [frame(1, "p1", "00:00:00:00:00:01", length=10)]
        log_bytes = acl_log(cfg, events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        code, _, err, _ = run_acl(log_bytes, "%s:1" % source, "21")
        self.assertEqual(code, 0, err)  # 5+16=21 等于上限合法
        code, out, err, _ = run_acl(log_bytes, "%s:1" % source, "20")
        self.assertEqual(code, 5)  # 首次超过
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"acl_work_limit"}\n')
        code, _, _, _ = run_acl(log_bytes, "%s:0" % source, "5")
        self.assertEqual(code, 0)  # 初始 5 等于上限合法
        code, _, _, _ = run_acl(log_bytes, "%s:0" % source, "4")
        self.assertEqual(code, 5)

    def test_work_counts_only_prefix_events(self):
        cfg = acl_config()
        events = [
            frame(1, "p1", "00:00:00:00:00:01", length=10),
            frame(2, "p1", "00:00:00:00:00:02", length=10),
            frame(3, "p1", "00:00:00:00:00:03", length=10),
        ]
        log_bytes = acl_log(cfg, events)
        source = json.loads(log_bytes.decode("utf-8"))["sha256"]
        # offset=2：5+16+16=37；第三条帧不计入
        code, _, err, _ = run_acl(log_bytes, "%s:2" % source, "37")
        self.assertEqual(code, 0, err)
        code, _, _, _ = run_acl(log_bytes, "%s:2" % source, "36")
        self.assertEqual(code, 5)
        # 全量 5+48=53：上限 37 对 offset=2 合法但全量超限
        code, _, _, _ = run_acl(log_bytes, "*", "53")
        self.assertEqual(code, 0)
        code, _, _, _ = run_acl(log_bytes, "*", "52")
        self.assertEqual(code, 5)

    def test_default_max_work_is_ten_million(self):
        cfg = acl_config()
        events = [frame(t, "p1", "00:00:00:00:00:%02x" % (t % 100 + 1))
                  for t in range(1, 100)]
        log_bytes = acl_log(cfg, events)
        code, _, err, _ = run_acl(log_bytes, "*")
        self.assertEqual(code, 0, err)


if __name__ == "__main__":
    unittest.main()
