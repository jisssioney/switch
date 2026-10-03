#!/usr/bin/env python3
"""lacp 子命令回归：显式事件时钟驱动的动态 LACP 聚合协商。

端到端驱动 `python switch.py lacp CONFIG EVENTS`。CONFIG 沿用 lag 语义，
lags 项新增 system_id/system_priority/key/mode/timeout/min_links，成员为
{name,port_id,port_priority}；EVENTS 支持链路、成员、数据帧、对端通告与
tick。校验 active 周期发送、passive 响应、short/long 周期与超时、伙伴冲突
选择、min_links 门槛、转发沿用 lag 规则、时间非递减与各类非法输入退出 4、
参数错误退出 2、工作量超限退出 5 及输出逐字节确定。仅用标准库。
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SWITCH = os.path.join(HERE, "switch.py")

BCAST = "ff:ff:ff:ff:ff:ff"
PEER = "00:bb:00:00:00:01"


def make_port(name, mode="access", pvid=1, allowed=None, untagged=None,
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


def make_config(mode="active", timeout="short", min_links=1,
                members=None, system_priority=32768, key=100):
    if members is None:
        members = [
            {"name": "p4", "port_id": 4, "port_priority": 100},
            {"name": "p5", "port_id": 5, "port_priority": 101},
        ]
    return {
        "bridges": ["b1", "b2"],
        "links": [
            {"id": "L1", "x": ["b1", "p1"], "y": ["b2", "p1"],
             "cost": 1, "up": True},
        ],
        "delay": 2,
        "bridge": "b1",
        "ports": [
            make_port("p1", mode="trunk", allowed=[1, 2], untagged=[]),
            make_port("p2"),
            make_port("p3"),
            make_port("p4"),
            make_port("p5"),
        ],
        "age": 100,
        "storm": {
            "window": 10,
            "limits": {"broadcast": 100, "multicast": 100, "unknown": 100},
            "move_limit": 100,
            "hold": 50,
        },
        "lags": [
            {
                "name": "LG1",
                "members": members,
                "hash": ["src"],
                "system_id": "00:aa:00:00:00:01",
                "system_priority": system_priority,
                "key": key,
                "mode": mode,
                "timeout": timeout,
                "min_links": min_links,
            }
        ],
    }


def tick(t):
    return {"t": t, "tick": True}


def frame(t, port, src, dst=BCAST, vlan=None):
    return {"t": t, "port": port, "src": src, "dst": dst, "vlan": vlan}


def link(t, lid, up):
    return {"t": t, "id": lid, "up": up}


def member(t, name, up):
    return {"t": t, "member": name, "up": up}


def peer(t, name, peer_port_id, *, peer_system_id=PEER,
         peer_system_priority=32768, peer_key=100,
         peer_port_priority=200, aggregation=True, synchronization=True,
         collecting=True, distributing=True):
    return {
        "t": t,
        "member": name,
        "peer_system_id": peer_system_id,
        "peer_system_priority": peer_system_priority,
        "peer_key": peer_key,
        "peer_port_id": peer_port_id,
        "peer_port_priority": peer_port_priority,
        "aggregation": aggregation,
        "synchronization": synchronization,
        "collecting": collecting,
        "distributing": distributing,
    }


def run(config, events, *extra):
    with tempfile.TemporaryDirectory() as d:
        cfg = os.path.join(d, "config.json")
        evt = os.path.join(d, "events.json")
        with open(cfg, "wb") as handle:
            handle.write(json.dumps(config).encode("utf-8"))
        with open(evt, "wb") as handle:
            handle.write(json.dumps(events).encode("utf-8"))
        proc = subprocess.run(
            [sys.executable, SWITCH, "lacp", cfg, evt, *extra],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    return proc


def good_pair(t=2):
    return [peer(t, "p4", 40), peer(t, "p5", 50)]


class LacpBasicTest(unittest.TestCase):
    def test_active_periodic_short(self):
        proc = run(make_config(), [tick(0), tick(1), tick(2)])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        doc = json.loads(proc.stdout.decode())
        # short 周期为 1：t=0、1、2 均发送，成员名升序
        for result in doc["results"]:
            self.assertEqual(
                [ad["member"] for ad in result["sent"]], ["p4", "p5"]
            )
            ad = result["sent"][0]
            self.assertEqual(ad["system_id"], "00:aa:00:00:00:01")
            self.assertEqual(ad["system_priority"], 32768)
            self.assertEqual(ad["key"], 100)
            self.assertEqual(ad["port_id"], 4)
            self.assertFalse(ad["aggregation"])
        self.assertFalse(doc["results"][0]["lags"][0]["up"])

    def test_active_periodic_long(self):
        proc = run(make_config(timeout="long"), [tick(0), tick(29), tick(30)])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        doc = json.loads(proc.stdout.decode())
        # long 周期为 30：仅 t=0 与 t=30 到期
        self.assertEqual(len(doc["results"][0]["sent"]), 2)
        self.assertEqual(doc["results"][1]["sent"], [])
        self.assertEqual(len(doc["results"][2]["sent"]), 2)

    def test_same_timepoint_single_periodic_batch(self):
        # 同一时间点多个事件，到期发送只出现在首个事件结果中
        proc = run(
            make_config(),
            [tick(0), frame(1, "p2", "00:00:00:00:00:01"),
             frame(1, "p3", "00:00:00:00:00:02")],
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        doc = json.loads(proc.stdout.decode())
        self.assertEqual(len(doc["results"][1]["sent"]), 2)
        self.assertEqual(doc["results"][2]["sent"], [])

    def test_passive_only_replies(self):
        proc = run(
            make_config(mode="passive"),
            [tick(0)] + good_pair(5),
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        doc = json.loads(proc.stdout.decode())
        self.assertEqual(doc["results"][0]["sent"], [])
        # 两条对端通告同刻按输入顺序各响应一条
        self.assertEqual(
            [ad["member"] for ad in doc["results"][1]["sent"]], ["p4"]
        )
        self.assertEqual(
            [ad["member"] for ad in doc["results"][2]["sent"]], ["p5"]
        )

    def test_aggregation_comes_up(self):
        proc = run(make_config(), [tick(0)] + good_pair(2) + [tick(3)])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        doc = json.loads(proc.stdout.decode())
        lag = doc["results"][-1]["lags"][0]
        self.assertTrue(lag["up"])
        for member_state in lag["members"]:
            self.assertFalse(member_state["individual"])
            self.assertTrue(member_state["synchronization"])
            self.assertTrue(member_state["collecting"])
            self.assertTrue(member_state["distributing"])
        ad = doc["results"][-1]["sent"][0]
        self.assertTrue(ad["aggregation"])

    def test_min_links_gate(self):
        events = [peer(1, "p4", 40), peer(2, "p5", 50)]
        proc = run(make_config(min_links=2), events)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        doc = json.loads(proc.stdout.decode())
        # 仅 p4 有效时未达 2 条门槛：逻辑口 down
        self.assertFalse(doc["results"][0]["lags"][0]["up"])
        self.assertTrue(doc["results"][1]["lags"][0]["up"])

    def test_short_timeout_expiry(self):
        # t=2 建立，对端静默；short 超时 3，t=5 失效
        events = good_pair(2) + [tick(3), tick(4), tick(5)]
        proc = run(make_config(), events)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        doc = json.loads(proc.stdout.decode())
        self.assertTrue(doc["results"][1]["lags"][0]["up"])
        self.assertTrue(doc["results"][3]["lags"][0]["up"])
        self.assertFalse(doc["results"][4]["lags"][0]["up"])
        for member_state in doc["results"][4]["lags"][0]["members"]:
            self.assertTrue(member_state["individual"])

    def test_long_timeout_expiry(self):
        # long 超时 90：seen=2，t=92 失效
        events = good_pair(2) + [tick(30), tick(60), tick(91), tick(92)]
        proc = run(make_config(timeout="long"), events)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        doc = json.loads(proc.stdout.decode())
        self.assertTrue(doc["results"][4]["lags"][0]["up"])
        self.assertFalse(doc["results"][5]["lags"][0]["up"])

    def test_partner_system_conflict(self):
        events = [
            peer(1, "p4", 40, peer_system_priority=100,
                 peer_system_id="00:00:00:00:00:0a"),
            peer(1, "p5", 50, peer_system_priority=200,
                 peer_system_id="00:00:00:00:00:0b"),
        ]
        proc = run(make_config(), events)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        doc = json.loads(proc.stdout.decode())
        members = doc["results"][-1]["lags"][0]["members"]
        # 对端 system_priority 100 更优：p4 入选，p5 保持 individual
        self.assertFalse(members[0]["individual"])
        self.assertTrue(members[1]["individual"])

    def test_duplicate_peer_port_uses_local_priority(self):
        events = [
            peer(1, "p4", 40, peer_system_priority=100,
                 peer_system_id="00:00:00:00:00:0a"),
            peer(1, "p5", 40, peer_system_priority=100,
                 peer_system_id="00:00:00:00:00:0a"),
            peer(2, "p5", 51, peer_system_priority=100,
                 peer_system_id="00:00:00:00:00:0a"),
        ]
        proc = run(make_config(min_links=2), events)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        doc = json.loads(proc.stdout.decode())
        members = doc["results"][1]["lags"][0]["members"]
        # 同一对端端口接到两个本地成员：本地 port_priority 低的 p4 入选
        self.assertFalse(members[0]["individual"])
        self.assertTrue(members[1]["individual"])
        self.assertFalse(doc["results"][1]["lags"][0]["up"])
        # 对端端口变为不同后双成员入选，逻辑口 up
        self.assertTrue(doc["results"][2]["lags"][0]["up"])

    def test_key_mismatch_is_individual(self):
        events = [
            peer(1, "p4", 40, peer_key=999),
            peer(1, "p5", 50, aggregation=False),
        ]
        proc = run(make_config(), events)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        doc = json.loads(proc.stdout.decode())
        for member_state in doc["results"][-1]["lags"][0]["members"]:
            self.assertTrue(member_state["individual"])
        self.assertFalse(doc["results"][-1]["lags"][0]["up"])

    def test_partner_not_synchronized_blocks_forwarding(self):
        events = [peer(1, "p4", 40, synchronization=False)] + [
            frame(2, "p2", "00:00:00:00:00:01")
        ]
        proc = run(make_config(), events)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        doc = json.loads(proc.stdout.decode())
        member_state = doc["results"][0]["lags"][0]["members"][0]
        self.assertFalse(member_state["individual"])
        self.assertFalse(member_state["synchronization"])
        # 广播泛洪只到 p3，不经过未同步的 LAG
        ports = [p["name"] for p in doc["results"][1]["frame"]["ports"]]
        self.assertEqual(ports, ["p3"])

    def test_frame_forwarding_through_lag(self):
        events = good_pair(1) + [
            frame(2, "p4", "00:00:00:00:00:09"),
            frame(3, "p3", "00:00:00:00:00:07",
                  dst="00:00:00:00:00:09"),
        ]
        proc = run(make_config(), events)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        doc = json.loads(proc.stdout.decode())
        # LAG 成员学习为逻辑口 LG1
        self.assertEqual(
            {entry["mac"]: entry["port"] for entry in doc["fdb"]},
            {
                "00:00:00:00:00:09": "LG1",
                "00:00:00:00:00:07": "p3",
            },
        )
        unicast = doc["results"][3]["frame"]
        self.assertEqual(unicast["action"], "unicast")
        self.assertEqual(len(unicast["ports"]), 1)
        self.assertIn(unicast["ports"][0]["name"], ("p4", "p5"))

    def test_member_admin_event(self):
        events = (
            good_pair(1)
            + [member(2, "p4", False), member(3, "p4", True),
               peer(3, "p4", 40)]
        )
        proc = run(make_config(), events)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        doc = json.loads(proc.stdout.decode())
        members = doc["results"][2]["lags"][0]["members"]
        self.assertFalse(members[0]["up"])
        self.assertTrue(members[0]["individual"])
        self.assertTrue(doc["results"][3]["lags"][0]["up"])

    def test_peer_on_non_member_is_invalid(self):
        events = [
            link(0, "L1", False),
            peer(1, "p2", 40),
        ]
        # p2 不是成员：对端通告引用非成员属非法输入
        proc = run(make_config(), events)
        self.assertEqual(proc.returncode, 4)

    def test_final_counters(self):
        events = good_pair(1) + [
            frame(2, "p3", "00:00:00:00:00:07"),
            frame(2, "p4", "00:00:00:00:00:08"),
        ]
        proc = run(make_config(), events)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        doc = json.loads(proc.stdout.decode())
        by_name = {entry["name"]: entry for entry in doc["ports"]}
        self.assertEqual(by_name["p3"]["rx"], 1)
        self.assertEqual(by_name["p4"]["rx"], 1)
        tx_total = sum(entry["tx"] for entry in doc["ports"])
        self.assertGreater(tx_total, 0)
        # VLAN 计数与端口计数一致：1 个 VLAN 存在
        self.assertEqual([entry["vlan"] for entry in doc["vlans"]], [1, 2])

    def test_deterministic_output(self):
        events = [tick(0)] + good_pair(2) + [
            frame(3, "p2", "00:00:00:00:00:01")
        ]
        first = run(make_config(), events).stdout
        second = run(make_config(), events).stdout
        self.assertEqual(first, second)


class LacpInvalidInputTest(unittest.TestCase):
    def assert_invalid(self, config, events):
        proc = run(config, events)
        self.assertEqual(proc.returncode, 4, proc.stderr)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b'{"error":"invalid_input"}\n')

    def test_time_regression(self):
        self.assert_invalid(make_config(), [tick(2), tick(1)])

    def test_unknown_event_field(self):
        self.assert_invalid(make_config(), [{"t": 0, "tick": True, "x": 1}])

    def test_tick_must_be_true(self):
        self.assert_invalid(make_config(), [{"t": 0, "tick": False}])

    def test_bad_system_mac(self):
        config = make_config()
        config["lags"][0]["system_id"] = "01:00:00:00:00:00"
        self.assert_invalid(config, [tick(0)])

    def test_bad_system_priority(self):
        config = make_config()
        config["lags"][0]["system_priority"] = 70000
        self.assert_invalid(config, [tick(0)])

    def test_bad_key(self):
        config = make_config()
        config["lags"][0]["key"] = -1
        self.assert_invalid(config, [tick(0)])

    def test_bad_mode(self):
        config = make_config()
        config["lags"][0]["mode"] = "auto"
        self.assert_invalid(config, [tick(0)])

    def test_bad_timeout(self):
        config = make_config()
        config["lags"][0]["timeout"] = "medium"
        self.assert_invalid(config, [tick(0)])

    def test_duplicate_port_id(self):
        config = make_config(members=[
            {"name": "p4", "port_id": 4, "port_priority": 100},
            {"name": "p5", "port_id": 4, "port_priority": 101},
        ])
        self.assert_invalid(config, [tick(0)])

    def test_duplicate_port_priority(self):
        config = make_config(members=[
            {"name": "p4", "port_id": 4, "port_priority": 100},
            {"name": "p5", "port_id": 5, "port_priority": 100},
        ])
        self.assert_invalid(config, [tick(0)])

    def test_cross_aggregation_reuse(self):
        config = make_config()
        config["lags"].append({
            "name": "LG2",
            "members": [
                {"name": "p4", "port_id": 6, "port_priority": 102},
                {"name": "p3", "port_id": 7, "port_priority": 103},
            ],
            "hash": ["src"],
            "system_id": "00:aa:00:00:00:02",
            "system_priority": 32768,
            "key": 100,
            "mode": "active",
            "timeout": "short",
            "min_links": 1,
        })
        self.assert_invalid(config, [tick(0)])

    def test_bad_min_links(self):
        self.assert_invalid(make_config(min_links=3), [tick(0)])

    def test_peer_bad_mac(self):
        bad = peer(0, "p4", 40, peer_system_id="zz:00:00:00:00:01")
        self.assert_invalid(make_config(), [bad])

    def test_peer_unknown_member(self):
        bad = peer(0, "p2", 40)
        self.assert_invalid(make_config(), [bad])

    def test_peer_non_boolean_flag(self):
        bad = peer(0, "p4", 40, aggregation="yes")
        self.assert_invalid(make_config(), [bad])

    def test_events_not_list(self):
        self.assert_invalid(make_config(), {"t": 0})

    def test_unknown_config_field(self):
        config = make_config()
        config["extra"] = 1
        self.assert_invalid(config, [tick(0)])


class LacpLimitsTest(unittest.TestCase):
    def test_usage_on_bad_argc(self):
        proc = subprocess.run(
            [sys.executable, SWITCH, "lacp"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stderr, b'{"error":"usage"}\n')

    def test_usage_on_bad_limit_token(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = os.path.join(d, "config.json")
            evt = os.path.join(d, "events.json")
            with open(cfg, "w") as handle:
                json.dump(make_config(), handle)
            with open(evt, "w") as handle:
                json.dump([tick(0)], handle)
            proc = subprocess.run(
                [sys.executable, SWITCH, "lacp", cfg, evt,
                 "1", "2", "3", "4", "0"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(proc.returncode, 2)

    def test_work_limit(self):
        # 初始收敛 B+L+2U=5；首个时间点后超过 4
        proc = run(make_config(), [tick(0)], "1048576", "16777216",
                   "100000", "16777216", "4")
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b'{"error":"lacp_work_limit"}\n')

    def test_item_limit(self):
        proc = run(make_config(), [tick(0), tick(1)], "1048576",
                   "16777216", "1", "16777216")
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(proc.stderr, b'{"error":"item_limit"}\n')


if __name__ == "__main__":
    unittest.main()
