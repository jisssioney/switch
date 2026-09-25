#!/usr/bin/env python3
"""qos 确定性 WRR 与服务镜像的回归测试。"""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_SPEC = importlib.util.spec_from_file_location(
    "switch_under_test", os.path.join(_HERE, "switch.py")
)
sw = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(sw)


def edge_port(name, up=True):
    return {
        "name": name,
        "mode": "trunk",
        "pvid": 1,
        "allowed": [1],
        "untagged": [],
        "up": up,
    }


def link(lid, bx, px, by, py, up=True, cost=1):
    return {"id": lid, "x": [bx, px], "y": [by, py], "cost": cost, "up": up}


def make_config(
    weights=(2, 3, 4, 5),
    mode="wrr",
    drop="tail",
    cap=100,
    qos_map=None,
    sources=None,
    target="mon",
    target_up=True,
    direction="egress",
    ports=None,
    bridges=None,
    links=None,
):
    if ports is None:
        ports = ["p1", "p2", "p3", "mon", "la", "lb"]
    if sources is None:
        sources = ["p3"]
    return {
        "bridges": bridges or ["b1"],
        "links": links or [],
        "delay": 1,
        "bridge": "b1",
        "ports": [edge_port(name, up=(name != target or target_up))
                  for name in ports],
        "age": 100,
        "storm": {
            "window": 10,
            "limits": {"broadcast": 100, "multicast": 100, "unknown": 100},
            "move_limit": 100,
            "hold": 10,
        },
        "lags": [
            {"name": "lg1", "members": ["la", "lb"], "hash": ["src"]}
        ],
        "mirror": {
            "sources": sources,
            "target": target,
            "direction": direction,
        },
        "acl": [
            {
                "src": None,
                "dst": None,
                "vlan": None,
                "ethertype": None,
                "priority": None,
                "action": "allow",
                "to_vlan": None,
            }
        ],
        "qos": {
            "map": qos_map or [0, 1, 2, 3, 0, 1, 2, 3],
            "cap": cap,
            "mode": mode,
            "weights": list(weights),
            "drop": drop,
        },
    }


def frame(t, src_idx, dst="ff:ff:ff:ff:ff:ff", port="p1",
          vlan=None, ethertype=2048, priority=0):
    return {
        "t": t,
        "port": port,
        "src": "02:00:00:00:00:%02x" % src_idx,
        "dst": dst,
        "vlan": vlan,
        "ethertype": ethertype,
        "priority": priority,
    }


def service(t, port, count):
    return {"t": t, "port": port, "count": count}


def link_event(t, lid, up):
    return {"t": t, "id": lid, "up": up}


def run(config, events):
    parsed = sw.validate_qos_config(json.loads(json.dumps(config)))
    (
        bridges, links, delay, bridge, ports, age, storm, lags, mirror, acl,
        qos,
    ) = parsed
    ev = sw.validate_qos_events(
        json.loads(json.dumps(events)), ports,
        {l["id"] for l in links}, lags
    )
    return sw.forward_qos(
        bridges, links, delay, bridge, ports, age, storm, lags, mirror, acl,
        qos, ev
    )


def service_results(result):
    return [r for r in result["results"] if "frames" in r]


class WRRTests(unittest.TestCase):
    def test_weighted_round_robin_full_drain(self):
        # 每队列各 5 帧：prio p 的帧 id 为 p*5+k；flood 自 p1 入 p3。
        config = make_config(weights=(2, 3, 4, 5))
        events = []
        idx = 0
        for prio in range(4):
            for _ in range(5):
                events.append(
                    frame(0, idx, dst="02:00:00:00:01:%02x" % idx,
                          priority=prio)
                )
                idx += 1
        events.append(service(1, "p3", 100))
        result = run(config, events)
        sent = service_results(result)[0]["frames"]
        # (3,5) 起：q3 取 5；q2 取 4（余 1）；q1 取 3（余 2）；q0 取 2（余 3）；
        # 回 q3 空 -> q2 取 1 空 -> q1 取 2 空 -> q0 取 2 后 rem 尽推进，
        # 再扫描到 q0 取最后 1 帧。
        expected = (
            [15, 16, 17, 18, 19]
            + [10, 11, 12, 13]
            + [5, 6, 7]
            + [0, 1]
            + [14]
            + [8, 9]
            + [2, 3]
            + [4]
        )
        self.assertEqual(sent, expected)

    def test_count_exhausted_keeps_rem_and_resumes(self):
        config = make_config(weights=(2, 3, 4, 5))
        events = [
            frame(0, i, dst="02:00:00:00:02:%02x" % i, priority=3)
            for i in range(8)
        ]
        events.append(service(1, "p3", 2))  # count 尽，rem=3，队仍非空
        events.append(service(2, "p3", 100))  # 同口续用 rem
        result = run(config, events)
        services = service_results(result)
        self.assertEqual(services[0]["frames"], [0, 1])
        # 续取 3 (id2,3,4) 后 rem 尽推进；其余队空，回 q3 weight 5 取 5,6,7
        self.assertEqual(services[1]["frames"], [2, 3, 4, 5, 6, 7])

    def test_empty_current_queue_advances_and_resets(self):
        config = make_config(weights=(2, 3, 4, 5))
        events = [
            frame(0, i, dst="02:00:00:00:03:%02x" % i, priority=3)
            for i in range(5)
        ]
        events += [
            frame(0, 10 + i, dst="02:00:00:00:04:%02x" % i, priority=1)
            for i in range(2)
        ]
        events.append(service(1, "p3", 100))
        result = run(config, events)
        sent = service_results(result)[0]["frames"]
        # 帧 id 按全局序：q3 为 0..4，q1 为 5,6
        # q3 rem 尽推进；q2 空跳过并重置 rem；q1 取 2 后队空推进；全空停
        self.assertEqual(sent, [0, 1, 2, 3, 4, 5, 6])

    def test_empty_skip_resets_rem_to_new_weight(self):
        config = make_config(weights=(1, 7, 1, 2))
        events = [frame(0, 0, dst="02:00:00:00:05:00", priority=3)]
        events += [
            frame(0, 10 + i, dst="02:00:00:00:06:%02x" % i, priority=1)
            for i in range(10)
        ]
        events.append(service(1, "p3", 4))
        events.append(service(2, "p3", 100))
        result = run(config, events)
        services = service_results(result)
        # 第一次：q3 取 id0 后队空 -> 跳过空 q2 -> q1(rem=7)，
        # count 余 3 取 id1,2,3，rem 余 4 留存
        self.assertEqual(services[0]["frames"], [0, 1, 2, 3])
        # 第二次：续 rem=4 取 4,5,6,7；回 q1(weight7) 取完 8,9,10
        self.assertEqual(services[1]["frames"], [4, 5, 6, 7, 8, 9, 10])

    def test_all_empty_stops_and_keeps_state(self):
        config = make_config(weights=(2, 3, 4, 5))
        events = [
            service(1, "p3", 10),  # 四队全空：停止且状态不变 (3,5)
            frame(2, 0, dst="02:00:00:00:07:00", priority=3),
            service(3, "p3", 1),  # 仍从 q3 起、rem=5
        ]
        result = run(config, events)
        services = service_results(result)
        self.assertEqual(services[0]["frames"], [])
        self.assertEqual(services[1]["frames"], [0])

    def test_state_independent_between_ports(self):
        config = make_config(weights=(2, 3, 4, 5))
        events = [frame(0, i, priority=3) for i in range(8)]  # flood 至各口
        events.append(service(1, "p2", 2))  # p2：rem 余 3
        events.append(service(2, "p3", 3))  # p3：独立初值，rem 余 2
        result = run(config, events)
        services = service_results(result)
        self.assertEqual(services[0]["frames"], [0, 1])
        self.assertEqual(services[1]["frames"], [0, 1, 2])


class ServiceMirrorTests(unittest.TestCase):
    def test_egress_mirror_entries_align_with_frames(self):
        config = make_config(direction="egress", sources=["p3"], target="mon")
        events = [
            frame(0, i, dst="02:00:00:00:08:%02x" % i, priority=3)
            for i in range(3)
        ]
        events.append(service(1, "p3", 3))
        result = run(config, events)
        svc = service_results(result)[0]
        self.assertEqual(svc["frames"], [0, 1, 2])
        self.assertEqual(
            svc["mirrors"],
            [
                {"name": "mon", "vlan": 1, "direction": "egress",
                 "source": "p3"}
                for _ in range(3)
            ],
        )
        self.assertEqual(
            list(svc["mirrors"][0]), ["name", "vlan", "direction", "source"]
        )

    def test_target_unavailable_no_placeholder(self):
        # mon 物理 down：帧照常服务计 p3 tx，mirrors 为空，绝无 null
        config = make_config(target_up=False)
        events = [
            frame(0, i, dst="02:00:00:00:09:%02x" % i, priority=3)
            for i in range(3)
        ]
        events.append(service(1, "p3", 3))
        result = run(config, events)
        svc = service_results(result)[0]
        self.assertEqual(svc["frames"], [0, 1, 2])
        self.assertEqual(svc["mirrors"], [])
        mon = next(p for p in result["ports"] if p["name"] == "mon")
        p3 = next(p for p in result["ports"] if p["name"] == "p3")
        self.assertEqual(mon["tx"], 0)
        self.assertEqual(p3["tx"], 3)

    def test_target_availability_toggled_by_link(self):
        # target tp 经链路 l2 接入；link 事件切换其可用性，镜像随隐现
        config = make_config(
            sources=["p3"],
            target="tp",
            ports=["p1", "p2", "p3", "tp", "la", "lb"],
            bridges=["b1", "b2"],
            links=[
                link("l1", "b1", "p3", "b2", "cp"),
                link("l2", "b1", "tp", "b2", "dp"),
            ],
        )
        events = [frame(2, i, priority=3) for i in range(3)]
        events.append(service(3, "p3", 1))   # l2 up：有镜像
        events.append(link_event(4, "l2", False))
        events.append(service(5, "p3", 1))   # target 不可用：无镜像仍出帧
        events.append(link_event(6, "l2", True))
        events.append(service(7, "p3", 1))   # 恢复：镜像重现
        result = run(config, events)
        services = service_results(result)
        self.assertEqual([s["frames"] for s in services],
                         [[0], [1], [2]])
        self.assertEqual(len(services[0]["mirrors"]), 1)
        self.assertEqual(services[1]["mirrors"], [])
        self.assertEqual(len(services[2]["mirrors"]), 1)
        self.assertEqual(services[2]["mirrors"][0]["name"], "tp")

    def test_ingress_direction_no_egress_mirror(self):
        config = make_config(direction="ingress")
        events = [
            frame(0, i, dst="02:00:00:00:0b:%02x" % i, priority=3)
            for i in range(2)
        ]
        events.append(service(1, "p3", 2))
        result = run(config, events)
        svc = service_results(result)[0]
        self.assertEqual(svc["frames"], [0, 1])
        self.assertEqual(svc["mirrors"], [])

    def test_non_source_port_no_mirror(self):
        config = make_config(direction="egress", sources=["p2"])
        events = [
            frame(0, i, dst="02:00:00:00:0c:%02x" % i, priority=3)
            for i in range(2)
        ]
        events.append(service(1, "p3", 2))
        result = run(config, events)
        svc = service_results(result)[0]
        self.assertEqual(svc["frames"], [0, 1])
        self.assertEqual(svc["mirrors"], [])


class NonForwardingTests(unittest.TestCase):
    def test_leave_forwarding_clears_counts_drop_and_empty_service(self):
        # p3 经 l1 接入 b2；t=2 入队，t=3 链路 down 离开 forwarding 清队
        config = make_config(
            target="mon",
            ports=["p1", "p2", "p3", "mon", "la", "lb"],
            bridges=["b1", "b2"],
            links=[link("l1", "b1", "p3", "b2", "cp")],
        )
        events = [
            frame(2, 0),  # broadcast，t=2 时 p3 恰 forwarding，入队
            link_event(3, "l1", False),  # 清队：计 drop
            service(4, "p3", 5),
        ]
        result = run(config, events)
        svc = service_results(result)[0]
        self.assertEqual(svc["frames"], [])
        self.assertEqual(svc["mirrors"], [])
        p3 = next(p for p in result["ports"] if p["name"] == "p3")
        self.assertEqual(p3["drop"], 1)
        self.assertEqual(p3["tx"], 0)
        vlan1 = next(v for v in result["vlans"] if v["vlan"] == 1)
        self.assertEqual(vlan1["drop"], 1)


class CLIValidationTests(unittest.TestCase):
    def _write(self, data):
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8"
        )
        handle.write(json.dumps(data, ensure_ascii=False))
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def test_invalid_config_exit4_empty_stdout(self):
        config = make_config()
        config["qos"]["weights"] = [1, 1, 1, 0]  # 非法权重
        cfg = self._write(config)
        ev = self._write([])
        proc = subprocess.run(
            [sys.executable, os.path.join(_HERE, "switch.py"),
             "qos", cfg, ev],
            capture_output=True,
        )
        self.assertEqual(proc.returncode, 4)
        self.assertEqual(proc.stdout, b"")
        self.assertIn(b"invalid_input", proc.stderr)

    def test_invalid_events_exit4_empty_stdout(self):
        cfg = self._write(make_config())
        ev = self._write([{"t": 0, "port": "p3"}])  # 缺键
        proc = subprocess.run(
            [sys.executable, os.path.join(_HERE, "switch.py"),
             "qos", cfg, ev],
            capture_output=True,
        )
        self.assertEqual(proc.returncode, 4)
        self.assertEqual(proc.stdout, b"")

    def test_output_compact_lf_key_order_no_null(self):
        config = make_config(target_up=False)  # 强制出现“无镜像”路径
        events = [
            frame(0, 0, dst="02:00:00:00:0d:00", priority=3),
            service(1, "p3", 1),
        ]
        cfg = self._write(config)
        ev = self._write(events)
        proc = subprocess.run(
            [sys.executable, os.path.join(_HERE, "switch.py"),
             "qos", cfg, ev],
            capture_output=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(proc.stdout.endswith(b"\n"))
        self.assertNotIn(b" ", proc.stdout)  # 紧凑 UTF-8 JSON
        self.assertNotIn(b"null", proc.stdout)
        svc = json.loads(proc.stdout.decode("utf-8"))["results"][-1]
        self.assertEqual(list(svc), ["t", "port", "frames", "mirrors"])


if __name__ == "__main__":
    unittest.main()
