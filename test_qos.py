#!/usr/bin/env python3
"""qos 子命令回归：确定性 WRR 持久状态 (q,rem) 与服务镜像合同。

仅用标准库；通过 `python switch.py qos CONFIG EVENTS` 端到端驱动，
另对持久状态做单元级直接调用。
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SWITCH = os.path.join(HERE, "switch.py")


def make_port(name, up=True, mode="access", pvid=1):
    return {
        "name": name,
        "mode": mode,
        "pvid": pvid,
        "allowed": [pvid],
        "untagged": [pvid],
        "up": up,
    }


def base_config(
    weights,
    mode="wrr",
    drop="tail",
    cap=1000,
    qos_map=None,
    mirror=None,
    ports=None,
    lags=None,
):
    if ports is None:
        # p1 入、p2/p3 为被测出口（vlan1）；p4 镜像口、p5/p6 为 LAG 成员
        # （vlan2，隔离泛洪，且 target 不得为 LAG 成员）
        ports = [
            make_port("p1"),
            make_port("p2"),
            make_port("p3"),
            make_port("p4", pvid=2),
            make_port("p5", pvid=2),
            make_port("p6", pvid=2),
        ]
    if lags is None:
        lags = [{"name": "L1", "members": ["p5", "p6"], "hash": ["src"]}]
    if mirror is None:
        mirror = {"sources": ["p1"], "target": "p4", "direction": "both"}
    if qos_map is None:
        qos_map = [0, 1, 2, 3, 0, 1, 2, 3]
    return {
        "bridges": ["b1"],
        "links": [],
        "delay": 1,
        "bridge": "b1",
        "ports": ports,
        "age": 100,
        "storm": {
            "window": 10,
            "limits": {"broadcast": 100, "multicast": 100, "unknown": 100},
            "move_limit": 100,
            "hold": 10,
        },
        "lags": lags,
        "mirror": mirror,
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
            "map": qos_map,
            "cap": cap,
            "mode": mode,
            "weights": weights,
            "drop": drop,
        },
    }


def frame(t, port, dst, priority=0, src="00:00:00:00:00:01", vlan=None,
          ethertype=0x0800):
    return {
        "t": t,
        "port": port,
        "src": src,
        "dst": dst,
        "vlan": vlan,
        "ethertype": ethertype,
        "priority": priority,
    }


def service(t, port, count):
    return {"t": t, "port": port, "count": count}


def run_cli(config, events):
    """返回 (returncode, stdout_bytes, stderr_bytes)。"""
    with tempfile.TemporaryDirectory() as tmp:
        cfg = os.path.join(tmp, "config.json")
        evt = os.path.join(tmp, "events.json")
        with open(cfg, "wb") as handle:
            handle.write(json.dumps(config).encode("utf-8"))
        with open(evt, "wb") as handle:
            handle.write(json.dumps(events).encode("utf-8"))
        proc = subprocess.run(
            [sys.executable, SWITCH, "qos", cfg, evt],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    return proc.returncode, proc.stdout, proc.stderr


def run(config, events):
    code, out, err = run_cli(config, events)
    assert code == 0, (code, err.decode("utf-8"))
    return json.loads(out.decode("utf-8"))


# p1 发往未知目的的单播帧（同 VLAN、access），priority 直接映射到队列号；
# 目的 MAC 取 00:..:fe，避免与各帧自增的源 MAC 相撞而被 FDB 吸收
def unicast_events(priorities, service_calls, t0=0):
    events = []
    for i, prio in enumerate(priorities):
        events.append(
            frame(
                t0 + i,
                "p1",
                "00:00:00:00:00:fe",
                priority=prio,
                src="00:00:00:00:00:%02x" % (i + 1),
            )
        )
    base = t0 + len(priorities)
    for i, (port, count) in enumerate(service_calls):
        events.append(service(base + i, port, count))
    return events


def service_results(result):
    return [r for r in result["results"] if "frames" in r]


class WrrSchedulingTests(unittest.TestCase):
    def test_weights_round_robin_and_state(self):
        # weights=[1,2,3,4]（队列 0..3），初始 (q=3,rem=4)，按 3,2,1,0 轮转
        config = base_config([1, 2, 3, 4])
        # 每队 3 帧；priority 直映队列号。帧 id 按入队序：
        # q3=[0,1,2] q2=[3,4,5] q1=[6,7,8] q0=[9,10,11]
        events = unicast_events(
            [3, 3, 3, 2, 2, 2, 1, 1, 1, 0, 0, 0],
            [("p2", 100)],
        )
        result = run(config, events)
        sent = service_results(result)[0]["frames"]
        # (3,4) 发 0,1,2 后 q3 空 -> 推进；(2,3) 发 3,4,5；(1,2) 发 6,7；
        # (0,1) 发 9；绕回跳空空队到 q1 发 8，再 q0 发 10,11
        self.assertEqual(sent, [0, 1, 2, 3, 4, 5, 6, 7, 9, 8, 10, 11])

    def test_empty_current_queue_advances_and_resets(self):
        # 只有 q3 有 2 帧，weights[3]=4；发空 q3 后推进，全空则停
        config = base_config([1, 1, 1, 4])
        events = unicast_events([3, 3], [("p2", 10)])
        result = run(config, events)
        svc = service_results(result)[0]
        self.assertEqual(svc["frames"], [0, 1])

    def test_count_exhausted_preserves_rem_and_resumes(self):
        # q3 weight=4：先服务 count=2，rem 应由 4->2 且不推进；
        # 下次同端口服务继续 q3，再发 2 帧后 rem=0 才推进
        config = base_config([1, 1, 1, 4])
        events = unicast_events(
            [3, 3, 3, 3, 2, 2, 2, 2],
            [("p2", 2), ("p2", 2), ("p2", 10)],
        )
        result = run(config, events)
        svc = service_results(result)
        self.assertEqual(svc[0]["frames"], [0, 1])       # q3 rem 4->2
        self.assertEqual(svc[1]["frames"], [2, 3])       # q3 rem 2->0，推进
        # 此时状态 q=2,rem=1：先发 q2 一帧（id4..7 中的首帧 id=4）
        self.assertEqual(svc[2]["frames"], [4, 5, 6, 7])

    def test_all_empty_keeps_state(self):
        config = base_config([1, 1, 1, 4])
        events = []
        events.append(service(0, "p2", 5))  # 全空：空结果，状态保持 (3,4)
        # 再让 q3 入 1 帧、q2 入 1 帧
        events.append(frame(1, "p1", "00:00:00:00:00:02", priority=3,
                            src="00:00:00:00:00:10"))
        events.append(frame(2, "p1", "00:00:00:00:00:02", priority=2,
                            src="00:00:00:00:00:11"))
        events.append(service(3, "p2", 10))
        result = run(config, events)
        svc = service_results(result)
        self.assertEqual(svc[0]["frames"], [])
        # 状态仍是 q3：先取 q3(id0) 耗尽推进，再取 q2(id1)
        self.assertEqual(svc[1]["frames"], [0, 1])

    def test_queue_empties_mid_quota_advances(self):
        # q3 weight=4 但只有 2 帧：第 2 帧后队空立即推进，不浪费配额
        config = base_config([1, 1, 1, 4])
        events = unicast_events([3, 3, 2, 2], [("p2", 10)])
        result = run(config, events)
        sent = service_results(result)[0]["frames"]
        # q3 ids0,1 -> 队空推进；q2 ids2,3(weight1) 发一帧 id2 推进
        self.assertEqual(sent, [0, 1, 2, 3])

    def test_per_port_independent_state(self):
        # weights 全 1：p2 服务后游标应推进；p3 必须独立仍从 q3 起。
        config = base_config([1, 1, 1, 1])
        events = [
            # id0：未知单播泛洪 -> p2、p3 的 q3；学习 A@p1
            frame(0, "p1", "00:00:00:00:00:20", priority=3,
                  src="00:00:00:00:00:10"),
            # 学习 B@p2、C@p3（单播回 p1，不入 p2/p3 队）
            frame(1, "p2", "00:00:00:00:00:10", priority=3,
                  src="00:00:00:00:00:20"),
            frame(2, "p3", "00:00:00:00:00:10", priority=3,
                  src="00:00:00:00:00:30"),
            # id3：已知单播 A->C，仅入 p3 的 q2
            frame(3, "p1", "00:00:00:00:00:30", priority=2,
                  src="00:00:00:00:00:10"),
            service(4, "p2", 10),  # p2：发 q3 的 id0 后推进到 q2
            service(5, "p3", 10),  # p3 独立：仍从 q3 发 id0，再 q2 发 id3
        ]
        result = run(config, events)
        svc = service_results(result)
        self.assertEqual(svc[0]["frames"], [0])
        self.assertEqual(svc[1]["frames"], [0, 3])


class ServiceMirrorTests(unittest.TestCase):
    def test_egress_mirror_aligned_with_frames(self):
        # sources=[p2]，target=p3 available，direction=egress
        mirror = {"sources": ["p2"], "target": "p3", "direction": "egress"}
        config = base_config([1, 1, 1, 1], mirror=mirror)
        events = unicast_events([3, 3], [("p2", 10)])
        result = run(config, events)
        svc = service_results(result)[0]
        self.assertEqual(svc["frames"], [0, 1])
        self.assertEqual(
            svc["mirrors"],
            [
                {"name": "p3", "vlan": None, "direction": "egress",
                 "source": "p2"},
                {"name": "p3", "vlan": None, "direction": "egress",
                 "source": "p2"},
            ],
        )
        # 镜像副本只计 target 的 tx：p2 两帧 + p3 两副本
        stats = {p["name"]: p for p in result["ports"]}
        self.assertEqual(stats["p2"]["tx"], 2)
        self.assertEqual(stats["p3"]["tx"], 2)

    def test_target_unavailable_no_null_placeholder(self):
        # target=p3 物理 down：无镜像副本，mirrors 为空且绝无 null
        ports = [
            make_port("p1"),
            make_port("p2"),
            make_port("p3", up=False),
            make_port("p4", pvid=2),
            make_port("p5", pvid=2),
            make_port("p6", pvid=2),
        ]
        mirror = {"sources": ["p2"], "target": "p3", "direction": "egress"}
        config = base_config([1, 1, 1, 1], mirror=mirror, ports=ports)
        events = unicast_events([3, 3], [("p2", 10)])
        result = run(config, events)
        svc = service_results(result)[0]
        self.assertEqual(svc["frames"], [0, 1])
        self.assertEqual(svc["mirrors"], [])
        raw = json.dumps(svc)
        self.assertNotIn("null", raw)

    def test_direction_ingress_no_egress_copy_on_service(self):
        mirror = {"sources": ["p2"], "target": "p3", "direction": "ingress"}
        config = base_config([1, 1, 1, 1], mirror=mirror)
        events = unicast_events([3, 3], [("p2", 10)])
        result = run(config, events)
        svc = service_results(result)[0]
        self.assertEqual(svc["frames"], [0, 1])
        self.assertEqual(svc["mirrors"], [])

    def test_non_source_port_no_mirror(self):
        mirror = {"sources": ["p1"], "target": "p3", "direction": "egress"}
        config = base_config([1, 1, 1, 1], mirror=mirror)
        # 帧由 p2 入、去往 p3；服务端口 p3 不在 sources
        events = [
            frame(0, "p2", "00:00:00:00:00:03", priority=3,
                  src="00:00:00:00:00:20"),
            service(1, "p3", 10),
        ]
        result = run(config, events)
        svc = service_results(result)[0]
        self.assertEqual(svc["frames"], [0])
        self.assertEqual(svc["mirrors"], [])

    def test_target_link_flap_between_services(self):
        # 镜像口 p4 挂在链路上：服务间链路 down/up 切换可用性，
        # 仅可用时追加副本，绝无 null 占位
        config = base_config(
            [1, 1, 1, 1],
            mirror={"sources": ["p2"], "target": "p4", "direction": "egress"},
        )
        config["bridges"] = ["b1", "b2"]
        config["links"] = [
            {"id": "L2", "x": ["b1", "p4"], "y": ["b2", "x"],
             "cost": 1, "up": True}
        ]
        events = unicast_events([3, 3, 3, 3], [])
        # 服务间插入链路 down/up，切换镜像目标可用性
        events += [
            service(4, "p2", 2),
            {"t": 5, "id": "L2", "up": False},
            service(6, "p2", 1),
            {"t": 7, "id": "L2", "up": True},
            service(8, "p2", 1),
        ]
        result = run(config, events)
        svc = service_results(result)
        entry = {"name": "p4", "vlan": None, "direction": "egress",
                 "source": "p2"}
        self.assertEqual(svc[0]["frames"], [0, 1])
        self.assertEqual(svc[0]["mirrors"], [entry, entry])
        self.assertEqual(svc[1]["frames"], [2])
        self.assertEqual(svc[1]["mirrors"], [])  # 目标不可用：无副本
        self.assertEqual(svc[2]["frames"], [3])
        self.assertEqual(svc[2]["mirrors"], [entry])
        # 副本只计 target 的 tx
        stats = {p["name"]: p for p in result["ports"]}
        self.assertEqual(stats["p4"]["tx"], 3)

    def test_service_result_and_mirror_key_order(self):
        # 服务结果键序 t,port,frames,mirrors；镜像项键序 name,vlan,direction,source
        config = base_config(
            [1, 1, 1, 1],
            mirror={"sources": ["p2"], "target": "p4", "direction": "egress"},
        )
        events = unicast_events([3], [("p2", 1)])
        code, out, err = run_cli(config, events)
        self.assertEqual(code, 0)
        text = out.decode("utf-8")
        self.assertIn(
            '"t":1,"port":"p2","frames":[0],"mirrors":['
            '{"name":"p4","vlan":null,"direction":"egress","source":"p2"}]',
            text,
        )


class NonForwardingAndDropTests(unittest.TestCase):
    def _config_with_link(self, mirror=None):
        # b1-p2 <-> b2-x 的链路，初始 up；p2 经 STP 收敛后 forwarding
        ports = [
            make_port("p1"),
            make_port("p2"),
            make_port("p3"),
            make_port("p4", pvid=2),
            make_port("p5", pvid=2),
            make_port("p6", pvid=2),
        ]
        if mirror is None:
            mirror = {"sources": ["p2"], "target": "p4", "direction": "both"}
        config = base_config(
            [1, 1, 1, 1], mirror=mirror, ports=ports,
            lags=[{"name": "LG1", "members": ["p5", "p6"], "hash": ["src"]}],
        )
        config["bridges"] = ["b1", "b2"]
        config["links"] = [
            {"id": "L1", "x": ["b1", "p2"], "y": ["b2", "x"],
             "cost": 1, "up": True}
        ]
        return config

    def test_non_forwarding_clears_queue_and_counts_drop(self):
        config = self._config_with_link()
        # p2 在 t>=2*delay=2 才 forwarding。t=3 的未知单播泛洪入 p2 队；
        # t=6 断链使 p2 离开 forwarding，清 1 帧并计 drop；t=7 空服务。
        events = [
            frame(3, "p1", "ff:ff:ff:ff:ff:ff", priority=3,
                  src="00:00:00:00:00:10"),
            {"t": 6, "id": "L1", "up": False},  # p2 离开：清 1 帧计 drop
            service(7, "p2", 1),                 # 非 forwarding：空服务
        ]
        result = run(config, events)
        svc = service_results(result)[0]
        self.assertEqual(svc["frames"], [])
        stats = {p["name"]: p for p in result["ports"]}
        self.assertEqual(stats["p2"]["drop"], 1)
        self.assertEqual(stats["p2"]["tx"], 0)

    def test_tail_drop_admission_counts(self):
        config = base_config([1, 1, 1, 1], cap=2, drop="tail")
        # 3 帧泛洪到 p2、p3，cap=2：每口第 3 帧被拒计 drop
        events = [
            frame(0, "p1", "ff:ff:ff:ff:ff:ff", priority=3,
                  src="00:00:00:00:00:10"),
            frame(1, "p1", "ff:ff:ff:ff:ff:ff", priority=3,
                  src="00:00:00:00:00:11"),
            frame(2, "p1", "ff:ff:ff:ff:ff:ff", priority=3,
                  src="00:00:00:00:00:12"),
        ]
        result = run(config, events)
        stats = {p["name"]: p for p in result["ports"]}
        # p2、p3 各收 2 入队、1 拒绝
        self.assertEqual(stats["p2"]["drop"], 1)
        self.assertEqual(stats["p3"]["drop"], 1)


class InvalidInputTests(unittest.TestCase):
    def test_bad_config_exit4_empty_stdout(self):
        config = base_config([1, 1, 1, 1])
        del config["qos"]
        code, out, err = run_cli(config, [])
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertIn("invalid_input", err.decode("utf-8"))

    def test_bad_qos_weights_exit4(self):
        config = base_config([1, 1, 1, 0])  # 权重须为正
        code, out, err = run_cli(config, [])
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")

    def test_bad_service_count_exit4(self):
        config = base_config([1, 1, 1, 1])
        code, out, err = run_cli(config, [service(0, "p2", 0)])
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")

    def test_bad_event_exit4_no_partial_output(self):
        config = base_config([1, 1, 1, 1])
        events = [service(0, "p2", 1), {"t": 1, "port": "nope", "count": 1}]
        code, out, err = run_cli(config, events)
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")  # 全量校验先于输出：无部分状态

    def test_output_is_compact_json_with_single_lf(self):
        config = base_config([1, 1, 1, 4])
        events = unicast_events([3], [("p2", 1)])
        code, out, err = run_cli(config, events)
        self.assertEqual(code, 0)
        self.assertTrue(out.endswith(b"\n"))
        self.assertFalse(out.endswith(b"\n\n"))
        text = out.decode("utf-8")
        # 紧凑：无 ", " / ": " 分隔
        self.assertNotIn(", ", text)
        self.assertNotIn('": ', text)
        json.loads(text)  # 合法 UTF-8 JSON


if __name__ == "__main__":
    unittest.main()
