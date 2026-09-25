#!/usr/bin/env python3
"""二层以太网交换机仿真（仅标准库）。"""

from collections import deque
import hashlib
import heapq
import json
import os
import re
import sys
import tempfile
import zlib

MAC_RE = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z")
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
CONFIG_KEYS = frozenset(("ports", "age"))
EVENT_KEYS = frozenset(("t", "port", "mac", "vlan"))
PORT_KEYS = frozenset(("name", "vlan", "up"))
FRAME_KEYS = frozenset(("t", "port", "src", "dst"))
PORT_KEYS_V2 = frozenset(("name", "mode", "pvid", "allowed", "untagged", "up"))
FRAME_KEYS_V2 = frozenset(("t", "port", "src", "dst", "vlan"))
PORT_MODES = ("access", "trunk", "hybrid")
STP_CONFIG_KEYS = frozenset(("bridges", "links", "delay"))
STP_LINK_KEYS = frozenset(("id", "x", "y", "cost", "up"))
STP_EVENT_KEYS = frozenset(("t", "id", "up"))
STP_TIMED_ROLES = ("root", "designated")
FORWARD_STP_CONFIG_KEYS = frozenset(
    ("bridges", "links", "delay", "bridge", "ports", "age")
)
STORM_CONFIG_KEYS = frozenset(
    ("bridges", "links", "delay", "bridge", "ports", "age", "storm")
)
STORM_KEYS = frozenset(("window", "limits", "move_limit", "hold"))
STORM_LIMIT_KEYS = frozenset(("broadcast", "multicast", "unknown"))
STORM_CATEGORIES = ("broadcast", "multicast", "unknown")
LAG_CONFIG_KEYS = frozenset(
    ("bridges", "links", "delay", "bridge", "ports", "age", "storm", "lags")
)
LAG_KEYS = frozenset(("name", "members", "hash"))
LAG_HASH_FIELDS = ("src", "dst", "vlan")
MEMBER_EVENT_KEYS = frozenset(("t", "member", "up"))
MIRROR_CONFIG_KEYS = frozenset(
    ("bridges", "links", "delay", "bridge", "ports", "age", "storm", "lags",
     "mirror")
)
MIRROR_KEYS = frozenset(("sources", "target", "direction"))
MIRROR_DIRECTIONS = ("ingress", "egress", "both")
ACL_CONFIG_KEYS = frozenset(
    ("bridges", "links", "delay", "bridge", "ports", "age", "storm", "lags",
     "mirror", "acl")
)
ACL_RULE_KEYS = frozenset(
    ("src", "dst", "vlan", "ethertype", "priority", "action", "to_vlan")
)
ACL_ACTIONS = ("allow", "drop", "remark")
FRAME_KEYS_ACL = frozenset(
    ("t", "port", "src", "dst", "vlan", "ethertype", "priority")
)
QOS_CONFIG_KEYS = frozenset(
    ("bridges", "links", "delay", "bridge", "ports", "age", "storm", "lags",
     "mirror", "acl", "qos")
)
QOS_KEYS = frozenset(("map", "cap", "mode", "weights", "drop"))
QOS_SCHED_MODES = ("sp", "wrr")
QOS_DROP_MODES = ("tail", "weighted")
SERVICE_EVENT_KEYS = frozenset(("t", "port", "count"))
SECURITY_CONFIG_KEYS = frozenset(
    ("bridges", "links", "delay", "bridge", "ports", "age", "storm", "lags",
     "mirror", "acl", "qos", "security")
)
SECURITY_KEYS = frozenset(("port", "limit", "action", "static"))
SECURITY_ACTIONS = ("drop", "shutdown")
SECURITY_STATIC_KEYS = frozenset(("mac", "vlan"))
RELOAD_EVENT_KEYS = frozenset(("t", "config"))
RELOAD_MUTABLE_KEYS = ("age", "acl", "security")


class InvalidInput(Exception):
    pass


class StpWorkLimit(Exception):
    pass


class FdbWorkLimit(Exception):
    pass


class ForwardWorkLimit(Exception):
    pass


class ForwardStpWorkLimit(Exception):
    pass


class StormWorkLimit(Exception):
    pass


class LagWorkLimit(Exception):
    pass


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _reject_constant(value):
    raise InvalidInput("invalid json constant")


def _object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidInput("duplicate json key")
        result[key] = value
    return result


def parse_json(raw):
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise InvalidInput("not utf-8")
    try:
        return json.loads(
            text,
            parse_constant=_reject_constant,
            object_pairs_hook=_object_pairs,
        )
    except (ValueError, RecursionError):
        raise InvalidInput("invalid json")


def _canonical(value):
    """配置值规范化：各层对象键按 Unicode 码点升序，数组保序。"""
    if isinstance(value, dict):
        return {key: _canonical(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [_canonical(item) for item in value]
    return value


def valid_mac(value):
    if not isinstance(value, str) or MAC_RE.fullmatch(value) is None:
        return False
    octets = [int(part, 16) for part in value.split(":")]
    if octets[0] & 1:  # 组播位（含广播）
        return False
    if not any(octets):  # 全零
        return False
    return True


def validate_config(config):
    if not isinstance(config, dict) or frozenset(config) != CONFIG_KEYS:
        raise InvalidInput("bad config")
    ports = config["ports"]
    age = config["age"]
    if not isinstance(ports, list):
        raise InvalidInput("ports must be a list")
    if not all(isinstance(p, str) and p for p in ports):
        raise InvalidInput("ports must be non-empty strings")
    if len(set(ports)) != len(ports):
        raise InvalidInput("ports must be distinct")
    if not _is_int(age) or age <= 0:
        raise InvalidInput("age must be a positive integer")
    return ports, age


def validate_events(events, ports):
    if not isinstance(events, list):
        raise InvalidInput("events must be a list")
    port_set = set(ports)
    result = []
    prev_t = None
    for event in events:
        if not isinstance(event, dict) or frozenset(event) != EVENT_KEYS:
            raise InvalidInput("bad event")
        t = event["t"]
        port = event["port"]
        mac = event["mac"]
        vlan = event["vlan"]
        if not _is_int(t) or t < 0:
            raise InvalidInput("bad t")
        if prev_t is not None and t < prev_t:
            raise InvalidInput("t not monotonic")
        prev_t = t
        if not isinstance(port, str) or port not in port_set:
            raise InvalidInput("unknown port")
        if not valid_mac(mac):
            raise InvalidInput("bad mac")
        if not _is_int(vlan) or not 1 <= vlan <= 4094:
            raise InvalidInput("bad vlan")
        result.append((t, port, mac, vlan))
    return result


def simulate(events, age):
    fdb = {}  # (vlan, mac) -> [port, seen]
    for t, port, mac, vlan in events:
        for key in [k for k, (_, seen) in fdb.items() if t - seen >= age]:
            del fdb[key]
        fdb[(vlan, mac)] = [port, t]
    entries = []
    for (vlan, mac), (port, seen) in sorted(fdb.items(), key=lambda item: item[0]):
        entries.append(
            {"vlan": vlan, "mac": mac, "port": port, "seen": seen}
        )
    return {"fdb": entries}


def fdb_work(events, age, limit):
    """按既有老化/学习规则用独立空映射无副作用预演并累计工作量。

    逐事件以老化前表项数 K 计 K+1（首事件成本 1，重复源与迁移同样计费）；
    累计等于上限合法，首次超过上限即抛 FdbWorkLimit。
    """
    fdb = {}  # (vlan, mac) -> [port, seen]
    work = 0
    for t, port, mac, vlan in events:
        work += len(fdb) + 1
        if work > limit:
            raise FdbWorkLimit
        for key in [k for k, (_, seen) in fdb.items() if t - seen >= age]:
            del fdb[key]
        fdb[(vlan, mac)] = [port, t]


def validate_forward_config(config):
    if not isinstance(config, dict) or frozenset(config) != CONFIG_KEYS:
        raise InvalidInput("bad config")
    ports = config["ports"]
    age = config["age"]
    if not isinstance(ports, list) or not ports:
        raise InvalidInput("ports must be a non-empty list")
    names = []
    for port in ports:
        if not isinstance(port, dict) or frozenset(port) != PORT_KEYS:
            raise InvalidInput("bad port")
        name = port["name"]
        vlan = port["vlan"]
        up = port["up"]
        if not isinstance(name, str) or not name:
            raise InvalidInput("bad port name")
        if not _is_int(vlan) or not 1 <= vlan <= 4094:
            raise InvalidInput("bad vlan")
        if not isinstance(up, bool):
            raise InvalidInput("bad up")
        names.append(name)
    if len(set(names)) != len(names):
        raise InvalidInput("ports must be distinct")
    if not _is_int(age) or age <= 0:
        raise InvalidInput("age must be a positive integer")
    return ports, age


def validate_frames(frames, ports):
    if not isinstance(frames, list):
        raise InvalidInput("frames must be a list")
    names = {port["name"] for port in ports}
    result = []
    prev_t = None
    for frame in frames:
        if not isinstance(frame, dict) or frozenset(frame) != FRAME_KEYS:
            raise InvalidInput("bad frame")
        t = frame["t"]
        port = frame["port"]
        src = frame["src"]
        dst = frame["dst"]
        if not _is_int(t) or t < 0:
            raise InvalidInput("bad t")
        if prev_t is not None and t < prev_t:
            raise InvalidInput("t not monotonic")
        prev_t = t
        if not isinstance(port, str) or port not in names:
            raise InvalidInput("unknown port")
        if not valid_mac(src):
            raise InvalidInput("bad src")
        if dst != BROADCAST_MAC and not valid_mac(dst):
            raise InvalidInput("bad dst")
        result.append((t, port, src, dst))
    return result


def forward(frames, ports, age):
    by_name = {port["name"]: port for port in ports}
    fdb = {}  # (vlan, mac) -> [port, seen]
    port_stats = {port["name"]: {"rx": 0, "tx": 0, "drop": 0} for port in ports}
    vlan_stats = {}
    for port in ports:
        vlan_stats.setdefault(port["vlan"], {"rx": 0, "tx": 0, "drop": 0})
    results = []
    for t, port_name, src, dst in frames:
        for key in [k for k, (_, seen) in fdb.items() if t - seen >= age]:
            del fdb[key]
        ingress = by_name[port_name]
        vlan = ingress["vlan"]
        port_stats[port_name]["rx"] += 1
        vlan_stats[vlan]["rx"] += 1
        egress = []
        action = "drop"
        if ingress["up"]:
            fdb[(vlan, src)] = [port_name, t]
            hit = None if dst == BROADCAST_MAC else fdb.get((vlan, dst))
            if hit is not None and hit[0] != port_name:
                egress = [hit[0]]
                action = "unicast"
            elif hit is None:
                egress = [
                    port["name"]
                    for port in ports
                    if port["vlan"] == vlan
                    and port["up"]
                    and port["name"] != port_name
                ]
                if egress:
                    action = "flood"
        for name in egress:
            port_stats[name]["tx"] += 1
            vlan_stats[by_name[name]["vlan"]]["tx"] += 1
        if not egress:
            port_stats[port_name]["drop"] += 1
            vlan_stats[vlan]["drop"] += 1
        results.append({"t": t, "action": action, "ports": egress})
    return {
        "results": results,
        "ports": [
            {
                "name": port["name"],
                "rx": port_stats[port["name"]]["rx"],
                "tx": port_stats[port["name"]]["tx"],
                "drop": port_stats[port["name"]]["drop"],
            }
            for port in ports
        ],
        "vlans": [
            {
                "vlan": vlan,
                "rx": vlan_stats[vlan]["rx"],
                "tx": vlan_stats[vlan]["tx"],
                "drop": vlan_stats[vlan]["drop"],
            }
            for vlan in sorted(vlan_stats)
        ],
    }


def _valid_vlan_id(value):
    return _is_int(value) and 1 <= value <= 4094


def _strictly_increasing(values):
    return all(values[i] < values[i + 1] for i in range(len(values) - 1))


def is_v2_config(config):
    if not isinstance(config, dict) or frozenset(config) != CONFIG_KEYS:
        return False
    ports = config["ports"]
    return (
        isinstance(ports, list)
        and bool(ports)
        and all(
            isinstance(port, dict) and frozenset(port) == PORT_KEYS_V2
            for port in ports
        )
    )


def validate_forward_config_v2(config):
    if not isinstance(config, dict) or frozenset(config) != CONFIG_KEYS:
        raise InvalidInput("bad config")
    ports = config["ports"]
    age = config["age"]
    if not isinstance(ports, list) or not ports:
        raise InvalidInput("ports must be a non-empty list")
    names = []
    for port in ports:
        if not isinstance(port, dict) or frozenset(port) != PORT_KEYS_V2:
            raise InvalidInput("bad port")
        name = port["name"]
        mode = port["mode"]
        pvid = port["pvid"]
        allowed = port["allowed"]
        untagged = port["untagged"]
        up = port["up"]
        if not isinstance(name, str) or not name:
            raise InvalidInput("bad port name")
        if mode not in PORT_MODES:
            raise InvalidInput("bad mode")
        if not _valid_vlan_id(pvid):
            raise InvalidInput("bad pvid")
        if (
            not isinstance(allowed, list)
            or not allowed
            or not all(_valid_vlan_id(vlan) for vlan in allowed)
            or not _strictly_increasing(allowed)
            or pvid not in allowed
        ):
            raise InvalidInput("bad allowed")
        if (
            not isinstance(untagged, list)
            or not all(_valid_vlan_id(vlan) for vlan in untagged)
            or not _strictly_increasing(untagged)
            or not all(vlan in allowed for vlan in untagged)
        ):
            raise InvalidInput("bad untagged")
        if not isinstance(up, bool):
            raise InvalidInput("bad up")
        if mode == "access" and (allowed != [pvid] or untagged != [pvid]):
            raise InvalidInput("bad access port")
        if mode == "trunk" and untagged:
            raise InvalidInput("bad trunk port")
        names.append(name)
    if len(set(names)) != len(names):
        raise InvalidInput("ports must be distinct")
    if not _is_int(age) or age <= 0:
        raise InvalidInput("age must be a positive integer")
    return ports, age


def validate_frames_v2(frames, ports):
    if not isinstance(frames, list):
        raise InvalidInput("frames must be a list")
    names = {port["name"] for port in ports}
    result = []
    prev_t = None
    for frame in frames:
        if not isinstance(frame, dict) or frozenset(frame) != FRAME_KEYS_V2:
            raise InvalidInput("bad frame")
        t = frame["t"]
        port = frame["port"]
        src = frame["src"]
        dst = frame["dst"]
        vlan = frame["vlan"]
        if not _is_int(t) or t < 0:
            raise InvalidInput("bad t")
        if prev_t is not None and t < prev_t:
            raise InvalidInput("t not monotonic")
        prev_t = t
        if not isinstance(port, str) or port not in names:
            raise InvalidInput("unknown port")
        if not valid_mac(src):
            raise InvalidInput("bad src")
        if dst != BROADCAST_MAC and not valid_mac(dst):
            raise InvalidInput("bad dst")
        if vlan is not None and not _valid_vlan_id(vlan):
            raise InvalidInput("bad vlan")
        result.append((t, port, src, dst, vlan))
    return result


def forward_v2(frames, ports, age):
    by_name = {port["name"]: port for port in ports}
    fdb = {}  # (vlan, mac) -> [port, seen]
    port_stats = {port["name"]: {"rx": 0, "tx": 0, "drop": 0} for port in ports}
    vlan_stats = {}
    for port in ports:
        for vlan in port["allowed"]:
            vlan_stats.setdefault(vlan, {"rx": 0, "tx": 0, "drop": 0})
    results = []
    for t, port_name, src, dst, tag in frames:
        for key in [k for k, (_, seen) in fdb.items() if t - seen >= age]:
            del fdb[key]
        ingress = by_name[port_name]
        port_stats[port_name]["rx"] += 1
        if tag is None:
            vlan = ingress["pvid"]
            rejected = False
        else:
            vlan = tag
            rejected = (
                ingress["mode"] == "access" or vlan not in ingress["allowed"]
            )
        if rejected:  # 拒绝帧丢弃且不学习、不计 VLAN
            port_stats[port_name]["drop"] += 1
            results.append({"t": t, "action": "drop", "ports": []})
            continue
        vlan_stats[vlan]["rx"] += 1
        egress = []
        action = "drop"
        if ingress["up"]:
            fdb[(vlan, src)] = [port_name, t]
            hit = None if dst == BROADCAST_MAC else fdb.get((vlan, dst))
            if hit is not None and hit[0] != port_name:
                target = by_name[hit[0]]
                if target["up"] and vlan in target["allowed"]:
                    egress = [hit[0]]
                    action = "unicast"
            elif hit is None:
                egress = [
                    port["name"]
                    for port in ports
                    if vlan in port["allowed"]
                    and port["up"]
                    and port["name"] != port_name
                ]
                if egress:
                    action = "flood"
        out_ports = []
        for name in egress:
            port_stats[name]["tx"] += 1
            vlan_stats[vlan]["tx"] += 1
            out_ports.append(
                {
                    "name": name,
                    "vlan": None if vlan in by_name[name]["untagged"] else vlan,
                }
            )
        if not egress:
            port_stats[port_name]["drop"] += 1
            vlan_stats[vlan]["drop"] += 1
        results.append({"t": t, "action": action, "ports": out_ports})
    return {
        "results": results,
        "ports": [
            {
                "name": port["name"],
                "rx": port_stats[port["name"]]["rx"],
                "tx": port_stats[port["name"]]["tx"],
                "drop": port_stats[port["name"]]["drop"],
            }
            for port in ports
        ],
        "vlans": [
            {
                "vlan": vlan,
                "rx": vlan_stats[vlan]["rx"],
                "tx": vlan_stats[vlan]["tx"],
                "drop": vlan_stats[vlan]["drop"],
            }
            for vlan in sorted(vlan_stats)
        ],
    }


def forward_work(frames, ports, age, limit):
    """旧式 access 转发的工作量预演：独立空 FDB，无副作用。

    P 为配置端口数；逐帧以该帧老化前表项数 K 计 K+P+1（拒绝、down 口、
    重复源及迁移帧均计费），随后按既有规则老化，仅入端口 up 时学习、
    刷新或迁移源 MAC。累计等于上限合法，首次超过即抛 ForwardWorkLimit。
    """
    by_name = {port["name"]: port for port in ports}
    width = len(ports) + 1
    fdb = {}  # (vlan, mac) -> [port, seen]
    work = 0
    for t, port_name, src, dst in frames:
        work += len(fdb) + width
        if work > limit:
            raise ForwardWorkLimit
        for key in [k for k, (_, seen) in fdb.items() if t - seen >= age]:
            del fdb[key]
        ingress = by_name[port_name]
        if ingress["up"]:
            fdb[(ingress["vlan"], src)] = [port_name, t]


def forward_work_v2(frames, ports, age, limit):
    """新式 802.1Q 转发的工作量预演：独立空 FDB，无副作用。

    计费规则同 forward_work；仅入端口 up 且通过 VLAN 准入时学习、
    刷新或迁移源 MAC。累计等于上限合法，首次超过即抛 ForwardWorkLimit。
    """
    by_name = {port["name"]: port for port in ports}
    width = len(ports) + 1
    fdb = {}  # (vlan, mac) -> [port, seen]
    work = 0
    for t, port_name, src, dst, tag in frames:
        work += len(fdb) + width
        if work > limit:
            raise ForwardWorkLimit
        for key in [k for k, (_, seen) in fdb.items() if t - seen >= age]:
            del fdb[key]
        ingress = by_name[port_name]
        if tag is None:
            vlan = ingress["pvid"]
            rejected = False
        else:
            vlan = tag
            rejected = (
                ingress["mode"] == "access" or vlan not in ingress["allowed"]
            )
        if not rejected and ingress["up"]:
            fdb[(vlan, src)] = [port_name, t]


def validate_stp_config(config):
    if not isinstance(config, dict) or frozenset(config) != STP_CONFIG_KEYS:
        raise InvalidInput("bad config")
    bridges = config["bridges"]
    links = config["links"]
    delay = config["delay"]
    if (
        not isinstance(bridges, list)
        or not bridges
        or not all(isinstance(name, str) and name for name in bridges)
        or len(set(bridges)) != len(bridges)
    ):
        raise InvalidInput("bad bridges")
    if not _is_int(delay) or delay <= 0:
        raise InvalidInput("bad delay")
    if not isinstance(links, list):
        raise InvalidInput("links must be a list")
    bridge_set = set(bridges)
    ids = []
    endpoints = set()
    parsed = []
    for link in links:
        if not isinstance(link, dict) or frozenset(link) != STP_LINK_KEYS:
            raise InvalidInput("bad link")
        lid = link["id"]
        cost = link["cost"]
        up = link["up"]
        if not isinstance(lid, str) or not lid:
            raise InvalidInput("bad link id")
        ends = []
        for end in (link["x"], link["y"]):
            if (
                not isinstance(end, list)
                or len(end) != 2
                or not isinstance(end[0], str)
                or end[0] not in bridge_set
                or not isinstance(end[1], str)
                or not end[1]
            ):
                raise InvalidInput("bad link endpoint")
            ends.append((end[0], end[1]))
        if ends[0][0] == ends[1][0]:
            raise InvalidInput("link endpoints on the same bridge")
        if ends[0] in endpoints or ends[1] in endpoints:
            raise InvalidInput("duplicate link endpoint")
        endpoints.update(ends)
        if not _is_int(cost) or cost <= 0:
            raise InvalidInput("bad cost")
        if not isinstance(up, bool):
            raise InvalidInput("bad up")
        ids.append(lid)
        parsed.append(
            {"id": lid, "x": ends[0], "y": ends[1], "cost": cost, "up": up}
        )
    if len(set(ids)) != len(ids):
        raise InvalidInput("link ids must be distinct")
    return bridges, parsed, delay


def validate_stp_events(events, link_ids):
    if not isinstance(events, list):
        raise InvalidInput("events must be a list")
    result = []
    prev_t = None
    for event in events:
        if not isinstance(event, dict) or frozenset(event) != STP_EVENT_KEYS:
            raise InvalidInput("bad event")
        t = event["t"]
        lid = event["id"]
        up = event["up"]
        if not _is_int(t) or t < 0:
            raise InvalidInput("bad t")
        if prev_t is not None and t < prev_t:
            raise InvalidInput("t not monotonic")
        prev_t = t
        if not isinstance(lid, str) or not lid or lid not in link_ids:
            raise InvalidInput("bad event id")
        if not isinstance(up, bool):
            raise InvalidInput("bad up")
        result.append((t, lid, up))
    return result


def stp_converge(bridges, links):
    """按当前 up 状态计算各桥分量根、根路径开销与端口角色。"""
    parent = {name: name for name in bridges}

    def find(name):
        while parent[name] != name:
            parent[name] = parent[parent[name]]
            name = parent[name]
        return name

    adjacency = {name: [] for name in bridges}
    for link in links:
        if not link["up"]:
            continue
        (bx, px), (by, py) = link["x"], link["y"]
        rx, ry = find(bx), find(by)
        if rx != ry:
            parent[rx] = ry
        adjacency[bx].append((px, by, py, link["cost"]))
        adjacency[by].append((py, bx, px, link["cost"]))
    members_of = {}
    for name in bridges:
        members_of.setdefault(find(name), []).append(name)
    root_of = {}
    for members in members_of.values():
        root = min(members)
        for name in members:
            root_of[name] = root
    cost = {name: 0 if root_of[name] == name else None for name in bridges}
    heap = [(0, name) for name in bridges if root_of[name] == name]
    heapq.heapify(heap)
    while heap:
        current, name = heapq.heappop(heap)
        if current > cost[name]:
            continue
        for _, neighbor, _, link_cost in adjacency[name]:
            new_cost = current + link_cost
            if cost[neighbor] is None or new_cost < cost[neighbor]:
                cost[neighbor] = new_cost
                heapq.heappush(heap, (new_cost, neighbor))
    roles = {name: {} for name in bridges}
    for name in bridges:
        if root_of[name] == name:
            continue
        best = None
        for port, neighbor, peer_port, link_cost in adjacency[name]:
            candidate = (cost[neighbor] + link_cost, neighbor, peer_port, port)
            if best is None or candidate < best:
                best = candidate
        if best is not None:
            roles[name][best[3]] = "root"
    for link in links:
        if not link["up"]:
            continue
        (bx, px), (by, py) = link["x"], link["y"]
        vector_x = (root_of[bx], cost[bx], bx, px)
        vector_y = (root_of[by], cost[by], by, py)
        winner = (bx, px) if vector_x < vector_y else (by, py)
        roles[winner[0]][winner[1]] = "designated"
    for link in links:
        for bridge, port in (link["x"], link["y"]):
            if link["up"]:
                roles[bridge].setdefault(port, "alternate")
            else:
                roles[bridge][port] = "disabled"
    return root_of, cost, roles


def stp(bridges, links, delay, events, max_work=None):
    by_id = {link["id"]: link for link in links}
    B = len(bridges)
    L = len(links)

    def up_count():
        return sum(1 for link in links if link["up"])

    def work_for(up):
        return B + L + 2 * up

    # 仅当 up 链路集合改变时才真正收敛；幂等事件复用缓存结果。
    # 先以独立链路状态无副作用预演，累计工作量超限即在仿真前报错。
    work = 0
    up = up_count()
    work += work_for(up)  # 初始 t=0 收敛
    sim_up = {lid: link["up"] for lid, link in by_id.items()}
    for _t, lid, new_up in events:
        if sim_up[lid] != new_up:
            sim_up[lid] = new_up
            up += 1 if new_up else -1
            work += work_for(up)
    if max_work is not None and work > max_work:
        raise StpWorkLimit

    previous = {}  # (bridge, port) -> 上一轮角色
    since = {}  # (bridge, port) -> 获得当前 root/designated 角色的时刻
    results = []
    cached = None  # 最近一次实际收敛的 (root_of, cost, roles)

    def snapshot(t):
        nonlocal cached
        if cached is None:
            cached = stp_converge(bridges, links)
        root_of, cost, roles = cached
        for name in bridges:
            for port, role in roles[name].items():
                key = (name, port)
                if role in STP_TIMED_ROLES:
                    if previous.get(key) != role:  # 同角色不重计时
                        since[key] = t
                else:
                    since.pop(key, None)
        previous.clear()
        for name in bridges:
            for port, role in roles[name].items():
                previous[(name, port)] = role
        entry = {"t": t, "bridges": []}
        for name in bridges:
            ports = []
            for port in sorted(roles[name]):
                role = roles[name][port]
                if role in STP_TIMED_ROLES:
                    elapsed = t - since[(name, port)]
                    if elapsed < delay:
                        state = "discarding"
                    elif elapsed < 2 * delay:
                        state = "learning"
                    else:
                        state = "forwarding"
                else:
                    state = "discarding"
                ports.append({"name": port, "role": role, "state": state})
            entry["bridges"].append(
                {
                    "name": name,
                    "root": root_of[name],
                    "cost": cost[name],
                    "ports": ports,
                }
            )
        results.append(entry)

    snapshot(0)
    for t, lid, new_up in events:
        if by_id[lid]["up"] != new_up:
            by_id[lid]["up"] = new_up
            cached = None
        snapshot(t)
    return {"results": results}


def valid_dst_mac(value):
    """目的 MAC：小写规范、非零，允许单播与组播（含广播）。"""
    if not isinstance(value, str) or MAC_RE.fullmatch(value) is None:
        return False
    return any(int(part, 16) for part in value.split(":"))


def validate_forward_stp_config(config):
    if (
        not isinstance(config, dict)
        or frozenset(config) != FORWARD_STP_CONFIG_KEYS
    ):
        raise InvalidInput("bad config")
    bridges, links, delay = validate_stp_config(
        {
            "bridges": config["bridges"],
            "links": config["links"],
            "delay": config["delay"],
        }
    )
    bridge = config["bridge"]
    if not isinstance(bridge, str) or bridge not in set(bridges):
        raise InvalidInput("bad bridge")
    ports, age = validate_forward_config_v2(
        {"ports": config["ports"], "age": config["age"]}
    )
    names = {port["name"] for port in ports}
    for link in links:
        for end_bridge, end_port in (link["x"], link["y"]):
            if end_bridge == bridge and end_port not in names:
                raise InvalidInput("bad bridge port")
    return bridges, links, delay, bridge, ports, age


def validate_forward_stp_events(events, ports, link_ids):
    if not isinstance(events, list):
        raise InvalidInput("events must be a list")
    names = {port["name"] for port in ports}
    result = []
    prev_t = None
    for event in events:
        if not isinstance(event, dict):
            raise InvalidInput("bad event")
        keys = frozenset(event)
        if keys == STP_EVENT_KEYS:
            t = event["t"]
            lid = event["id"]
            up = event["up"]
            if not _is_int(t) or t < 0:
                raise InvalidInput("bad t")
            if prev_t is not None and t < prev_t:
                raise InvalidInput("t not monotonic")
            if not isinstance(lid, str) or not lid or lid not in link_ids:
                raise InvalidInput("bad event id")
            if not isinstance(up, bool):
                raise InvalidInput("bad up")
            result.append(("link", t, lid, up))
        elif keys == FRAME_KEYS_V2:
            t = event["t"]
            port = event["port"]
            src = event["src"]
            dst = event["dst"]
            vlan = event["vlan"]
            if not _is_int(t) or t < 0:
                raise InvalidInput("bad t")
            if prev_t is not None and t < prev_t:
                raise InvalidInput("t not monotonic")
            if not isinstance(port, str) or port not in names:
                raise InvalidInput("unknown port")
            if not valid_mac(src):
                raise InvalidInput("bad src")
            if not valid_dst_mac(dst):
                raise InvalidInput("bad dst")
            if vlan is not None and not _valid_vlan_id(vlan):
                raise InvalidInput("bad vlan")
            result.append(("frame", t, port, src, dst, vlan))
        else:
            raise InvalidInput("bad event")
        prev_t = t
    return result


def forward_stp(bridges, links, delay, bridge_name, ports, age, events):
    by_id = {link["id"]: link for link in links}
    by_name = {port["name"]: port for port in ports}
    port_link = {}  # 本桥桥链路口名 -> link
    for link in links:
        for end_bridge, end_port in (link["x"], link["y"]):
            if end_bridge == bridge_name:
                port_link[end_port] = link
    fdb = {}  # (vlan, mac) -> [port, seen]
    port_stats = {
        port["name"]: {"rx": 0, "tx": 0, "drop": 0} for port in ports
    }
    vlan_stats = {}
    for port in ports:
        for vlan in port["allowed"]:
            vlan_stats.setdefault(vlan, {"rx": 0, "tx": 0, "drop": 0})
    results = []

    previous = {}  # (bridge, port) -> 上一轮角色
    since = {}  # (bridge, port) -> 获得当前 root/designated 角色的时刻
    roles = {name: {} for name in bridges}

    def converge(t):
        _, _, new_roles = stp_converge(bridges, links)
        for name in bridges:
            for port, role in new_roles[name].items():
                key = (name, port)
                if role in STP_TIMED_ROLES:
                    if previous.get(key) != role:  # 同角色不重计时
                        since[key] = t
                else:
                    since.pop(key, None)
        previous.clear()
        for name in bridges:
            for port, role in new_roles[name].items():
                previous[(name, port)] = role
        roles.clear()
        for name in bridges:
            roles[name] = new_roles[name]

    def forwarding_ports(t):
        result = set()
        for name, link in port_link.items():
            key = (bridge_name, name)
            role = roles[bridge_name][name]
            if (
                by_name[name]["up"]
                and link["up"]
                and role in STP_TIMED_ROLES
                and t - since[key] >= 2 * delay
            ):
                result.add(name)
        return result

    def port_status(name, t):
        """返回 (物理 up, STP 状态)；边缘口恒为 up 即 forwarding。"""
        port = by_name[name]
        link = port_link.get(name)
        if link is None:
            return port["up"], ("forwarding" if port["up"] else "down")
        if not port["up"]:
            return False, "down"
        if not link["up"]:
            return False, "disabled"
        role = roles[bridge_name][name]
        if role in STP_TIMED_ROLES:
            elapsed = t - since[(bridge_name, name)]
            if elapsed < delay:
                state = "discarding"
            elif elapsed < 2 * delay:
                state = "learning"
            else:
                state = "forwarding"
        else:
            state = "discarding"  # alternate
        return True, state

    converge(0)
    for item in events:
        t = item[1]
        for key in [k for k, (_, seen) in fdb.items() if t - seen >= age]:
            del fdb[key]
        if item[0] == "link":
            _, t, lid, up = item
            old_forwarding = forwarding_ports(t)
            by_id[lid]["up"] = up
            converge(t)
            for name in old_forwarding - forwarding_ports(t):
                for key in [k for k, (p, _) in fdb.items() if p == name]:
                    del fdb[key]
            continue
        _, t, port_name, src, dst, tag = item
        port_stats[port_name]["rx"] += 1
        if tag is None:
            vlan = by_name[port_name]["pvid"]
            rejected = False
        else:
            vlan = tag
            ingress = by_name[port_name]
            rejected = (
                ingress["mode"] == "access" or vlan not in ingress["allowed"]
            )
        if rejected:  # VLAN 准入拒绝：不学习、不计 VLAN
            port_stats[port_name]["drop"] += 1
            results.append({"t": t, "action": "drop", "ports": []})
            continue
        vlan_stats[vlan]["rx"] += 1
        _, state = port_status(port_name, t)
        egress = []
        action = "drop"
        if state == "learning":
            fdb[(vlan, src)] = [port_name, t]
        elif state == "forwarding":
            fdb[(vlan, src)] = [port_name, t]
            is_group = int(dst[:2], 16) & 1
            hit = None if is_group else fdb.get((vlan, dst))
            if hit is not None and hit[0] != port_name:
                target = hit[0]
                target_up, target_state = port_status(target, t)
                if (
                    target_up
                    and target_state == "forwarding"
                    and vlan in by_name[target]["allowed"]
                ):
                    egress = [target]
                    action = "unicast"
            elif hit is None:
                egress = [
                    port["name"]
                    for port in ports
                    if vlan in port["allowed"]
                    and port["name"] != port_name
                    and port_status(port["name"], t) == (True, "forwarding")
                ]
                if egress:
                    action = "flood"
        out_ports = []
        for name in egress:
            port_stats[name]["tx"] += 1
            vlan_stats[vlan]["tx"] += 1
            out_ports.append(
                {
                    "name": name,
                    "vlan": None if vlan in by_name[name]["untagged"] else vlan,
                }
            )
        if not egress:
            port_stats[port_name]["drop"] += 1
            vlan_stats[vlan]["drop"] += 1
        results.append({"t": t, "action": action, "ports": out_ports})
    return {
        "results": results,
        "ports": [
            {
                "name": port["name"],
                "rx": port_stats[port["name"]]["rx"],
                "tx": port_stats[port["name"]]["tx"],
                "drop": port_stats[port["name"]]["drop"],
            }
            for port in ports
        ],
        "vlans": [
            {
                "vlan": vlan,
                "rx": vlan_stats[vlan]["rx"],
                "tx": vlan_stats[vlan]["tx"],
                "drop": vlan_stats[vlan]["drop"],
            }
            for vlan in sorted(vlan_stats)
        ],
    }


def forward_stp_work(bridges, links, ports, events, limit):
    """forward-stp 的工作量预演：仅跟踪 up 链路数与帧数，无副作用。

    B、L、P 分别为桥、链路、端口数，U 为 up 链路数，E 为此前帧数。
    初始收敛计 B+L+2U；逐事件先按原规则老化：帧计 E+P+1 再令 E 加 1；
    链路先应用 up，再计 E*(P+1)+B+L+2U+2P+1，幂等也计。
    累计等于上限合法，首次超过即抛 ForwardStpWorkLimit。
    """
    B = len(bridges)
    L = len(links)
    P = len(ports)
    sim_up = {link["id"]: link["up"] for link in links}
    U = sum(1 for link in links if link["up"])
    E = 0
    work = B + L + 2 * U  # 初始收敛
    if work > limit:
        raise ForwardStpWorkLimit
    for item in events:
        if item[0] == "link":
            _, _, lid, up = item
            if sim_up[lid] != up:
                sim_up[lid] = up
                U += 1 if up else -1
            work += E * (P + 1) + B + L + 2 * U + 2 * P + 1
        else:
            work += E + P + 1
            E += 1
        if work > limit:
            raise ForwardStpWorkLimit


def validate_forward_stp_storm_config(config):
    if not isinstance(config, dict) or frozenset(config) != STORM_CONFIG_KEYS:
        raise InvalidInput("bad config")
    bridges, links, delay, bridge, ports, age = validate_forward_stp_config(
        {
            "bridges": config["bridges"],
            "links": config["links"],
            "delay": config["delay"],
            "bridge": config["bridge"],
            "ports": config["ports"],
            "age": config["age"],
        }
    )
    storm = config["storm"]
    if not isinstance(storm, dict) or frozenset(storm) != STORM_KEYS:
        raise InvalidInput("bad storm")
    window = storm["window"]
    limits = storm["limits"]
    move_limit = storm["move_limit"]
    hold = storm["hold"]
    for name, value in (
        ("window", window),
        ("move_limit", move_limit),
        ("hold", hold),
    ):
        if not _is_int(value) or value <= 0:
            raise InvalidInput("bad storm " + name)
    if not isinstance(limits, dict) or frozenset(limits) != STORM_LIMIT_KEYS:
        raise InvalidInput("bad storm limits")
    for name in STORM_CATEGORIES:
        if not _is_int(limits[name]) or limits[name] <= 0:
            raise InvalidInput("bad storm limit")
    return bridges, links, delay, bridge, ports, age, storm


def forward_stp_storm(
    bridges, links, delay, bridge_name, ports, age, storm, events
):
    window = storm["window"]
    limits = storm["limits"]
    move_limit = storm["move_limit"]
    hold = storm["hold"]
    by_id = {link["id"]: link for link in links}
    by_name = {port["name"]: port for port in ports}
    port_link = {}  # 本桥桥链路口名 -> link
    for link in links:
        for end_bridge, end_port in (link["x"], link["y"]):
            if end_bridge == bridge_name:
                port_link[end_port] = link
    fdb = {}  # (vlan, mac) -> [port, seen]
    port_stats = {
        port["name"]: {"rx": 0, "tx": 0, "drop": 0} for port in ports
    }
    vlan_stats = {}
    for port in ports:
        for vlan in port["allowed"]:
            vlan_stats.setdefault(vlan, {"rx": 0, "tx": 0, "drop": 0})
    rate_queues = {}  # (入端口, vlan, 类别) -> 放行时刻 deque
    move_queues = {}  # (vlan, src) -> 迁移时刻 deque
    last_learn = {}  # (vlan, src) -> 最后学习端口
    blocked = {}  # (入端口, vlan) -> 封锁截止时刻
    results = []

    previous = {}  # (bridge, port) -> 上一轮角色
    since = {}  # (bridge, port) -> 获得当前 root/designated 角色的时刻
    roles = {name: {} for name in bridges}

    def converge(t):
        _, _, new_roles = stp_converge(bridges, links)
        for name in bridges:
            for port, role in new_roles[name].items():
                key = (name, port)
                if role in STP_TIMED_ROLES:
                    if previous.get(key) != role:  # 同角色不重计时
                        since[key] = t
                else:
                    since.pop(key, None)
        previous.clear()
        for name in bridges:
            for port, role in new_roles[name].items():
                previous[(name, port)] = role
        roles.clear()
        for name in bridges:
            roles[name] = new_roles[name]

    def forwarding_ports(t):
        result = set()
        for name, link in port_link.items():
            key = (bridge_name, name)
            role = roles[bridge_name][name]
            if (
                by_name[name]["up"]
                and link["up"]
                and role in STP_TIMED_ROLES
                and t - since[key] >= 2 * delay
            ):
                result.add(name)
        return result

    def port_status(name, t):
        """返回 (物理 up, STP 状态)；边缘口恒为 up 即 forwarding。"""
        port = by_name[name]
        link = port_link.get(name)
        if link is None:
            return port["up"], ("forwarding" if port["up"] else "down")
        if not port["up"]:
            return False, "down"
        if not link["up"]:
            return False, "disabled"
        role = roles[bridge_name][name]
        if role in STP_TIMED_ROLES:
            elapsed = t - since[(bridge_name, name)]
            if elapsed < delay:
                state = "discarding"
            elif elapsed < 2 * delay:
                state = "learning"
            else:
                state = "forwarding"
        else:
            state = "discarding"  # alternate
        return True, state

    def suppress(t, port_name, vlan, src, dst, state):
        """风暴控制：返回 True 表示本帧被抑制（不学习、不发送）。"""
        if (port_name, vlan) in blocked:  # 封锁帧不检测
            return True
        if state not in ("learning", "forwarding"):
            return False
        is_group = int(dst[:2], 16) & 1
        if dst == BROADCAST_MAC:
            category = "broadcast"
        elif is_group:
            category = "multicast"
        else:
            category = None if fdb.get((vlan, dst)) else "unknown"
        if category is not None:
            queue = rate_queues.get((port_name, vlan, category))
            if queue is None:
                queue = deque(maxlen=limits[category])
                rate_queues[(port_name, vlan, category)] = queue
            while queue and t - queue[0] >= window:
                queue.popleft()
            if len(queue) >= limits[category]:  # 余量已达上限：丢弃
                return True
        prev = last_learn.get((vlan, src))
        if prev is not None and prev != port_name:  # 学习端口迁移
            queue = move_queues.get((vlan, src))
            if queue is None:
                queue = deque(maxlen=move_limit)
                move_queues[(vlan, src)] = queue
            while queue and t - queue[0] >= window:
                queue.popleft()
            queue.append(t)
            if len(queue) >= move_limit:  # 迁移数达上限：封锁入端口/VLAN 并丢弃
                blocked[(port_name, vlan)] = t + hold
                return True
        if category is not None:  # 速率名额仅在帧实际放行时占用
            rate_queues[(port_name, vlan, category)].append(t)
        fdb[(vlan, src)] = [port_name, t]
        last_learn[(vlan, src)] = port_name
        return False

    converge(0)
    for item in events:
        t = item[1]
        for key in [k for k, (_, seen) in fdb.items() if t - seen >= age]:
            del fdb[key]
        for key in [k for k, until in blocked.items() if t >= until]:
            del blocked[key]
        if item[0] == "link":
            _, t, lid, up = item
            if by_id[lid]["up"] != up:  # 幂等链路事件不重算拓扑
                old_forwarding = forwarding_ports(t)
                by_id[lid]["up"] = up
                converge(t)
                for name in old_forwarding - forwarding_ports(t):
                    for key in [k for k, (p, _) in fdb.items() if p == name]:
                        del fdb[key]
            continue
        _, t, port_name, src, dst, tag = item
        port_stats[port_name]["rx"] += 1
        if tag is None:
            vlan = by_name[port_name]["pvid"]
            rejected = False
        else:
            vlan = tag
            ingress = by_name[port_name]
            rejected = (
                ingress["mode"] == "access" or vlan not in ingress["allowed"]
            )
        if rejected:  # VLAN 准入拒绝：不学习、不计 VLAN
            port_stats[port_name]["drop"] += 1
            results.append({"t": t, "action": "drop", "ports": []})
            continue
        vlan_stats[vlan]["rx"] += 1
        _, state = port_status(port_name, t)
        suppressed = suppress(t, port_name, vlan, src, dst, state)
        egress = []
        action = "drop"
        if not suppressed and state == "forwarding":
            is_group = int(dst[:2], 16) & 1
            hit = None if is_group else fdb.get((vlan, dst))
            if hit is not None and hit[0] != port_name:
                target = hit[0]
                target_up, target_state = port_status(target, t)
                if (
                    target_up
                    and target_state == "forwarding"
                    and vlan in by_name[target]["allowed"]
                ):
                    egress = [target]
                    action = "unicast"
            elif hit is None:
                egress = [
                    port["name"]
                    for port in ports
                    if vlan in port["allowed"]
                    and port["name"] != port_name
                    and port_status(port["name"], t)
                    == (True, "forwarding")
                ]
                if egress:
                    action = "flood"
        out_ports = []
        for name in egress:
            port_stats[name]["tx"] += 1
            vlan_stats[vlan]["tx"] += 1
            out_ports.append(
                {
                    "name": name,
                    "vlan": None if vlan in by_name[name]["untagged"] else vlan,
                }
            )
        if not egress:
            port_stats[port_name]["drop"] += 1
            vlan_stats[vlan]["drop"] += 1
        results.append({"t": t, "action": action, "ports": out_ports})
    return {
        "results": results,
        "ports": [
            {
                "name": port["name"],
                "rx": port_stats[port["name"]]["rx"],
                "tx": port_stats[port["name"]]["tx"],
                "drop": port_stats[port["name"]]["drop"],
            }
            for port in ports
        ],
        "vlans": [
            {
                "vlan": vlan,
                "rx": vlan_stats[vlan]["rx"],
                "tx": vlan_stats[vlan]["tx"],
                "drop": vlan_stats[vlan]["drop"],
            }
            for vlan in sorted(vlan_stats)
        ],
    }


def forward_stp_storm_work(
    bridges, links, delay, bridge_name, ports, age, storm, events, limit
):
    """forward-stp-storm 的工作量预演：独立链路副本与空状态，无副作用。

    B、L、P 为桥、链路、端口数，U 为 up 链路数；初始收敛计 B+L+2U。
    各事件在按 t 老化 FDB 与解封前取 K=FDB 项数、H=封锁项数、
    Q=速率与迁移队列时间戳总数：帧计 K+H+Q+P+1；链路先应用 up，
    改变计 K+H+Q+B+L+2U+2P+1，幂等计 K+H+Q+1。再按既有规则处理
    并更新预演状态。累计等于上限合法，首次超过即抛 StormWorkLimit。
    """
    window = storm["window"]
    limits = storm["limits"]
    move_limit = storm["move_limit"]
    hold = storm["hold"]
    B = len(bridges)
    L = len(links)
    P = len(ports)
    sim_links = [dict(link) for link in links]
    by_id = {link["id"]: link for link in sim_links}
    by_name = {port["name"]: port for port in ports}
    port_link = {}  # 本桥桥链路口名 -> link
    for link in sim_links:
        for end_bridge, end_port in (link["x"], link["y"]):
            if end_bridge == bridge_name:
                port_link[end_port] = link
    fdb = {}  # (vlan, mac) -> [port, seen]
    rate_queues = {}  # (入端口, vlan, 类别) -> 放行时刻 deque
    move_queues = {}  # (vlan, src) -> 迁移时刻 deque
    last_learn = {}  # (vlan, src) -> 最后学习端口
    blocked = {}  # (入端口, vlan) -> 封锁截止时刻

    previous = {}  # (bridge, port) -> 上一轮角色
    since = {}  # (bridge, port) -> 获得当前 root/designated 角色的时刻
    roles = {name: {} for name in bridges}

    def converge(t):
        _, _, new_roles = stp_converge(bridges, sim_links)
        for name in bridges:
            for port, role in new_roles[name].items():
                key = (name, port)
                if role in STP_TIMED_ROLES:
                    if previous.get(key) != role:  # 同角色不重计时
                        since[key] = t
                else:
                    since.pop(key, None)
        previous.clear()
        for name in bridges:
            for port, role in new_roles[name].items():
                previous[(name, port)] = role
        roles.clear()
        for name in bridges:
            roles[name] = new_roles[name]

    def forwarding_ports(t):
        result = set()
        for name, link in port_link.items():
            key = (bridge_name, name)
            role = roles[bridge_name][name]
            if (
                by_name[name]["up"]
                and link["up"]
                and role in STP_TIMED_ROLES
                and t - since[key] >= 2 * delay
            ):
                result.add(name)
        return result

    def port_status(name, t):
        """返回 (物理 up, STP 状态)；边缘口恒为 up 即 forwarding。"""
        port = by_name[name]
        link = port_link.get(name)
        if link is None:
            return port["up"], ("forwarding" if port["up"] else "down")
        if not port["up"]:
            return False, "down"
        if not link["up"]:
            return False, "disabled"
        role = roles[bridge_name][name]
        if role in STP_TIMED_ROLES:
            elapsed = t - since[(bridge_name, name)]
            if elapsed < delay:
                state = "discarding"
            elif elapsed < 2 * delay:
                state = "learning"
            else:
                state = "forwarding"
        else:
            state = "discarding"  # alternate
        return True, state

    def suppress(t, port_name, vlan, src, dst, state):
        """风暴控制：返回 True 表示本帧被抑制（不学习、不发送）。"""
        if (port_name, vlan) in blocked:  # 封锁帧不检测
            return True
        if state not in ("learning", "forwarding"):
            return False
        is_group = int(dst[:2], 16) & 1
        if dst == BROADCAST_MAC:
            category = "broadcast"
        elif is_group:
            category = "multicast"
        else:
            category = None if fdb.get((vlan, dst)) else "unknown"
        if category is not None:
            queue = rate_queues.get((port_name, vlan, category))
            if queue is None:
                queue = deque(maxlen=limits[category])
                rate_queues[(port_name, vlan, category)] = queue
            while queue and t - queue[0] >= window:
                queue.popleft()
            if len(queue) >= limits[category]:  # 余量已达上限：丢弃
                return True
        prev = last_learn.get((vlan, src))
        if prev is not None and prev != port_name:  # 学习端口迁移
            queue = move_queues.get((vlan, src))
            if queue is None:
                queue = deque(maxlen=move_limit)
                move_queues[(vlan, src)] = queue
            while queue and t - queue[0] >= window:
                queue.popleft()
            queue.append(t)
            if len(queue) >= move_limit:  # 迁移数达上限：封锁入端口/VLAN 并丢弃
                blocked[(port_name, vlan)] = t + hold
                return True
        if category is not None:  # 速率名额仅在帧实际放行时占用
            rate_queues[(port_name, vlan, category)].append(t)
        fdb[(vlan, src)] = [port_name, t]
        last_learn[(vlan, src)] = port_name
        return False

    U = sum(1 for link in sim_links if link["up"])
    work = B + L + 2 * U  # 初始收敛
    if work > limit:
        raise StormWorkLimit
    converge(0)
    for item in events:
        t = item[1]
        # 老化与解封前取 K、H、Q
        K = len(fdb)
        H = len(blocked)
        Q = sum(len(queue) for queue in rate_queues.values()) + sum(
            len(queue) for queue in move_queues.values()
        )
        changed = False
        if item[0] == "link":
            up = item[3]
            changed = by_id[item[2]]["up"] != up
            if changed:  # 先应用 up 再计费
                U += 1 if up else -1
                work += K + H + Q + B + L + 2 * U + 2 * P + 1
            else:
                work += K + H + Q + 1
        else:
            work += K + H + Q + P + 1
        if work > limit:
            raise StormWorkLimit
        # 以下按既有规则处理并更新预演状态
        for key in [k for k, (_, seen) in fdb.items() if t - seen >= age]:
            del fdb[key]
        for key in [k for k, until in blocked.items() if t >= until]:
            del blocked[key]
        if item[0] == "link":
            if changed:  # 幂等链路事件不重算拓扑
                old_forwarding = forwarding_ports(t)
                by_id[item[2]]["up"] = item[3]
                converge(t)
                for name in old_forwarding - forwarding_ports(t):
                    for key in [k for k, (p, _) in fdb.items() if p == name]:
                        del fdb[key]
            continue
        _, _, port_name, src, dst, tag = item
        if tag is None:
            vlan = by_name[port_name]["pvid"]
            rejected = False
        else:
            vlan = tag
            ingress = by_name[port_name]
            rejected = (
                ingress["mode"] == "access" or vlan not in ingress["allowed"]
            )
        if rejected:  # VLAN 准入拒绝：不学习
            continue
        _, state = port_status(port_name, t)
        suppress(t, port_name, vlan, src, dst, state)


def validate_lag_config(config):
    if not isinstance(config, dict) or frozenset(config) != LAG_CONFIG_KEYS:
        raise InvalidInput("bad config")
    bridges, links, delay, bridge, ports, age, storm = (
        validate_forward_stp_storm_config(
            {
                "bridges": config["bridges"],
                "links": config["links"],
                "delay": config["delay"],
                "bridge": config["bridge"],
                "ports": config["ports"],
                "age": config["age"],
                "storm": config["storm"],
            }
        )
    )
    lags = config["lags"]
    if not isinstance(lags, list) or not lags:
        raise InvalidInput("bad lags")
    by_name = {port["name"]: port for port in ports}
    names = []
    used = set()
    parsed = []
    for lag in lags:
        if not isinstance(lag, dict) or frozenset(lag) != LAG_KEYS:
            raise InvalidInput("bad lag")
        name = lag["name"]
        members = lag["members"]
        hash_fields = lag["hash"]
        if not isinstance(name, str) or not name or name in by_name:
            raise InvalidInput("bad lag name")
        if (
            not isinstance(members, list)
            or len(members) < 2
            or not all(isinstance(m, str) and m in by_name for m in members)
            or len(set(members)) != len(members)
        ):
            raise InvalidInput("bad lag members")
        if used.intersection(members):
            raise InvalidInput("lag members must be globally distinct")
        used.update(members)
        first = by_name[members[0]]
        for member in members[1:]:
            port = by_name[member]
            if (
                port["mode"] != first["mode"]
                or port["pvid"] != first["pvid"]
                or port["allowed"] != first["allowed"]
                or port["untagged"] != first["untagged"]
            ):
                raise InvalidInput("lag members must share vlan config")
        if (
            not isinstance(hash_fields, list)
            or not hash_fields
            or len(set(hash_fields)) != len(hash_fields)
            or any(field not in LAG_HASH_FIELDS for field in hash_fields)
            or [f for f in LAG_HASH_FIELDS if f in hash_fields] != hash_fields
        ):
            raise InvalidInput("bad lag hash")
        names.append(name)
        parsed.append(
            {"name": name, "members": list(members), "hash": list(hash_fields)}
        )
    if len(set(names)) != len(names):
        raise InvalidInput("lag names must be distinct")
    return bridges, links, delay, bridge, ports, age, storm, parsed


def validate_mirror_config(config):
    if not isinstance(config, dict) or frozenset(config) != MIRROR_CONFIG_KEYS:
        raise InvalidInput("bad config")
    bridges, links, delay, bridge, ports, age, storm, lags = validate_lag_config(
        {
            "bridges": config["bridges"],
            "links": config["links"],
            "delay": config["delay"],
            "bridge": config["bridge"],
            "ports": config["ports"],
            "age": config["age"],
            "storm": config["storm"],
            "lags": config["lags"],
        }
    )
    mirror = config["mirror"]
    if not isinstance(mirror, dict) or frozenset(mirror) != MIRROR_KEYS:
        raise InvalidInput("bad mirror")
    sources = mirror["sources"]
    target = mirror["target"]
    direction = mirror["direction"]
    by_name = {port["name"]: port for port in ports}
    member_set = {member for lag in lags for member in lag["members"]}
    if (
        not isinstance(sources, list)
        or not sources
        or not all(isinstance(name, str) and name in by_name for name in sources)
        or len(set(sources)) != len(sources)
    ):
        raise InvalidInput("bad mirror sources")
    if not isinstance(target, str) or target not in by_name:
        raise InvalidInput("bad mirror target")
    if target in sources or target in member_set:
        raise InvalidInput("bad mirror target")
    if direction not in MIRROR_DIRECTIONS:
        raise InvalidInput("bad mirror direction")
    parsed = {
        "sources": list(sources),
        "target": target,
        "direction": direction,
    }
    return bridges, links, delay, bridge, ports, age, storm, lags, parsed


def validate_acl_config(config):
    if not isinstance(config, dict) or frozenset(config) != ACL_CONFIG_KEYS:
        raise InvalidInput("bad config")
    (
        bridges,
        links,
        delay,
        bridge,
        ports,
        age,
        storm,
        lags,
        mirror,
    ) = validate_mirror_config(
        {
            "bridges": config["bridges"],
            "links": config["links"],
            "delay": config["delay"],
            "bridge": config["bridge"],
            "ports": config["ports"],
            "age": config["age"],
            "storm": config["storm"],
            "lags": config["lags"],
            "mirror": config["mirror"],
        }
    )
    acl = config["acl"]
    if not isinstance(acl, list) or not acl:
        raise InvalidInput("bad acl")
    parsed = []
    for rule in acl:
        if not isinstance(rule, dict) or frozenset(rule) != ACL_RULE_KEYS:
            raise InvalidInput("bad acl rule")
        src = rule["src"]
        dst = rule["dst"]
        vlan = rule["vlan"]
        ethertype = rule["ethertype"]
        priority = rule["priority"]
        action = rule["action"]
        to_vlan = rule["to_vlan"]
        if src is not None and not valid_mac(src):
            raise InvalidInput("bad acl src")
        if dst is not None and not valid_dst_mac(dst):
            raise InvalidInput("bad acl dst")
        if vlan is not None and not _valid_vlan_id(vlan):
            raise InvalidInput("bad acl vlan")
        if ethertype is not None and not (
            _is_int(ethertype) and 0 <= ethertype <= 65535
        ):
            raise InvalidInput("bad acl ethertype")
        if priority is not None and not (
            _is_int(priority) and 0 <= priority <= 7
        ):
            raise InvalidInput("bad acl priority")
        if action not in ACL_ACTIONS:
            raise InvalidInput("bad acl action")
        if action == "remark":
            if not _valid_vlan_id(to_vlan):
                raise InvalidInput("bad acl to_vlan")
        elif to_vlan is not None:
            raise InvalidInput("bad acl to_vlan")
        parsed.append(
            {
                "src": src,
                "dst": dst,
                "vlan": vlan,
                "ethertype": ethertype,
                "priority": priority,
                "action": action,
                "to_vlan": to_vlan,
            }
        )
    return bridges, links, delay, bridge, ports, age, storm, lags, mirror, parsed


def validate_qos_config(config):
    if not isinstance(config, dict) or frozenset(config) != QOS_CONFIG_KEYS:
        raise InvalidInput("bad config")
    (
        bridges,
        links,
        delay,
        bridge,
        ports,
        age,
        storm,
        lags,
        mirror,
        acl,
    ) = validate_acl_config(
        {
            "bridges": config["bridges"],
            "links": config["links"],
            "delay": config["delay"],
            "bridge": config["bridge"],
            "ports": config["ports"],
            "age": config["age"],
            "storm": config["storm"],
            "lags": config["lags"],
            "mirror": config["mirror"],
            "acl": config["acl"],
        }
    )
    qos = config["qos"]
    if not isinstance(qos, dict) or frozenset(qos) != QOS_KEYS:
        raise InvalidInput("bad qos")
    mapping = qos["map"]
    cap = qos["cap"]
    mode = qos["mode"]
    weights = qos["weights"]
    drop = qos["drop"]
    if (
        not isinstance(mapping, list)
        or len(mapping) != 8
        or not all(_is_int(q) and 0 <= q <= 3 for q in mapping)
    ):
        raise InvalidInput("bad qos map")
    if not _is_int(cap) or cap <= 0:
        raise InvalidInput("bad qos cap")
    if mode not in QOS_SCHED_MODES:
        raise InvalidInput("bad qos mode")
    if (
        not isinstance(weights, list)
        or len(weights) != 4
        or not all(_is_int(w) and w > 0 for w in weights)
    ):
        raise InvalidInput("bad qos weights")
    if drop not in QOS_DROP_MODES:
        raise InvalidInput("bad qos drop")
    parsed = {
        "map": list(mapping),
        "cap": cap,
        "mode": mode,
        "weights": list(weights),
        "drop": drop,
    }
    return (
        bridges, links, delay, bridge, ports, age, storm, lags, mirror, acl,
        parsed,
    )


def validate_security_config(config):
    if not isinstance(config, dict) or frozenset(config) != SECURITY_CONFIG_KEYS:
        raise InvalidInput("bad config")
    (
        bridges,
        links,
        delay,
        bridge,
        ports,
        age,
        storm,
        lags,
        mirror,
        acl,
        qos,
    ) = validate_qos_config(
        {
            "bridges": config["bridges"],
            "links": config["links"],
            "delay": config["delay"],
            "bridge": config["bridge"],
            "ports": config["ports"],
            "age": config["age"],
            "storm": config["storm"],
            "lags": config["lags"],
            "mirror": config["mirror"],
            "acl": config["acl"],
            "qos": config["qos"],
        }
    )
    security = config["security"]
    if not isinstance(security, list):
        raise InvalidInput("bad security")
    names = {port["name"] for port in ports}
    seen = set()
    statics = set()  # 全局互异的 (vlan, mac)
    parsed = []
    for entry in security:
        if not isinstance(entry, dict) or frozenset(entry) != SECURITY_KEYS:
            raise InvalidInput("bad security entry")
        port = entry["port"]
        limit = entry["limit"]
        action = entry["action"]
        static = entry["static"]
        if not isinstance(port, str) or port not in names or port in seen:
            raise InvalidInput("bad security port")
        seen.add(port)
        if not _is_int(limit) or limit < 0:
            raise InvalidInput("bad security limit")
        if action not in SECURITY_ACTIONS:
            raise InvalidInput("bad security action")
        if not isinstance(static, list):
            raise InvalidInput("bad security static")
        items = []
        for item in static:
            if (
                not isinstance(item, dict)
                or frozenset(item) != SECURITY_STATIC_KEYS
            ):
                raise InvalidInput("bad security static entry")
            mac = item["mac"]
            vlan = item["vlan"]
            if not valid_mac(mac):
                raise InvalidInput("bad security static mac")
            if not _valid_vlan_id(vlan):
                raise InvalidInput("bad security static vlan")
            if (vlan, mac) in statics:
                raise InvalidInput("security static must be globally distinct")
            statics.add((vlan, mac))
            items.append({"mac": mac, "vlan": vlan})
        parsed.append(
            {
                "port": port,
                "limit": limit,
                "action": action,
                "static": items,
            }
        )
    if seen != names:  # 须互异覆盖全部物理口
        raise InvalidInput("security must cover all ports")
    return (
        bridges, links, delay, bridge, ports, age, storm, lags, mirror, acl,
        qos, parsed,
    )


def validate_lag_events(events, ports, link_ids, lags):
    if not isinstance(events, list):
        raise InvalidInput("events must be a list")
    names = {port["name"] for port in ports}
    member_set = {member for lag in lags for member in lag["members"]}
    result = []
    prev_t = None
    for event in events:
        if not isinstance(event, dict):
            raise InvalidInput("bad event")
        keys = frozenset(event)
        if keys == STP_EVENT_KEYS:
            t = event["t"]
            lid = event["id"]
            up = event["up"]
            if not _is_int(t) or t < 0:
                raise InvalidInput("bad t")
            if prev_t is not None and t < prev_t:
                raise InvalidInput("t not monotonic")
            if not isinstance(lid, str) or not lid or lid not in link_ids:
                raise InvalidInput("bad event id")
            if not isinstance(up, bool):
                raise InvalidInput("bad up")
            result.append(("link", t, lid, up))
        elif keys == MEMBER_EVENT_KEYS:
            t = event["t"]
            member = event["member"]
            up = event["up"]
            if not _is_int(t) or t < 0:
                raise InvalidInput("bad t")
            if prev_t is not None and t < prev_t:
                raise InvalidInput("t not monotonic")
            if not isinstance(member, str) or member not in member_set:
                raise InvalidInput("bad event member")
            if not isinstance(up, bool):
                raise InvalidInput("bad up")
            result.append(("member", t, member, up))
        elif keys == FRAME_KEYS_V2:
            t = event["t"]
            port = event["port"]
            src = event["src"]
            dst = event["dst"]
            vlan = event["vlan"]
            if not _is_int(t) or t < 0:
                raise InvalidInput("bad t")
            if prev_t is not None and t < prev_t:
                raise InvalidInput("t not monotonic")
            if not isinstance(port, str) or port not in names:
                raise InvalidInput("unknown port")
            if not valid_mac(src):
                raise InvalidInput("bad src")
            if not valid_dst_mac(dst):
                raise InvalidInput("bad dst")
            if vlan is not None and not _valid_vlan_id(vlan):
                raise InvalidInput("bad vlan")
            result.append(("frame", t, port, src, dst, vlan))
        else:
            raise InvalidInput("bad event")
        prev_t = t
    return result


def validate_acl_events(events, ports, link_ids, lags):
    if not isinstance(events, list):
        raise InvalidInput("events must be a list")
    names = {port["name"] for port in ports}
    member_set = {member for lag in lags for member in lag["members"]}
    result = []
    prev_t = None
    for event in events:
        if not isinstance(event, dict):
            raise InvalidInput("bad event")
        keys = frozenset(event)
        if keys == STP_EVENT_KEYS:
            t = event["t"]
            lid = event["id"]
            up = event["up"]
            if not _is_int(t) or t < 0:
                raise InvalidInput("bad t")
            if prev_t is not None and t < prev_t:
                raise InvalidInput("t not monotonic")
            if not isinstance(lid, str) or not lid or lid not in link_ids:
                raise InvalidInput("bad event id")
            if not isinstance(up, bool):
                raise InvalidInput("bad up")
            result.append(("link", t, lid, up))
        elif keys == MEMBER_EVENT_KEYS:
            t = event["t"]
            member = event["member"]
            up = event["up"]
            if not _is_int(t) or t < 0:
                raise InvalidInput("bad t")
            if prev_t is not None and t < prev_t:
                raise InvalidInput("t not monotonic")
            if not isinstance(member, str) or member not in member_set:
                raise InvalidInput("bad event member")
            if not isinstance(up, bool):
                raise InvalidInput("bad up")
            result.append(("member", t, member, up))
        elif keys == FRAME_KEYS_ACL:
            t = event["t"]
            port = event["port"]
            src = event["src"]
            dst = event["dst"]
            vlan = event["vlan"]
            ethertype = event["ethertype"]
            priority = event["priority"]
            if not _is_int(t) or t < 0:
                raise InvalidInput("bad t")
            if prev_t is not None and t < prev_t:
                raise InvalidInput("t not monotonic")
            if not isinstance(port, str) or port not in names:
                raise InvalidInput("unknown port")
            if not valid_mac(src):
                raise InvalidInput("bad src")
            if not valid_dst_mac(dst):
                raise InvalidInput("bad dst")
            if vlan is not None and not _valid_vlan_id(vlan):
                raise InvalidInput("bad vlan")
            if not _is_int(ethertype) or not 0 <= ethertype <= 65535:
                raise InvalidInput("bad ethertype")
            if not _is_int(priority) or not 0 <= priority <= 7:
                raise InvalidInput("bad priority")
            result.append(
                ("frame", t, port, src, dst, vlan, ethertype, priority)
            )
        else:
            raise InvalidInput("bad event")
        prev_t = t
    return result


def validate_qos_events(events, ports, link_ids, lags):
    if not isinstance(events, list):
        raise InvalidInput("events must be a list")
    names = {port["name"] for port in ports}
    member_set = {member for lag in lags for member in lag["members"]}
    result = []
    prev_t = None
    for event in events:
        if not isinstance(event, dict):
            raise InvalidInput("bad event")
        keys = frozenset(event)
        if keys == STP_EVENT_KEYS:
            t = event["t"]
            lid = event["id"]
            up = event["up"]
            if not _is_int(t) or t < 0:
                raise InvalidInput("bad t")
            if prev_t is not None and t < prev_t:
                raise InvalidInput("t not monotonic")
            if not isinstance(lid, str) or not lid or lid not in link_ids:
                raise InvalidInput("bad event id")
            if not isinstance(up, bool):
                raise InvalidInput("bad up")
            result.append(("link", t, lid, up))
        elif keys == MEMBER_EVENT_KEYS:
            t = event["t"]
            member = event["member"]
            up = event["up"]
            if not _is_int(t) or t < 0:
                raise InvalidInput("bad t")
            if prev_t is not None and t < prev_t:
                raise InvalidInput("t not monotonic")
            if not isinstance(member, str) or member not in member_set:
                raise InvalidInput("bad event member")
            if not isinstance(up, bool):
                raise InvalidInput("bad up")
            result.append(("member", t, member, up))
        elif keys == SERVICE_EVENT_KEYS:
            t = event["t"]
            port = event["port"]
            count = event["count"]
            if not _is_int(t) or t < 0:
                raise InvalidInput("bad t")
            if prev_t is not None and t < prev_t:
                raise InvalidInput("t not monotonic")
            if not isinstance(port, str) or port not in names:
                raise InvalidInput("unknown port")
            if not _is_int(count) or count <= 0:
                raise InvalidInput("bad count")
            result.append(("service", t, port, count))
        elif keys == FRAME_KEYS_ACL:
            t = event["t"]
            port = event["port"]
            src = event["src"]
            dst = event["dst"]
            vlan = event["vlan"]
            ethertype = event["ethertype"]
            priority = event["priority"]
            if not _is_int(t) or t < 0:
                raise InvalidInput("bad t")
            if prev_t is not None and t < prev_t:
                raise InvalidInput("t not monotonic")
            if not isinstance(port, str) or port not in names:
                raise InvalidInput("unknown port")
            if not valid_mac(src):
                raise InvalidInput("bad src")
            if not valid_dst_mac(dst):
                raise InvalidInput("bad dst")
            if vlan is not None and not _valid_vlan_id(vlan):
                raise InvalidInput("bad vlan")
            if not _is_int(ethertype) or not 0 <= ethertype <= 65535:
                raise InvalidInput("bad ethertype")
            if not _is_int(priority) or not 0 <= priority <= 7:
                raise InvalidInput("bad priority")
            result.append(
                ("frame", t, port, src, dst, vlan, ethertype, priority)
            )
        else:
            raise InvalidInput("bad event")
        prev_t = t
    return result


def validate_reload_events(events, ports, link_ids, lags, config):
    """reload 子命令事件：普通事件沿用 qos，另含 {t, config} 重载事件。

    返回 (事件序列, 末态原始配置)；重载事件的 config 须为完整有效配置，
    且仅 age/acl/security 可与当时配置不同。全部校验先于执行。
    """
    if not isinstance(events, list):
        raise InvalidInput("events must be a list")
    names = {port["name"] for port in ports}
    member_set = {member for lag in lags for member in lag["members"]}
    result = []
    prev_t = None
    current = config
    for event in events:
        if not isinstance(event, dict):
            raise InvalidInput("bad event")
        keys = frozenset(event)
        if keys == STP_EVENT_KEYS:
            t = event["t"]
            lid = event["id"]
            up = event["up"]
            if not _is_int(t) or t < 0:
                raise InvalidInput("bad t")
            if prev_t is not None and t < prev_t:
                raise InvalidInput("t not monotonic")
            if not isinstance(lid, str) or not lid or lid not in link_ids:
                raise InvalidInput("bad event id")
            if not isinstance(up, bool):
                raise InvalidInput("bad up")
            result.append(("link", t, lid, up))
        elif keys == MEMBER_EVENT_KEYS:
            t = event["t"]
            member = event["member"]
            up = event["up"]
            if not _is_int(t) or t < 0:
                raise InvalidInput("bad t")
            if prev_t is not None and t < prev_t:
                raise InvalidInput("t not monotonic")
            if not isinstance(member, str) or member not in member_set:
                raise InvalidInput("bad event member")
            if not isinstance(up, bool):
                raise InvalidInput("bad up")
            result.append(("member", t, member, up))
        elif keys == SERVICE_EVENT_KEYS:
            t = event["t"]
            port = event["port"]
            count = event["count"]
            if not _is_int(t) or t < 0:
                raise InvalidInput("bad t")
            if prev_t is not None and t < prev_t:
                raise InvalidInput("t not monotonic")
            if not isinstance(port, str) or port not in names:
                raise InvalidInput("unknown port")
            if not _is_int(count) or count <= 0:
                raise InvalidInput("bad count")
            result.append(("service", t, port, count))
        elif keys == FRAME_KEYS_ACL:
            t = event["t"]
            port = event["port"]
            src = event["src"]
            dst = event["dst"]
            vlan = event["vlan"]
            ethertype = event["ethertype"]
            priority = event["priority"]
            if not _is_int(t) or t < 0:
                raise InvalidInput("bad t")
            if prev_t is not None and t < prev_t:
                raise InvalidInput("t not monotonic")
            if not isinstance(port, str) or port not in names:
                raise InvalidInput("unknown port")
            if not valid_mac(src):
                raise InvalidInput("bad src")
            if not valid_dst_mac(dst):
                raise InvalidInput("bad dst")
            if vlan is not None and not _valid_vlan_id(vlan):
                raise InvalidInput("bad vlan")
            if not _is_int(ethertype) or not 0 <= ethertype <= 65535:
                raise InvalidInput("bad ethertype")
            if not _is_int(priority) or not 0 <= priority <= 7:
                raise InvalidInput("bad priority")
            result.append(
                ("frame", t, port, src, dst, vlan, ethertype, priority)
            )
        elif keys == RELOAD_EVENT_KEYS:
            t = event["t"]
            new_config = event["config"]
            if not _is_int(t) or t < 0:
                raise InvalidInput("bad t")
            if prev_t is not None and t < prev_t:
                raise InvalidInput("t not monotonic")
            if not isinstance(new_config, dict):
                raise InvalidInput("bad reload config")
            (
                _bridges,
                _links,
                _delay,
                _bridge,
                _ports,
                new_age,
                _storm,
                _lags,
                _mirror,
                new_acl,
                _qos,
                new_security,
            ) = validate_security_config(new_config)
            for key in current:
                if (
                    key not in RELOAD_MUTABLE_KEYS
                    and new_config[key] != current[key]
                ):
                    raise InvalidInput("reload may only change age/acl/security")
            changes = []
            for key in RELOAD_MUTABLE_KEYS:
                if new_config[key] != current[key]:
                    changes.append(
                        {
                            "key": key,
                            "before": _canonical(current[key]),
                            "after": _canonical(new_config[key]),
                        }
                    )
            current = new_config
            result.append(
                ("reload", t, new_age, new_acl, new_security, changes)
            )
        else:
            raise InvalidInput("bad event")
        prev_t = t
    return result, current


def lag_work(
    bridges, links, delay, bridge_name, ports, age, storm, lags, events, limit
):
    """lag 的工作量预演：独立链路副本与空状态，无副作用。

    B、L、P、M 为桥、链路、端口、成员数，U 为 up 链路数；初始收敛计
    B+L+2U。各事件在按 t 老化 FDB 与解封前取 K=FDB 项数、H=封锁项数、
    Q=速率与迁移队列时间戳总数：帧计 K+H+Q+P+M+1；链路先应用 up，
    改变计 K+H+Q+B+L+2U+2P+1，幂等计 K+H+Q+1；成员事件均计
    K+H+Q+1。再按既有规则处理并更新预演状态。累计等于上限合法，
    首次超过即抛 LagWorkLimit。
    """
    window = storm["window"]
    limits = storm["limits"]
    move_limit = storm["move_limit"]
    hold = storm["hold"]
    B = len(bridges)
    L = len(links)
    P = len(ports)
    M = sum(len(lag["members"]) for lag in lags)
    sim_links = [dict(link) for link in links]
    by_id = {link["id"]: link for link in sim_links}
    by_name = {port["name"]: port for port in ports}
    lag_of = {}  # 成员物理口 -> lag
    member_up = {}  # 成员物理口 -> 动态可用（初始可用）
    for lag in lags:
        for member in lag["members"]:
            lag_of[member] = lag
            member_up[member] = True
    port_link = {}  # 本桥桥链路口名 -> link
    for link in sim_links:
        for end_bridge, end_port in (link["x"], link["y"]):
            if end_bridge == bridge_name:
                port_link[end_port] = link
    fdb = {}  # (vlan, mac) -> [逻辑口（物理口名或 lag 名）, seen]
    rate_queues = {}  # (入端口, vlan, 类别) -> 放行时刻 deque
    move_queues = {}  # (vlan, src) -> 迁移时刻 deque
    last_learn = {}  # (vlan, src) -> 最后学习逻辑口
    blocked = {}  # (入端口, vlan) -> 封锁截止时刻

    previous = {}  # (bridge, port) -> 上一轮角色
    since = {}  # (bridge, port) -> 获得当前 root/designated 角色的时刻
    roles = {name: {} for name in bridges}

    def converge(t):
        _, _, new_roles = stp_converge(bridges, sim_links)
        for name in bridges:
            for port, role in new_roles[name].items():
                key = (name, port)
                if role in STP_TIMED_ROLES:
                    if previous.get(key) != role:  # 同角色不重计时
                        since[key] = t
                else:
                    since.pop(key, None)
        previous.clear()
        for name in bridges:
            for port, role in new_roles[name].items():
                previous[(name, port)] = role
        roles.clear()
        for name in bridges:
            roles[name] = new_roles[name]

    def forwarding_ports(t):
        result = set()
        for name, link in port_link.items():
            key = (bridge_name, name)
            role = roles[bridge_name][name]
            if (
                by_name[name]["up"]
                and link["up"]
                and role in STP_TIMED_ROLES
                and t - since[key] >= 2 * delay
            ):
                result.add(name)
        return result

    def port_status(name, t):
        """返回 (物理 up, STP 状态)；边缘口恒为 up 即 forwarding。"""
        port = by_name[name]
        link = port_link.get(name)
        if link is None:
            return port["up"], ("forwarding" if port["up"] else "down")
        if not port["up"]:
            return False, "down"
        if not link["up"]:
            return False, "disabled"
        role = roles[bridge_name][name]
        if role in STP_TIMED_ROLES:
            elapsed = t - since[(bridge_name, name)]
            if elapsed < delay:
                state = "discarding"
            elif elapsed < 2 * delay:
                state = "learning"
            else:
                state = "forwarding"
        else:
            state = "discarding"  # alternate
        return True, state

    def member_available(name, t, vlan):
        """成员可用：动态 up、端口 up、STP forwarding 且允许该 VLAN。"""
        port = by_name[name]
        if not member_up[name] or not port["up"] or vlan not in port["allowed"]:
            return False
        return port_status(name, t) == (True, "forwarding")

    def suppress(t, port_name, vlan, src, dst, state, learn_port):
        """风暴控制：返回 True 表示本帧被抑制（不学习、不发送）。"""
        if (port_name, vlan) in blocked:  # 封锁帧不检测
            return True
        if state not in ("learning", "forwarding"):
            return False
        is_group = int(dst[:2], 16) & 1
        if dst == BROADCAST_MAC:
            category = "broadcast"
        elif is_group:
            category = "multicast"
        else:
            category = None if fdb.get((vlan, dst)) else "unknown"
        if category is not None:
            queue = rate_queues.get((port_name, vlan, category))
            if queue is None:
                queue = deque(maxlen=limits[category])
                rate_queues[(port_name, vlan, category)] = queue
            while queue and t - queue[0] >= window:
                queue.popleft()
            if len(queue) >= limits[category]:  # 余量已达上限：丢弃
                return True
        prev = last_learn.get((vlan, src))
        if prev is not None and prev != learn_port:  # 学习端口迁移
            queue = move_queues.get((vlan, src))
            if queue is None:
                queue = deque(maxlen=move_limit)
                move_queues[(vlan, src)] = queue
            while queue and t - queue[0] >= window:
                queue.popleft()
            queue.append(t)
            if len(queue) >= move_limit:  # 迁移数达上限：封锁入端口/VLAN 并丢弃
                blocked[(port_name, vlan)] = t + hold
                return True
        if category is not None:  # 速率名额仅在帧实际放行时占用
            rate_queues[(port_name, vlan, category)].append(t)
        fdb[(vlan, src)] = [learn_port, t]
        last_learn[(vlan, src)] = learn_port
        return False

    U = sum(1 for link in sim_links if link["up"])
    work = B + L + 2 * U  # 初始收敛
    if work > limit:
        raise LagWorkLimit
    converge(0)
    for item in events:
        t = item[1]
        # 老化与解封前取 K、H、Q
        K = len(fdb)
        H = len(blocked)
        Q = sum(len(queue) for queue in rate_queues.values()) + sum(
            len(queue) for queue in move_queues.values()
        )
        changed = False
        if item[0] == "link":
            up = item[3]
            changed = by_id[item[2]]["up"] != up
            if changed:  # 先应用 up 再计费
                U += 1 if up else -1
                work += K + H + Q + B + L + 2 * U + 2 * P + 1
            else:
                work += K + H + Q + 1
        elif item[0] == "member":
            work += K + H + Q + 1
        else:
            work += K + H + Q + P + M + 1
        if work > limit:
            raise LagWorkLimit
        # 以下按既有规则处理并更新预演状态
        for key in [k for k, (_, seen) in fdb.items() if t - seen >= age]:
            del fdb[key]
        for key in [k for k, until in blocked.items() if t >= until]:
            del blocked[key]
        if item[0] == "link":
            if changed:  # 幂等链路事件不重算拓扑
                old_forwarding = forwarding_ports(t)
                by_id[item[2]]["up"] = item[3]
                converge(t)
                for name in old_forwarding - forwarding_ports(t):
                    for key in [k for k, (p, _) in fdb.items() if p == name]:
                        del fdb[key]
            continue
        if item[0] == "member":
            member_up[item[2]] = item[3]  # 幂等无作用；可用性变化不清 FDB
            continue
        _, _, port_name, src, dst, tag = item
        if tag is None:
            vlan = by_name[port_name]["pvid"]
            rejected = False
        else:
            vlan = tag
            ingress = by_name[port_name]
            rejected = (
                ingress["mode"] == "access" or vlan not in ingress["allowed"]
            )
        if rejected:  # VLAN 准入拒绝：不学习
            continue
        ingress_lag = lag_of.get(port_name)
        if ingress_lag is not None:
            usable = member_available(port_name, t, vlan)
            state = "forwarding" if usable else None
        else:
            usable = True
            _, state = port_status(port_name, t)
        if usable:  # 不可用成员入帧丢弃且不学习
            learn_port = ingress_lag["name"] if ingress_lag else port_name
            suppress(t, port_name, vlan, src, dst, state, learn_port)


def forward_lag(
    bridges, links, delay, bridge_name, ports, age, storm, lags, events
):
    window = storm["window"]
    limits = storm["limits"]
    move_limit = storm["move_limit"]
    hold = storm["hold"]
    by_id = {link["id"]: link for link in links}
    by_name = {port["name"]: port for port in ports}
    lag_by_name = {lag["name"]: lag for lag in lags}
    lag_of = {}  # 成员物理口 -> lag
    member_up = {}  # 成员物理口 -> 动态可用（初始可用）
    for lag in lags:
        for member in lag["members"]:
            lag_of[member] = lag
            member_up[member] = True
    port_link = {}  # 本桥桥链路口名 -> link
    for link in links:
        for end_bridge, end_port in (link["x"], link["y"]):
            if end_bridge == bridge_name:
                port_link[end_port] = link
    fdb = {}  # (vlan, mac) -> [逻辑口（物理口名或 lag 名）, seen]
    port_stats = {
        port["name"]: {"rx": 0, "tx": 0, "drop": 0} for port in ports
    }
    vlan_stats = {}
    for port in ports:
        for vlan in port["allowed"]:
            vlan_stats.setdefault(vlan, {"rx": 0, "tx": 0, "drop": 0})
    rate_queues = {}  # (入端口, vlan, 类别) -> 放行时刻 deque
    move_queues = {}  # (vlan, src) -> 迁移时刻 deque
    last_learn = {}  # (vlan, src) -> 最后学习逻辑口
    blocked = {}  # (入端口, vlan) -> 封锁截止时刻
    results = []

    previous = {}  # (bridge, port) -> 上一轮角色
    since = {}  # (bridge, port) -> 获得当前 root/designated 角色的时刻
    roles = {name: {} for name in bridges}

    def converge(t):
        _, _, new_roles = stp_converge(bridges, links)
        for name in bridges:
            for port, role in new_roles[name].items():
                key = (name, port)
                if role in STP_TIMED_ROLES:
                    if previous.get(key) != role:  # 同角色不重计时
                        since[key] = t
                else:
                    since.pop(key, None)
        previous.clear()
        for name in bridges:
            for port, role in new_roles[name].items():
                previous[(name, port)] = role
        roles.clear()
        for name in bridges:
            roles[name] = new_roles[name]

    def forwarding_ports(t):
        result = set()
        for name, link in port_link.items():
            key = (bridge_name, name)
            role = roles[bridge_name][name]
            if (
                by_name[name]["up"]
                and link["up"]
                and role in STP_TIMED_ROLES
                and t - since[key] >= 2 * delay
            ):
                result.add(name)
        return result

    def port_status(name, t):
        """返回 (物理 up, STP 状态)；边缘口恒为 up 即 forwarding。"""
        port = by_name[name]
        link = port_link.get(name)
        if link is None:
            return port["up"], ("forwarding" if port["up"] else "down")
        if not port["up"]:
            return False, "down"
        if not link["up"]:
            return False, "disabled"
        role = roles[bridge_name][name]
        if role in STP_TIMED_ROLES:
            elapsed = t - since[(bridge_name, name)]
            if elapsed < delay:
                state = "discarding"
            elif elapsed < 2 * delay:
                state = "learning"
            else:
                state = "forwarding"
        else:
            state = "discarding"  # alternate
        return True, state

    def member_available(name, t, vlan):
        """成员可用：动态 up、端口 up、STP forwarding 且允许该 VLAN。"""
        port = by_name[name]
        if not member_up[name] or not port["up"] or vlan not in port["allowed"]:
            return False
        return port_status(name, t) == (True, "forwarding")

    def lag_candidates(lag, t, vlan):
        """可用候选成员，按 members 顺序。"""
        return [
            member
            for member in lag["members"]
            if member_available(member, t, vlan)
        ]

    def lag_pick(lag, candidates, src, dst, vlan):
        parts = []
        for field in lag["hash"]:
            if field == "src":
                parts.append(src)
            elif field == "dst":
                parts.append(dst)
            else:
                parts.append(str(vlan))
        digest = zlib.crc32("|".join(parts).encode("utf-8")) & 0xFFFFFFFF
        return candidates[digest % len(candidates)]

    def suppress(t, port_name, vlan, src, dst, state, learn_port):
        """风暴控制：返回 True 表示本帧被抑制（不学习、不发送）。"""
        if (port_name, vlan) in blocked:  # 封锁帧不检测
            return True
        if state not in ("learning", "forwarding"):
            return False
        is_group = int(dst[:2], 16) & 1
        if dst == BROADCAST_MAC:
            category = "broadcast"
        elif is_group:
            category = "multicast"
        else:
            category = None if fdb.get((vlan, dst)) else "unknown"
        if category is not None:
            queue = rate_queues.get((port_name, vlan, category))
            if queue is None:
                queue = deque(maxlen=limits[category])
                rate_queues[(port_name, vlan, category)] = queue
            while queue and t - queue[0] >= window:
                queue.popleft()
            if len(queue) >= limits[category]:  # 余量已达上限：丢弃
                return True
        prev = last_learn.get((vlan, src))
        if prev is not None and prev != learn_port:  # 学习端口迁移
            queue = move_queues.get((vlan, src))
            if queue is None:
                queue = deque(maxlen=move_limit)
                move_queues[(vlan, src)] = queue
            while queue and t - queue[0] >= window:
                queue.popleft()
            queue.append(t)
            if len(queue) >= move_limit:  # 迁移数达上限：封锁入端口/VLAN 并丢弃
                blocked[(port_name, vlan)] = t + hold
                return True
        if category is not None:  # 速率名额仅在帧实际放行时占用
            rate_queues[(port_name, vlan, category)].append(t)
        fdb[(vlan, src)] = [learn_port, t]
        last_learn[(vlan, src)] = learn_port
        return False

    converge(0)
    for item in events:
        t = item[1]
        for key in [k for k, (_, seen) in fdb.items() if t - seen >= age]:
            del fdb[key]
        for key in [k for k, until in blocked.items() if t >= until]:
            del blocked[key]
        if item[0] == "link":
            _, t, lid, up = item
            if by_id[lid]["up"] != up:  # 幂等链路事件不重算拓扑
                old_forwarding = forwarding_ports(t)
                by_id[lid]["up"] = up
                converge(t)
                for name in old_forwarding - forwarding_ports(t):
                    for key in [k for k, (p, _) in fdb.items() if p == name]:
                        del fdb[key]
            continue
        if item[0] == "member":
            _, t, member, up = item
            member_up[member] = up  # 幂等无作用；可用性变化不清 FDB
            continue
        _, t, port_name, src, dst, tag = item
        port_stats[port_name]["rx"] += 1
        if tag is None:
            vlan = by_name[port_name]["pvid"]
            rejected = False
        else:
            vlan = tag
            ingress = by_name[port_name]
            rejected = (
                ingress["mode"] == "access" or vlan not in ingress["allowed"]
            )
        if rejected:  # VLAN 准入拒绝：不学习、不计 VLAN
            port_stats[port_name]["drop"] += 1
            results.append({"t": t, "action": "drop", "ports": []})
            continue
        vlan_stats[vlan]["rx"] += 1
        ingress_lag = lag_of.get(port_name)
        if ingress_lag is not None:
            usable = member_available(port_name, t, vlan)
            state = "forwarding" if usable else None
        else:
            usable = True
            _, state = port_status(port_name, t)
        egress = []
        action = "drop"
        if usable:  # 不可用成员入帧丢弃且不学习
            learn_port = ingress_lag["name"] if ingress_lag else port_name
            suppressed = suppress(
                t, port_name, vlan, src, dst, state, learn_port
            )
            if not suppressed and state == "forwarding":
                is_group = int(dst[:2], 16) & 1
                hit = None if is_group else fdb.get((vlan, dst))
                if hit is not None and hit[0] != learn_port:
                    target = hit[0]
                    target_lag = lag_by_name.get(target)
                    if target_lag is not None:
                        candidates = lag_candidates(target_lag, t, vlan)
                        if candidates:  # 无候选按无出口丢弃
                            egress = [
                                lag_pick(target_lag, candidates, src, dst, vlan)
                            ]
                            action = "unicast"
                    else:
                        target_up, target_state = port_status(target, t)
                        if (
                            target_up
                            and target_state == "forwarding"
                            and vlan in by_name[target]["allowed"]
                        ):
                            egress = [target]
                            action = "unicast"
                elif hit is None:
                    selected = {}  # lag 名 -> 本帧选中的成员
                    for lag in lags:
                        if ingress_lag is not None and lag is ingress_lag:
                            continue  # 禁止组内回送
                        candidates = lag_candidates(lag, t, vlan)
                        if candidates:
                            selected[lag["name"]] = lag_pick(
                                lag, candidates, src, dst, vlan
                            )
                    for port in ports:
                        name = port["name"]
                        lag = lag_of.get(name)
                        if lag is not None:
                            if selected.get(lag["name"]) == name:
                                egress.append(name)
                        elif (
                            vlan in port["allowed"]
                            and name != port_name
                            and port_status(name, t) == (True, "forwarding")
                        ):
                            egress.append(name)
                    if egress:
                        action = "flood"
        out_ports = []
        for name in egress:
            port_stats[name]["tx"] += 1
            vlan_stats[vlan]["tx"] += 1
            out_ports.append(
                {
                    "name": name,
                    "vlan": None if vlan in by_name[name]["untagged"] else vlan,
                }
            )
        if not egress:
            port_stats[port_name]["drop"] += 1
            vlan_stats[vlan]["drop"] += 1
        results.append({"t": t, "action": action, "ports": out_ports})
    return {
        "results": results,
        "ports": [
            {
                "name": port["name"],
                "rx": port_stats[port["name"]]["rx"],
                "tx": port_stats[port["name"]]["tx"],
                "drop": port_stats[port["name"]]["drop"],
            }
            for port in ports
        ],
        "vlans": [
            {
                "vlan": vlan,
                "rx": vlan_stats[vlan]["rx"],
                "tx": vlan_stats[vlan]["tx"],
                "drop": vlan_stats[vlan]["drop"],
            }
            for vlan in sorted(vlan_stats)
        ],
    }


def forward_mirror(
    bridges, links, delay, bridge_name, ports, age, storm, lags, mirror, events
):
    window = storm["window"]
    limits = storm["limits"]
    move_limit = storm["move_limit"]
    hold = storm["hold"]
    sources = mirror["sources"]
    mirror_target = mirror["target"]
    direction = mirror["direction"]
    source_set = set(sources)
    by_id = {link["id"]: link for link in links}
    by_name = {port["name"]: port for port in ports}
    lag_by_name = {lag["name"]: lag for lag in lags}
    lag_of = {}  # 成员物理口 -> lag
    member_up = {}  # 成员物理口 -> 动态可用（初始可用）
    for lag in lags:
        for member in lag["members"]:
            lag_of[member] = lag
            member_up[member] = True
    port_link = {}  # 本桥桥链路口名 -> link
    for link in links:
        for end_bridge, end_port in (link["x"], link["y"]):
            if end_bridge == bridge_name:
                port_link[end_port] = link
    fdb = {}  # (vlan, mac) -> [逻辑口（物理口名或 lag 名）, seen]
    port_stats = {
        port["name"]: {"rx": 0, "tx": 0, "drop": 0} for port in ports
    }
    vlan_stats = {}
    for port in ports:
        for vlan in port["allowed"]:
            vlan_stats.setdefault(vlan, {"rx": 0, "tx": 0, "drop": 0})
    rate_queues = {}  # (入端口, vlan, 类别) -> 放行时刻 deque
    move_queues = {}  # (vlan, src) -> 迁移时刻 deque
    last_learn = {}  # (vlan, src) -> 最后学习逻辑口
    blocked = {}  # (入端口, vlan) -> 封锁截止时刻
    results = []

    previous = {}  # (bridge, port) -> 上一轮角色
    since = {}  # (bridge, port) -> 获得当前 root/designated 角色的时刻
    roles = {name: {} for name in bridges}

    def converge(t):
        _, _, new_roles = stp_converge(bridges, links)
        for name in bridges:
            for port, role in new_roles[name].items():
                key = (name, port)
                if role in STP_TIMED_ROLES:
                    if previous.get(key) != role:  # 同角色不重计时
                        since[key] = t
                else:
                    since.pop(key, None)
        previous.clear()
        for name in bridges:
            for port, role in new_roles[name].items():
                previous[(name, port)] = role
        roles.clear()
        for name in bridges:
            roles[name] = new_roles[name]

    def forwarding_ports(t):
        result = set()
        for name, link in port_link.items():
            key = (bridge_name, name)
            role = roles[bridge_name][name]
            if (
                by_name[name]["up"]
                and link["up"]
                and role in STP_TIMED_ROLES
                and t - since[key] >= 2 * delay
            ):
                result.add(name)
        return result

    def port_status(name, t):
        """返回 (物理 up, STP 状态)；边缘口恒为 up 即 forwarding。"""
        port = by_name[name]
        link = port_link.get(name)
        if link is None:
            return port["up"], ("forwarding" if port["up"] else "down")
        if not port["up"]:
            return False, "down"
        if not link["up"]:
            return False, "disabled"
        role = roles[bridge_name][name]
        if role in STP_TIMED_ROLES:
            elapsed = t - since[(bridge_name, name)]
            if elapsed < delay:
                state = "discarding"
            elif elapsed < 2 * delay:
                state = "learning"
            else:
                state = "forwarding"
        else:
            state = "discarding"  # alternate
        return True, state

    def member_available(name, t, vlan):
        """成员可用：动态 up、端口 up、STP forwarding 且允许该 VLAN。"""
        port = by_name[name]
        if not member_up[name] or not port["up"] or vlan not in port["allowed"]:
            return False
        return port_status(name, t) == (True, "forwarding")

    def lag_candidates(lag, t, vlan):
        """可用候选成员，按 members 顺序。"""
        return [
            member
            for member in lag["members"]
            if member_available(member, t, vlan)
        ]

    def lag_pick(lag, candidates, src, dst, vlan):
        parts = []
        for field in lag["hash"]:
            if field == "src":
                parts.append(src)
            elif field == "dst":
                parts.append(dst)
            else:
                parts.append(str(vlan))
        digest = zlib.crc32("|".join(parts).encode("utf-8")) & 0xFFFFFFFF
        return candidates[digest % len(candidates)]

    def suppress(t, port_name, vlan, src, dst, state, learn_port):
        """风暴控制：返回 True 表示本帧被抑制（不学习、不发送）。"""
        if (port_name, vlan) in blocked:  # 封锁帧不检测
            return True
        if state not in ("learning", "forwarding"):
            return False
        is_group = int(dst[:2], 16) & 1
        if dst == BROADCAST_MAC:
            category = "broadcast"
        elif is_group:
            category = "multicast"
        else:
            category = None if fdb.get((vlan, dst)) else "unknown"
        if category is not None:
            queue = rate_queues.get((port_name, vlan, category))
            if queue is None:
                queue = deque(maxlen=limits[category])
                rate_queues[(port_name, vlan, category)] = queue
            while queue and t - queue[0] >= window:
                queue.popleft()
            if len(queue) >= limits[category]:  # 余量已达上限：丢弃
                return True
        prev = last_learn.get((vlan, src))
        if prev is not None and prev != learn_port:  # 学习端口迁移
            queue = move_queues.get((vlan, src))
            if queue is None:
                queue = deque(maxlen=move_limit)
                move_queues[(vlan, src)] = queue
            while queue and t - queue[0] >= window:
                queue.popleft()
            queue.append(t)
            if len(queue) >= move_limit:  # 迁移数达上限：封锁入端口/VLAN 并丢弃
                blocked[(port_name, vlan)] = t + hold
                return True
        if category is not None:  # 速率名额仅在帧实际放行时占用
            rate_queues[(port_name, vlan, category)].append(t)
        fdb[(vlan, src)] = [learn_port, t]
        last_learn[(vlan, src)] = learn_port
        return False

    def target_available(t):
        """镜像输出口须物理 up；其本桥链路（若有）也须 up。STP 不阻止镜像。"""
        port = by_name[mirror_target]
        if not port["up"]:
            return False
        link = port_link.get(mirror_target)
        if link is not None and not link["up"]:
            return False
        return True

    def mirror_entry(direction_name, tag, source, t):
        """构造镜像副本；tag 为源侧线路上实际携带的标签（可为 None）。"""
        if not target_available(t):  # 不可用则无副本
            return None
        port_stats[mirror_target]["tx"] += 1  # 副本只计 target 的 tx
        return {
            "name": mirror_target,
            "vlan": tag,
            "direction": direction_name,
            "source": source,
        }

    converge(0)
    for item in events:
        t = item[1]
        for key in [k for k, (_, seen) in fdb.items() if t - seen >= age]:
            del fdb[key]
        for key in [k for k, until in blocked.items() if t >= until]:
            del blocked[key]
        if item[0] == "link":
            _, t, lid, up = item
            if by_id[lid]["up"] != up:  # 幂等链路事件不重算拓扑
                old_forwarding = forwarding_ports(t)
                by_id[lid]["up"] = up
                converge(t)
                for name in old_forwarding - forwarding_ports(t):
                    for key in [k for k, (p, _) in fdb.items() if p == name]:
                        del fdb[key]
            continue
        if item[0] == "member":
            _, t, member, up = item
            member_up[member] = up  # 幂等无作用；可用性变化不清 FDB
            continue
        _, t, port_name, src, dst, tag = item
        port_stats[port_name]["rx"] += 1
        if tag is None:
            vlan = by_name[port_name]["pvid"]
            rejected = False
        else:
            vlan = tag
            ingress = by_name[port_name]
            rejected = (
                ingress["mode"] == "access" or vlan not in ingress["allowed"]
            )
        if rejected:  # VLAN 准入拒绝：不学习、不计 VLAN
            port_stats[port_name]["drop"] += 1
            results.append(
                {"t": t, "action": "drop", "ports": [], "mirrors": []}
            )
            continue
        # VLAN 准入后：入端口命中 sources 则复制入站标签
        ingress_copy = None
        if direction in ("ingress", "both") and port_name in source_set:
            ingress_copy = mirror_entry("ingress", tag, port_name, t)
        vlan_stats[vlan]["rx"] += 1
        ingress_lag = lag_of.get(port_name)
        if ingress_lag is not None:
            usable = member_available(port_name, t, vlan)
            state = "forwarding" if usable else None
        else:
            usable = True
            _, state = port_status(port_name, t)
        egress = []
        action = "drop"
        if usable:  # 不可用成员入帧丢弃且不学习
            learn_port = ingress_lag["name"] if ingress_lag else port_name
            suppressed = suppress(
                t, port_name, vlan, src, dst, state, learn_port
            )
            if not suppressed and state == "forwarding":
                is_group = int(dst[:2], 16) & 1
                hit = None if is_group else fdb.get((vlan, dst))
                if hit is not None and hit[0] != learn_port:
                    target = hit[0]
                    target_lag = lag_by_name.get(target)
                    if target_lag is not None:
                        candidates = lag_candidates(target_lag, t, vlan)
                        if candidates:  # 无候选按无出口丢弃
                            egress = [
                                lag_pick(target_lag, candidates, src, dst, vlan)
                            ]
                            action = "unicast"
                    else:
                        target_up, target_state = port_status(target, t)
                        if (
                            target_up
                            and target_state == "forwarding"
                            and vlan in by_name[target]["allowed"]
                        ):
                            egress = [target]
                            action = "unicast"
                elif hit is None:
                    selected = {}  # lag 名 -> 本帧选中的成员
                    for lag in lags:
                        if ingress_lag is not None and lag is ingress_lag:
                            continue  # 禁止组内回送
                        candidates = lag_candidates(lag, t, vlan)
                        if candidates:
                            selected[lag["name"]] = lag_pick(
                                lag, candidates, src, dst, vlan
                            )
                    for port in ports:
                        name = port["name"]
                        lag = lag_of.get(name)
                        if lag is not None:
                            if selected.get(lag["name"]) == name:
                                egress.append(name)
                        elif (
                            vlan in port["allowed"]
                            and name != port_name
                            and port_status(name, t) == (True, "forwarding")
                        ):
                            egress.append(name)
                    if egress:
                        action = "flood"
        out_ports = []
        for name in egress:
            port_stats[name]["tx"] += 1
            vlan_stats[vlan]["tx"] += 1
            out_ports.append(
                {
                    "name": name,
                    "vlan": None if vlan in by_name[name]["untagged"] else vlan,
                }
            )
        if not egress:
            port_stats[port_name]["drop"] += 1
            vlan_stats[vlan]["drop"] += 1
        mirrors = []
        if ingress_copy is not None:  # both 时 ingress 在前
            mirrors.append(ingress_copy)
        if direction in ("egress", "both"):
            for name in egress:  # egress 按 ports 序
                if name in source_set:
                    out_tag = (
                        None if vlan in by_name[name]["untagged"] else vlan
                    )
                    copy = mirror_entry("egress", out_tag, name, t)
                    if copy is not None:
                        mirrors.append(copy)
        results.append(
            {"t": t, "action": action, "ports": out_ports, "mirrors": mirrors}
        )
    return {
        "results": results,
        "ports": [
            {
                "name": port["name"],
                "rx": port_stats[port["name"]]["rx"],
                "tx": port_stats[port["name"]]["tx"],
                "drop": port_stats[port["name"]]["drop"],
            }
            for port in ports
        ],
        "vlans": [
            {
                "vlan": vlan,
                "rx": vlan_stats[vlan]["rx"],
                "tx": vlan_stats[vlan]["tx"],
                "drop": vlan_stats[vlan]["drop"],
            }
            for vlan in sorted(vlan_stats)
        ],
    }


def forward_acl(
    bridges, links, delay, bridge_name, ports, age, storm, lags, mirror,
    acl, events
):
    window = storm["window"]
    limits = storm["limits"]
    move_limit = storm["move_limit"]
    hold = storm["hold"]
    sources = mirror["sources"]
    mirror_target = mirror["target"]
    direction = mirror["direction"]
    source_set = set(sources)
    by_id = {link["id"]: link for link in links}
    by_name = {port["name"]: port for port in ports}
    lag_by_name = {lag["name"]: lag for lag in lags}
    lag_of = {}  # 成员物理口 -> lag
    member_up = {}  # 成员物理口 -> 动态可用（初始可用）
    for lag in lags:
        for member in lag["members"]:
            lag_of[member] = lag
            member_up[member] = True
    port_link = {}  # 本桥桥链路口名 -> link
    for link in links:
        for end_bridge, end_port in (link["x"], link["y"]):
            if end_bridge == bridge_name:
                port_link[end_port] = link
    fdb = {}  # (vlan, mac) -> [逻辑口（物理口名或 lag 名）, seen]
    port_stats = {
        port["name"]: {"rx": 0, "tx": 0, "drop": 0} for port in ports
    }
    vlan_stats = {}
    for port in ports:
        for vlan in port["allowed"]:
            vlan_stats.setdefault(vlan, {"rx": 0, "tx": 0, "drop": 0})
    rate_queues = {}  # (入端口, vlan, 类别) -> 放行时刻 deque
    move_queues = {}  # (vlan, src) -> 迁移时刻 deque
    last_learn = {}  # (vlan, src) -> 最后学习逻辑口
    blocked = {}  # (入端口, vlan) -> 封锁截止时刻
    results = []

    previous = {}  # (bridge, port) -> 上一轮角色
    since = {}  # (bridge, port) -> 获得当前 root/designated 角色的时刻
    roles = {name: {} for name in bridges}

    def converge(t):
        _, _, new_roles = stp_converge(bridges, links)
        for name in bridges:
            for port, role in new_roles[name].items():
                key = (name, port)
                if role in STP_TIMED_ROLES:
                    if previous.get(key) != role:  # 同角色不重计时
                        since[key] = t
                else:
                    since.pop(key, None)
        previous.clear()
        for name in bridges:
            for port, role in new_roles[name].items():
                previous[(name, port)] = role
        roles.clear()
        for name in bridges:
            roles[name] = new_roles[name]

    def forwarding_ports(t):
        result = set()
        for name, link in port_link.items():
            key = (bridge_name, name)
            role = roles[bridge_name][name]
            if (
                by_name[name]["up"]
                and link["up"]
                and role in STP_TIMED_ROLES
                and t - since[key] >= 2 * delay
            ):
                result.add(name)
        return result

    def port_status(name, t):
        """返回 (物理 up, STP 状态)；边缘口恒为 up 即 forwarding。"""
        port = by_name[name]
        link = port_link.get(name)
        if link is None:
            return port["up"], ("forwarding" if port["up"] else "down")
        if not port["up"]:
            return False, "down"
        if not link["up"]:
            return False, "disabled"
        role = roles[bridge_name][name]
        if role in STP_TIMED_ROLES:
            elapsed = t - since[(bridge_name, name)]
            if elapsed < delay:
                state = "discarding"
            elif elapsed < 2 * delay:
                state = "learning"
            else:
                state = "forwarding"
        else:
            state = "discarding"  # alternate
        return True, state

    def member_available(name, t, vlan):
        """成员可用：动态 up、端口 up、STP forwarding 且允许该 VLAN。"""
        port = by_name[name]
        if not member_up[name] or not port["up"] or vlan not in port["allowed"]:
            return False
        return port_status(name, t) == (True, "forwarding")

    def lag_candidates(lag, t, vlan):
        """可用候选成员，按 members 顺序。"""
        return [
            member
            for member in lag["members"]
            if member_available(member, t, vlan)
        ]

    def lag_pick(lag, candidates, src, dst, vlan):
        parts = []
        for field in lag["hash"]:
            if field == "src":
                parts.append(src)
            elif field == "dst":
                parts.append(dst)
            else:
                parts.append(str(vlan))
        digest = zlib.crc32("|".join(parts).encode("utf-8")) & 0xFFFFFFFF
        return candidates[digest % len(candidates)]

    def suppress(t, port_name, vlan, src, dst, state, learn_port):
        """风暴控制：返回 True 表示本帧被抑制（不学习、不发送）。"""
        if (port_name, vlan) in blocked:  # 封锁帧不检测
            return True
        if state not in ("learning", "forwarding"):
            return False
        is_group = int(dst[:2], 16) & 1
        if dst == BROADCAST_MAC:
            category = "broadcast"
        elif is_group:
            category = "multicast"
        else:
            category = None if fdb.get((vlan, dst)) else "unknown"
        if category is not None:
            queue = rate_queues.get((port_name, vlan, category))
            if queue is None:
                queue = deque(maxlen=limits[category])
                rate_queues[(port_name, vlan, category)] = queue
            while queue and t - queue[0] >= window:
                queue.popleft()
            if len(queue) >= limits[category]:  # 余量已达上限：丢弃
                return True
        prev = last_learn.get((vlan, src))
        if prev is not None and prev != learn_port:  # 学习端口迁移
            queue = move_queues.get((vlan, src))
            if queue is None:
                queue = deque(maxlen=move_limit)
                move_queues[(vlan, src)] = queue
            while queue and t - queue[0] >= window:
                queue.popleft()
            queue.append(t)
            if len(queue) >= move_limit:  # 迁移数达上限：封锁入端口/VLAN 并丢弃
                blocked[(port_name, vlan)] = t + hold
                return True
        if category is not None:  # 速率名额仅在帧实际放行时占用
            rate_queues[(port_name, vlan, category)].append(t)
        fdb[(vlan, src)] = [learn_port, t]
        last_learn[(vlan, src)] = learn_port
        return False

    def target_available(t):
        """镜像输出口须物理 up；其本桥链路（若有）也须 up。STP 不阻止镜像。"""
        port = by_name[mirror_target]
        if not port["up"]:
            return False
        link = port_link.get(mirror_target)
        if link is not None and not link["up"]:
            return False
        return True

    def mirror_entry(direction_name, tag, source, t):
        """构造镜像副本；tag 为源侧线路上实际携带的标签（可为 None）。"""
        if not target_available(t):  # 不可用则无副本
            return None
        port_stats[mirror_target]["tx"] += 1  # 副本只计 target 的 tx
        return {
            "name": mirror_target,
            "vlan": tag,
            "direction": direction_name,
            "source": source,
        }

    def acl_match(vlan, src, dst, ethertype, priority):
        """按数组序首条命中；未命中视为 allow。"""
        for rule in acl:
            if (
                (rule["src"] is None or rule["src"] == src)
                and (rule["dst"] is None or rule["dst"] == dst)
                and (rule["vlan"] is None or rule["vlan"] == vlan)
                and (
                    rule["ethertype"] is None
                    or rule["ethertype"] == ethertype
                )
                and (
                    rule["priority"] is None or rule["priority"] == priority
                )
            ):
                return rule["action"], rule["to_vlan"]
        return "allow", None

    converge(0)
    for item in events:
        t = item[1]
        for key in [k for k, (_, seen) in fdb.items() if t - seen >= age]:
            del fdb[key]
        for key in [k for k, until in blocked.items() if t >= until]:
            del blocked[key]
        if item[0] == "link":
            _, t, lid, up = item
            if by_id[lid]["up"] != up:  # 幂等链路事件不重算拓扑
                old_forwarding = forwarding_ports(t)
                by_id[lid]["up"] = up
                converge(t)
                for name in old_forwarding - forwarding_ports(t):
                    for key in [k for k, (p, _) in fdb.items() if p == name]:
                        del fdb[key]
            continue
        if item[0] == "member":
            _, t, member, up = item
            member_up[member] = up  # 幂等无作用；可用性变化不清 FDB
            continue
        _, t, port_name, src, dst, tag, ethertype, priority = item
        port_stats[port_name]["rx"] += 1
        if tag is None:
            vlan = by_name[port_name]["pvid"]
            rejected = False
        else:
            vlan = tag
            ingress = by_name[port_name]
            rejected = (
                ingress["mode"] == "access" or vlan not in ingress["allowed"]
            )
        if rejected:  # VLAN 准入拒绝：不学习、不计 VLAN
            port_stats[port_name]["drop"] += 1
            results.append(
                {"t": t, "action": "drop", "ports": [], "mirrors": []}
            )
            continue
        # VLAN 准入后：以有效 VLAN 及原字段做 ACL 匹配（每帧仅一次）
        acl_action, to_vlan = acl_match(vlan, src, dst, ethertype, priority)
        if acl_action == "remark":
            if to_vlan in by_name[port_name]["allowed"]:
                vlan = to_vlan  # 新 VLAN 用于后续全部处理
            else:  # remark 目标不在入端口 allowed：按 drop 处理
                acl_action = "drop"
        if acl_action == "drop":  # 不学习、不计风暴、不镜像、不发送
            port_stats[port_name]["drop"] += 1
            vlan_stats[vlan]["rx"] += 1
            vlan_stats[vlan]["drop"] += 1
            results.append(
                {"t": t, "action": "drop", "ports": [], "mirrors": []}
            )
            continue
        # 入端口命中 sources 则复制；remark 后副本携带新 VLAN
        ingress_copy = None
        if direction in ("ingress", "both") and port_name in source_set:
            copy_tag = vlan if acl_action == "remark" else tag
            ingress_copy = mirror_entry("ingress", copy_tag, port_name, t)
        vlan_stats[vlan]["rx"] += 1
        ingress_lag = lag_of.get(port_name)
        if ingress_lag is not None:
            usable = member_available(port_name, t, vlan)
            state = "forwarding" if usable else None
        else:
            usable = True
            _, state = port_status(port_name, t)
        egress = []
        action = "drop"
        if usable:  # 不可用成员入帧丢弃且不学习
            learn_port = ingress_lag["name"] if ingress_lag else port_name
            suppressed = suppress(
                t, port_name, vlan, src, dst, state, learn_port
            )
            if not suppressed and state == "forwarding":
                is_group = int(dst[:2], 16) & 1
                hit = None if is_group else fdb.get((vlan, dst))
                if hit is not None and hit[0] != learn_port:
                    target = hit[0]
                    target_lag = lag_by_name.get(target)
                    if target_lag is not None:
                        candidates = lag_candidates(target_lag, t, vlan)
                        if candidates:  # 无候选按无出口丢弃
                            egress = [
                                lag_pick(target_lag, candidates, src, dst, vlan)
                            ]
                            action = "unicast"
                    else:
                        target_up, target_state = port_status(target, t)
                        if (
                            target_up
                            and target_state == "forwarding"
                            and vlan in by_name[target]["allowed"]
                        ):
                            egress = [target]
                            action = "unicast"
                elif hit is None:
                    selected = {}  # lag 名 -> 本帧选中的成员
                    for lag in lags:
                        if ingress_lag is not None and lag is ingress_lag:
                            continue  # 禁止组内回送
                        candidates = lag_candidates(lag, t, vlan)
                        if candidates:
                            selected[lag["name"]] = lag_pick(
                                lag, candidates, src, dst, vlan
                            )
                    for port in ports:
                        name = port["name"]
                        lag = lag_of.get(name)
                        if lag is not None:
                            if selected.get(lag["name"]) == name:
                                egress.append(name)
                        elif (
                            vlan in port["allowed"]
                            and name != port_name
                            and port_status(name, t) == (True, "forwarding")
                        ):
                            egress.append(name)
                    if egress:
                        action = "flood"
        out_ports = []
        for name in egress:
            port_stats[name]["tx"] += 1
            vlan_stats[vlan]["tx"] += 1
            out_ports.append(
                {
                    "name": name,
                    "vlan": None if vlan in by_name[name]["untagged"] else vlan,
                }
            )
        if not egress:
            port_stats[port_name]["drop"] += 1
            vlan_stats[vlan]["drop"] += 1
        mirrors = []
        if ingress_copy is not None:  # both 时 ingress 在前
            mirrors.append(ingress_copy)
        if direction in ("egress", "both"):
            for name in egress:  # egress 按 ports 序
                if name in source_set:
                    out_tag = (
                        None if vlan in by_name[name]["untagged"] else vlan
                    )
                    copy = mirror_entry("egress", out_tag, name, t)
                    if copy is not None:
                        mirrors.append(copy)
        results.append(
            {"t": t, "action": action, "ports": out_ports, "mirrors": mirrors}
        )
    return {
        "results": results,
        "ports": [
            {
                "name": port["name"],
                "rx": port_stats[port["name"]]["rx"],
                "tx": port_stats[port["name"]]["tx"],
                "drop": port_stats[port["name"]]["drop"],
            }
            for port in ports
        ],
        "vlans": [
            {
                "vlan": vlan,
                "rx": vlan_stats[vlan]["rx"],
                "tx": vlan_stats[vlan]["tx"],
                "drop": vlan_stats[vlan]["drop"],
            }
            for vlan in sorted(vlan_stats)
        ],
    }


def forward_qos(
    bridges, links, delay, bridge_name, ports, age, storm, lags, mirror,
    acl, qos, events
):
    window = storm["window"]
    limits = storm["limits"]
    move_limit = storm["move_limit"]
    hold = storm["hold"]
    sources = mirror["sources"]
    mirror_target = mirror["target"]
    direction = mirror["direction"]
    source_set = set(sources)
    qos_map = qos["map"]
    cap = qos["cap"]
    sched_mode = qos["mode"]
    weights = qos["weights"]
    drop_mode = qos["drop"]
    weight_total = sum(weights)
    quotas = [-(-(cap * w) // weight_total) for w in weights]  # 上取整
    by_id = {link["id"]: link for link in links}
    by_name = {port["name"]: port for port in ports}
    lag_by_name = {lag["name"]: lag for lag in lags}
    lag_of = {}  # 成员物理口 -> lag
    member_up = {}  # 成员物理口 -> 动态可用（初始可用）
    for lag in lags:
        for member in lag["members"]:
            lag_of[member] = lag
            member_up[member] = True
    port_link = {}  # 本桥桥链路口名 -> link
    for link in links:
        for end_bridge, end_port in (link["x"], link["y"]):
            if end_bridge == bridge_name:
                port_link[end_port] = link
    fdb = {}  # (vlan, mac) -> [逻辑口（物理口名或 lag 名）, seen]
    port_stats = {
        port["name"]: {"rx": 0, "tx": 0, "drop": 0} for port in ports
    }
    vlan_stats = {}
    for port in ports:
        for vlan in port["allowed"]:
            vlan_stats.setdefault(vlan, {"rx": 0, "tx": 0, "drop": 0})
    rate_queues = {}  # (入端口, vlan, 类别) -> 放行时刻 deque
    move_queues = {}  # (vlan, src) -> 迁移时刻 deque
    last_learn = {}  # (vlan, src) -> 最后学习逻辑口
    blocked = {}  # (入端口, vlan) -> 封锁截止时刻
    results = []
    # 出口队列：每端口 4 个优先级 FIFO，存 {"id","vlan","mirror"}
    egress_queues = {
        port["name"]: [deque(), deque(), deque(), deque()] for port in ports
    }
    # 每物理出口持久 WRR 状态 (当前队, 剩余配额)；初始服务 3 队
    wrr_state = {
        port["name"]: [3, weights[3]] for port in ports
    }
    frame_seq = 0  # 全局零基帧序号（仅帧事件占用）

    def converge(t):
        _, _, new_roles = stp_converge(bridges, links)
        for name in bridges:
            for port, role in new_roles[name].items():
                key = (name, port)
                if role in STP_TIMED_ROLES:
                    if previous.get(key) != role:  # 同角色不重计时
                        since[key] = t
                else:
                    since.pop(key, None)
        previous.clear()
        for name in bridges:
            for port, role in new_roles[name].items():
                previous[(name, port)] = role
        roles.clear()
        for name in bridges:
            roles[name] = new_roles[name]

    def forwarding_ports(t):
        result = set()
        for name, link in port_link.items():
            key = (bridge_name, name)
            role = roles[bridge_name][name]
            if (
                by_name[name]["up"]
                and link["up"]
                and role in STP_TIMED_ROLES
                and t - since[key] >= 2 * delay
            ):
                result.add(name)
        return result

    def port_status(name, t):
        """返回 (物理 up, STP 状态)；边缘口恒为 up 即 forwarding。"""
        port = by_name[name]
        link = port_link.get(name)
        if link is None:
            return port["up"], ("forwarding" if port["up"] else "down")
        if not port["up"]:
            return False, "down"
        if not link["up"]:
            return False, "disabled"
        role = roles[bridge_name][name]
        if role in STP_TIMED_ROLES:
            elapsed = t - since[(bridge_name, name)]
            if elapsed < delay:
                state = "discarding"
            elif elapsed < 2 * delay:
                state = "learning"
            else:
                state = "forwarding"
        else:
            state = "discarding"  # alternate
        return True, state

    def is_forwarding(name, t):
        """LAG 成员还需动态 up 才算 forwarding。"""
        phys_up, state = port_status(name, t)
        if not phys_up or state != "forwarding":
            return False
        return name not in member_up or member_up[name]

    def member_available(name, t, vlan):
        """成员可用：动态 up、端口 up、STP forwarding 且允许该 VLAN。"""
        port = by_name[name]
        if not member_up[name] or not port["up"] or vlan not in port["allowed"]:
            return False
        return port_status(name, t) == (True, "forwarding")

    def lag_candidates(lag, t, vlan):
        """可用候选成员，按 members 顺序。"""
        return [
            member
            for member in lag["members"]
            if member_available(member, t, vlan)
        ]

    def lag_pick(lag, candidates, src, dst, vlan):
        parts = []
        for field in lag["hash"]:
            if field == "src":
                parts.append(src)
            elif field == "dst":
                parts.append(dst)
            else:
                parts.append(str(vlan))
        digest = zlib.crc32("|".join(parts).encode("utf-8")) & 0xFFFFFFFF
        return candidates[digest % len(candidates)]

    def suppress(t, port_name, vlan, src, dst, state, learn_port):
        """风暴控制：返回 True 表示本帧被抑制（不学习、不发送）。"""
        if (port_name, vlan) in blocked:  # 封锁帧不检测
            return True
        if state not in ("learning", "forwarding"):
            return False
        is_group = int(dst[:2], 16) & 1
        if dst == BROADCAST_MAC:
            category = "broadcast"
        elif is_group:
            category = "multicast"
        else:
            category = None if fdb.get((vlan, dst)) else "unknown"
        if category is not None:
            queue = rate_queues.get((port_name, vlan, category))
            if queue is None:
                queue = deque(maxlen=limits[category])
                rate_queues[(port_name, vlan, category)] = queue
            while queue and t - queue[0] >= window:
                queue.popleft()
            if len(queue) >= limits[category]:  # 余量已达上限：丢弃
                return True
        prev = last_learn.get((vlan, src))
        if prev is not None and prev != learn_port:  # 学习端口迁移
            queue = move_queues.get((vlan, src))
            if queue is None:
                queue = deque(maxlen=move_limit)
                move_queues[(vlan, src)] = queue
            while queue and t - queue[0] >= window:
                queue.popleft()
            queue.append(t)
            if len(queue) >= move_limit:  # 迁移数达上限：封锁入端口/VLAN 并丢弃
                blocked[(port_name, vlan)] = t + hold
                return True
        if category is not None:  # 速率名额仅在帧实际放行时占用
            rate_queues[(port_name, vlan, category)].append(t)
        fdb[(vlan, src)] = [learn_port, t]
        last_learn[(vlan, src)] = learn_port
        return False

    def target_available(t):
        """镜像输出口须物理 up；其本桥链路（若有）也须 up。STP 不阻止镜像。"""
        port = by_name[mirror_target]
        if not port["up"]:
            return False
        link = port_link.get(mirror_target)
        if link is not None and not link["up"]:
            return False
        return True

    def mirror_entry(direction_name, tag, source, t):
        """构造镜像副本；tag 为源侧线路上实际携带的标签（可为 None）。"""
        if not target_available(t):  # 不可用则无副本
            return None
        port_stats[mirror_target]["tx"] += 1  # 副本只计 target 的 tx
        return {
            "name": mirror_target,
            "vlan": tag,
            "direction": direction_name,
            "source": source,
        }

    def acl_match(vlan, src, dst, ethertype, priority):
        """按数组序首条命中；未命中视为 allow。"""
        for rule in acl:
            if (
                (rule["src"] is None or rule["src"] == src)
                and (rule["dst"] is None or rule["dst"] == dst)
                and (rule["vlan"] is None or rule["vlan"] == vlan)
                and (
                    rule["ethertype"] is None
                    or rule["ethertype"] == ethertype
                )
                and (
                    rule["priority"] is None or rule["priority"] == priority
                )
            ):
                return rule["action"], rule["to_vlan"]
        return "allow", None

    def clear_queue(name):
        """非 forwarding 清队：逐帧计出口与 VLAN drop。"""
        for q in range(4):
            while egress_queues[name][q]:
                frame = egress_queues[name][q].popleft()
                port_stats[name]["drop"] += 1
                vlan_stats[frame["vlan"]]["drop"] += 1

    def admit(name, queue_idx):
        """tail：总数达 cap 即拒；weighted：任一队列配额满即拒。"""
        queues = egress_queues[name]
        if drop_mode == "tail":
            return sum(len(q) for q in queues) < cap
        return all(len(queues[q]) < quotas[q] for q in range(4))

    previous = {}  # (bridge, port) -> 上一轮角色
    since = {}  # (bridge, port) -> 获得当前 root/designated 角色的时刻
    roles = {name: {} for name in bridges}

    converge(0)
    for item in events:
        t = item[1]
        for key in [k for k, (_, seen) in fdb.items() if t - seen >= age]:
            del fdb[key]
        for key in [k for k, until in blocked.items() if t >= until]:
            del blocked[key]
        if item[0] == "link":
            _, t, lid, up = item
            if by_id[lid]["up"] != up:  # 幂等链路事件不重算拓扑
                old_forwarding = forwarding_ports(t)
                by_id[lid]["up"] = up
                converge(t)
                for name in old_forwarding - forwarding_ports(t):
                    for key in [k for k, (p, _) in fdb.items() if p == name]:
                        del fdb[key]
                    clear_queue(name)  # 离开 forwarding：清队
            continue
        if item[0] == "member":
            _, t, member, up = item
            member_up[member] = up  # 幂等无作用；可用性变化不清 FDB
            if not up:  # 成员下线即非 forwarding：清队
                clear_queue(member)
            continue
        if item[0] == "service":
            _, t, port_name, count = item
            frames = []
            mirrors = []
            if not is_forwarding(port_name, t):  # 非 forwarding：清队不服务
                clear_queue(port_name)
            else:
                queues = egress_queues[port_name]
                served = 0

                def dequeue_one():
                    frame = queues[q].popleft()
                    port_stats[port_name]["tx"] += 1  # tx 仅服务时计
                    vlan_stats[frame["vlan"]]["tx"] += 1
                    frames.append(frame["id"])
                    # 仅实际产生出站副本才追加（无 null 占位），与发送帧同序
                    if (
                        direction in ("egress", "both")
                        and port_name in source_set
                    ):
                        copy = mirror_entry(
                            "egress", frame["mirror"], port_name, t
                        )
                        if copy is not None:
                            mirrors.append(copy)

                while served < count:
                    if sched_mode == "sp":
                        q = next(
                            (q for q in (3, 2, 1, 0) if queues[q]), None
                        )
                        if q is None:
                            break
                        dequeue_one()
                        served += 1
                    else:  # wrr：持久状态 (q, rem)
                        q, rem = wrr_state[port_name]
                        if not any(queues):  # 四队全空：停止且状态不变
                            break
                        while not queues[q]:  # 当前队空：推进并重置配额
                            q = (q - 1) % 4
                            rem = weights[q]
                        dequeue_one()
                        served += 1
                        rem -= 1  # 每发一帧 rem 减 1
                        if rem == 0 or not queues[q]:
                            # rem 用尽或当前队变空：推进并重置配额；
                            # count 用尽而 rem 未尽且队非空：状态保留续用
                            q = (q - 1) % 4
                            rem = weights[q]
                        wrr_state[port_name] = [q, rem]
            results.append(
                {"t": t, "port": port_name, "frames": frames,
                 "mirrors": mirrors}
            )
            continue
        _, t, port_name, src, dst, tag, ethertype, priority = item
        fid = frame_seq
        frame_seq += 1
        port_stats[port_name]["rx"] += 1
        if tag is None:
            vlan = by_name[port_name]["pvid"]
            rejected = False
        else:
            vlan = tag
            ingress = by_name[port_name]
            rejected = (
                ingress["mode"] == "access" or vlan not in ingress["allowed"]
            )
        if rejected:  # VLAN 准入拒绝：不学习、不计 VLAN
            port_stats[port_name]["drop"] += 1
            results.append(
                {"t": t, "action": "drop", "ports": [], "dropped": [],
                 "mirrors": []}
            )
            continue
        # VLAN 准入后：以有效 VLAN 及原字段做 ACL 匹配（每帧仅一次）
        acl_action, to_vlan = acl_match(vlan, src, dst, ethertype, priority)
        if acl_action == "remark":
            if to_vlan in by_name[port_name]["allowed"]:
                vlan = to_vlan  # 新 VLAN 用于后续全部处理
            else:  # remark 目标不在入端口 allowed：按 drop 处理
                acl_action = "drop"
        if acl_action == "drop":  # 不学习、不计风暴、不镜像、不发送
            port_stats[port_name]["drop"] += 1
            vlan_stats[vlan]["rx"] += 1
            vlan_stats[vlan]["drop"] += 1
            results.append(
                {"t": t, "action": "drop", "ports": [], "dropped": [],
                 "mirrors": []}
            )
            continue
        # 入端口命中 sources 则复制；remark 后副本携带新 VLAN（镜像不入队）
        ingress_copy = None
        if direction in ("ingress", "both") and port_name in source_set:
            copy_tag = vlan if acl_action == "remark" else tag
            ingress_copy = mirror_entry("ingress", copy_tag, port_name, t)
        vlan_stats[vlan]["rx"] += 1
        ingress_lag = lag_of.get(port_name)
        if ingress_lag is not None:
            usable = member_available(port_name, t, vlan)
            state = "forwarding" if usable else None
        else:
            usable = True
            _, state = port_status(port_name, t)
        egress = []
        action = "drop"
        if usable:  # 不可用成员入帧丢弃且不学习
            learn_port = ingress_lag["name"] if ingress_lag else port_name
            suppressed = suppress(
                t, port_name, vlan, src, dst, state, learn_port
            )
            if not suppressed and state == "forwarding":
                is_group = int(dst[:2], 16) & 1
                hit = None if is_group else fdb.get((vlan, dst))
                if hit is not None and hit[0] != learn_port:
                    target = hit[0]
                    target_lag = lag_by_name.get(target)
                    if target_lag is not None:
                        candidates = lag_candidates(target_lag, t, vlan)
                        if candidates:  # 无候选按无出口丢弃
                            egress = [
                                lag_pick(target_lag, candidates, src, dst, vlan)
                            ]
                            action = "unicast"
                    else:
                        target_up, target_state = port_status(target, t)
                        if (
                            target_up
                            and target_state == "forwarding"
                            and vlan in by_name[target]["allowed"]
                        ):
                            egress = [target]
                            action = "unicast"
                elif hit is None:
                    selected = {}  # lag 名 -> 本帧选中的成员
                    for lag in lags:
                        if ingress_lag is not None and lag is ingress_lag:
                            continue  # 禁止组内回送
                        candidates = lag_candidates(lag, t, vlan)
                        if candidates:
                            selected[lag["name"]] = lag_pick(
                                lag, candidates, src, dst, vlan
                            )
                    for port in ports:
                        name = port["name"]
                        lag = lag_of.get(name)
                        if lag is not None:
                            if selected.get(lag["name"]) == name:
                                egress.append(name)
                        elif (
                            vlan in port["allowed"]
                            and name != port_name
                            and port_status(name, t) == (True, "forwarding")
                        ):
                            egress.append(name)
                    if egress:
                        action = "flood"
        out_ports = []
        dropped = []
        queue_idx = qos_map[priority]
        for name in egress:  # 按 egress 序逐口入队；镜像不随之产生
            out_tag = None if vlan in by_name[name]["untagged"] else vlan
            if admit(name, queue_idx):
                egress_queues[name][queue_idx].append(
                    {"id": fid, "vlan": vlan, "mirror": out_tag}
                )
                out_ports.append({"name": name, "vlan": out_tag})
            else:  # 拒绝：计出口与 VLAN drop，不入队
                port_stats[name]["drop"] += 1
                vlan_stats[vlan]["drop"] += 1
                dropped.append(name)
        if not egress:  # 无出口：沿用 acl，计入口与 VLAN drop
            port_stats[port_name]["drop"] += 1
            vlan_stats[vlan]["drop"] += 1
        results.append(
            {"t": t, "action": action, "ports": out_ports,
             "dropped": dropped,
             "mirrors": [ingress_copy] if ingress_copy is not None else []}
        )
    return {
        "results": results,
        "ports": [
            {
                "name": port["name"],
                "rx": port_stats[port["name"]]["rx"],
                "tx": port_stats[port["name"]]["tx"],
                "drop": port_stats[port["name"]]["drop"],
            }
            for port in ports
        ],
        "vlans": [
            {
                "vlan": vlan,
                "rx": vlan_stats[vlan]["rx"],
                "tx": vlan_stats[vlan]["tx"],
                "drop": vlan_stats[vlan]["drop"],
            }
            for vlan in sorted(vlan_stats)
        ],
    }


def forward_security(
    bridges, links, delay, bridge_name, ports, age, storm, lags, mirror,
    acl, qos, security, events, observer=None
):
    window = storm["window"]
    limits = storm["limits"]
    move_limit = storm["move_limit"]
    hold = storm["hold"]
    sources = mirror["sources"]
    mirror_target = mirror["target"]
    direction = mirror["direction"]
    source_set = set(sources)
    qos_map = qos["map"]
    cap = qos["cap"]
    sched_mode = qos["mode"]
    weights = qos["weights"]
    drop_mode = qos["drop"]
    weight_total = sum(weights)
    quotas = [-(-(cap * w) // weight_total) for w in weights]  # 上取整
    sec_by_port = {entry["port"]: entry for entry in security}
    sec_order = [entry["port"] for entry in security]
    static_owner = {}  # (vlan, mac) -> 所属物理口
    for entry in security:
        for item in entry["static"]:
            static_owner[(item["vlan"], item["mac"])] = entry["port"]
    sec_down = set()  # 被 shutdown 永久禁用的物理口
    bound = {}  # (vlan, mac) -> 动态绑定的物理口（不老化、状态变化不清除）
    dynamic = {entry["port"]: set() for entry in security}  # 口 -> 动态绑定集
    violations = {entry["port"]: 0 for entry in security}
    if observer is not None:  # record：逐事件记录 applied 与新增输出
        observer["items"] = []
    by_id = {link["id"]: link for link in links}
    by_name = {port["name"]: port for port in ports}
    lag_by_name = {lag["name"]: lag for lag in lags}
    lag_of = {}  # 成员物理口 -> lag
    member_up = {}  # 成员物理口 -> 动态可用（初始可用）
    for lag in lags:
        for member in lag["members"]:
            lag_of[member] = lag
            member_up[member] = True
    port_link = {}  # 本桥桥链路口名 -> link
    for link in links:
        for end_bridge, end_port in (link["x"], link["y"]):
            if end_bridge == bridge_name:
                port_link[end_port] = link
    fdb = {}  # (vlan, mac) -> [逻辑口（物理口名或 lag 名）, seen]
    port_stats = {
        port["name"]: {"rx": 0, "tx": 0, "drop": 0} for port in ports
    }
    vlan_stats = {}
    for port in ports:
        for vlan in port["allowed"]:
            vlan_stats.setdefault(vlan, {"rx": 0, "tx": 0, "drop": 0})
    rate_queues = {}  # (入端口, vlan, 类别) -> 放行时刻 deque
    move_queues = {}  # (vlan, src) -> 迁移时刻 deque
    last_learn = {}  # (vlan, src) -> 最后学习逻辑口
    blocked = {}  # (入端口, vlan) -> 封锁截止时刻
    results = []
    # 出口队列：每端口 4 个优先级 FIFO，存 {"id","vlan","mirror"}
    egress_queues = {
        port["name"]: [deque(), deque(), deque(), deque()] for port in ports
    }
    # 每物理出口持久 WRR 状态 (当前队, 剩余配额)；初始服务 3 队
    wrr_state = {
        port["name"]: [3, weights[3]] for port in ports
    }
    frame_seq = 0  # 全局零基帧序号（仅帧事件占用）

    def converge(t):
        _, _, new_roles = stp_converge(bridges, links)
        for name in bridges:
            for port, role in new_roles[name].items():
                key = (name, port)
                if role in STP_TIMED_ROLES:
                    if previous.get(key) != role:  # 同角色不重计时
                        since[key] = t
                else:
                    since.pop(key, None)
        previous.clear()
        for name in bridges:
            for port, role in new_roles[name].items():
                previous[(name, port)] = role
        roles.clear()
        for name in bridges:
            roles[name] = new_roles[name]

    def forwarding_ports(t):
        result = set()
        for name, link in port_link.items():
            key = (bridge_name, name)
            role = roles[bridge_name][name]
            if (
                by_name[name]["up"]
                and name not in sec_down
                and link["up"]
                and role in STP_TIMED_ROLES
                and t - since[key] >= 2 * delay
            ):
                result.add(name)
        return result

    def port_status(name, t):
        """返回 (物理 up, STP 状态)；边缘口恒为 up 即 forwarding。"""
        if name in sec_down:  # shutdown：永久按 down 口处理
            return False, "down"
        port = by_name[name]
        link = port_link.get(name)
        if link is None:
            return port["up"], ("forwarding" if port["up"] else "down")
        if not port["up"]:
            return False, "down"
        if not link["up"]:
            return False, "disabled"
        role = roles[bridge_name][name]
        if role in STP_TIMED_ROLES:
            elapsed = t - since[(bridge_name, name)]
            if elapsed < delay:
                state = "discarding"
            elif elapsed < 2 * delay:
                state = "learning"
            else:
                state = "forwarding"
        else:
            state = "discarding"  # alternate
        return True, state

    def is_forwarding(name, t):
        """LAG 成员还需动态 up 才算 forwarding。"""
        phys_up, state = port_status(name, t)
        if not phys_up or state != "forwarding":
            return False
        return name not in member_up or member_up[name]

    def member_available(name, t, vlan):
        """成员可用：动态 up、端口 up、STP forwarding 且允许该 VLAN。"""
        port = by_name[name]
        if not member_up[name] or not port["up"] or vlan not in port["allowed"]:
            return False
        return port_status(name, t) == (True, "forwarding")

    def lag_candidates(lag, t, vlan):
        """可用候选成员，按 members 顺序。"""
        return [
            member
            for member in lag["members"]
            if member_available(member, t, vlan)
        ]

    def lag_pick(lag, candidates, src, dst, vlan):
        parts = []
        for field in lag["hash"]:
            if field == "src":
                parts.append(src)
            elif field == "dst":
                parts.append(dst)
            else:
                parts.append(str(vlan))
        digest = zlib.crc32("|".join(parts).encode("utf-8")) & 0xFFFFFFFF
        return candidates[digest % len(candidates)]

    def suppress(t, port_name, vlan, src, dst, state, learn_port):
        """风暴控制：返回 True 表示本帧被抑制（不学习、不发送）。"""
        if (port_name, vlan) in blocked:  # 封锁帧不检测
            return True
        if state not in ("learning", "forwarding"):
            return False
        is_group = int(dst[:2], 16) & 1
        if dst == BROADCAST_MAC:
            category = "broadcast"
        elif is_group:
            category = "multicast"
        else:
            category = None if fdb.get((vlan, dst)) else "unknown"
        if category is not None:
            queue = rate_queues.get((port_name, vlan, category))
            if queue is None:
                queue = deque(maxlen=limits[category])
                rate_queues[(port_name, vlan, category)] = queue
            while queue and t - queue[0] >= window:
                queue.popleft()
            if len(queue) >= limits[category]:  # 余量已达上限：丢弃
                return True
        prev = last_learn.get((vlan, src))
        if prev is not None and prev != learn_port:  # 学习端口迁移
            queue = move_queues.get((vlan, src))
            if queue is None:
                queue = deque(maxlen=move_limit)
                move_queues[(vlan, src)] = queue
            while queue and t - queue[0] >= window:
                queue.popleft()
            queue.append(t)
            if len(queue) >= move_limit:  # 迁移数达上限：封锁入端口/VLAN 并丢弃
                blocked[(port_name, vlan)] = t + hold
                return True
        if category is not None:  # 速率名额仅在帧实际放行时占用
            rate_queues[(port_name, vlan, category)].append(t)
        fdb[(vlan, src)] = [learn_port, t]
        last_learn[(vlan, src)] = learn_port
        return False

    def target_available(t):
        """镜像输出口须物理 up；其本桥链路（若有）也须 up。STP 不阻止镜像。"""
        if mirror_target in sec_down:
            return False
        port = by_name[mirror_target]
        if not port["up"]:
            return False
        link = port_link.get(mirror_target)
        if link is not None and not link["up"]:
            return False
        return True

    def mirror_entry(direction_name, tag, source, t):
        """构造镜像副本；tag 为源侧线路上实际携带的标签（可为 None）。"""
        if not target_available(t):  # 不可用则无副本
            return None
        port_stats[mirror_target]["tx"] += 1  # 副本只计 target 的 tx
        return {
            "name": mirror_target,
            "vlan": tag,
            "direction": direction_name,
            "source": source,
        }

    def acl_match(vlan, src, dst, ethertype, priority):
        """按数组序首条命中；未命中视为 allow。"""
        for rule in acl:
            if (
                (rule["src"] is None or rule["src"] == src)
                and (rule["dst"] is None or rule["dst"] == dst)
                and (rule["vlan"] is None or rule["vlan"] == vlan)
                and (
                    rule["ethertype"] is None
                    or rule["ethertype"] == ethertype
                )
                and (
                    rule["priority"] is None or rule["priority"] == priority
                )
            ):
                return rule["action"], rule["to_vlan"]
        return "allow", None

    def clear_queue(name):
        """非 forwarding 清队：逐帧计出口与 VLAN drop。"""
        for q in range(4):
            while egress_queues[name][q]:
                frame = egress_queues[name][q].popleft()
                port_stats[name]["drop"] += 1
                vlan_stats[frame["vlan"]]["drop"] += 1

    def admit(name, queue_idx):
        """tail：总数达 cap 即拒；weighted：任一队列配额满即拒。"""
        queues = egress_queues[name]
        if drop_mode == "tail":
            return sum(len(q) for q in queues) < cap
        return all(len(queues[q]) < quotas[q] for q in range(4))

    def security_check(port_name, vlan, src):
        """端口安全：返回 True 表示违例（丢本帧；shutdown 另永久禁口）。"""
        entry = sec_by_port[port_name]
        key = (vlan, src)
        owner = static_owner.get(key)
        if owner is not None:  # 静态源只准从所属口进入
            if owner == port_name:
                return False
        else:
            bound_port = bound.get(key)
            if bound_port == port_name:  # 重复源不增数
                return False
            if bound_port is None and len(dynamic[port_name]) < entry["limit"]:
                bound[key] = port_name  # 首次绑定入端口
                dynamic[port_name].add(key)
                return False
            # 已绑定别口，或本口动态数达到 limit
        violations[port_name] += 1
        if entry["action"] == "shutdown":
            sec_down.add(port_name)  # 永久按 down 口禁用
            for old in dynamic[port_name]:  # 清动态绑定
                del bound[old]
            dynamic[port_name].clear()
            clear_queue(port_name)  # 离开 forwarding：清队
        return True

    previous = {}  # (bridge, port) -> 上一轮角色
    since = {}  # (bridge, port) -> 获得当前 root/designated 角色的时刻
    roles = {name: {} for name in bridges}

    converge(0)
    for item in events:
        t = item[1]
        for key in [k for k, (_, seen) in fdb.items() if t - seen >= age]:
            del fdb[key]
        for key in [k for k, until in blocked.items() if t >= until]:
            del blocked[key]
        if item[0] == "link":
            _, t, lid, up = item
            link_changed = by_id[lid]["up"] != up
            if link_changed:  # 幂等链路事件不重算拓扑
                old_forwarding = forwarding_ports(t)
                by_id[lid]["up"] = up
                converge(t)
                for name in old_forwarding - forwarding_ports(t):
                    for key in [k for k, (p, _) in fdb.items() if p == name]:
                        del fdb[key]
                    clear_queue(name)  # 离开 forwarding：清队
            if observer is not None:
                observer["items"].append(
                    {"kind": "link", "t": t, "applied": link_changed,
                     "output": None}
                )
            continue
        if item[0] == "member":
            _, t, member, up = item
            member_changed = member_up[member] != up
            member_up[member] = up  # 幂等无作用；可用性变化不清 FDB
            if not up:  # 成员下线即非 forwarding：清队
                clear_queue(member)
            if observer is not None:
                observer["items"].append(
                    {"kind": "member", "t": t, "applied": member_changed,
                     "output": None}
                )
            continue
        if item[0] == "service":
            _, t, port_name, count = item
            frames = []
            mirrors = []
            if not is_forwarding(port_name, t):  # 非 forwarding：清队不服务
                clear_queue(port_name)
            else:
                queues = egress_queues[port_name]
                served = 0

                def dequeue_one():
                    frame = queues[q].popleft()
                    port_stats[port_name]["tx"] += 1  # tx 仅服务时计
                    vlan_stats[frame["vlan"]]["tx"] += 1
                    frames.append(frame["id"])
                    # 仅实际产生出站副本才追加（无 null 占位），与发送帧同序
                    if (
                        direction in ("egress", "both")
                        and port_name in source_set
                    ):
                        copy = mirror_entry(
                            "egress", frame["mirror"], port_name, t
                        )
                        if copy is not None:
                            mirrors.append(copy)

                while served < count:
                    if sched_mode == "sp":
                        q = next(
                            (q for q in (3, 2, 1, 0) if queues[q]), None
                        )
                        if q is None:
                            break
                        dequeue_one()
                        served += 1
                    else:  # wrr：持久状态 (q, rem)
                        q, rem = wrr_state[port_name]
                        if not any(queues):  # 四队全空：停止且状态不变
                            break
                        while not queues[q]:  # 当前队空：推进并重置配额
                            q = (q - 1) % 4
                            rem = weights[q]
                        dequeue_one()
                        served += 1
                        rem -= 1  # 每发一帧 rem 减 1
                        if rem == 0 or not queues[q]:
                            # rem 用尽或当前队变空：推进并重置配额；
                            # count 用尽而 rem 未尽且队非空：状态保留续用
                            q = (q - 1) % 4
                            rem = weights[q]
                        wrr_state[port_name] = [q, rem]
            results.append(
                {"t": t, "port": port_name, "frames": frames,
                 "mirrors": mirrors}
            )
            if observer is not None:
                observer["items"].append(
                    {"kind": "service", "t": t, "applied": True,
                     "output": results[-1]}
                )
            continue
        if item[0] == "reload":
            _, t, new_age, new_acl, new_security, changes = item
            new_by_port = {entry["port"]: entry for entry in new_security}
            new_static_owner = {}
            for entry in new_security:
                for static in entry["static"]:
                    new_static_owner[(static["vlan"], static["mac"])] = (
                        entry["port"]
                    )
            # 动态绑定数超新 limit 或动态 (vlan, mac) 入新 static：整批无效
            for name, macs in dynamic.items():
                if len(macs) > new_by_port[name]["limit"]:
                    raise InvalidInput("dynamic bindings exceed new limit")
            for key in bound:
                if key in new_static_owner:
                    raise InvalidInput("dynamic binding in new static")
            # 原子替换 age/acl/security；FDB、绑定、安全状态、队列、调度、
            # 风暴记录与计数全部保留，新规则自下一事件生效
            age = new_age
            acl = new_acl
            sec_by_port = new_by_port
            sec_order = [entry["port"] for entry in new_security]
            static_owner = new_static_owner
            results.append({"t": t, "action": "reload", "changes": changes})
            if observer is not None:
                observer["items"].append(
                    {"kind": "reload", "t": t, "applied": True,
                     "output": results[-1]}
                )
            continue
        _, t, port_name, src, dst, tag, ethertype, priority = item
        fid = frame_seq
        frame_seq += 1
        port_stats[port_name]["rx"] += 1
        if tag is None:
            vlan = by_name[port_name]["pvid"]
            rejected = False
        else:
            vlan = tag
            ingress = by_name[port_name]
            rejected = (
                ingress["mode"] == "access" or vlan not in ingress["allowed"]
            )
        if rejected:  # VLAN 准入拒绝：不学习、不计 VLAN
            port_stats[port_name]["drop"] += 1
            results.append(
                {"t": t, "action": "drop", "ports": [], "dropped": [],
                 "mirrors": []}
            )
            if observer is not None:
                observer["items"].append(
                    {"kind": "frame", "t": t, "applied": True,
                     "output": results[-1]}
                )
            continue
        # VLAN 准入后：以有效 VLAN 及原字段做 ACL 匹配（每帧仅一次）
        acl_action, to_vlan = acl_match(vlan, src, dst, ethertype, priority)
        if acl_action == "remark":
            if to_vlan in by_name[port_name]["allowed"]:
                vlan = to_vlan  # 新 VLAN 用于后续全部处理
            else:  # remark 目标不在入端口 allowed：按 drop 处理
                acl_action = "drop"
        if acl_action == "drop":  # 不学习、不计风暴、不镜像、不发送
            port_stats[port_name]["drop"] += 1
            vlan_stats[vlan]["rx"] += 1
            vlan_stats[vlan]["drop"] += 1
            results.append(
                {"t": t, "action": "drop", "ports": [], "dropped": [],
                 "mirrors": []}
            )
            if observer is not None:
                observer["items"].append(
                    {"kind": "frame", "t": t, "applied": True,
                     "output": results[-1]}
                )
            continue
        ingress_lag = lag_of.get(port_name)
        if ingress_lag is not None:
            usable = member_available(port_name, t, vlan)
            state = "forwarding" if usable else None
        else:
            usable = True
            _, state = port_status(port_name, t)
        # 可学习帧在 FDB 前做端口安全检查；违例不学习、不计风暴、不镜像
        if (
            usable
            and state in ("learning", "forwarding")
            and security_check(port_name, vlan, src)
        ):
            port_stats[port_name]["drop"] += 1
            vlan_stats[vlan]["rx"] += 1
            vlan_stats[vlan]["drop"] += 1
            results.append(
                {"t": t, "action": "drop", "ports": [], "dropped": [],
                 "mirrors": []}
            )
            if observer is not None:
                observer["items"].append(
                    {"kind": "frame", "t": t, "applied": True,
                     "output": results[-1]}
                )
            continue
        # 入端口命中 sources 则复制；remark 后副本携带新 VLAN（镜像不入队）
        ingress_copy = None
        if direction in ("ingress", "both") and port_name in source_set:
            copy_tag = vlan if acl_action == "remark" else tag
            ingress_copy = mirror_entry("ingress", copy_tag, port_name, t)
        vlan_stats[vlan]["rx"] += 1
        egress = []
        action = "drop"
        if usable:  # 不可用成员入帧丢弃且不学习
            learn_port = ingress_lag["name"] if ingress_lag else port_name
            suppressed = suppress(
                t, port_name, vlan, src, dst, state, learn_port
            )
            if not suppressed and state == "forwarding":
                is_group = int(dst[:2], 16) & 1
                hit = None if is_group else fdb.get((vlan, dst))
                if hit is not None and hit[0] != learn_port:
                    target = hit[0]
                    target_lag = lag_by_name.get(target)
                    if target_lag is not None:
                        candidates = lag_candidates(target_lag, t, vlan)
                        if candidates:  # 无候选按无出口丢弃
                            egress = [
                                lag_pick(target_lag, candidates, src, dst, vlan)
                            ]
                            action = "unicast"
                    else:
                        target_up, target_state = port_status(target, t)
                        if (
                            target_up
                            and target_state == "forwarding"
                            and vlan in by_name[target]["allowed"]
                        ):
                            egress = [target]
                            action = "unicast"
                elif hit is None:
                    selected = {}  # lag 名 -> 本帧选中的成员
                    for lag in lags:
                        if ingress_lag is not None and lag is ingress_lag:
                            continue  # 禁止组内回送
                        candidates = lag_candidates(lag, t, vlan)
                        if candidates:
                            selected[lag["name"]] = lag_pick(
                                lag, candidates, src, dst, vlan
                            )
                    for port in ports:
                        name = port["name"]
                        lag = lag_of.get(name)
                        if lag is not None:
                            if selected.get(lag["name"]) == name:
                                egress.append(name)
                        elif (
                            vlan in port["allowed"]
                            and name != port_name
                            and port_status(name, t) == (True, "forwarding")
                        ):
                            egress.append(name)
                    if egress:
                        action = "flood"
        out_ports = []
        dropped = []
        queue_idx = qos_map[priority]
        for name in egress:  # 按 egress 序逐口入队；镜像不随之产生
            out_tag = None if vlan in by_name[name]["untagged"] else vlan
            if admit(name, queue_idx):
                egress_queues[name][queue_idx].append(
                    {"id": fid, "vlan": vlan, "mirror": out_tag}
                )
                out_ports.append({"name": name, "vlan": out_tag})
            else:  # 拒绝：计出口与 VLAN drop，不入队
                port_stats[name]["drop"] += 1
                vlan_stats[vlan]["drop"] += 1
                dropped.append(name)
        if not egress:  # 无出口：沿用 acl，计入口与 VLAN drop
            port_stats[port_name]["drop"] += 1
            vlan_stats[vlan]["drop"] += 1
        results.append(
            {"t": t, "action": action, "ports": out_ports,
             "dropped": dropped,
             "mirrors": [ingress_copy] if ingress_copy is not None else []}
        )
        if observer is not None:
            observer["items"].append(
                {"kind": "frame", "t": t, "applied": True,
                 "output": results[-1]}
            )
    return {
        "results": results,
        "ports": [
            {
                "name": port["name"],
                "rx": port_stats[port["name"]]["rx"],
                "tx": port_stats[port["name"]]["tx"],
                "drop": port_stats[port["name"]]["drop"],
            }
            for port in ports
        ],
        "vlans": [
            {
                "vlan": vlan,
                "rx": vlan_stats[vlan]["rx"],
                "tx": vlan_stats[vlan]["tx"],
                "drop": vlan_stats[vlan]["drop"],
            }
            for vlan in sorted(vlan_stats)
        ],
        "security": [
            {
                "port": name,
                "learned": [
                    {"vlan": vlan, "mac": mac}
                    for vlan, mac in sorted(dynamic[name])
                ],
                "violations": violations[name],
                "shutdown": name in sec_down,
            }
            for name in sec_order
        ],
    }


def _fail(message):
    sys.stderr.buffer.write(
        ('{"error":"%s"}\n' % message).encode("utf-8")
    )


DEFAULT_MAX_EVENTS = 100000
DEFAULT_MAX_LOG_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_CONFIG_BYTES = 1024 * 1024
DEFAULT_MAX_EVENTS_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_DATA_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_ITEMS = 100000
DEFAULT_MAX_OUTPUT_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_STP_WORK = 10000000
DEFAULT_MAX_FDB_WORK = 10000000
DEFAULT_MAX_FORWARD_WORK = 10000000
DEFAULT_MAX_FORWARD_STP_WORK = 10000000
DEFAULT_MAX_STORM_WORK = 10000000
DEFAULT_MAX_LAG_WORK = 10000000
_LIMIT_RE = re.compile(r"[1-9][0-9]*")
_READ_CHUNK = 65536


def _limit_value(token):
    """十进制上限串转整数：逐位累加，任意长度按数学整数处理。"""
    value = 0
    for char in token:
        value = value * 10 + ord(char) - ord("0")
    return value


def _parse_limits(tokens, counts, defaults):
    """解析可选上限（个数须属于 counts，均须匹配 [1-9][0-9]*）。

    返回解析值加 defaults 中缺省项；个数不对或任一参数非法返回 None
    （调用方按 usage 处理）。
    """
    if len(tokens) not in counts:
        return None
    if any(_LIMIT_RE.fullmatch(token) is None for token in tokens):
        return None
    parsed = tuple(_limit_value(token) for token in tokens)
    return parsed + defaults[len(parsed):]


def _read_limited(handle, limit):
    """按至多 65536 字节分块读取；超过 limit 即停止并返回 None。

    额度未尽时单次至多请求剩余量，耗尽后只读 1 字节探测超限。
    """
    chunks = []
    total = 0
    while True:
        remaining = limit - total
        if remaining > 0:
            chunk = handle.read(min(_READ_CHUNK, remaining))
        else:
            chunk = handle.read(1)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            return None


RECORD_SCHEMA = 1
LOG_KEYS = ("schema", "config", "records", "sha256")
RECORD_KEYS = ("t", "version", "event", "applied", "output")
EVENT_KIND_BY_KEYS = {
    STP_EVENT_KEYS: "link",
    MEMBER_EVENT_KEYS: "member",
    SERVICE_EVENT_KEYS: "service",
    FRAME_KEYS_ACL: "frame",
    RELOAD_EVENT_KEYS: "reload",
}
_HEX64_RE = re.compile(r"[0-9a-f]{64}\Z")


def _event_kind(event):
    if not isinstance(event, dict):
        raise InvalidInput("bad log event")
    kind = EVENT_KIND_BY_KEYS.get(frozenset(event))
    if kind is None:
        raise InvalidInput("bad log event")
    return kind


def _run_reload(config, events, observe):
    """reload/record/replay 共用：校验配置与事件并执行 port-security 仿真。

    返回 (reload 结果 dict, observer 或 None)。全部校验与非法重载检测先于返回。
    """
    (
        bridges,
        links,
        delay,
        bridge,
        ports,
        age,
        storm,
        lags,
        mirror,
        acl,
        qos,
        security,
    ) = validate_security_config(config)
    link_ids = {link["id"] for link in links}
    reload_events, final_config = validate_reload_events(
        events, ports, link_ids, lags, config
    )
    observer = {} if observe else None
    result = forward_security(
        bridges,
        links,
        delay,
        bridge,
        ports,
        age,
        storm,
        lags,
        mirror,
        acl,
        qos,
        security,
        reload_events,
        observer=observer,
    )
    result["config"] = _canonical(final_config)
    return result, observer


def _build_log_doc(config, events, items):
    """构造 LOG 文档（含 sha256）；records 与事件等长、同序。"""
    if len(events) != len(items):
        raise InvalidInput("bad log")
    records = []
    version = 0  # version 初值 0，取事件后值；每次 reload（无变化亦算）加 1
    for event, observed in zip(events, items):
        kind = _event_kind(event)
        if kind != observed["kind"]:
            raise InvalidInput("bad log")
        if kind == "reload":
            version += 1
        records.append(
            {
                "t": event["t"],
                "version": version,
                "event": _canonical(event),
                "applied": observed["applied"],
                "output": observed["output"],
            }
        )
    doc = {
        "schema": RECORD_SCHEMA,
        "config": _canonical(config),
        "records": records,
    }
    doc["sha256"] = hashlib.sha256(_log_prefix_bytes(doc)).hexdigest()
    return doc


def _log_prefix_bytes(doc):
    """sha256 摘要文本：schema,config,records 规范序列化后含 LF。"""
    prefix = {
        "schema": doc["schema"],
        "config": doc["config"],
        "records": doc["records"],
    }
    return (
        json.dumps(prefix, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _log_bytes(doc):
    ordered = {key: doc[key] for key in LOG_KEYS}
    return (
        json.dumps(ordered, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _assert_canonical_order(value):
    """config/event 内对象键须递归按 Unicode 码点升序，数组保序。"""
    if isinstance(value, dict):
        keys = list(value)
        if keys != sorted(keys):
            raise InvalidInput("bad log key order")
        for item in value.values():
            _assert_canonical_order(item)
    elif isinstance(value, list):
        for item in value:
            _assert_canonical_order(item)


def _json_equal(a, b):
    """JSON 值深比较；bool 不与 int 混同，键序无关，数组保序。"""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(
            _json_equal(a[key], b[key]) for key in a
        )
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(
            _json_equal(x, y) for x, y in zip(a, b)
        )
    if a is None or b is None:
        return a is None and b is None
    return type(a) is type(b) and a == b


def _validate_log_shape(log):
    """严格校验 LOG 字段、类型、键序；不含语义重放。"""
    if not isinstance(log, dict) or list(log) != list(LOG_KEYS):
        raise InvalidInput("bad log")
    if not _is_int(log["schema"]) or log["schema"] != RECORD_SCHEMA:
        raise InvalidInput("bad log schema")
    config = log["config"]
    if not isinstance(config, dict):
        raise InvalidInput("bad log config")
    _assert_canonical_order(config)
    records = log["records"]
    if not isinstance(records, list):
        raise InvalidInput("bad log records")
    for record in records:
        if not isinstance(record, dict) or list(record) != list(RECORD_KEYS):
            raise InvalidInput("bad log record")
        if not _is_int(record["t"]) or record["t"] < 0:
            raise InvalidInput("bad log t")
        if not _is_int(record["version"]) or record["version"] < 0:
            raise InvalidInput("bad log version")
        event = record["event"]
        if not isinstance(event, dict):
            raise InvalidInput("bad log event")
        _assert_canonical_order(event)
        _event_kind(event)
        if not isinstance(record["applied"], bool):
            raise InvalidInput("bad log applied")
        if record["output"] is not None and not isinstance(
            record["output"], dict
        ):
            raise InvalidInput("bad log output")
    digest = log["sha256"]
    if not isinstance(digest, str) or _HEX64_RE.fullmatch(digest) is None:
        raise InvalidInput("bad log sha256")


def _verify_records(log, events, items):
    """重放后逐项核对 t/version/event/applied/output。"""
    records = log["records"]
    if len(records) != len(items):
        raise InvalidInput("bad log records")
    version = 0
    for event, observed, record in zip(events, items, records):
        kind = _event_kind(event)
        if kind != observed["kind"]:
            raise InvalidInput("bad log record")
        if kind == "reload":
            version += 1
        if record["t"] != event["t"]:
            raise InvalidInput("bad log t")
        if record["version"] != version:
            raise InvalidInput("bad log version")
        if not _json_equal(record["event"], _canonical(event)):
            raise InvalidInput("bad log event")
        if record["applied"] is not observed["applied"]:
            raise InvalidInput("bad log applied")
        if not _json_equal(record["output"], observed["output"]):
            raise InvalidInput("bad log output")


def _atomic_write(path, payload):
    """同目录临时文件 + os.replace 原子写入；失败不改动目标。"""
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp_path = tempfile.mkstemp(prefix=".switch-log-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except OSError:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _result_bytes(result):
    """stdout 载荷：紧凑 UTF-8 JSON 加一个 LF。"""
    return (
        json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
        + b"\n"
    )


def _cmd_record(
    config_path,
    events_path,
    log_path,
    max_events,
    max_log_bytes,
    max_config_bytes,
    max_events_bytes,
    max_output_bytes,
):
    try:
        with open(config_path, "rb") as config_handle, open(
            events_path, "rb"
        ) as events_handle:
            # 两文件均可读后，先判 CONFIG 原始字节，再判 EVENTS 原始字节
            config_raw = _read_limited(config_handle, max_config_bytes)
            if config_raw is None:
                _fail("config_limit")
                return 5
            events_raw = _read_limited(events_handle, max_events_bytes)
            if events_raw is None:
                _fail("events_limit")
                return 5
    except OSError:
        _fail("file_not_found")
        return 3
    try:
        # 事件上界先于解析与预演判定；超限时绝不触碰 LOG
        events_preview = parse_json(events_raw)
        if isinstance(events_preview, list) and len(events_preview) > max_events:
            _fail("event_limit")
            return 5
        # 先无副作用预演：解析、全部校验与各重载点检测均在内存完成
        config = parse_json(config_raw)
        events = events_preview
        result, observer = _run_reload(config, events, True)
        doc = _build_log_doc(config, events, observer["items"])
        payload = _log_bytes(doc)
        # 字节上界（含末尾 LF）在写入前判定；等于上限合法
        if len(payload) > max_log_bytes:
            _fail("log_limit")
            return 5
        # 输出上界在 log_limit 之后、原子写 LOG 之前判定；超限时绝不触碰 LOG
        output = _result_bytes(result)
        if len(output) > max_output_bytes:
            _fail("output_limit")
            return 5
        _atomic_write(log_path, payload)  # 成功后才原子写 LOG
    except InvalidInput:
        _fail("invalid_input")
        return 4
    except OSError:
        _fail("file_not_found")
        return 3
    sys.stdout.buffer.write(output)
    return 0


def _cmd_replay(log_path, max_events, max_log_bytes, max_output_bytes):
    try:
        with open(log_path, "rb") as handle:
            log_raw = _read_limited(handle, max_log_bytes)
    except OSError:
        _fail("file_not_found")
        return 3
    # 字节上界先判定（分块读取、超限即停，含末尾 LF）
    if log_raw is None:
        _fail("log_limit")
        return 5
    try:
        log = parse_json(log_raw)  # 全量校验先于重放
        _validate_log_shape(log)
        if hashlib.sha256(_log_prefix_bytes(log)).hexdigest() != log["sha256"]:
            raise InvalidInput("bad log sha256")
        config = log["config"]
        events = [record["event"] for record in log["records"]]
        # records 上界在解析校验后、重放前判定
        if len(log["records"]) > max_events:
            _fail("event_limit")
            return 5
        result, observer = _run_reload(config, events, True)
        _verify_records(log, events, observer["items"])
        # 重放重建的 LOG 须与原文件逐字节一致（含 sha256 与 LF）
        rebuilt = _build_log_doc(config, events, observer["items"])
        if _log_bytes(rebuilt) != log_raw:
            raise InvalidInput("bad log")
        # 输出上界在全部日志语义与重放核对成功后判定；LOG 保持不动
        output = _result_bytes(result)
        if len(output) > max_output_bytes:
            _fail("output_limit")
            return 5
    except InvalidInput:
        _fail("invalid_input")
        return 4
    sys.stdout.buffer.write(output)
    return 0


def main(argv):
    args = argv[1:]
    if args[:1] == ["record"]:
        # record CONFIG EVENTS LOG [MAX_EVENTS MAX_LOG_BYTES
        #   [MAX_CONFIG_BYTES MAX_EVENTS_BYTES [MAX_OUTPUT_BYTES]]]
        if len(args) not in (4, 6, 8, 9):
            _fail("usage")
            return 2
        limits = _parse_limits(
            args[4:],
            (0, 2, 4, 5),
            (
                DEFAULT_MAX_EVENTS,
                DEFAULT_MAX_LOG_BYTES,
                DEFAULT_MAX_CONFIG_BYTES,
                DEFAULT_MAX_EVENTS_BYTES,
                DEFAULT_MAX_OUTPUT_BYTES,
            ),
        )
        if limits is None:
            _fail("usage")
            return 2
        return _cmd_record(args[1], args[2], args[3], *limits)
    if args[:1] == ["replay"]:
        # replay LOG [MAX_EVENTS MAX_LOG_BYTES [MAX_OUTPUT_BYTES]]
        if len(args) not in (2, 4, 5):
            _fail("usage")
            return 2
        limits = _parse_limits(
            args[2:],
            (0, 2, 3),
            (DEFAULT_MAX_EVENTS, DEFAULT_MAX_LOG_BYTES, DEFAULT_MAX_OUTPUT_BYTES),
        )
        if limits is None:
            _fail("usage")
            return 2
        return _cmd_replay(args[1], *limits)
    # stp/fdb/forward/forward-stp/forward-stp-storm/lag 额外允许 5 项上限
    # （末尾分别为 MAX_STP_WORK/MAX_FDB_WORK/MAX_FORWARD_WORK/
    # MAX_FORWARD_STP_WORK/MAX_STORM_WORK/MAX_LAG_WORK）；其余 MODE 仅
    # 0、2、4 项
    is_stp = args[:1] == ["stp"]
    is_fdb = args[:1] == ["fdb"]
    is_forward = args[:1] == ["forward"]
    is_forward_stp = args[:1] == ["forward-stp"]
    is_forward_stp_storm = args[:1] == ["forward-stp-storm"]
    is_lag = args[:1] == ["lag"]
    allowed_counts = (
        (3, 5, 7, 8)
        if is_stp or is_fdb or is_forward or is_forward_stp
        or is_forward_stp_storm or is_lag
        else (3, 5, 7)
    )
    if len(args) not in allowed_counts or args[0] not in (
        "fdb",
        "forward",
        "stp",
        "forward-stp",
        "forward-stp-storm",
        "lag",
        "mirror",
        "acl",
        "qos",
        "port-security",
        "reload",
    ):
        _fail("usage")
        return 2
    # MODE CONFIG DATA [MAX_CONFIG_BYTES MAX_DATA_BYTES [MAX_ITEMS MAX_OUTPUT_BYTES [MAX_STP_WORK|MAX_FDB_WORK|MAX_FORWARD_WORK|MAX_FORWARD_STP_WORK|MAX_STORM_WORK|MAX_LAG_WORK]]]
    # 上限均须匹配 [1-9][0-9]*，按数学整数比较
    if any(_LIMIT_RE.fullmatch(token) is None for token in args[3:]):
        _fail("usage")
        return 2
    limits = (
        DEFAULT_MAX_CONFIG_BYTES,
        DEFAULT_MAX_DATA_BYTES,
        DEFAULT_MAX_ITEMS,
        DEFAULT_MAX_OUTPUT_BYTES,
    )
    parsed = tuple(_limit_value(token) for token in args[3:])
    if is_stp:
        stp_limits = limits + (DEFAULT_MAX_STP_WORK,)
        (
            max_config_bytes,
            max_data_bytes,
            max_items,
            max_output_bytes,
            max_stp_work,
        ) = parsed + stp_limits[len(parsed):]
        max_fdb_work = None
        max_forward_work = None
        max_forward_stp_work = None
        max_storm_work = None
        max_lag_work = None
    elif is_fdb:
        fdb_limits = limits + (DEFAULT_MAX_FDB_WORK,)
        (
            max_config_bytes,
            max_data_bytes,
            max_items,
            max_output_bytes,
            max_fdb_work,
        ) = parsed + fdb_limits[len(parsed):]
        max_stp_work = None
        max_forward_work = None
        max_forward_stp_work = None
        max_lag_work = None
    elif is_forward:
        forward_limits = limits + (DEFAULT_MAX_FORWARD_WORK,)
        (
            max_config_bytes,
            max_data_bytes,
            max_items,
            max_output_bytes,
            max_forward_work,
        ) = parsed + forward_limits[len(parsed):]
        max_stp_work = None
        max_fdb_work = None
        max_forward_stp_work = None
        max_lag_work = None
    elif is_forward_stp:
        forward_stp_limits = limits + (DEFAULT_MAX_FORWARD_STP_WORK,)
        (
            max_config_bytes,
            max_data_bytes,
            max_items,
            max_output_bytes,
            max_forward_stp_work,
        ) = parsed + forward_stp_limits[len(parsed):]
        max_stp_work = None
        max_fdb_work = None
        max_forward_work = None
        max_lag_work = None
    elif is_forward_stp_storm:
        storm_limits = limits + (DEFAULT_MAX_STORM_WORK,)
        (
            max_config_bytes,
            max_data_bytes,
            max_items,
            max_output_bytes,
            max_storm_work,
        ) = parsed + storm_limits[len(parsed):]
        max_stp_work = None
        max_fdb_work = None
        max_forward_work = None
        max_forward_stp_work = None
        max_lag_work = None
    elif is_lag:
        lag_limits = limits + (DEFAULT_MAX_LAG_WORK,)
        (
            max_config_bytes,
            max_data_bytes,
            max_items,
            max_output_bytes,
            max_lag_work,
        ) = parsed + lag_limits[len(parsed):]
        max_stp_work = None
        max_fdb_work = None
        max_forward_work = None
        max_forward_stp_work = None
        max_storm_work = None
    else:
        max_config_bytes, max_data_bytes, max_items, max_output_bytes = (
            parsed + limits[len(parsed):]
        )
        max_stp_work = None
        max_fdb_work = None
        max_forward_work = None
        max_forward_stp_work = None
        max_lag_work = None
    mode = args[0]
    config_path, data_path = args[1], args[2]
    try:
        # 先打开两文件，任一失败即停；均可读后按 CONFIG、DATA 顺序分块读
        with open(config_path, "rb") as config_handle, open(
            data_path, "rb"
        ) as data_handle:
            config_raw = _read_limited(config_handle, max_config_bytes)
            if config_raw is None:
                _fail("config_limit")
                return 5
            data_raw = _read_limited(data_handle, max_data_bytes)
            if data_raw is None:
                _fail("data_limit")
                return 5
    except OSError:
        _fail("file_not_found")
        return 3
    try:
        config = parse_json(config_raw)
        data = parse_json(data_raw)
        # 项数上界在解析后、语义校验前判定；DATA 非数组仍按非法输入处理
        if isinstance(data, list) and len(data) > max_items:
            _fail("item_limit")
            return 5
        if mode == "fdb":
            ports, age = validate_config(config)
            events = validate_events(data, ports)
            # 两文件解析及全量语义校验后，用独立空映射无副作用预演；
            # 超限时不得调用正式仿真
            fdb_work(events, age, max_fdb_work)
            result = simulate(events, age)
        elif mode == "stp":
            bridges, links, delay = validate_stp_config(config)
            link_ids = {link["id"] for link in links}
            result = stp(
                bridges,
                links,
                delay,
                validate_stp_events(data, link_ids),
                max_stp_work,
            )
        elif mode == "forward-stp":
            bridges, links, delay, bridge, ports, age = (
                validate_forward_stp_config(config)
            )
            link_ids = {link["id"] for link in links}
            events = validate_forward_stp_events(data, ports, link_ids)
            # 全量语义校验后无副作用预演；超限时不得调用正式仿真
            forward_stp_work(
                bridges, links, ports, events, max_forward_stp_work
            )
            result = forward_stp(
                bridges,
                links,
                delay,
                bridge,
                ports,
                age,
                events,
            )
        elif mode == "forward-stp-storm":
            bridges, links, delay, bridge, ports, age, storm = (
                validate_forward_stp_storm_config(config)
            )
            link_ids = {link["id"] for link in links}
            events = validate_forward_stp_events(data, ports, link_ids)
            # 全量语义校验后无副作用预演；超限时不得调用正式仿真
            forward_stp_storm_work(
                bridges,
                links,
                delay,
                bridge,
                ports,
                age,
                storm,
                events,
                max_storm_work,
            )
            result = forward_stp_storm(
                bridges,
                links,
                delay,
                bridge,
                ports,
                age,
                storm,
                events,
            )
        elif mode == "lag":
            (
                bridges,
                links,
                delay,
                bridge,
                ports,
                age,
                storm,
                lags,
            ) = validate_lag_config(config)
            link_ids = {link["id"] for link in links}
            events = validate_lag_events(data, ports, link_ids, lags)
            # 全量语义校验后无副作用预演；超限时不得调用正式仿真
            lag_work(
                bridges,
                links,
                delay,
                bridge,
                ports,
                age,
                storm,
                lags,
                events,
                max_lag_work,
            )
            result = forward_lag(
                bridges,
                links,
                delay,
                bridge,
                ports,
                age,
                storm,
                lags,
                events,
            )
        elif mode == "mirror":
            (
                bridges,
                links,
                delay,
                bridge,
                ports,
                age,
                storm,
                lags,
                mirror,
            ) = validate_mirror_config(config)
            link_ids = {link["id"] for link in links}
            result = forward_mirror(
                bridges,
                links,
                delay,
                bridge,
                ports,
                age,
                storm,
                lags,
                mirror,
                validate_lag_events(data, ports, link_ids, lags),
            )
        elif mode == "acl":
            (
                bridges,
                links,
                delay,
                bridge,
                ports,
                age,
                storm,
                lags,
                mirror,
                acl,
            ) = validate_acl_config(config)
            link_ids = {link["id"] for link in links}
            result = forward_acl(
                bridges,
                links,
                delay,
                bridge,
                ports,
                age,
                storm,
                lags,
                mirror,
                acl,
                validate_acl_events(data, ports, link_ids, lags),
            )
        elif mode == "qos":
            (
                bridges,
                links,
                delay,
                bridge,
                ports,
                age,
                storm,
                lags,
                mirror,
                acl,
                qos,
            ) = validate_qos_config(config)
            link_ids = {link["id"] for link in links}
            result = forward_qos(
                bridges,
                links,
                delay,
                bridge,
                ports,
                age,
                storm,
                lags,
                mirror,
                acl,
                qos,
                validate_qos_events(data, ports, link_ids, lags),
            )
        elif mode == "port-security":
            (
                bridges,
                links,
                delay,
                bridge,
                ports,
                age,
                storm,
                lags,
                mirror,
                acl,
                qos,
                security,
            ) = validate_security_config(config)
            link_ids = {link["id"] for link in links}
            result = forward_security(
                bridges,
                links,
                delay,
                bridge,
                ports,
                age,
                storm,
                lags,
                mirror,
                acl,
                qos,
                security,
                validate_qos_events(data, ports, link_ids, lags),
            )
        elif mode == "reload":
            (
                bridges,
                links,
                delay,
                bridge,
                ports,
                age,
                storm,
                lags,
                mirror,
                acl,
                qos,
                security,
            ) = validate_security_config(config)
            link_ids = {link["id"] for link in links}
            reload_events, final_config = validate_reload_events(
                data, ports, link_ids, lags, config
            )
            result = forward_security(
                bridges,
                links,
                delay,
                bridge,
                ports,
                age,
                storm,
                lags,
                mirror,
                acl,
                qos,
                security,
                reload_events,
            )
            result["config"] = _canonical(final_config)
        else:
            if is_v2_config(config):
                ports, age = validate_forward_config_v2(config)
                frames = validate_frames_v2(data, ports)
                # 两文件解析及全量语义校验后，用独立空 FDB 无副作用预演；
                # 超限时不得正式转发
                forward_work_v2(frames, ports, age, max_forward_work)
                result = forward_v2(frames, ports, age)
            else:
                ports, age = validate_forward_config(config)
                frames = validate_frames(data, ports)
                forward_work(frames, ports, age, max_forward_work)
                result = forward(frames, ports, age)
    except InvalidInput:
        _fail("invalid_input")
        return 4
    except StpWorkLimit:
        _fail("stp_work_limit")
        return 5
    except FdbWorkLimit:
        _fail("fdb_work_limit")
        return 5
    except ForwardWorkLimit:
        _fail("forward_work_limit")
        return 5
    except ForwardStpWorkLimit:
        _fail("forward_stp_work_limit")
        return 5
    except StormWorkLimit:
        _fail("storm_work_limit")
        return 5
    except LagWorkLimit:
        _fail("lag_work_limit")
        return 5
    payload = (
        json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
        + b"\n"
    )
    # 输出字节上界（含末尾 LF）在写出前判定；等于上限合法，超限时 stdout 为空
    if len(payload) > max_output_bytes:
        _fail("output_limit")
        return 5
    sys.stdout.buffer.write(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
