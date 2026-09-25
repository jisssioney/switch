#!/usr/bin/env python3
"""二层以太网交换机仿真（仅标准库）。"""

from collections import deque
import heapq
import json
import re
import sys
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
SECURITY_ITEM_KEYS = frozenset(("port", "limit", "action", "static"))
SECURITY_ACTIONS = ("drop", "shutdown")
SECURITY_STATIC_KEYS = frozenset(("mac", "vlan"))


class InvalidInput(Exception):
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


def stp(bridges, links, delay, events):
    by_id = {link["id"]: link for link in links}
    previous = {}  # (bridge, port) -> 上一轮角色
    since = {}  # (bridge, port) -> 获得当前 root/designated 角色的时刻
    results = []

    def snapshot(t):
        root_of, cost, roles = stp_converge(bridges, links)
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
    for t, lid, up in events:
        by_id[lid]["up"] = up
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
    if not isinstance(security, list) or not security:
        raise InvalidInput("bad security")
    names = {port["name"] for port in ports}
    used_ports = set()
    static_keys = set()
    parsed = []
    for item in security:
        if not isinstance(item, dict) or frozenset(item) != SECURITY_ITEM_KEYS:
            raise InvalidInput("bad security item")
        port = item["port"]
        limit = item["limit"]
        action = item["action"]
        static = item["static"]
        if not isinstance(port, str) or port not in names or port in used_ports:
            raise InvalidInput("bad security port")
        used_ports.add(port)
        if not _is_int(limit) or limit < 0:
            raise InvalidInput("bad security limit")
        if action not in SECURITY_ACTIONS:
            raise InvalidInput("bad security action")
        if not isinstance(static, list):
            raise InvalidInput("bad security static")
        parsed_static = []
        for entry in static:
            if (
                not isinstance(entry, dict)
                or frozenset(entry) != SECURITY_STATIC_KEYS
            ):
                raise InvalidInput("bad security static entry")
            mac = entry["mac"]
            vlan = entry["vlan"]
            if not valid_mac(mac):
                raise InvalidInput("bad security static mac")
            if not _valid_vlan_id(vlan):
                raise InvalidInput("bad security static vlan")
            if (vlan, mac) in static_keys:
                raise InvalidInput("security static must be globally distinct")
            static_keys.add((vlan, mac))
            parsed_static.append({"mac": mac, "vlan": vlan})
        parsed.append(
            {
                "port": port,
                "limit": limit,
                "action": action,
                "static": parsed_static,
            }
        )
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
    acl, qos, security, events
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
    # 端口安全：静态归属 (vlan, mac) -> 口；动态绑定同上；动态项按口归集
    sec_by_port = {item["port"]: item for item in security}
    sec_static = {}
    for item in security:
        for entry in item["static"]:
            sec_static[(entry["vlan"], entry["mac"])] = item["port"]
    sec_dynamic = {item["port"]: set() for item in security}
    sec_bind = {}
    sec_violations = {item["port"]: 0 for item in security}
    sec_shutdown = {item["port"]: False for item in security}

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
        if sec_shutdown.get(name):  # 安全 shutdown：永久按物理 down 处理
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
        if sec_shutdown.get(mirror_target):  # 安全 shutdown 视同 down
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

    def security_violation(port_name, vlan):
        """违例处置：累计；shutdown 永久按 down 禁用并清动态绑定。"""
        sec_violations[port_name] += 1
        if sec_by_port[port_name]["action"] == "shutdown":
            sec_shutdown[port_name] = True
            for key in sec_dynamic[port_name]:
                del sec_bind[key]
            sec_dynamic[port_name] = set()
            clear_queue(port_name)

    def security_check(port_name, vlan, src):
        """FDB 前的端口安全检查；返回 True 表示违例。

        静态源只准从所属口进入；非静态源首次绑定入端口，已绑定别口或
        本口动态数达到 limit 即违例；重复源不增数。绑定不老化，端口状态
        变化不清除。
        """
        item = sec_by_port.get(port_name)
        if item is None or sec_shutdown[port_name]:
            return False  # 未启用端口安全；shutdown 后按 down 口常规处理
        owner = sec_static.get((vlan, src))
        if owner is not None:
            return owner != port_name
        bound = sec_bind.get((vlan, src))
        if bound is not None:
            return bound != port_name  # 本口重复源：合法且不增数
        if len(sec_dynamic[port_name]) >= item["limit"]:
            return True
        sec_bind[(vlan, src)] = port_name
        sec_dynamic[port_name].add((vlan, src))
        return False

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
        # VLAN 与 ACL 之后、FDB 之前：端口安全违例沿用 ACL-drop 结果与统计
        if security_check(port_name, vlan, src):
            security_violation(port_name, vlan)
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
        "security": [
            {
                "port": item["port"],
                "learned": [
                    {"vlan": vlan, "mac": mac}
                    for vlan, mac in sorted(sec_dynamic[item["port"]])
                ],
                "violations": sec_violations[item["port"]],
                "shutdown": sec_shutdown[item["port"]],
            }
            for item in security
        ],
    }


def _fail(message):
    sys.stderr.buffer.write(
        ('{"error":"%s"}\n' % message).encode("utf-8")
    )


def main(argv):
    args = argv[1:]
    if len(args) != 3 or args[0] not in (
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
    ):
        _fail("usage")
        return 2
    mode = args[0]
    config_path, data_path = args[1], args[2]
    try:
        with open(config_path, "rb") as handle:
            config_raw = handle.read()
        with open(data_path, "rb") as handle:
            data_raw = handle.read()
    except OSError:
        _fail("file_not_found")
        return 3
    try:
        config = parse_json(config_raw)
        data = parse_json(data_raw)
        if mode == "fdb":
            ports, age = validate_config(config)
            result = simulate(validate_events(data, ports), age)
        elif mode == "stp":
            bridges, links, delay = validate_stp_config(config)
            link_ids = {link["id"] for link in links}
            result = stp(
                bridges, links, delay, validate_stp_events(data, link_ids)
            )
        elif mode == "forward-stp":
            bridges, links, delay, bridge, ports, age = (
                validate_forward_stp_config(config)
            )
            link_ids = {link["id"] for link in links}
            result = forward_stp(
                bridges,
                links,
                delay,
                bridge,
                ports,
                age,
                validate_forward_stp_events(data, ports, link_ids),
            )
        elif mode == "forward-stp-storm":
            bridges, links, delay, bridge, ports, age, storm = (
                validate_forward_stp_storm_config(config)
            )
            link_ids = {link["id"] for link in links}
            result = forward_stp_storm(
                bridges,
                links,
                delay,
                bridge,
                ports,
                age,
                storm,
                validate_forward_stp_events(data, ports, link_ids),
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
            result = forward_lag(
                bridges,
                links,
                delay,
                bridge,
                ports,
                age,
                storm,
                lags,
                validate_lag_events(data, ports, link_ids, lags),
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
        else:
            if is_v2_config(config):
                ports, age = validate_forward_config_v2(config)
                result = forward_v2(validate_frames_v2(data, ports), ports, age)
            else:
                ports, age = validate_forward_config(config)
                result = forward(validate_frames(data, ports), ports, age)
    except InvalidInput:
        _fail("invalid_input")
        return 4
    payload = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.buffer.write(payload.encode("utf-8") + b"\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
