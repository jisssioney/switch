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
            {key: config[key] for key in STORM_CONFIG_KEYS}
        )
    )
    lags = config["lags"]
    if not isinstance(lags, list) or not lags:
        raise InvalidInput("bad lags")
    by_name = {port["name"]: port for port in ports}
    names = set()
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
        if name in names:
            raise InvalidInput("lag names must be distinct")
        names.add(name)
        if (
            not isinstance(members, list)
            or len(members) < 2
            or len(set(members)) != len(members)
            or not all(
                isinstance(member, str) and member in by_name
                for member in members
            )
        ):
            raise InvalidInput("bad lag members")
        if used & set(members):
            raise InvalidInput("lag members must be globally distinct")
        used.update(members)
        first = by_name[members[0]]
        for member in members[1:]:
            other = by_name[member]
            if (
                other["mode"] != first["mode"]
                or other["pvid"] != first["pvid"]
                or other["allowed"] != first["allowed"]
                or other["untagged"] != first["untagged"]
            ):
                raise InvalidInput("lag members must share vlan settings")
        if (
            not isinstance(hash_fields, list)
            or not hash_fields
            or not all(field in LAG_HASH_FIELDS for field in hash_fields)
            or not _strictly_increasing(
                [LAG_HASH_FIELDS.index(field) for field in hash_fields]
            )
        ):
            raise InvalidInput("bad lag hash")
        parsed.append({"name": name, "members": members, "hash": hash_fields})
    return bridges, links, delay, bridge, ports, age, storm, parsed


def validate_lag_events(events, ports, link_ids, lags):
    if not isinstance(events, list):
        raise InvalidInput("events must be a list")
    names = {port["name"] for port in ports}
    members = set()
    for lag in lags:
        members.update(lag["members"])
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
        elif keys == MEMBER_EVENT_KEYS:
            t = event["t"]
            member = event["member"]
            up = event["up"]
            if not _is_int(t) or t < 0:
                raise InvalidInput("bad t")
            if prev_t is not None and t < prev_t:
                raise InvalidInput("t not monotonic")
            if not isinstance(member, str) or member not in members:
                raise InvalidInput("bad event member")
            if not isinstance(up, bool):
                raise InvalidInput("bad up")
            result.append(("member", t, member, up))
        else:
            raise InvalidInput("bad event")
        prev_t = t
    return result


def forward_stp_lag(
    bridges, links, delay, bridge_name, ports, age, storm, lags, events
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
    lag_by_name = {lag["name"]: lag for lag in lags}
    member_of = {}  # 物理成员口名 -> lag
    for lag in lags:
        for member in lag["members"]:
            member_of[member] = lag
    member_up = {member: True for lag in lags for member in lag["members"]}
    fdb = {}  # (vlan, mac) -> [逻辑口（组名或物理口名）, seen]
    port_stats = {
        port["name"]: {"rx": 0, "tx": 0, "drop": 0} for port in ports
    }
    vlan_stats = {}
    for port in ports:
        for vlan in port["allowed"]:
            vlan_stats.setdefault(vlan, {"rx": 0, "tx": 0, "drop": 0})
    rate_queues = {}  # (入端口, vlan, 类别) -> 放行时刻 deque
    move_queues = {}  # (vlan, src) -> 迁移时刻 deque
    last_learn = {}  # (vlan, src) -> 最后学习物理端口
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

    def member_available(name, vlan, t):
        """成员可用：端口 up、STP forwarding 且允许该 VLAN。"""
        return (
            member_up[name]
            and vlan in by_name[name]["allowed"]
            and port_status(name, t) == (True, "forwarding")
        )

    def select_member(lag, vlan, src, dst, t):
        """按 members 顺序取可用候选，hash 取模选定；无候选返回 None。"""
        candidates = [
            member
            for member in lag["members"]
            if member_available(member, vlan, t)
        ]
        if not candidates:
            return None
        fields = {"src": src, "dst": dst, "vlan": str(vlan)}
        text = "|".join(fields[field] for field in lag["hash"])
        index = zlib.crc32(text.encode("utf-8")) % len(candidates)
        return candidates[index]

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
        ingress_lag = member_of.get(port_name)
        logical = ingress_lag["name"] if ingress_lag is not None else port_name
        fdb[(vlan, src)] = [logical, t]
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
        if item[0] == "member":
            _, t, member, up = item
            member_up[member] = up  # 可用性变化不清 FDB，下帧重算
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
        ingress_lag = member_of.get(port_name)
        if ingress_lag is not None and not (
            member_up[port_name] and state == "forwarding"
        ):
            # 不可用成员：入帧丢弃且不学习
            port_stats[port_name]["drop"] += 1
            vlan_stats[vlan]["drop"] += 1
            results.append({"t": t, "action": "drop", "ports": []})
            continue
        suppressed = suppress(t, port_name, vlan, src, dst, state)
        ingress_logical = (
            ingress_lag["name"] if ingress_lag is not None else port_name
        )
        egress = []
        action = "drop"
        if not suppressed and state == "forwarding":
            is_group = int(dst[:2], 16) & 1
            hit = None if is_group else fdb.get((vlan, dst))
            if hit is not None and hit[0] != ingress_logical:
                target = hit[0]
                target_lag = lag_by_name.get(target)
                if target_lag is not None:
                    chosen = select_member(target_lag, vlan, src, dst, t)
                    if chosen is not None:
                        egress = [chosen]
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
                picked = {}  # 组名 -> 选中的成员口（泛洪每组至多一份）
                for lag in lags:
                    if lag["name"] == ingress_logical:  # 禁止组内回送
                        continue
                    chosen = select_member(lag, vlan, src, dst, t)
                    if chosen is not None:
                        picked[lag["name"]] = chosen
                for port in ports:
                    name = port["name"]
                    owner = member_of.get(name)
                    if owner is not None:
                        if picked.get(owner["name"]) == name:
                            egress.append(name)
                        continue
                    if (
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
            bridges, links, delay, bridge, ports, age, storm, lags = (
                validate_lag_config(config)
            )
            link_ids = {link["id"] for link in links}
            result = forward_stp_lag(
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
