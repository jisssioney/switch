#!/usr/bin/env python3
"""二层以太网交换机仿真（仅标准库）。"""

import heapq
import json
import re
import sys

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
    if not isinstance(bridges, list) or not bridges:
        raise InvalidInput("bridges must be a non-empty list")
    if not all(isinstance(b, str) and b for b in bridges):
        raise InvalidInput("bridges must be non-empty strings")
    if len(set(bridges)) != len(bridges):
        raise InvalidInput("bridges must be distinct")
    bridge_set = set(bridges)
    if not isinstance(links, list):
        raise InvalidInput("links must be a list")
    endpoints = set()
    link_ids = set()
    for link in links:
        if not isinstance(link, dict) or frozenset(link) != STP_LINK_KEYS:
            raise InvalidInput("bad link")
        lid = link["id"]
        x = link["x"]
        y = link["y"]
        cost = link["cost"]
        up = link["up"]
        if not isinstance(lid, str) or not lid:
            raise InvalidInput("bad link id")
        if lid in link_ids:
            raise InvalidInput("link ids must be distinct")
        link_ids.add(lid)
        if not isinstance(x, list) or len(x) != 2:
            raise InvalidInput("bad endpoint")
        if not isinstance(y, list) or len(y) != 2:
            raise InvalidInput("bad endpoint")
        xb, xp = x
        yb, yp = y
        if not all(isinstance(v, str) and v for v in (xb, xp, yb, yp)):
            raise InvalidInput("bad endpoint")
        if xb not in bridge_set or yb not in bridge_set:
            raise InvalidInput("unknown bridge")
        if xb == yb:
            raise InvalidInput("link endpoints must be on different bridges")
        if tuple(x) in endpoints or tuple(y) in endpoints:
            raise InvalidInput("link endpoints must be unique")
        endpoints.add(tuple(x))
        endpoints.add(tuple(y))
        if not _is_int(cost) or cost <= 0:
            raise InvalidInput("cost must be a positive integer")
        if not isinstance(up, bool):
            raise InvalidInput("bad up")
    if not _is_int(delay) or delay <= 0:
        raise InvalidInput("delay must be a positive integer")
    return bridges, links, delay


def validate_stp_events(events, links):
    if not isinstance(events, list):
        raise InvalidInput("events must be a list")
    link_ids = {link["id"] for link in links}
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
            raise InvalidInput("unknown link id")
        if not isinstance(up, bool):
            raise InvalidInput("bad up")
        result.append((t, lid, up))
    return result


def _stp_roles(bridges, links, link_up):
    # 仅在 up 链路上按连通分量计算：分量根为分量内最小桥名，
    # 最短路按 (总cost, 下一跳桥名, 对端口, 本端口) 比较。
    adj = {b: [] for b in bridges}
    for link in links:
        if not link_up[link["id"]]:
            continue
        xb, xp = link["x"]
        yb, yp = link["y"]
        adj[xb].append((yb, link["cost"], xp, yp))
        adj[yb].append((xb, link["cost"], yp, xp))
    seen = set()
    root_of = {}
    costs = {}
    best = {}
    for start in bridges:
        if start in seen:
            continue
        stack = [start]
        component = []
        seen.add(start)
        while stack:
            u = stack.pop()
            component.append(u)
            for v, _, _, _ in adj[u]:
                if v not in seen:
                    seen.add(v)
                    stack.append(v)
        root = min(component)
        root_of[root] = root
        dist = {root: (0, None, None, None)}
        done = set()
        while True:
            u = None
            for b in component:
                if b not in done and b in dist and (u is None or dist[b] < dist[u]):
                    u = b
            if u is None:
                break
            du = dist[u][0]
            done.add(u)
            for v, c, local_p, peer_p in adj[u]:
                cand = (du + c, u, local_p, peer_p)
                if v not in dist or cand < dist[v]:
                    dist[v] = cand
        for b in component:
            root_of[b] = root
            costs[b] = dist[b][0]
            best[b] = dist[b]
    # 各 up 链路先按通告向量取 designated 端：(根名, 根路径cost, 桥名, 端口)
    # 较小者胜，相等时取配置序在先的一端。
    designated_end = {}
    for link in links:
        lid = link["id"]
        if not link_up[lid]:
            continue
        xb, xp = link["x"]
        yb, yp = link["y"]
        vx = (root_of[xb], costs[xb], xb, xp)
        vy = (root_of[yb], costs[yb], yb, yp)
        if vy < vx:
            win = 1
        else:
            win = 0  # vx 更小或完全相等：配置序在先端
        designated_end[lid] = win
    roles = {}
    for link in links:
        xb, xp = link["x"]
        yb, yp = link["y"]
        if not link_up[link["id"]]:
            roles[(xb, xp)] = "disabled"
            roles[(yb, yp)] = "disabled"
            continue
        win = designated_end[link["id"]]
        roles[(xb, xp)] = "designated" if win == 0 else "alternate"
        roles[(yb, yp)] = "designated" if win == 1 else "alternate"
    component_roots = {}
    for b in bridges:
        component_roots.setdefault(root_of[b], set()).add(b)
    for root, members in component_roots.items():
        for b in members:
            if b == root:
                continue
            _, _, _, local_p = best[b]
            roles[(b, local_p)] = "root"
    return root_of, costs, roles


def stp(bridges, links, delay, events):
    ports = {b: set() for b in bridges}
    for link in links:
        xb, xp = link["x"]
        yb, yp = link["y"]
        ports[xb].add(xp)
        ports[yb].add(yp)
    link_up = {link["id"]: link["up"] for link in links}
    role = {}
    state = {}
    timers = []  # (time, seq, bridge, port, expected_role, new_state)
    seq = 0

    def clear_timers(bp):
        timers[:] = [item for item in timers if (item[2], item[3]) != bp]
        heapq.heapify(timers)

    def pop_due(now):
        changed = False
        while timers and timers[0][0] <= now:
            tm, _, b, p, expected_role, new_state = heapq.heappop(timers)
            if role.get((b, p)) == expected_role:
                state[(b, p)] = new_state
                changed = True
        return changed

    def snapshot(t):
        return {
            "t": t,
            "bridges": [
                {
                    "name": b,
                    "root": root_of[b],
                    "cost": costs[b],
                    "ports": [
                        {"name": p, "role": role[(b, p)], "state": state[(b, p)]}
                        for p in sorted(ports[b])
                    ],
                }
                for b in bridges
            ],
        }

    root_of, costs, new_roles = _stp_roles(bridges, links, link_up)
    for b in bridges:
        for p in ports[b]:
            bp = (b, p)
            r = new_roles[bp]
            role[bp] = r
            if r in ("root", "designated"):
                state[bp] = "discarding"
                heapq.heappush(timers, (delay, seq, b, p, r, "learning"))
                seq += 1
                heapq.heappush(timers, (2 * delay, seq, b, p, r, "forwarding"))
                seq += 1
            else:
                state[bp] = "discarding"
    results = [snapshot(0)]

    for t, lid, up in events:
        pop_due(t)
        if link_up[lid] != up:
            link_up[lid] = up
            root_of, costs, new_roles = _stp_roles(bridges, links, link_up)
            for b in bridges:
                for p in ports[b]:
                    bp = (b, p)
                    r = new_roles[bp]
                    if role[bp] == r:
                        continue
                    clear_timers(bp)
                    role[bp] = r
                    if r in ("root", "designated"):
                        state[bp] = "discarding"
                        heapq.heappush(timers, (t + delay, seq, b, p, r, "learning"))
                        seq += 1
                        heapq.heappush(
                            timers, (t + 2 * delay, seq, b, p, r, "forwarding")
                        )
                        seq += 1
                    else:
                        state[bp] = "discarding"
        results.append(snapshot(t))
    return {"results": results}


def _fail(message):
    sys.stderr.buffer.write(
        ('{"error":"%s"}\n' % message).encode("utf-8")
    )


def main(argv):
    args = argv[1:]
    if len(args) != 3 or args[0] not in ("fdb", "forward", "stp"):
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
            result = stp(bridges, links, delay, validate_stp_events(data, links))
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
