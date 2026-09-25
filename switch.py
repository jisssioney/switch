#!/usr/bin/env python3
"""二层以太网交换机仿真（仅标准库）。"""

import json
import re
import sys

MAC_RE = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z")
CONFIG_KEYS = frozenset(("ports", "age"))
EVENT_KEYS = frozenset(("t", "port", "mac", "vlan"))
PORT_KEYS = frozenset(("name", "vlan", "up"))
FRAME_KEYS = frozenset(("t", "port", "src", "dst"))
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


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
    names = set()
    result = []
    for port in ports:
        if not isinstance(port, dict) or frozenset(port) != PORT_KEYS:
            raise InvalidInput("bad port")
        name = port["name"]
        vlan = port["vlan"]
        up = port["up"]
        if not isinstance(name, str) or not name:
            raise InvalidInput("bad port name")
        if name in names:
            raise InvalidInput("port names must be distinct")
        names.add(name)
        if not _is_int(vlan) or not 1 <= vlan <= 4094:
            raise InvalidInput("bad vlan")
        if not isinstance(up, bool):
            raise InvalidInput("bad up")
        result.append((name, vlan, up))
    if not _is_int(age) or age <= 0:
        raise InvalidInput("age must be a positive integer")
    return result, age


def validate_frames(frames, ports):
    if not isinstance(frames, list):
        raise InvalidInput("frames must be a list")
    port_set = set(name for name, _, _ in ports)
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
        if not isinstance(port, str) or port not in port_set:
            raise InvalidInput("unknown port")
        if not valid_mac(src):
            raise InvalidInput("bad src")
        if dst != BROADCAST_MAC and not valid_mac(dst):
            raise InvalidInput("bad dst")
        result.append((t, port, src, dst))
    return result


def simulate_forward(frames, ports, age):
    port_vlan = {}
    port_up = {}
    port_stats = {}
    for name, vlan, up in ports:
        port_vlan[name] = vlan
        port_up[name] = up
        port_stats[name] = [0, 0, 0]  # rx, tx, drop
    vlan_stats = {}
    for _, vlan, _ in ports:
        vlan_stats.setdefault(vlan, [0, 0, 0])
    fdb = {}  # (vlan, mac) -> [port, seen]
    results = []
    for t, port, src, dst in frames:
        for key in [k for k, (_, seen) in fdb.items() if t - seen >= age]:
            del fdb[key]
        vlan = port_vlan[port]
        port_stats[port][0] += 1
        vlan_stats[vlan][0] += 1
        egress = []
        if port_up[port]:
            fdb[(vlan, src)] = [port, t]
            if dst == BROADCAST_MAC or (vlan, dst) not in fdb:
                egress = [
                    name
                    for name, member_vlan, up in ports
                    if name != port and member_vlan == vlan and up
                ]
                action = "flood" if egress else "drop"
            else:
                out = fdb[(vlan, dst)][0]
                if out != port:
                    egress = [out]
                    action = "unicast"
                else:
                    action = "drop"
        else:
            action = "drop"
        if egress:
            for name in egress:
                port_stats[name][1] += 1
                vlan_stats[port_vlan[name]][1] += 1
        else:
            port_stats[port][2] += 1
            vlan_stats[vlan][2] += 1
        results.append({"t": t, "action": action, "ports": egress})
    return {
        "results": results,
        "ports": [
            {
                "name": name,
                "rx": port_stats[name][0],
                "tx": port_stats[name][1],
                "drop": port_stats[name][2],
            }
            for name, _, _ in ports
        ],
        "vlans": [
            {
                "vlan": vlan,
                "rx": stats[0],
                "tx": stats[1],
                "drop": stats[2],
            }
            for vlan, stats in sorted(vlan_stats.items())
        ],
    }


def _fail(message):
    sys.stderr.buffer.write(
        ('{"error":"%s"}\n' % message).encode("utf-8")
    )


def main(argv):
    args = argv[1:]
    if len(args) != 3 or args[0] not in ("fdb", "forward"):
        _fail("usage")
        return 2
    config_path, events_path = args[1], args[2]
    try:
        with open(config_path, "rb") as handle:
            config_raw = handle.read()
        with open(events_path, "rb") as handle:
            events_raw = handle.read()
    except OSError:
        _fail("file_not_found")
        return 3
    try:
        config = parse_json(config_raw)
        events = parse_json(events_raw)
        if args[0] == "fdb":
            ports, age = validate_config(config)
            result = simulate(validate_events(events, ports), age)
        else:
            ports, age = validate_forward_config(config)
            result = simulate_forward(validate_frames(events, ports), ports, age)
    except InvalidInput:
        _fail("invalid_input")
        return 4
    payload = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.buffer.write(payload.encode("utf-8") + b"\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
