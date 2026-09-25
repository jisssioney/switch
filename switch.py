#!/usr/bin/env python3
"""二层以太网交换机仿真（仅标准库）。"""

import json
import re
import sys

MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


class InvalidInput(Exception):
    pass


def _fail(kind, code):
    sys.stderr.write('{"error":"%s"}\n' % kind)
    sys.exit(code)


def _is_int(value):
    # bool 是 int 的子类，此处不接受布尔值。
    return isinstance(value, int) and not isinstance(value, bool)


def _load_json(path):
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        _fail("file_not_found", 3)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        _fail("invalid_input", 4)
    def _no_duplicate_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise InvalidInput
            result[key] = value
        return result

    try:
        return json.loads(text, object_pairs_hook=_no_duplicate_keys)
    except (ValueError, InvalidInput):
        _fail("invalid_input", 4)


def _validate_config(config):
    if not isinstance(config, dict) or set(config.keys()) != {"ports", "age"}:
        raise InvalidInput
    ports = config["ports"]
    if not isinstance(ports, list):
        raise InvalidInput
    for port in ports:
        if not isinstance(port, str) or port == "":
            raise InvalidInput
    if len(set(ports)) != len(ports):
        raise InvalidInput
    age = config["age"]
    if not _is_int(age) or age <= 0:
        raise InvalidInput
    return ports, age


def _valid_mac(mac):
    if not isinstance(mac, str) or not MAC_RE.match(mac):
        return False
    octets = [int(part, 16) for part in mac.split(":")]
    if not any(octets):  # 非零
        return False
    if octets[0] & 1:  # 单播：首字节最低位为 0
        return False
    return True


def _validate_events(events, port_set):
    if not isinstance(events, list):
        raise InvalidInput
    prev_t = 0
    normalized = []
    for event in events:
        if not isinstance(event, dict) or set(event.keys()) != {
            "t",
            "port",
            "mac",
            "vlan",
        }:
            raise InvalidInput
        t, port, mac, vlan = event["t"], event["port"], event["mac"], event["vlan"]
        if not _is_int(t) or t < 0 or t < prev_t:
            raise InvalidInput
        if not isinstance(port, str) or port not in port_set:
            raise InvalidInput
        if not _valid_mac(mac):
            raise InvalidInput
        if not _is_int(vlan) or not (1 <= vlan <= 4094):
            raise InvalidInput
        normalized.append((t, port, mac, vlan))
        prev_t = t
    return normalized


def _run_fdb(config_path, events_path):
    config = _load_json(config_path)
    try:
        ports, age = _validate_config(config)
    except InvalidInput:
        _fail("invalid_input", 4)

    events = _load_json(events_path)
    try:
        events = _validate_events(events, set(ports))
    except InvalidInput:
        _fail("invalid_input", 4)

    # (vlan, mac) -> [port, seen]
    fdb = {}
    for t, port, mac, vlan in events:
        for key in [k for k, (_, seen) in fdb.items() if t - seen >= age]:
            del fdb[key]
        fdb[(vlan, mac)] = [port, t]

    entries = [
        {"vlan": vlan, "mac": mac, "port": port, "seen": seen}
        for (vlan, mac), (port, seen) in sorted(
            fdb.items(), key=lambda item: (item[0][0], item[0][1])
        )
    ]
    sys.stdout.write(
        json.dumps({"fdb": entries}, ensure_ascii=False, separators=(",", ":")) + "\n"
    )


def main(argv):
    if len(argv) != 4 or argv[1] != "fdb":
        _fail("usage", 2)
    _run_fdb(argv[2], argv[3])


if __name__ == "__main__":
    main(sys.argv)
