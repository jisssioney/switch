#!/usr/bin/env python3
"""link-state 子命令回归：链路协商（down/bad/wait/up）与全量校验。

仅用标准库；通过 `python switch.py link-state CONFIG EVENTS` 端到端驱动。
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SWITCH = os.path.join(HERE, "switch.py")


def run_cli(config, events, *limits):
    with tempfile.TemporaryDirectory() as tmp:
        cfg = os.path.join(tmp, "config.json")
        evt = os.path.join(tmp, "events.json")
        with open(cfg, "wb") as handle:
            handle.write(json.dumps(config).encode("utf-8"))
        with open(evt, "wb") as handle:
            handle.write(json.dumps(events).encode("utf-8"))
        proc = subprocess.run(
            [sys.executable, SWITCH, "link-state", cfg, evt,
             *[str(x) for x in limits]],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    return proc.returncode, proc.stdout, proc.stderr


def run(config, events, *limits):
    code, out, err = run_cli(config, events, *limits)
    assert code == 0, (code, err.decode("utf-8"))
    return json.loads(out.decode("utf-8"))


def config(delay=10, ports=None):
    if ports is None:
        ports = [
            {"name": "p1", "rates": [10, 100, 1000], "modes": ["full"]},
            {"name": "p2", "rates": [100, 1000, 10000],
             "modes": ["half", "full"]},
        ]
    return {"delay": delay, "ports": ports}


def event(t, port, admin=True, peer=True, rates=None, modes=None):
    return {
        "t": t,
        "port": port,
        "admin": admin,
        "peer": peer,
        "rates": [100, 1000] if rates is None else rates,
        "modes": ["full"] if modes is None else modes,
    }


def states(doc):
    return [
        (r["t"], r["port"], r["state"], r["rate"], r["mode"])
        for r in doc["results"]
    ]


class NegotiationTests(unittest.TestCase):
    def test_wait_then_up_and_unchanged_does_not_reset(self):
        events = [
            event(0, "p1"),                       # wait，截止 10
            event(5, "p1"),                       # 目标未变：不重置
            event(10, "p1"),                      # 到期 up
        ]
        doc = run(config(), events)
        self.assertEqual(
            states(doc),
            [
                (0, "p1", "wait", None, None),
                (5, "p1", "wait", None, None),
                (10, "p1", "up", 1000, "full"),
            ],
        )

    def test_target_change_resets_timer(self):
        events = [
            event(0, "p1", rates=[100]),          # wait 截止 10
            event(5, "p1", rates=[1000]),         # 目标变化：重置到 15
            event(10, "p1", rates=[1000]),        # 旧协商失效，仍 wait
            event(15, "p1", rates=[1000]),        # 到期 up
        ]
        doc = run(config(), events)
        self.assertEqual(
            [r["state"] for r in doc["results"]],
            ["wait", "wait", "wait", "up"],
        )

    def test_down_cancels_pending(self):
        events = [
            event(0, "p1"),                       # wait 截止 10
            event(5, "p1", admin=False),          # down，撤销在途协商
            event(10, "p1", admin=False),         # 不得再 up
        ]
        doc = run(config(), events)
        self.assertEqual(
            [r["state"] for r in doc["results"]],
            ["wait", "down", "down"],
        )

    def test_peer_false_is_down(self):
        doc = run(config(), [event(0, "p1", peer=False)])
        self.assertEqual(doc["results"][0]["state"], "down")

    def test_no_common_rate_is_bad(self):
        # p1 最高 1000；对端仅 10000
        doc = run(config(), [event(0, "p1", rates=[10000])])
        self.assertEqual(doc["results"][0]["state"], "bad")

    def test_no_common_mode_is_bad(self):
        # p1 仅 full，对端仅 half：双工无交集
        doc = run(config(), [event(0, "p1", modes=["half"])])
        self.assertEqual(doc["results"][0]["state"], "bad")

    def test_highest_rate_and_full_preferred(self):
        doc = run(
            config(),
            [
                event(0, "p2", rates=[100, 1000, 10000],
                      modes=["half", "full"]),
                event(10, "p2", rates=[100, 1000, 10000],
                      modes=["half", "full"]),
            ],
        )
        r = doc["results"]
        self.assertEqual((r[0]["state"], r[0]["rate"], r[0]["mode"]),
                         ("wait", None, None))
        self.assertEqual((r[1]["state"], r[1]["rate"], r[1]["mode"]),
                         ("up", 10000, "full"))

    def test_half_when_full_not_common(self):
        cfg = config()
        cfg["ports"][1]["modes"] = ["half"]
        doc = run(
            cfg,
            [
                event(0, "p2", modes=["half"]),
                event(10, "p2", modes=["half"]),
            ],
        )
        self.assertEqual(
            (doc["results"][1]["state"], doc["results"][1]["mode"]),
            ("up", "half"),
        )

    def test_same_t_input_order(self):
        events = [
            event(0, "p1"),
            event(0, "p1", admin=False),
        ]
        doc = run(config(), events)
        self.assertEqual(
            [r["state"] for r in doc["results"]], ["wait", "down"]
        )

    def test_cross_port_settlement_independent(self):
        events = [
            event(0, "p1"),                       # p1 wait 截止 10
            event(5, "p2", admin=False),          # p2 down
            event(10, "p2", admin=False),         # 此刻 p1 到期 up
            event(10, "p1"),                      # p1 报 up
        ]
        doc = run(config(), events)
        self.assertEqual(
            [r["state"] for r in doc["results"]],
            ["wait", "down", "down", "up"],
        )


class OutputContractTests(unittest.TestCase):
    def test_results_only_and_equal_length(self):
        events = [event(0, "p1"), event(1, "p2")]
        code, raw, err = run_cli(config(), events)
        self.assertEqual(code, 0, err)
        doc = json.loads(raw.decode("utf-8"))
        self.assertEqual(list(doc), ["results"])
        self.assertEqual(len(doc["results"]), len(events))
        for result in doc["results"]:
            self.assertEqual(
                list(result), ["t", "port", "state", "rate", "mode"]
            )

    def test_null_rate_mode_unless_up(self):
        doc = run(
            config(),
            [
                event(0, "p1"),
                event(1, "p1", admin=False),
                event(2, "p1", rates=[10000]),
            ],
        )
        for state in ("wait", "down", "bad"):
            result = next(r for r in doc["results"] if r["state"] == state)
            self.assertIsNone(result["rate"])
            self.assertIsNone(result["mode"])

    def test_compact_utf8_with_lf(self):
        cfg = config(ports=[{"name": "口1", "rates": [100],
                             "modes": ["full"]}])
        code, raw, err = run_cli(cfg, [event(0, "口1")])
        self.assertEqual(code, 0, err)
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b": ", raw)
        self.assertNotIn(b"\\u", raw)
        self.assertIn("口1", raw.decode("utf-8"))

    def test_empty_events(self):
        code, raw, err = run_cli(config(), [])
        self.assertEqual(code, 0, err)
        self.assertEqual(raw, b'{"results":[]}\n')


class ValidationTests(unittest.TestCase):
    def _assert_exit4(self, cfg, events):
        code, out, err = run_cli(cfg, events)
        self.assertEqual(code, 4, err)
        self.assertEqual(out, b"")

    def test_bad_config(self):
        good_port = {"name": "p1", "rates": [10, 100],
                     "modes": ["half", "full"]}
        bad_ports = []

        def with_port(port):
            return {"delay": 5, "ports": [port]}

        bad_ports.append({"delay": 5})                          # 缺 ports
        bad_ports.append({"delay": 5, "ports": [good_port],
                          "x": 1})                              # 多余键
        bad_ports.append({"delay": True, "ports": [good_port]})
        bad_ports.append({"delay": 0, "ports": [good_port]})
        bad_ports.append({"delay": -1, "ports": [good_port]})
        bad_ports.append({"delay": "5", "ports": [good_port]})
        bad_ports.append({"delay": 5, "ports": []})
        for value in (
            {},
            json.loads('["x"]'),
            1,
        ):
            bad_ports.append(value)
        for rates in ([], [100, 10], [12], [True], [10, 10], "10"):
            port = json.loads(json.dumps(good_port))
            port["rates"] = rates
            bad_ports.append(with_port(port))
        for modes in ([], ["full", "half"], ["x"],
                      ["half", "half"], "full"):
            port = json.loads(json.dumps(good_port))
            port["modes"] = modes
            bad_ports.append(with_port(port))
        for name in ("", 1, None):
            port = json.loads(json.dumps(good_port))
            port["name"] = name
            bad_ports.append(with_port(port))
        port = json.loads(json.dumps(good_port))
        port["extra"] = 1
        bad_ports.append(with_port(port))
        bad_ports.append({"delay": 5, "ports": [good_port, good_port]})

        for cfg in bad_ports:
            self._assert_exit4(cfg, [event(0, "p1")])

    def test_bad_events(self):
        cfg = config()
        bad = []
        bad.append({})                                          # 非数组
        bad.append([event(0, "p1"), {"t": 1}])                 # 缺键
        bad_event = event(0, "p1")
        bad_event["x"] = 1
        bad.append([bad_event])                                 # 多键
        bad.append([event(-1, "p1")])
        bad.append([{**event(0, "p1"), "t": True}])
        bad.append([{**event(0, "p1"), "t": "0"}])
        bad.append([event(1, "p1"), event(0, "p1")])           # t 下降
        bad.append([event(0, "nope")])
        bad.append([{**event(0, "p1"), "admin": 1}])
        bad.append([{**event(0, "p1"), "peer": 0}])
        bad.append([event(0, "p1", rates=[])])
        bad.append([event(0, "p1", rates=[100, 10])])
        bad.append([event(0, "p1", rates=[5])])
        bad.append([event(0, "p1", modes=[])])
        bad.append([event(0, "p1", modes=["full", "half"])])
        bad.append([event(0, "p1", modes=["x"])])
        for events in bad:
            self._assert_exit4(cfg, events)

    def test_equal_t_allowed(self):
        code, _, err = run_cli(config(), [event(0, "p1"),
                                          event(0, "p1")])
        self.assertEqual(code, 0, err)


class LimitAndExitTests(unittest.TestCase):
    def test_item_limit(self):
        code, out, err = run_cli(
            config(), [event(0, "p1"), event(1, "p1")],
            1000000, 1000000, 1, 1000000,
        )
        self.assertEqual(code, 5)
        self.assertEqual(out, b"")
        self.assertIn(b"item_limit", err)

    def test_config_and_data_limit(self):
        events = [event(0, "p1")]
        code, out, _ = run_cli(config(), events, 10, 1000000,
                               1000000, 1000000)
        self.assertEqual((code, out), (5, b""))
        code, out, _ = run_cli(config(), events, 1000000, 10,
                               1000000, 1000000)
        self.assertEqual((code, out), (5, b""))

    def test_output_limit_equal_is_legal(self):
        code, exact, err = run_cli(config(), [event(0, "p1")])
        self.assertEqual(code, 0, err)
        code, _, _ = run_cli(config(), [event(0, "p1")],
                             1000000, 1000000, 1000000, len(exact))
        self.assertEqual(code, 0)
        code, out, _ = run_cli(config(), [event(0, "p1")],
                               1000000, 1000000, 1000000, len(exact) - 1)
        self.assertEqual((code, out), (5, b""))

    def test_file_not_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "no.json")
            proc = subprocess.run(
                [sys.executable, SWITCH, "link-state", missing, missing],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(proc.stdout, b"")

    def test_usage(self):
        proc = subprocess.run(
            [sys.executable, SWITCH, "link-state"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, b"")
        proc = subprocess.run(
            [sys.executable, SWITCH, "link-state", "a", "b", "0", "1"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main()
