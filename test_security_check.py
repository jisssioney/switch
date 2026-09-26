#!/usr/bin/env python3
"""security-check 子命令回归：端口安全下的帧合法性（class 分类、坏帧合同）。

仅用标准库；通过 `python switch.py security-check CONFIG EVENTS` 端到端驱动。
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SWITCH = os.path.join(HERE, "switch.py")
sys.path.insert(0, HERE)

from test_record import base_config as record_base_config  # noqa: E402
from test_record import frame as plain_frame  # noqa: E402
from test_record import service  # noqa: E402


def check_frame(t, port, src, dst="ff:ff:ff:ff:ff:ff", length=100, fcs=True,
                alignment=True):
    result = plain_frame(t, port, src, dst)
    result.update({"length": length, "fcs": fcs, "alignment": alignment})
    return result


def run_cli(config, events, *limits):
    with tempfile.TemporaryDirectory() as tmp:
        cfg = os.path.join(tmp, "config.json")
        evt = os.path.join(tmp, "events.json")
        with open(cfg, "wb") as handle:
            handle.write(json.dumps(config).encode("utf-8"))
        with open(evt, "wb") as handle:
            handle.write(json.dumps(events).encode("utf-8"))
        proc = subprocess.run(
            [sys.executable, SWITCH, "security-check", cfg, evt,
             *[str(x) for x in limits]],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    return proc.returncode, proc.stdout, proc.stderr


def run(config, events, *limits):
    code, out, err = run_cli(config, events, *limits)
    assert code == 0, (code, err.decode("utf-8"))
    return json.loads(out.decode("utf-8"))


def config():
    result = json.loads(json.dumps(record_base_config()))
    result["max_frame"] = 1518
    return result


BCAST = "ff:ff:ff:ff:ff:ff"


class BadFrameContractTests(unittest.TestCase):
    def test_class_priority_runt_giant_alignment_fcs(self):
        # 同帧依次落入各 class：runt < 64；giant > max_frame；
        # 长度合法时 alignment 优先于 fcs
        events = [
            check_frame(0, "p1", "00:00:00:00:00:01", length=63),
            check_frame(1, "p1", "00:00:00:00:00:01", length=1519),
            check_frame(2, "p1", "00:00:00:00:00:01", length=100,
                        alignment=False),
            check_frame(3, "p1", "00:00:00:00:00:01", length=100, fcs=False),
            check_frame(4, "p1", "00:00:00:00:00:01", length=100, fcs=False,
                        alignment=False),
        ]
        out = run(config(), events)
        self.assertEqual(
            [r["class"] for r in out["results"]],
            ["runt", "giant", "alignment", "bad_fcs", "alignment"],
        )
        for r in out["results"]:
            self.assertEqual(r["action"], "drop")
            self.assertEqual(r["ports"], [])
            self.assertEqual(r["dropped"], [])
            self.assertEqual(r["mirrors"], [])

    def test_bad_frame_consumes_frame_id_but_skips_security_path(self):
        # fid0 好帧、fid1 坏帧、fid2 好帧；服务仅见 0、2：坏帧占号但
        # 不入队、不计 VLAN、不生成镜像、不产生动态绑定
        events = [
            check_frame(0, "p1", "00:00:00:00:00:01"),
            check_frame(1, "p1", "00:00:00:00:00:02", length=10),
            check_frame(2, "p1", "00:00:00:00:00:03"),
            service(3, "p3", 10),
        ]
        out = run(config(), events)
        self.assertEqual(out["results"][3]["frames"], [0, 2])
        # 坏帧结果无镜像；好帧仍有入向镜像
        self.assertEqual(out["results"][1]["mirrors"], [])
        self.assertEqual(len(out["results"][0]["mirrors"]), 1)
        p1 = out["ports"][0]
        self.assertEqual(p1["rx"], 3)
        self.assertEqual(p1["drop"], 1)
        self.assertEqual(p1["good"], 2)
        self.assertEqual(p1["runt"], 1)
        # VLAN 只记好帧
        self.assertEqual(out["vlans"][0]["rx"], 2)
        # 坏帧源未绑定：仅两个好帧源动态学习
        sec = {s["port"]: s for s in out["security"]}
        self.assertEqual(
            sec["p1"]["learned"],
            [{"vlan": 1, "mac": "00:00:00:00:00:01"},
             {"vlan": 1, "mac": "00:00:00:00:00:03"}],
        )
        self.assertEqual(sec["p1"]["violations"], 0)

    def test_bad_frame_does_not_trigger_violation_or_shutdown(self):
        # limit 0 + shutdown：坏帧不违例不禁口；随后好帧违例并永久禁口
        cfg = config()
        cfg["security"][0]["limit"] = 0
        cfg["security"][0]["action"] = "shutdown"
        events = [
            check_frame(0, "p1", "00:00:00:00:00:01", length=10),
            check_frame(1, "p1", "00:00:00:00:00:02"),
        ]
        out = run(cfg, events)
        sec = {s["port"]: s for s in out["security"]}
        self.assertEqual(sec["p1"]["violations"], 1)
        self.assertTrue(sec["p1"]["shutdown"])
        self.assertEqual(sec["p1"]["learned"], [])

    def test_good_frame_security_unchanged(self):
        # good 帧沿用 port-security：limit 2 下第三源违例丢帧
        events = [
            check_frame(0, "p1", "00:00:00:00:00:01"),
            check_frame(1, "p1", "00:00:00:00:00:02"),
            check_frame(2, "p1", "00:00:00:00:00:03"),
        ]
        out = run(config(), events)
        self.assertEqual(out["results"][2]["action"], "drop")
        sec = {s["port"]: s for s in out["security"]}
        self.assertEqual(sec["p1"]["violations"], 1)
        self.assertEqual(len(sec["p1"]["learned"]), 2)

    def test_good_frame_continues_from_vlan_admission(self):
        # good 帧在 bad 帧之后完全沿用 port-security：flood 入队、服务发出
        events = [
            check_frame(0, "p1", "00:00:00:00:00:01", length=64),
            service(1, "p3", 1),
        ]
        out = run(config(), events)
        self.assertEqual(out["results"][0]["class"], "good")
        self.assertEqual(out["results"][0]["action"], "flood")
        self.assertEqual(out["results"][1]["frames"], [0])
        self.assertEqual(out["ports"][2]["tx"], 1)

    def test_service_result_unchanged(self):
        events = [service(0, "p3", 2)]
        out = run(config(), events)
        self.assertEqual(
            list(out["results"][0]), ["t", "port", "frames", "mirrors"]
        )

    def test_key_orders(self):
        events = [
            check_frame(0, "p1", "00:00:00:00:00:01", length=10),
            check_frame(1, "p1", "00:00:00:00:00:02"),
            service(2, "p3", 1),
        ]
        code, raw, err = run_cli(config(), events)
        self.assertEqual(code, 0, err)
        text = raw.decode("utf-8").rstrip("\n")
        decoded = json.loads(text)
        self.assertEqual(list(decoded), ["results", "ports", "vlans",
                                         "security"])
        self.assertEqual(
            list(decoded["results"][0]),
            ["t", "class", "action", "ports", "dropped", "mirrors"],
        )
        self.assertEqual(
            list(decoded["results"][1]),
            ["t", "class", "action", "ports", "dropped", "mirrors"],
        )
        self.assertEqual(
            list(decoded["ports"][0]),
            ["name", "rx", "tx", "drop", "good", "runt", "giant",
             "alignment", "bad_fcs"],
        )
        self.assertEqual(
            list(decoded["security"][0]),
            ["port", "learned", "violations", "shutdown"],
        )
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b': ', raw)


class ValidationTests(unittest.TestCase):
    def _assert_exit4(self, cfg, events):
        code, out, err = run_cli(cfg, events)
        self.assertEqual(code, 4, err)
        self.assertEqual(out, b"")

    def test_bad_max_frame(self):
        for value in (1517, 9217, "x", True):
            cfg = config()
            cfg["max_frame"] = value
            self._assert_exit4(cfg, [check_frame(0, "p1", "00:00:00:00:00:01")])

    def test_missing_max_frame(self):
        cfg = config()
        del cfg["max_frame"]
        self._assert_exit4(cfg, [check_frame(0, "p1", "00:00:00:00:00:01")])

    def test_missing_security(self):
        cfg = config()
        del cfg["security"]
        self._assert_exit4(cfg, [check_frame(0, "p1", "00:00:00:00:00:01")])

    def test_bad_new_frame_fields(self):
        for key, value in (("length", -1), ("length", True), ("fcs", 1),
                           ("fcs", "x"), ("alignment", 0), ("alignment", None)):
            bad = check_frame(0, "p1", "00:00:00:00:00:01")
            bad[key] = value
            self._assert_exit4(config(), [bad])

    def test_old_frame_shape_rejected(self):
        # port-security 旧帧项（无 length/fcs/alignment）不再合法
        self._assert_exit4(config(), [plain_frame(0, "p1", "00:00:00:00:00:01")])

    def test_extra_frame_key_rejected(self):
        bad = check_frame(0, "p1", "00:00:00:00:00:01")
        bad["extra"] = 1
        self._assert_exit4(config(), [bad])


class WorkLimitTests(unittest.TestCase):
    def test_bad_frame_billed_like_frame(self):
        # P=5, M=2, R=1：初始 C=1；首帧（坏帧同价）计 X+3P+M+R+D+S+1 = 19，
        # 累计 20
        good = check_frame(0, "p1", "00:00:00:00:00:01", length=100)
        bad = check_frame(0, "p1", "00:00:00:00:00:01", length=10)
        limits = (1000000, 1000000, 1000000, 1000000)
        code, out, _ = run_cli(config(), [good], *limits, 20)
        self.assertEqual(code, 0)
        code, out, err = run_cli(config(), [bad], *limits, 20)
        self.assertEqual(code, 0, err)
        code, out, err = run_cli(config(), [bad], *limits, 19)
        self.assertEqual(code, 5)
        self.assertEqual(err.strip(), b'{"error":"security_work_limit"}')
        self.assertEqual(out, b"")


if __name__ == "__main__":
    unittest.main()
