#!/usr/bin/env python3
"""replay --expect-sha256 外部承诺回归：堵住“等价改写事件 + 重算内部摘要”
的重放完整性漏洞。

旧 `replay LOG` 仅以 LOG 内嵌 sha256（覆盖同样内嵌的 config/records）自证：
把帧 src 改成另一合法 MAC、重算内部摘要，且 applied/version/output 与原
事件等价时，重放逐项核对与字节重建仍全部通过。新形式要求调用方提供从
成功 record 产物顶层 sha256 独立保存的承诺，承诺不符即 invalid_input。

仅用标准库；端到端驱动 `python switch.py record ...` / `replay ...`。
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

from test_record import base_config  # noqa: E402
from test_record import frame as plain_frame  # noqa: E402
from test_record import prefix_digest  # noqa: E402
from test_record import record as record_log  # noqa: E402
from test_record import run_cli as record_run_cli  # noqa: E402
from test_security_check import check_frame  # noqa: E402
from test_security_check import config as security_config  # noqa: E402


BCAST = "ff:ff:ff:ff:ff:ff"
MAC_A = "00:00:00:00:00:01"
MAC_B = "00:00:00:00:00:02"


def digest_of(doc):
    """成功 record 产物顶层 sha256（调用方独立保存的外部承诺）。"""
    return doc["sha256"]


def rehashed(doc):
    """按改写后的 schema/config/records 重算 LOG 内部 sha256，紧凑序列化。"""
    doc["sha256"] = prefix_digest(doc)[0]
    return (json.dumps(doc, separators=(",", ":")) + "\n").encode("utf-8")


def run_replay(log_bytes, *extra):
    """把 in.log 写入临时目录，其余 token 原样传给 replay，并回读 LOG。"""
    with tempfile.TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "in.log")
        with open(log_path, "wb") as handle:
            handle.write(log_bytes)
        proc = subprocess.run(
            [sys.executable, SWITCH, "replay", log_path, *extra],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        with open(log_path, "rb") as handle:
            after = handle.read()
    return proc.returncode, proc.stdout, proc.stderr, {"in.log": after}


class ExpectShaHappyPathTests(unittest.TestCase):
    def test_security_check_original_log_with_original_commitment(self):
        # 安全检查模式：单个 good 广播帧
        events = [check_frame(0, "p1", MAC_A)]
        out, log_bytes = record_log(security_config(), events)
        commit = digest_of(json.loads(log_bytes.decode()))
        # 原 LOG + 原承诺：stdout 与 record 逐字节相同，退出 0，LOG 不动
        code, rep_out, err, logs = run_replay(
            log_bytes, "--expect-sha256", commit
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(err, b"")
        self.assertEqual(rep_out, out)
        self.assertEqual(logs["in.log"], log_bytes)

    def test_security_check_with_all_four_limits(self):
        events = [check_frame(0, "p1", MAC_A)]
        out, log_bytes = record_log(security_config(), events)
        commit = digest_of(json.loads(log_bytes.decode()))
        code, rep_out, err, logs = run_replay(
            log_bytes, "--expect-sha256", commit,
            "100000", "16777216", "16777216", "10000000",
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(rep_out, out)
        self.assertEqual(logs["in.log"], log_bytes)

    def test_default_security_mode_original_commitment(self):
        # port-security（reload 语义）模式同样支持外部承诺
        events = [plain_frame(0, "p1", MAC_A)]
        out, log_bytes = record_log(base_config(), events)
        commit = digest_of(json.loads(log_bytes.decode()))
        code, rep_out, err, _ = run_replay(
            log_bytes, "--expect-sha256", commit
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(rep_out, out)

    def test_no_flag_form_remains_byte_identical(self):
        # 旧形式行为逐字节不变：即便 LOG 是等价改写产物，旧形式仍按内部
        # 自洽放行（这正是漏洞），证明改动没有收紧旧形式
        events = [check_frame(0, "p1", MAC_A)]
        _, log_bytes = record_log(security_config(), events)
        doc = json.loads(log_bytes.decode())
        doc["records"][0]["event"]["src"] = MAC_B
        forged = rehashed(doc)
        code, out, err, _ = record_run_cli(
            ["replay", "in.log"], {"in.log": forged}
        )
        self.assertEqual(code, 0, err)
        # 旧形式无承诺，等价重写重放成功
        self.assertTrue(out.endswith(b"\n"))


class ExternalCommitmentBlocksRewriteTests(unittest.TestCase):
    def _forged_security_log(self):
        """记录 good 广播帧，再把帧 src 改为另一合法 MAC，重算内部摘要。

        该帧 flood，逐项 output（action/ports/dropped/mirrors）与 src
        无关；帧恒 applied 且不递增 version，故 records 内 applied、
        version、output 与新事件重放结果等价，重建字节一致——内部校验
        全部通过，仅外部承诺能识别。

        返回 (改写前独立保存的原承诺, 改写并重算摘要后的 LOG 字节)。
        """
        events = [check_frame(0, "p1", MAC_A)]
        _, log_bytes = record_log(security_config(), events)
        original_commit = digest_of(json.loads(log_bytes.decode()))
        doc = json.loads(log_bytes.decode())
        doc["records"][0]["event"]["src"] = MAC_B
        return original_commit, rehashed(doc)

    def test_rehashed_src_rewrite_replays_without_commitment(self):
        # 前置：等价改写 + 重算摘要在旧形式下确实重放成功（漏洞可复现）
        _, forged = self._forged_security_log()
        code, out, err, _ = record_run_cli(
            ["replay", "in.log"], {"in.log": forged}
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(
            json.loads(out.decode())["results"][0]["action"], "flood"
        )

    def test_rehashed_src_rewrite_fails_external_commitment(self):
        # 攻击核心：即便 src 改为另一合法 MAC、内部摘要重算、applied/
        # version/output 与原事件等价，也须因外部承诺不符失败
        original_commit, forged = self._forged_security_log()
        # 改写后的顶层 sha256 已不同于原承诺
        self.assertNotEqual(
            json.loads(forged.decode())["sha256"], original_commit
        )
        code, out, err, logs = run_replay(
            forged, "--expect-sha256", original_commit
        )
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')
        self.assertEqual(logs["in.log"], forged)  # LOG 不被改动

    def test_commitment_equal_to_rewritten_digest_would_pass(self):
        # 对照：若承诺取自待重放 LOG 自身（错误用法），则失去外部约束；
        # 但 EXPECTED 语义要求独立保存，故安全用法下不会发生
        _, forged = self._forged_security_log()
        forged_commit = json.loads(forged.decode())["sha256"]
        code, out, err, _ = run_replay(
            forged, "--expect-sha256", forged_commit
        )
        self.assertEqual(code, 0, err)


class CommitmentCheckOrderTests(unittest.TestCase):
    def setUp(self):
        # 两个 good 广播帧：max_events=1 时本应触发 event_limit(5)
        events = [
            check_frame(0, "p1", MAC_A),
            check_frame(1, "p1", MAC_A),
        ]
        _, self.log_bytes = record_log(security_config(), events)
        self.good_commit = digest_of(json.loads(self.log_bytes.decode()))

    def _forged(self):
        doc = json.loads(self.log_bytes.decode())
        doc["records"][0]["event"]["src"] = MAC_B
        return rehashed(doc)

    def test_mismatch_beats_event_limit(self):
        # 承诺比较先于事件数上界：2 条记录配 max_events=1 本会触发
        # event_limit(5)，承诺不符仍报 invalid_input(4)
        forged = self._forged()
        code, out, err, _ = run_replay(
            forged, "--expect-sha256", self.good_commit,
            "1", "16777216",
        )
        self.assertEqual(code, 4)
        self.assertEqual(out, b"")
        self.assertEqual(err, b'{"error":"invalid_input"}\n')

    def test_mismatch_beats_output_limit(self):
        # 承诺比较先于输出上界：max_output_bytes=1 本会触发 output_limit
        forged = self._forged()
        code, out, err, _ = run_replay(
            forged, "--expect-sha256", self.good_commit,
            "100000", "16777216", "1",
        )
        self.assertEqual(code, 4)
        self.assertEqual(err, b'{"error":"invalid_input"}\n')

    def test_mismatch_beats_work_limit(self):
        # 承诺比较先于工作量预演：max_replay_work=1 本会触发 work_limit
        forged = self._forged()
        code, out, err, _ = run_replay(
            forged, "--expect-sha256", self.good_commit,
            "100000", "16777216", "16777216", "1",
        )
        self.assertEqual(code, 4)
        self.assertEqual(err, b'{"error":"invalid_input"}\n')

    def test_byte_limit_precedes_commitment(self):
        # 文件/字节上限先于承诺比较：超 max_log_bytes 报 log_limit(5)
        code, out, err, _ = run_replay(
            self.log_bytes + b" ", "--expect-sha256", self.good_commit,
            "100000", "1",
        )
        self.assertEqual(code, 5)
        self.assertEqual(err, b'{"error":"log_limit"}\n')

    def test_internal_digest_mismatch_precedes_commitment(self):
        # LOG 内摘要先于外部承诺校验：不重算内部摘要即篡改，即便外部
        # 承诺恰好等于被篡改的顶层 sha256，也按 invalid_input 失败
        doc = json.loads(self.log_bytes.decode())
        doc["records"][0]["event"]["src"] = MAC_B  # 改事件但不重算
        tampered = (
            json.dumps(doc, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        claimed = json.loads(tampered.decode())["sha256"]
        code, out, err, _ = run_replay(
            tampered, "--expect-sha256", claimed
        )
        self.assertEqual(code, 4)
        self.assertEqual(err, b'{"error":"invalid_input"}\n')

    def test_missing_file_precedes_commitment(self):
        with tempfile.TemporaryDirectory() as tmp:
            argv = [
                sys.executable, SWITCH, "replay",
                os.path.join(tmp, "nope.log"),
                "--expect-sha256", self.good_commit,
            ]
            proc = subprocess.run(
                argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b'{"error":"file_not_found"}\n')


class ExpectShaUsageTests(unittest.TestCase):
    def setUp(self):
        events = [check_frame(0, "p1", MAC_A)]
        _, self.log_bytes = record_log(security_config(), events)
        self.commit = digest_of(json.loads(self.log_bytes.decode()))

    def _usage(self, *extra):
        code, out, err, _ = run_replay(self.log_bytes, *extra)
        self.assertEqual((code, out, err),
                         (2, b"", b'{"error":"usage"}\n'), extra)

    def test_flag_without_value(self):
        self._usage("--expect-sha256")

    def test_flag_value_then_one_limit(self):
        # flag 形式仅允许 0、2、3、4 个上限
        self._usage("--expect-sha256", self.commit, "100000")

    def test_flag_value_then_five_limits(self):
        self._usage(
            "--expect-sha256", self.commit,
            "1", "2", "3", "4", "5",
        )

    def test_uppercase_hex_rejected(self):
        self._usage("--expect-sha256", self.commit.upper())

    def test_short_hex_rejected(self):
        self._usage("--expect-sha256", "0" * 63)

    def test_long_hex_rejected(self):
        self._usage("--expect-sha256", "0" * 65)

    def test_non_hex_rejected(self):
        self._usage("--expect-sha256", "g" * 64)

    def test_empty_value_rejected(self):
        self._usage("--expect-sha256", "")

    def test_flag_in_wrong_position(self):
        # flag 必须紧跟 LOG；旧形式里把 flag 当上限同样按 usage
        self._usage(
            "100000", "16777216", "--expect-sha256", self.commit
        )

    def test_flag_after_some_limits_rejected(self):
        self._usage(
            "100000", "--expect-sha256", self.commit, "16777216"
        )

    def test_bad_limit_with_flag_is_usage(self):
        # EXPECTED 合法但上限非法仍是 usage(2)，而非 invalid_input(4)
        self._usage(
            "--expect-sha256", self.commit, "0", "16777216"
        )

    def test_old_form_arity_unchanged(self):
        # 旧形式数量限制不变：1 个或 5 个上限仍 usage
        self._usage("100000")
        self._usage("1", "2", "3", "4", "5")


class ExpectShaDoesNotTouchLogTests(unittest.TestCase):
    def test_failure_leaves_log_byte_identical(self):
        events = [check_frame(0, "p1", MAC_A)]
        _, log_bytes = record_log(security_config(), events)
        good = digest_of(json.loads(log_bytes.decode()))
        doc = json.loads(log_bytes.decode())
        doc["records"][0]["event"]["src"] = MAC_B
        forged = rehashed(doc)
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "in.log")
            with open(log_path, "wb") as handle:
                handle.write(forged)
            proc = subprocess.run(
                [sys.executable, SWITCH, "replay", log_path,
                 "--expect-sha256", good],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            with open(log_path, "rb") as handle:
                after = handle.read()
        self.assertEqual(proc.returncode, 4)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b'{"error":"invalid_input"}\n')
        self.assertEqual(after, forged)


if __name__ == "__main__":
    unittest.main()
