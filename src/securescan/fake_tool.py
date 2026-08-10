from __future__ import annotations

import argparse
import json
import sys
import time


def report(observations: list[dict[str, object]], warnings: list[str] | None = None) -> None:
    print(
        json.dumps(
            {
                "schema_version": "1.0",
                "tool": "fake-scanner",
                "observations": observations,
                "warnings": warnings or [],
            }
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True)
    parser.add_argument("--seconds", type=float, default=10)
    parser.add_argument("--bytes", type=int, default=2_000_000)
    args = parser.parse_args()

    if args.mode == "findings":
        report(
            [
                {
                    "rule_id": "FAKE-001",
                    "message": "Controlled test observation",
                    "path": "sample.py",
                    "line": 7,
                    "severity": "HIGH",
                    "cwe": "CWE-20",
                }
            ]
        )
        return 0
    if args.mode == "zero":
        report([])
        return 0
    if args.mode == "warning":
        report([], ["Controlled warning"])
        return 0
    if args.mode == "nonzero-valid":
        report(
            [
                {
                    "rule_id": "FAKE-002",
                    "message": "Valid result despite non-zero tool exit",
                    "path": None,
                    "line": None,
                    "severity": "MEDIUM",
                    "cwe": None,
                }
            ]
        )
        return 1
    if args.mode == "malformed":
        print('{"schema_version": "1.0",')
        return 0
    if args.mode == "wrong-schema":
        print(
            json.dumps(
                {
                    "schema_version": "2.0",
                    "tool": "fake-scanner",
                    "observations": [],
                    "warnings": [],
                }
            )
        )
        return 0
    if args.mode == "crash":
        print("Controlled scanner crash", file=sys.stderr)
        return 2
    if args.mode == "timeout":
        time.sleep(args.seconds)
        report([])
        return 0
    if args.mode == "oversized":
        sys.stdout.write("X" * args.bytes)
        sys.stdout.flush()
        return 0
    if args.mode == "secret":
        report(
            [
                {
                    "rule_id": "FAKE-SECRET",
                    "message": "SECURESCAN_TEST_SECRET=abc123_SUPER_SECRET",
                    "path": "config.py",
                    "line": 2,
                    "severity": "HIGH",
                    "cwe": "CWE-798",
                }
            ]
        )
        print("SECURESCAN_TEST_SECRET=stderrSecret999", file=sys.stderr)
        return 0
    if args.mode == "invalid-utf8":
        sys.stdout.buffer.write(b"\xff\xfe\xfd")
        return 0

    print(f"Unknown mode: {args.mode}", file=sys.stderr)
    return 64


if __name__ == "__main__":
    raise SystemExit(main())
