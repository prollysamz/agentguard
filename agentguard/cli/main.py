import argparse
import json
import sys

from agentguard.audit.reader import read_log
from agentguard.core.decision import GuardError


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="agentguard", description="Inspect and demonstrate guarded agent tool calls"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    logs = sub.add_parser("logs", help="Read verified audit events")
    logs.add_argument("--risk", choices=["low", "medium", "high", "critical"])
    logs.add_argument("--decision", choices=["allow", "ask", "deny"])
    inspect = sub.add_parser("inspect", help="Inspect one audit event")
    inspect.add_argument("event_id")
    verify = sub.add_parser("verify-log", help="Verify the JSONL hash chain")
    for command in (logs, inspect, verify):
        command.add_argument("--audit", default="agentguard.jsonl")
    demo = sub.add_parser("demo", help="Run the isolated prompt-injection demo")
    demo.add_argument("--audit", default="agentguard-demo.jsonl")
    demo.add_argument("--model", help="Use this locally installed Ollama Gemma model")
    demo.add_argument(
        "--judge", action="store_true", help="Enable optional local Gemma semantic judge"
    )
    demo.add_argument("--interactive", action="store_true", help="Ask for approval in the terminal")
    args = parser.parse_args(argv)
    try:
        if args.command == "demo":
            from agentguard.demo.scenario import run_demo

            run_demo(args.audit, args.model, args.judge, args.interactive)
            return 0
        events = read_log(args.audit)
        if args.command == "verify-log":
            print(
                f"Verified {len(events)} events; chain is consistent (no external integrity anchor)."
            )
            return 0
        if args.command == "inspect":
            matches = [e for e in events if e["event_id"] == args.event_id]
            if not matches:
                print("Event not found", file=sys.stderr)
                return 1
            print(json.dumps(matches[0], indent=2))
            return 0
        bands = {"low": (0, 25), "medium": (26, 50), "high": (51, 90), "critical": (91, 100)}
        for event in events:
            if (
                args.decision
                and event.get("final_decision", event.get("evaluated_decision")) != args.decision
            ):
                continue
            if (
                args.risk
                and not bands[args.risk][0] <= event.get("risk_score", 0) <= bands[args.risk][1]
            ):
                continue
            print(json.dumps(event))
        return 0
    except (OSError, ValueError, GuardError) as exc:
        print(f"AgentGuard: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(
            f"AgentGuard: {type(exc).__name__}; check local model/service availability",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
