import argparse
import json
import os
import sys
from pathlib import Path

from agentguard.audit.reader import read_log
from agentguard.audit.segments import rotated_segments
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
        command.add_argument(
            "--key-env",
            metavar="VAR",
            help="Environment variable holding the audit signing key; verifies signatures",
        )
    check = sub.add_parser("check-policy", help="Validate a policy file and summarize it")
    check.add_argument("policy")
    explain = sub.add_parser(
        "explain", help="Show which rules and risk factors decide a proposed call"
    )
    explain.add_argument("policy")
    explain.add_argument("capability", help="e.g. filesystem.read, shell.execute, db.query")
    explain.add_argument(
        "--arg",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="Call argument; VALUE is parsed as JSON when possible (repeatable)",
    )
    explain.add_argument("--cwd", help="Working directory for relative paths (default: here)")
    explain.add_argument(
        "--env",
        default="development",
        choices=["development", "test", "staging", "production"],
    )
    explain.add_argument("--json", action="store_true", help="Print the full result as JSON")
    demo = sub.add_parser("demo", help="Run the isolated prompt-injection demo")
    demo.add_argument("--audit", default="agentguard-demo.jsonl")
    source = demo.add_mutually_exclusive_group()
    source.add_argument("--model", help="Use this locally installed Ollama Gemma model")
    source.add_argument(
        "--scripted", action="store_true", help="Replay fixed proposals; no model required"
    )
    demo.add_argument(
        "--judge", action="store_true", help="Enable optional local Gemma semantic judge"
    )
    demo.add_argument("--interactive", action="store_true", help="Ask for approval in the terminal")
    args = parser.parse_args(argv)
    try:
        if args.command == "demo":
            from agentguard.demo import gemma_agent
            from agentguard.demo.scenario import run_demo

            needs_detection = not args.model and (args.judge or not args.scripted)
            detected = gemma_agent.detect_gemma() if needs_detection else None
            model = None if args.scripted else args.model or detected
            if not args.scripted and not args.model:
                if detected:
                    print(f"Using local Gemma model {detected} (--scripted runs offline)")
                else:
                    print(
                        "No local Gemma model found through Ollama; running the scripted demo. "
                        "Install one with: ollama pull " + gemma_agent.PREFERRED_MODEL
                    )
            judge_model = None
            if args.judge:
                judge_model = args.model or detected or gemma_agent.PREFERRED_MODEL
            run_demo(args.audit, model, judge_model, args.interactive)
            return 0
        if args.command == "check-policy":
            return check_policy(args.policy)
        if args.command == "explain":
            return explain_call(args)
        key = None
        if args.key_env:
            if not os.environ.get(args.key_env):
                raise ValueError(f"Environment variable {args.key_env} is not set")
            key = os.environ[args.key_env].encode()
        events = read_log(args.audit, key)
        if args.command == "verify-log":
            segments = len(rotated_segments(Path(args.audit))) + 1
            detail = (
                "signatures valid" if key else "unsigned check; pass --key-env to verify signatures"
            )
            print(
                f"Verified {len(events)} events in {segments} segment(s); chain is consistent ({detail})."
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


def _policy_errors(exc):
    """Readable messages from a policy load failure (validation or YAML)."""
    cause = exc.__cause__ or exc
    if hasattr(cause, "errors"):
        lines = []
        for error in cause.errors():
            location = ".".join(str(part) for part in error["loc"]) or "policy"
            lines.append(f"  {location}: {error['msg']}")
        return lines
    return [f"  {type(cause).__name__}: {cause}"]


def check_policy(path):
    from agentguard.policy.loader import load_policy

    try:
        policy = load_policy(path)
    except GuardError as exc:
        print(f"Invalid policy: {path}", file=sys.stderr)
        print("\n".join(_policy_errors(exc)), file=sys.stderr)
        return 1
    custom = ", ".join(sorted(policy.capabilities)) or "none"
    print(f"Policy OK: {path}")
    print(f"  rules: {len(policy.rules)}; default: {policy.defaults.effect.value}")
    print(f"  custom capabilities: {custom}")
    t, limits = policy.risk, policy.limits
    print(f"  risk thresholds: ask {t.ask}, strong approval {t.strong}, deny {t.deny}")
    print(
        f"  limits: {limits.max_calls_per_minute} calls/min, "
        f"{limits.max_argument_bytes} argument bytes, "
        f"{limits.max_recipients_per_action} recipients"
    )
    return 0


def _parse_args(pairs):
    arguments = {}
    for pair in pairs:
        name, separator, value = pair.partition("=")
        if not separator or not name:
            raise ValueError(f"--arg expects NAME=VALUE, got {pair!r}")
        try:
            arguments[name] = json.loads(value)
        except json.JSONDecodeError:
            arguments[name] = value
    return arguments


def explain_call(args):
    from agentguard.policy.explain import explain

    try:
        result = explain(
            args.policy,
            args.capability,
            _parse_args(args.arg),
            working_directory=args.cwd,
            environment=args.env,
        )
    except GuardError as exc:
        print(f"Invalid policy: {args.policy}", file=sys.stderr)
        print("\n".join(_policy_errors(exc)), file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, indent=2))
        return 0
    decision = result["decision"].upper()
    if result["strong_approval"]:
        decision += " (strong approval required)"
    print(f"Decision: {decision}")
    print(f"Policy: {result['policy_result']} ({result['policy_reason']})")
    matched = result["matched_rules"]
    if matched:
        for rule in matched:
            conditions = {
                k: v for k, v in rule.items() if k not in {"rule", "capability", "effect"}
            }
            detail = f" when {json.dumps(conditions)}" if conditions else ""
            print(f"  matches rule {rule['rule']}: {rule['effect']}{detail}")
    else:
        print("  no rule matches; the default applies")
    print(f"Risk: {result['risk_score']}/100" + (" (hard deny)" if result["hard_deny"] else ""))
    for reason in result["risk_reasons"]:
        print(f"  {reason}")
    t = result["thresholds"]
    print(f"Thresholds: ask {t['ask']}, strong approval {t['strong']}, deny {t['deny']}")
    print("Note: fresh session, no semantic judge; session history can raise risk.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
