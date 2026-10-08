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
    report = sub.add_parser("report", help="Summarize what policy asked about or denied")
    report.add_argument("--dry-run-only", action="store_true", help="Only calls made in dry-run")
    report.add_argument("--json", action="store_true", help="Print the report as JSON")
    for command in (logs, inspect, verify, report):
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
    approvers = sub.add_parser("approvers", help="Manage people who can approve actions")
    approvers_sub = approvers.add_subparsers(dest="approvers_command", required=True)
    add = approvers_sub.add_parser("add", help="Create an approver and print their token")
    add.add_argument("name")
    add.add_argument("--slack-user", help="Slack user ID allowed to click approval buttons")
    add.add_argument("--strong", action="store_true", help="May give strong approval")
    remove = approvers_sub.add_parser("remove", help="Delete an approver and their logins")
    remove.add_argument("name")
    listing = approvers_sub.add_parser("list", help="List approvers")
    approvals = sub.add_parser("approvals", help="Inspect approval requests")
    approvals_sub = approvals.add_subparsers(dest="approvals_command", required=True)
    requests = approvals_sub.add_parser("list", help="List requests, newest first")
    requests.add_argument("--status", choices=["pending", "approved", "rejected", "expired"])
    requests.add_argument("--limit", type=int, default=50)
    for command in (add, remove, listing, requests):
        command.add_argument("--store", default="agentguard-approvals.db")
    dashboard = sub.add_parser("dashboard", help="Serve the approvals and audit dashboard")
    dashboard.add_argument("--audit", default="agentguard.jsonl")
    dashboard.add_argument("--store", default="agentguard-approvals.db")
    dashboard.add_argument("--host", default="127.0.0.1")
    dashboard.add_argument("--port", type=int, default=8765)
    dashboard.add_argument("--audit-key-env", metavar="VAR", help="Verify audit signatures")
    dashboard.add_argument(
        "--slack-signing-secret-env", metavar="VAR", help="Enable /slack/actions for buttons"
    )
    dashboard.add_argument(
        "--secure-cookies", action="store_true", help="Mark cookies Secure (behind HTTPS)"
    )
    egress = sub.add_parser("egress-proxy", help="Run an allowlisting HTTPS egress proxy")
    egress.add_argument("--allow", action="append", required=True, metavar="DOMAIN")
    egress.add_argument("--host", default="127.0.0.1")
    egress.add_argument("--port", type=int, default=3128)
    egress.add_argument("--ports", default="443", help="Comma-separated allowed upstream ports")
    egress.add_argument("--audit", help="Record every CONNECT decision in this audit log")
    bench = sub.add_parser("judge-bench", help="Measure a semantic judge on labeled actions")
    bench.add_argument("--model", help="Ollama model to judge with (omit for rules only)")
    bench.add_argument("--runs", type=int, default=3, help="Runs per case, for consistency")
    bench.add_argument("--cases", help="YAML file of labeled cases (default: built-in set)")
    bench.add_argument("--guidance", default="", help="Deployment context for the judge")
    bench.add_argument("--json", help="Write the full results to this file")
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
        if args.command == "judge-bench":
            return judge_bench(args)
        if args.command == "egress-proxy":
            return serve_egress(args)
        if args.command == "dashboard":
            return serve_dashboard(args)
        if args.command in {"approvers", "approvals"}:
            return manage_approvals(args)
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
        if args.command == "report":
            from agentguard.audit.report import build_report, format_report

            result = build_report(events, dry_run_only=args.dry_run_only)
            print(json.dumps(result, indent=2) if args.json else format_report(result))
            return 0
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
        hint = "; check local model/service availability" if args.command == "demo" else ""
        print(f"AgentGuard: {type(exc).__name__}{hint}", file=sys.stderr)
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


def _secret(variable):
    if not variable:
        return None
    if not os.environ.get(variable):
        raise ValueError(f"Environment variable {variable} is not set")
    return os.environ[variable]


def judge_bench(args):
    from agentguard.bench.judge import format_summary, load_cases, run_benchmark, summarize
    from agentguard.risk.gemma_judge import GemmaJudge

    cases = load_cases(args.cases)
    judge = GemmaJudge(model=args.model, guidance=args.guidance) if args.model else None

    def progress(index, total, result):
        marks = "".join("x" if f else "." for f in result.judge_flags) or "-"
        print(
            f"\r[{index}/{total}] {result.id:<32} {marks:<6}", end="", file=sys.stderr, flush=True
        )

    results = run_benchmark(judge, cases, runs=args.runs, progress=progress)
    print(file=sys.stderr)
    summary = summarize(results, model=args.model, runs=args.runs if judge else None)
    if args.json:
        Path(args.json).write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(format_summary(summary))
    return 0


def serve_egress(args):
    from agentguard.audit.logger import AuditLogger
    from agentguard.execution.egress import EgressProxy

    audit = AuditLogger(args.audit) if args.audit else None
    proxy = EgressProxy(
        args.allow,
        host=args.host,
        port=args.port,
        ports=[int(p) for p in args.ports.split(",")],
        on_decision=audit.append if audit else None,
    )
    print(
        f"AgentGuard egress proxy on http://{args.host}:{args.port} allowing {', '.join(args.allow)}"
    )
    try:
        proxy.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def serve_dashboard(args):
    try:
        import uvicorn

        from agentguard.dashboard.app import create_app
    except ImportError:
        print(
            'Install the dashboard extra: pip install "agentguard-oss[dashboard]"', file=sys.stderr
        )
        return 1
    key = _secret(args.audit_key_env)
    app = create_app(
        audit_path=args.audit,
        store=args.store,
        audit_key=key.encode() if key else None,
        slack_signing_secret=_secret(args.slack_signing_secret_env),
        secure_cookies=args.secure_cookies,
    )
    if args.host not in {"127.0.0.1", "localhost", "::1"} and not args.secure_cookies:
        print(
            "Warning: serving beyond localhost without --secure-cookies. Put the dashboard "
            "behind HTTPS before exposing it.",
            file=sys.stderr,
        )
    print(f"AgentGuard dashboard on http://{args.host}:{args.port}  (Ctrl+C to stop)")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


def manage_approvals(args):
    from datetime import UTC, datetime

    from agentguard.approval.store import ApprovalStore

    store = ApprovalStore(args.store)
    if args.command == "approvals":
        for request in store.list_requests(status=args.status, limit=args.limit):
            created = datetime.fromtimestamp(request["created"], UTC).strftime("%Y-%m-%d %H:%M")
            decided = f" by {request['decided_by']}" if request["decided_by"] else ""
            print(
                f"{request['id']}  {request['status']:<8}{decided:<14} {created}  "
                f"{request['agent_id']}  {request['tool']} ({request['capability']})  "
                f"risk {request['risk']}"
            )
        return 0
    if args.approvers_command == "add":
        token = store.add_approver(args.name, slack_user_id=args.slack_user, can_strong=args.strong)
        print(f"Approver {args.name} created. Token (shown once; store it securely):")
        print(token)
        return 0
    if args.approvers_command == "remove":
        store.remove_approver(args.name)
        print(f"Approver {args.name} removed.")
        return 0
    for approver in store.list_approvers():
        flags = ["strong" if approver["can_strong"] else ""]
        if approver["slack_user_id"]:
            flags.append(f"slack {approver['slack_user_id']}")
        print(approver["name"], " ".join(f for f in flags if f))
    return 0


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
