"""Summaries of an audit log, for tuning a policy before enforcing it.

Run an agent with ``Guard(..., mode="dry-run")`` on a safe workload, then read the report:
every call that policy and risk would have sent to a human or blocked, grouped by tool and
reason, with how often it happened.
"""

import re
from collections import Counter, defaultdict

# Reasons that describe the score, not why the call was stopped.
_NOISE = re.compile(r"^(Capability baseline: \d+|Policy rule \d+: allow|Policy default: allow)$")


def build_report(events, *, dry_run_only=False):
    proposed = [
        e
        for e in events
        if e.get("stage") == "proposed" and (not dry_run_only or e.get("mode") == "dry-run")
    ]
    executed_anyway = {
        e.get("action_id")
        for e in events
        if e.get("stage") == "authorized" and e.get("dry_run_override")
    }
    decisions = Counter(e.get("evaluated_decision", "unknown") for e in proposed)
    tools = defaultdict(Counter)
    groups = {}
    for event in proposed:
        decision = event.get("evaluated_decision", "unknown")
        tools[(event.get("tool"), event.get("capability"))][decision] += 1
        if decision not in {"ask", "deny"}:
            continue
        key = (event.get("tool"), event.get("capability"), decision)
        group = groups.setdefault(
            key,
            {
                "tool": key[0],
                "capability": key[1],
                "decision": decision,
                "count": 0,
                "max_risk": 0,
                "reasons": Counter(),
                "examples": [],
                "executed_in_dry_run": 0,
            },
        )
        group["count"] += 1
        group["max_risk"] = max(group["max_risk"], event.get("risk_score") or 0)
        group["reasons"].update(r for r in event.get("reasons", []) if not _NOISE.match(r))
        if len(group["examples"]) < 3:
            group["examples"].append(
                {"action_id": event.get("action_id"), "arguments": event.get("arguments", {})}
            )
        if event.get("action_id") in executed_anyway:
            group["executed_in_dry_run"] += 1
    rejected = Counter(
        reason
        for e in events
        if e.get("stage") == "rejected" and (not dry_run_only or e.get("mode") == "dry-run")
        for reason in e.get("reasons", [])
    )
    would_change = sorted(
        groups.values(), key=lambda g: (g["decision"] != "deny", -g["count"], g["tool"] or "")
    )
    for group in would_change:
        group["reasons"] = [
            {"reason": reason, "count": count} for reason, count in group["reasons"].most_common(5)
        ]
    return {
        "events": len(events),
        "calls": len(proposed),
        "modes": dict(Counter(e.get("mode", "enforce") for e in proposed)),
        "decisions": {d: decisions.get(d, 0) for d in ("allow", "ask", "deny")},
        "would_change": would_change,
        "tools": [
            {
                "tool": tool,
                "capability": capability,
                **{d: c.get(d, 0) for d in ("allow", "ask", "deny")},
            }
            for (tool, capability), c in sorted(
                tools.items(), key=lambda item: -sum(item[1].values())
            )
        ],
        "rejected": [{"reason": r, "count": c} for r, c in rejected.most_common()],
    }


def format_report(report):
    lines = [
        f"{report['calls']} evaluated calls ({report['events']} audit events)",
        "Decisions: "
        + ", ".join(f"{d} {report['decisions'][d]}" for d in ("allow", "ask", "deny")),
    ]
    if report["modes"].get("dry-run"):
        lines.append(f"Dry-run calls: {report['modes']['dry-run']} (these executed regardless)")
    if not report["would_change"]:
        lines.append("Nothing would be asked or denied.")
    for group in report["would_change"]:
        verb = "denied" if group["decision"] == "deny" else "sent for approval"
        lines.append(
            f"\n{group['tool']} ({group['capability']}): {group['count']} call(s) {verb}, "
            f"max risk {group['max_risk']}"
        )
        lines.extend(f"  {r['count']}x {r['reason']}" for r in group["reasons"])
    if report["rejected"]:
        lines.append("\nRejected before evaluation:")
        lines.extend(f"  {r['count']}x {r['reason']}" for r in report["rejected"])
    return "\n".join(lines)
