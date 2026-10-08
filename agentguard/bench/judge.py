"""Measure a semantic judge on labeled actions: recall, false positives, consistency.

    agentguard judge-bench --model gemma3:4b --runs 3 --json results.json

Each case runs ``runs`` times. A detector "flags" a case when it would stop it or ask a
human: for the judge, a score at or above the policy's ask threshold or a deny flag; for
deterministic rules, a risk decision other than allow. Three detectors are reported: the
deterministic rules alone, the judge alone, and both combined (what a Guard with a judge
does). Consistency is how often repeated runs disagree with each other.
"""

import statistics
import tempfile
import time
from dataclasses import dataclass, field
from importlib.resources import files

import yaml

from agentguard.core.action import Action, Context
from agentguard.core.context import SessionRiskContext
from agentguard.core.decision import Effect
from agentguard.policy.explain import combine
from agentguard.policy.loader import load_policy
from agentguard.policy.matcher import absolute_path
from agentguard.risk.scorer import Risk, score

ALLOW_ALL = {
    "version": 1,
    "defaults": {"effect": "allow"},
    "rules": [],
}


def load_cases(path=None):
    if path:
        text = open(path, encoding="utf-8").read()
    else:
        text = files("agentguard.bench").joinpath("judge_cases.yaml").read_text(encoding="utf-8")
    cases = yaml.safe_load(text)["cases"]
    labels = {case["label"] for case in cases}
    if not labels <= {"safe", "unsafe"}:
        raise ValueError(f"Labels must be safe or unsafe, got {labels}")
    return cases


def case_action(case, working_directory):
    """The Action a Guard would build: paths made absolute, as in Guard normalization."""
    arguments = dict(case["arguments"])
    if case["capability"].startswith("filesystem.") and "path" in arguments:
        arguments["path"] = absolute_path(arguments["path"], working_directory)
    return Action(
        agent_id="bench",
        session_id="bench",
        tool=case.get("tool", case["capability"].split(".")[-1]),
        capability=case["capability"],
        arguments=arguments,
        context=Context(working_directory=working_directory),
    )


@dataclass
class CaseResult:
    id: str
    label: str
    category: str
    deterministic: bool
    judge_scores: list = field(default_factory=list)
    judge_flags: list = field(default_factory=list)
    errors: int = 0
    seconds: list = field(default_factory=list)

    @property
    def judge_majority(self):
        return sum(self.judge_flags) * 2 > len(self.judge_flags) if self.judge_flags else False

    @property
    def unstable(self):
        return len(set(self.judge_flags)) > 1


def run_benchmark(judge, cases, *, runs=3, policy=None, progress=None):
    policy = load_policy(policy or ALLOW_ALL)
    working_directory = tempfile.mkdtemp(prefix="agentguard-bench-")
    results = []
    for index, case in enumerate(cases, 1):
        action = case_action(case, working_directory)
        risk = score(action, SessionRiskContext(), policy.capabilities)
        effect, _ = combine(policy, Effect.ALLOW, risk)
        result = CaseResult(
            case["id"], case["label"], case.get("category", ""), effect != Effect.ALLOW
        )
        for _ in range(runs if judge else 0):
            started = time.perf_counter()
            try:
                verdict = judge.evaluate(action.model_copy(deep=True))
                if not isinstance(verdict, Risk):
                    raise ValueError("Judge did not return a Risk")
                result.judge_scores.append(verdict.score)
                result.judge_flags.append(verdict.hard_deny or verdict.score >= policy.risk.ask)
            except Exception:
                result.errors += 1
            result.seconds.append(time.perf_counter() - started)
        results.append(result)
        if progress:
            progress(index, len(cases), result)
    return results


def _rates(results, flagged):
    unsafe = [r for r in results if r.label == "unsafe"]
    safe = [r for r in results if r.label == "safe"]
    tp = sum(flagged(r) for r in unsafe)
    fp = sum(flagged(r) for r in safe)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / len(unsafe) if unsafe else 0.0
    return {
        "recall": round(recall, 3),
        "false_positive_rate": round(fp / len(safe), 3) if safe else 0.0,
        "precision": round(precision, 3),
        "f1": round(2 * precision * recall / (precision + recall), 3)
        if precision + recall
        else 0.0,
        "missed": [r.id for r in unsafe if not flagged(r)],
        "false_positives": [r.id for r in safe if flagged(r)],
    }


def summarize(results, *, model=None, runs=None):
    judged = [r for r in results if r.judge_flags]
    summary = {
        "model": model,
        "runs": runs,
        "cases": len(results),
        "unsafe": sum(r.label == "unsafe" for r in results),
        "safe": sum(r.label == "safe" for r in results),
        "deterministic": _rates(results, lambda r: r.deterministic),
    }
    if judged:
        spreads = [statistics.pstdev(r.judge_scores) for r in judged if len(r.judge_scores) > 1]
        latencies = [s for r in results for s in r.seconds]
        summary["judge"] = _rates(results, lambda r: r.judge_majority)
        summary["combined"] = _rates(results, lambda r: r.deterministic or r.judge_majority)
        summary["consistency"] = {
            "unstable_cases": [r.id for r in judged if r.unstable],
            "unstable_rate": round(sum(r.unstable for r in judged) / len(judged), 3),
            "mean_score_stdev": round(statistics.mean(spreads), 2) if spreads else 0.0,
            "max_score_spread": max(
                (max(r.judge_scores) - min(r.judge_scores) for r in judged), default=0
            ),
        }
        summary["errors"] = sum(r.errors for r in results)
        summary["median_seconds"] = round(statistics.median(latencies), 2) if latencies else None
    summary["per_case"] = [
        {
            "id": r.id,
            "label": r.label,
            "category": r.category,
            "deterministic": r.deterministic,
            "judge_scores": r.judge_scores,
            "judge_flags": r.judge_flags,
            "errors": r.errors,
        }
        for r in results
    ]
    return summary


def format_summary(summary):
    lines = [
        f"Judge benchmark: {summary['model'] or 'deterministic only'} "
        f"({summary['cases']} cases: {summary['unsafe']} unsafe, {summary['safe']} safe"
        + (f"; {summary['runs']} runs each)" if summary.get("runs") else ")"),
        "",
        f"{'detector':<15}{'recall':>8}{'FP rate':>9}{'precision':>11}{'F1':>7}",
    ]
    for name in ("deterministic", "judge", "combined"):
        if name in summary:
            r = summary[name]
            lines.append(
                f"{name:<15}{r['recall']:>8.0%}{r['false_positive_rate']:>9.0%}"
                f"{r['precision']:>11.0%}{r['f1']:>7.2f}"
            )
    if "consistency" in summary:
        c = summary["consistency"]
        lines += [
            "",
            f"Unstable decisions across runs: {c['unstable_rate']:.0%} of cases "
            f"(mean score stdev {c['mean_score_stdev']}, max spread {c['max_score_spread']})",
            f"Errors: {summary['errors']}; median latency {summary['median_seconds']}s per call",
        ]
    for name in ("deterministic", "judge", "combined"):
        if name in summary:
            if summary[name]["missed"]:
                lines.append(f"{name} missed: {', '.join(summary[name]['missed'])}")
            if summary[name]["false_positives"]:
                lines.append(
                    f"{name} false positives: {', '.join(summary[name]['false_positives'])}"
                )
    return "\n".join(lines)
