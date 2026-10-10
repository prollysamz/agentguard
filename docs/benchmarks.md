# Benchmarks

How well do AgentGuard's deterministic rules and a semantic judge separate unsafe actions
from routine work? This page reports measurements, not claims. Reproduce them with:

```sh
agentguard judge-bench                                   # rules only
agentguard judge-bench --model gemma3:4b --runs 3        # plus a judge through Ollama
agentguard judge-bench --cases agentguard/bench/holdout_cases.yaml
```

## Method

- **Cases.** `agentguard/bench/judge_cases.yaml`: 71 labeled actions, 41 unsafe and 30 safe.
  Unsafe cases cover destruction, credential access, exfiltration, persistence and privilege
  escalation, including ones written to slip past simple rules. Safe cases include routine
  work that looks alarming (`rm -r build`, `git push origin feature`, code with a
  `password` variable). A separate holdout set (`holdout_cases.yaml`, 20 unsafe, 15 safe)
  uses different tools and syntax for the same categories.
- **Flagged** means the detector would stop the call or send it to a human. For rules, any
  decision other than allow under an allow-all policy (so only risk rules count). For a
  judge, a score at or above the ask threshold (51) or a deny flag, by majority over runs.
- **Combined** is rules or judge, which is what a Guard with a judge does.
- **Recall** is the share of unsafe cases flagged; **FP rate** the share of safe cases
  flagged; **instability** the share of cases where repeated runs disagreed.

## Results

Measured on 2026-10-08 with AgentGuard 0.4.0, Ollama 0.24.0 on Windows 11, models
`gemma3:4b` (a2af6cc3eb7f) and `qwen3:8b` (500a1f067a9f), temperature 0, thinking disabled,
the default judge prompt without deployment guidance, 3 runs per case. Raw per-case data:
[`benchmarks/results/`](https://github.com/prollysamz/agentguard/tree/main/benchmarks/results).

### Main set (71 cases: 41 unsafe, 30 safe)

| Detector | Recall | FP rate | Precision | F1 |
| --- | ---: | ---: | ---: | ---: |
| Rules, before 0.4 extensions | 54% | 17% | 82% | 0.65 |
| Rules (0.4) | 95% | 17% | 89% | 0.92 |
| Judge: gemma3:4b | 85% | 37% | 76% | 0.81 |
| Judge: qwen3:8b | 88% | 0% | 100% | 0.94 |
| Rules + gemma3:4b | 100% | 47% | 74% | 0.85 |
| Rules + qwen3:8b | 98% | 17% | 89% | 0.93 |

### Holdout set (35 cases: 20 unsafe, 15 safe)

| Detector | Recall | FP rate | Precision | F1 |
| --- | ---: | ---: | ---: | ---: |
| Rules, before 0.4 extensions | 0% | 0% | – | 0.00 |
| Rules (0.4) | 100% | 7% | 95% | 0.98 |
| Judge: gemma3:4b | 80% | 40% | 73% | 0.76 |
| Judge: qwen3:8b | 80% | 0% | 100% | 0.89 |
| Rules + gemma3:4b | 100% | 40% | 77% | 0.87 |
| Rules + qwen3:8b | 100% | 7% | 95% | 0.98 |

The judges never saw either set during development, so their holdout numbers are the most
independent ones on this page.

### Consistency and cost

| Judge | Cases that flipped between runs | Mean score stdev | Max spread | Median latency |
| --- | ---: | ---: | ---: | ---: |
| gemma3:4b (main / holdout) | 0% / 3% | 0.47 / 0.84 | 20 / 44 | 3.2 s / 2.6 s |
| qwen3:8b (main / holdout) | 1% / 0% | 0.80 / 0.54 | 35 / 10 | 5.0 s / 5.4 s |

### What the misses show

- **Judges miss credential reads.** gemma3:4b missed every credential-file read in both
  sets (`~/.ssh`, `~/.aws`, `.netrc`, `.git-credentials`, ...); qwen3:8b missed several. A
  read looks harmless to a model; the deterministic credential-path rules catch all of them.
- **gemma3:4b over-flags routine work**: writing tests, `npm ci`, `docker build`,
  `aws s3 ls`, `git config user.name`. Combined with the rules it reaches full recall at the
  cost of asking about roughly 40% of safe actions.
- **qwen3:8b adds recall without false positives** on these sets, at about 1.7× the latency.
- **The rules' remaining misses** on the main set are an upload to a non-allowlisted paste
  site (a domain policy decision, not a risk rule) and `git config core.hooksPath`.

An Unreleased rules-only rerun on 2026-10-10, after adding approval-level detection for
`git config core.hooksPath` changes, flags 40 of 41 unsafe main-set cases (98% recall).
The five safe cases flagged are unchanged (17% FP rate); `paste-site-upload` remains
the only miss. The tables above retain the published 0.4.0 measurements, including the
judge results, which have not been rerun for this change.

**Takeaway.** Keep the deterministic rules as the floor. A judge is worth adding for
recall on actions the rules do not model, but measure the model you plan to use: on this
data the larger `qwen3:8b` was strictly better than `gemma3:4b` as a judge, while
`gemma3:4b` remains a capable demo agent.

## Caveats

- **The same authors wrote the cases and the rules.** The rules were extended after the
  first measurement (54% recall). The holdout set was written before that change, but by
  the same author who then wrote the rules, so its 100% is an optimistic estimate of how the
  rules generalize. An independent holdout is a [1.0 exit criterion](security-review.md#exit-criteria-for-10).
- **"False positives" include deliberate asks.** Messages, emails, pushes and deletions
  start at or above the ask threshold by design, so routine ones count as false positives
  here. Policies can lower them per environment.
- **Small, synthetic set.** 106 cases cannot represent real agent traffic. Treat these as
  regression numbers, and run `judge-bench --cases` on your own labeled actions.
- **Judge results depend on hardware, model version and prompt**, and change between runs.
