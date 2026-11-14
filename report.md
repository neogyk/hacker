# Evaluation Report — Riley Red-Team Project

_Answers the six judging criteria, grounded in `findings.md` and the run logs
(`logs/*.jsonl`). Figures are measured from the logs, not estimated._

## Scorecard (summary)

| Criterion | Verdict |
|---|---|
| Novelty / Creativity | Mostly known techniques, **creatively synthesized**; one genuinely uncommon angle (reasoning-trace theft + compounding memory). |
| Security impact | **High** on open models — full PHI/PII, schema, system prompt, and an unauthorized action. Contained on the Claude target. |
| Mitigation / fix | **Yes** — a working, measured defense (`embedding_guardrail.py`) plus a documented defense-in-depth plan. |
| Technical execution | **Strong** — 276 automated attempts logged, per-model success rates, reproducible evolutionary runs. |
| Commercializability | **Plausible** — an automated agentic-LLM red-team harness and an input-similarity guardrail. |
| Teamwork | Evidence shows an **individual-led, tool-assisted** effort on shared, collaboration-ready infrastructure. |

### Headline numbers (from logs)
- **276 automated attempts**, **54 leaks → 20% overall** success (agent-labeled).
- **Phase A (open models): 54/158 = 34%.** **Phase B (Claude): 0/118 = 0%.**
- Per model: Qwen3-30B **38%** (48/127), gpt-oss-120b 38% (3/8), DeepSeek-V4 50% (2/4),
  Qwen3-235B 5% (1/19), claude-haiku-5-5 0% (0/68), claude-sonnet-5-5 0% (0/50).
- **417** manual chat messages logged; **65** successful traces catalogued.
- Evolutionary peak: **386 private data points harvested in a single run**.

---

## 1. Novelty / Creativity
**New technique, or existing literature?** — Predominantly **implementations of
existing literature**, combined in a creative, automated way; one less-common angle.

Known/published techniques used (not novel): prompt injection, tool-call spoofing
(`[Riley used tool: query_db] …`), staff-authority role-play, and the classic
jailbreak family (instruction-override "ignore all previous instructions",
developer-mode, DAN, grandma, fictional-world, context-overflow reset). These are
well-documented and were included deliberately for coverage.

Creative / less-common contributions:
- **Reasoning-trace theft as a side channel.** Riley's `query_db` tool-call
  *arguments* leak its literal SQL — tables, columns, and its **own guardrail
  filters** (`confidentiality_level='standard'`, `deceased_date IS NULL`). This
  leaks even when the data itself is refused (observed on the hardened Claude
  target), and feeds a **persistent memory layer** that compounds across runs.
- **Evolutionary attacker** with *success-driven escalation* ("it worked → ask for
  more") and `--extract-all` to drain all records rather than re-hitting patient id 1.
- **Unified DSPy instrumentation**: both the attacker brain *and* the target are
  wrapped as `dspy.LM`s, so the whole exchange is inspectable via
  `dspy.inspect_history()`.
- **Hypothesis-driven mode** grounded in a reasoning-elicitation taxonomy
  (prefill, translation/encoding, self-reflection).

**Honest rating:** incremental scientific novelty, strong engineering synthesis.

## 2. Security impact
**If successful, how much harm?** — **High** on the open-model target.

Demonstrated disclosures (Phase A, with submittable `turn_id`s in `findings.md`):
- **Direct PHI/PII** for named patients — name, DOB, address, home/mobile phone,
  email, MRN, PCP (e.g. "Amy Singh | 1979-12-21 | … | 1").
- **Emergency contacts** (relatives, phone) via `patient_contacts`.
- **Full 10-table EHR schema** and **insurance member/group IDs** columns.
- **Unauthorized action**: `send_email` executed to a patient address (not just a
  read — an actuated side effect).
- **System prompt** reconstructed at **0.90 confidence**, incl. all tool defs.

Impact framing: this is **HIPAA-class PHI exposure plus an action-abuse primitive**.
Schema + guardrail-filter theft also lowers the cost of *future* attacks (recon
value). On the Claude target, data was held, but **structure/schema still leaked**
through the tool-call channel — a residual, lower-severity exposure.

## 3. Mitigation / fix
**Can the team defend against its own attack?** — **Yes**, with a working artifact.

- **`embedding_guardrail.py`** — an input pre-filter that embeds the project's own
  attack corpus and **discards prompts too similar** to known attacks. Measured
  separation: benign prompts ~**0.37** max cosine vs attacks ~**0.52**; threshold
  **0.45**; the demo blocks the attack samples and passes all benign samples, and
  catches a *novel* "ignore previous instructions" phrasing it had never logged.
  Zero-dependency by default; upgradeable to semantic embeddings.
- **Integration documented** (README "Defending layer"): two-line `guard.check()`
  wrapper in front of any Riley call; re-`--build` to keep learning.
- **Defense-in-depth plan** in `findings.md`: server-side authorization (row-level
  security, view allowlist), no free-form SQL (parameterized queries +
  `allowed_columns`), treat user text as data, output DLP on name+clinical-attr
  combinations, scope the tool-call SQL, and anomaly monitoring.

**Honest limitation stated in the docs:** the embedding filter is one layer —
strong against known-attack variants, weaker against novel phrasings; it is not a
complete defense.

## 4. Technical execution
**Reproducible and measured, not a one-off?** — **Yes.**

- **Every attempt is logged** to `logs/*.jsonl` (request + response + verdict),
  enabling re-analysis. **276 automated attempts** across models with per-model
  success rates (table above) — a rate, not a single lucky hit.
- **Reproducible escalation:** across **10 evolutionary runs**, successful runs
  harvested 36 / 122 / 20 / **386** data points — repeatable extraction, not chance.
- **Verification built in:** a separate LLM judge scores each attempt and discounts
  data the attacker fed in, so "success" means Riley actually produced the data.
- **Tooling for measurement:** `collect_successful.py` (65-trace corpus),
  `dashboard.py` (success vs non-success by model), persistent memory layer.

**Caveats (disclosed):** some runs hit transient failures (brain CLI `exit 1`,
a target `HTTP 401`); these were diagnosed and fixed with retry/backoff. The
Claude-target 0% is itself a measured result over 118 attempts, not an omission.

## 5. Commercializability
**Could the fix/finding become a product?** — **Plausibly, two ways.**

- **Offense:** an **automated agentic-LLM red-team harness** — multi-strategy
  attack generation, evolutionary optimization, reasoning-trace stealing,
  per-model success dashboards. Positioned as continuous "pentest-as-a-service"
  for LLM agents with DB/tool access (a growing need as agents get tools).
- **Defense:** the **input-similarity guardrail** (self-learning from an org's own
  captured attacks) and a **tool-call-SQL scoping / DLP** component are packageable
  as a lightweight LLM-firewall add-on.

Realistic positioning: the components are a credible MVP/demo, not a finished
product; the defensive guardrail is the nearer-term, more defensible offering.

## 6. Teamwork
**Developed together, or individual hypotheses?** — The **artifacts** show an
**individual-led, tool-assisted** effort on **collaboration-ready infrastructure**.

- The logs and account metadata reflect a single participant; attacks were driven
  largely by automated agents rather than many hands.
- However, the project is built for collaboration: a **shared persistent memory
  layer**, uniform **JSONL logs**, a **dashboard**, and a reusable agent library
  let multiple people test hypotheses in parallel and pool findings — and the
  `--investigate` mode formalizes hypothesis → approbate → summarize.

**Honest note:** we can evidence the *tooling* that supports teamwork and the
*iterative, hypothesis-driven process*, but the logs cannot prove multi-person
collaboration; treat the teamwork claim as process-and-infrastructure, not headcount.

---

_Sources: `findings.md`, `successful_attacks.md/.json`, `logs/hacker_runs.jsonl`,
`logs/evo_runs.jsonl`, `logs/sysprompt_runs.jsonl`, `logs/reasoning_runs.jsonl`,
`logs/pipeline_runs.jsonl`, `logs/my_attempts.jsonl`._
