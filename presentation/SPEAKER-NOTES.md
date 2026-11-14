# Riley — Break & Fix · Speaker notes (3-minute talk)

**Presenter:** Margaret · **Team:** Leonid Didukh · Mengyuan Xiao · Bernhard Eisvogel · Karlheinz Kiesewalter
**Deck:** `Riley-Break-and-Fix.pptx` / `.pdf` (10 slides: title + 5 main + 4 appendix; Appendix D = full tool coverage, use only if asked)
**Who did what (verified):** Leonid — automated red-team agent + runs across models. Margaret — cracked Qwen3-235B and built the policy gate + metrics. (No per-model attribution claimed for the other three.)
**Golden rule while speaking:** say "fictional hospital, synthetic data" once at the start; never read a real-looking value aloud; never claim the fix runs on the live Riley.

Everything below is the recorded, verified story. The three patient-data disclosures and the 40-call replay numbers were re-measured from the logs and the defense code at commit `8e1d9ea`.

---

## The script (read against a timer — target 3:00)

### Title slide — (say while it's up, ~0:10)
"Quick framing: this is a *fictional* hospital with *synthetic* data. Riley is its front-desk AI. We made it hand out patient records it should have protected — on four different models — and then we built and measured the fix."

### Slide 1 · Front desk — 0:00–0:25
"Same assistant, two questions. Ask for departments and you get a public directory — exactly right. But pose as staff doing callbacks and ask for recent visits, and the *same* assistant returns five fictional patients — name, medical-record number, phone. The values on screen are redacted; the proof is next."

### Slide 2 · What the log proves — 0:25–0:55
"This is the core of our evidence. On the Qwen3-235B turn, the patient values are in Riley's *reply text* — five patients. We did not count a database tool call, and we did not trust the red-team runner's 'success' flag. A flag can be wrong; a tool call only shows it queried something; the *reply* is what the user actually received. That's a real disclosure. Full turn ID is in the appendix."

### Slide 3 · Where the check belongs — 0:55–1:35
"Top row is what the logs show: visitor, Riley, its SQL tool, the database, the reply — and private fields came back. The missing piece is a per-role permission check; the only guard was a filter on the model's output, which a prompt can talk around. Bottom row is our fix: a policy gate at the database. It uses SQLite's own authorization callback to check every table and column against the public role's allow-list *before any row is read* — deterministic, no model in the loop. To be clear, this is our local prototype, not a change to the hosted server."

### Slide 4 · What changed — 1:35–2:25
"We replayed 40 recorded sensitive queries through the gate — 35 from my teammate's logs, 7 of mine, minus 2 public baseline. Zero returned data. 39 were stopped by the policy: 32 at the database engine, 7 at a static guard. The fortieth was malformed SQL that would fail anyway — so we report it separately instead of claiming it. And normal look-ups still work: three department rows, one provider row. We're deliberately *not* claiming universal zero-leak, and we fixed a cosmetic hard-coded '100%' in the demo's printout."

### Slide 5 · Adoption + close — 2:25–3:00
"Who'd use this: any team with an LLM in front of sensitive data. It installs as a wrapper on the agent's database tool — no retraining — and legitimate use still works. Credit where due: Leonid built the automated attack agent; I cracked the hardest model and built the gate and the metrics. A security lead will ask whether it holds on a *real* schema, not just our fixture — and the honest answer is a staging test that replays a week of live traffic and measures wrongly-blocked requests."

### Closing line — MEMORIZE (say it looking up, not at the screen)
> **"We didn't just break Riley — we built the lock that would have stopped us, and measured it."**

---

## Rubric coverage (keep in your back pocket)
| Criterion | Where it lands |
|---|---|
| Novelty 20% | Defense at the DB **authorization callback**, not a prompt/output filter |
| Security impact 20% | PHI disclosed across three models (name, DOB, MRN, phone) |
| Mitigation 20% | Working, **measured** gate — 40-call replay, 0 reached data |
| Technical execution 15% | Reproducible replay + full turn IDs (Appendix A/B) |
| Commercializability 10% | Drop-in wrapper — presented as a **hypothesis** |
| Teamwork 10% | Attack (teammate) + defense/metrics (Margaret), both tied to artifacts |
| Presentation 5% | This 3-minute deck |

## Five likely judge questions (full answers on Appendix C)
1. **Running on the real Riley?** No — local prototype on a synthetic replica; finding and fix kept separate.
2. **Was the 4th model (DeepSeek) really breached?** Partial — its reply gave an encounter identifier (visit number/time/department), not a patient-identifying field.
3. **How do errors affect the metric?** 39/40 stopped by policy; 1 was malformed SQL. Reported separately; no universal zero-leak claim.
4. **What public function did you test?** Departments/facilities (3 rows) and provider directory (1 row) still work.
5. **Why an authorizer over a prompt/output filter?** Deterministic, fires in the engine on every table/column before rows are read — can't be talked around.

---

## Submission (read before you send)
The Entropy form has three visible fields: **GitHub repo link (must be public)**, **Other links**, **one file upload (≤10 MB)**. There is **no turn-ID field** — so put the evidence in the uploaded PDF (Appendix A has the full turn IDs).

**Recommended values**
- **File upload:** `Riley-Break-and-Fix.pdf` (this deck; under 10 MB).
- **GitHub repo link (must be public):** ⚠️ **not available yet.** `github.com/neogyk/hacker` and PR #1 both return **404 to anonymous visitors** — the repo is private. *One owner action needed:* make a public repo (either flip `neogyk/hacker` to public — teammate's call — or push `defense/` to a new public repo). Until then this required field has no valid URL.
- **Other links:** the PR URL once the repo is public; optional.

**One owner action:** publish a repo so the "must be public" field has a working link. Nothing else blocks submission — the PDF carries the full narrative and evidence on its own.

## 10-second rehearsal checklist
- [ ] **Say:** "fictional hospital, synthetic data" in the first breath.
- [ ] **Show:** Slide 2 (evidence) and Slide 4 (counts) are the two that win points — slow down there.
- [ ] **Send:** upload `Riley-Break-and-Fix.pdf`; paste the public repo link *after* the owner publishes it.
- [ ] **Never:** read a real-looking value aloud, or claim the fix runs on the live server.
- [ ] **Close:** the memorized line, looking at the judges.
