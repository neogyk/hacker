# Riley / Break the Model — Defense track (3-minute pitch)

**Finding (from our own logs):** Riley answers questions by emitting **raw SQL**
to a `query_db` tool with full read access to the hospital database. Safety today
= the LLM "choosing" to behave + a text filter on the *output*. Both are
probabilistic and bypassable by prompt injection (encoding, role-play,
"read the schema first", UNION onto a public query…).

**Our fix — a deterministic SQL Policy Gate that removes the LLM from the trust
path.** It sits between the agent and SQLite and decides *before any row is read*
whether a query may run, using a per-role **allow-list** enforced by **SQLite's
own authorizer callback** (the engine calls us for every table/column the query
plan touches). If a sensitive column is not readable for a public session, no
prompt can leak it — the data never enters the model's context.

- **Three layers, defence in depth:**
  1. Static token guard (read-only, single SELECT, comment/quote stripping, no PRAGMA/`pragma_table_info`/`information_schema`/ATTACH/`sqlite_master`/writes);
  2. Engine-level column allow-list via `sqlite3.set_authorizer` (`SQLITE_READ` per `(table, column)`);
  3. **42 CFR Part 2** row filter (`Addiction Medicine (Part 2 Program)` hidden without explicit Part 2 consent token).
- **Reproducible result:** `2/2` legitimate queries still work (with 42 CFR Part 2 filtered), `7/7` synthetic exfiltration classes blocked, and **40/40 (100%) real `query_db` SQL tool calls replayed from our red-team logs blocked**, `0` leaks.
- **Verified red-team `turn_id`s across all 4/4 models (`metrics.py`):**
  - `Qwen/Qwen3-30B-A3B-Instruct-2507`: `9adc1316735a41198845bd88e11bce3c`
  - `openai/gpt-oss-120b`: `b424edf026e4407696c27bdd67598e8a`
  - `Qwen/Qwen3-235B-A22B-Instruct-2507`: `d7ea7dfa4461428fabc11bfc30610fbf`
  - `deepseek-ai/DeepSeek-V4-Pro-0813`: `8dfcf1bc930845c9a0af2df6878bc522`
- Deterministic, no LLM call, sub-millisecond, fully auditable.

## How it maps to the judging criteria
| Criterion | Weight | Our evidence |
|---|---|---|
| Novelty | 20% | Defence at the DB **authorizer** layer, not prompt/output filtering |
| Security impact | 20% | Blocks PHI, SSN, DOB, provider PII, service API secret, 42 CFR Part 2 |
| **Mitigation / fix** | **20%** | Working gate, `demo.py` before/after, 7/7 blocked |
| Technical execution | 15% | `metrics.py` = success-rate table + leak `turn_id`s across models |
| Commercializability | 10% | Drop-in `query_db` wrapper / sidecar for any NL→SQL agent |
| Teamwork | 10% | Partner runs attacks across models; this track hardens + measures |
| Presentation | 5% | One command each: attack → metrics → fix demo |

## Live demo script (90 seconds)
```bash
# 1. the attack worked (show one real leak turn_id from chat.py)
python3 defense/metrics.py       # success rate per model + leak turn_ids
# 2. the deterministic fix
python3 defense/seed_db.py
python3 defense/demo.py          # 7/7 blocked, 2/2 legit still work, 0 leaks
```

## Commercial angle (10%)
"Policy gate for LLM database agents": a sidecar that wraps any agent's SQL tool
with a declarative per-role column allow-list enforced at the engine. Ships as a
Python decorator today; same idea applies to Postgres (row-level security +
`SET ROLE`) and to MCP database tools. Sells to anyone putting an LLM in front of
PHI/PII/financial data under HIPAA / 42 CFR Part 2 / GDPR.

## Honest limitations (say these — judges reward it)
- Gate assumes the DB connection is per-session-role. If the agent is given one
  super-user connection, that's the thing to split first.
- Allow-list must be curated per schema; we ship a sane default for the public
  front-desk role.
- Defends the *exfiltration* path. A separate control is still needed for
  write/tool actions and for data the public role *is* allowed to see but should
  be rate-limited (scraping the full directory).
