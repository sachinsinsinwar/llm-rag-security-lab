# LLM and RAG Security Testing Lab

A small, **intentionally vulnerable** RAG (retrieval-augmented generation) app that I attack, fix and re-test, with before/after evidence. It maps findings to the **OWASP Top 10 for LLM Applications (2025)**.

> **Safety:** runs only on your own machine, with fake data only (fake "secrets", fake salaries, fake tools that only print). Do not point these attack scripts at systems you do not own. Do not deploy `vulnerable_rag.py`.

## Result in one line
Attacks that succeeded: **8 of 15 before the fixes, 1 of 15 after** (one filter bypass remains, documented). Read the 2-page report: [report/LLM_RAG_Security_Report.md](report/LLM_RAG_Security_Report.md).

## What is inside
```
app/vulnerable_rag.py   Weak RAG app (7 planted weaknesses, each commented and mapped to OWASP)
app/secure_rag.py       Hardened version (input filter, no prompt secrets, role-based retrieval,
                        untrusted-doc separation, output redaction, tool allowlist + approval,
                        HTML escaping, audit log)
docs/                   5 fake documents (one INTERNAL ONLY, one with a hidden instruction)
tests/run_attacks.py    15 attack tests -> one JSON evidence file each
tests/test_controls.py  16 deterministic tests of each security control (no LLM needed)
tests/run_utility.py    Checks normal questions still work after the fixes
tests/make_table.py     Builds evidence/BEFORE_AFTER.md from the JSON files
tests/promptfoo_*.yaml  promptfoo red-team config + generated tests; run_tools.ps1 = commands
evidence/               before/, after/, promptfoo/, garak/ results and summaries
report/                 The report
```

## Requirements
- Windows, Python 3.12, Git, Node.js (only for promptfoo), [Ollama](https://ollama.com)
- About 3 GB of disk for the two models. Free tools only; no API keys needed.

## Setup (PowerShell, from the project root)
```powershell
ollama pull llama3.2:3b
ollama pull nomic-embed-text
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```
Tip: keep the project in a **short folder path** (for example `D:\labs\llm`). Very long paths break pip on Windows. The first model call can take a few minutes while Ollama warms up.

## Run it
```powershell
# 1) Vulnerable app: load the docs, ask a question
.\.venv\Scripts\python.exe app\vulnerable_rag.py ingest
.\.venv\Scripts\python.exe app\vulnerable_rag.py ask "How many paid leave days do employees get per year?"

# 2) Attack it (writes evidence\before\*.json)
.\.venv\Scripts\python.exe tests\run_attacks.py --app vulnerable --tag before

# 3) Hardened app: ingest and attack again (writes evidence\after\*.json)
.\.venv\Scripts\python.exe app\secure_rag.py ingest
.\.venv\Scripts\python.exe tests\run_attacks.py --app secure --tag after

# 4) Prove each control without the model, check usability, build the table
.\.venv\Scripts\python.exe tests\test_controls.py
.\.venv\Scripts\python.exe tests\run_utility.py --app secure
.\.venv\Scripts\python.exe tests\make_table.py
```
Roles: `python app\secure_rag.py ask "..." --role hr` retrieves HR-level documents; the default role is `employee`.

## Automated tools (optional)
See `tests/run_tools.ps1`. promptfoo runs through `npx` with cloud generation and telemetry turned off (the local model generates and grades). garak needs its own venv (`python -m venv .venv-garak`, then `pip install garak`) and scans the bare model.

## Evidence format
Every attack test saves one JSON file: date, test id and name, OWASP category, payload, retrieved sources, response, tool calls, the exact success criteria, and `result` (`success` = the attack worked, `blocked` = it did not).

## Limitations (please read)
Small 3B local model, one run per payload, fake data, one machine. It is a learning lab, **not** a production deployment or a production test. No authentication, rate limiting or monitoring. PyRIT was not run. One attack (B1, a reworded direct injection) still succeeds against the hardened app. Details are in the report.
