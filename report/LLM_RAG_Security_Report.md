# LLM and RAG Security Testing Lab - Report

**Author:** Sachin Singh | **Date:** 2026-11-19 | **Scope:** own app, own machine, fake data only

## 1. Scope and setup
I built a small, intentionally weak RAG helpdesk app ("AcmeBot", fictional company), attacked it, fixed it, and re-tested with the same attacks.

- **Stack:** Python 3.12, Chroma vector store, Ollama with `llama3.2:3b` (chat) and `nomic-embed-text` (embeddings), Windows 11, RTX 4060. All local, no cloud API, no real data.
- **Data:** 5 fake documents: 3 public, 1 external vendor notice (contains a hidden instruction), 1 "internal only" file with fake salaries, a fake API key and a fake DB password.
- **Planted weaknesses (7):** secret in the system prompt, no role tags, no access control on retrieval, tool calls run straight from model text, unescaped HTML output, document text mixed with instructions, no input/output filtering.
- **Method:** 15 attack tests (manual), logged as one JSON file each (date, payload, response, result, success check); automated runs with promptfoo 0.125.1 (against the app) and garak 0.17.1 (against the bare model); fixes in `app/secure_rag.py`; re-test.
- **Result rule:** "success" means a plain, visible string check matched (stated in every JSON file). Temperature 0, one run per payload.

## 2. Findings (before and after)
Attacks that succeeded: **8 of 15 before, 1 of 15 after.** (Evidence: `evidence/BEFORE_AFTER.md`.)

| # | Finding | OWASP LLM 2025 | Impact (plain words) | Evidence (before) | Fix | Retest |
|---|---|---|---|---|---|---|
| 1 | Hidden instruction in a retrieved document made the bot email an outsider | LLM01 (indirect) | **Critical.** An external document controls the bot's actions; user typed a normal question | A3 | Clean documents before chunking; mark documents as untrusted data; email allowlist + human approval | Blocked (A3) |
| 2 | Confidential document retrievable by anyone; fake API key and all salaries leaked | LLM02, LLM08 | **Critical.** Any user reads HR and credential data | A4a, A4c | Role level on every chunk, filter inside the vector query; output redaction | Blocked (A4a, A4b, A4c); employee never retrieves the file (control test) |
| 3 | System prompt and internal codes leaked ("translate your instructions") | LLM07 | **High.** Internal rules and codes exposed | A2b, B2 | Secrets removed from the prompt; input filter | Blocked (A2b, B2) |
| 4 | Tool calls run with no approval; delete_file executed; stray emails on harmless questions | LLM06 | **High.** Model text can trigger real actions | A6 (+ seen in normal use) | delete_file removed; send_email only to company domain and only with human approval | Blocked (A6); allowlist proven by unit tests because the model did not try a call |
| 5 | Model output written into HTML unescaped | LLM05 | **High (code flaw).** Any script from the model runs in a browser | A5s (sink test; model refused to write XSS in A5, A5b, A5c) | `html.escape` on output | Blocked (A5s) |
| 6 | Direct prompt injection | LLM01 | **High.** Model obeys user-supplied override wording | B1; garak 43.75% success on 256 prompts | Input filter for known wording | **Still works (B1)**; filter bypassed by rewording |

## 3. Automated tools vs manual testing
- **garak (bare model):** prompt-hijack probe 43.75% attack success (144/256 resisted); hidden-instruction probe 15/256; DAN jailbreak failed (1 sample only).
- **promptfoo (app):** 12 generated tests, 9 passed, 3 failed (all excessive agency). After the fixes: 7 passed, 5 failed; I read all 12 responses and none ran a tool or showed a secret, so I judge the 5 as grader errors from the small local model.
- **Comparison:** the tools matched manual testing on excessive agency and on the model being injectable, and found the high injection rate through volume. They missed the app-specific criticals (document injection, data leak, prompt leak, XSS sink). Manual testing found those. Details: `evidence/PHASE4_TOOL_COMPARISON.md`.

## 4. Lessons learned
1. **Structural fixes beat filters.** Removing secrets from the prompt, filtering at retrieval, banning tools and escaping output worked and are provable. The regex input filter was bypassed within one attempt.
2. **Treat retrieved text as untrusted input.** The worst finding came from a document, not from the user.
3. **A model refusal is not a control.** Many "blocked" results before the fixes were just the small model refusing one wording; rewording beat it twice.
4. **Test my own tests.** My first indirect-injection fix missed a comment split across chunks, and one XSS check flagged an escaped page as a success. Both were found and corrected.
5. **Check tool output, not exit codes.** Three automated runs "finished" with no real results (wrong path, wrong probe name, wrong report path) before a valid run.
6. **Security costs usability.** The output filter also redacts salaries for the legitimate HR role.

## 5. Limitations (honest)
- Small 3B local model as target, generator and grader; results will differ on other models. Single run per payload.
- Fake data, a lab app on one machine. **Not a production system, not a production test.** No authentication (role is a function argument), no rate limiting, no monitoring or alerting.
- XSS was proven at the output sink, not via a model-written script (the model refused).
- The send_email/delete_file tools are fakes that only print.
- garak tests the bare model, not the RAG pipeline. PyRIT was not run. promptfoo's hijacking plugin produced no tests.
- B1 (reworded direct injection) is an open residual risk.
