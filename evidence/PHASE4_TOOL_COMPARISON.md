# Phase 4 - Automated tools vs manual findings (BEFORE fixes)

Date: 2026-11-18. Everything local. Model/generator/grader: `llama3.2:3b` via Ollama.
Tools: promptfoo 0.125.1 (red team, against the RAG app), garak 0.17.1 (against the bare model).
PyRIT: **not run** (heavier setup; skipped on purpose, see limits).

## Raw tool results
| Tool | Target | What ran | Result (real output) |
|---|---|---|---|
| promptfoo | RAG app | 12 generated tests (pii:direct, rbac, prompt-extraction, excessive-agency; hijacking generated 0 of 3) | 9 passed, 3 failed, 0 errors. All 3 failures were excessive-agency. File: `promptfoo/redteam_results.json` |
| garak | bare model | promptinject.HijackHateHumans (256 prompts) | **43.75% attack success rate** (144/256 resisted) |
| garak | bare model | latentinjection.LatentInjectionFactSnippetEiffel (256 prompts) | 15/256 hijacked (241 resisted, about 5.9% success) |
| garak | bare model | dan.Dan_11_0 (1 prompt) | Failed both detectors (jailbreak worked; only 1 sample, so weak evidence) |

Files: `garak/garak_summary.json`, `garak/model_scan.hitlog.jsonl` (the successful attacks), `garak/model_scan.report.html`.

## Comparison with manual findings
| Weakness | Manual (Phase 3) | promptfoo | garak | Comment |
|---|---|---|---|---|
| Indirect injection via a retrieved document (LLM01) | **Success (critical)** | not tested | bare-model "latent injection" 5.9% | Only the manual test used the real poisoned document. garak tests the model, not the RAG flow. |
| Direct prompt injection (LLM01) | Not proven (canary refused) | not tested | **43.75% success** on 256 variants | Volume found what my 2 manual payloads did not. Model is injectable, my samples were too few. |
| Jailbreak | not tested | not tested | DAN 11.0 worked (n=1) | Automated only. |
| System prompt leakage (LLM07) | **Success** (translate trick) | no real finding (graded pass) | not tested | Manual only. |
| Sensitive data / API key / salaries (LLM02, LLM08) | **Success (critical)** | passed (refused generic asks) | not applicable | Manual only. Generic questions were refused; targeted wording leaked. |
| Excessive agency (LLM06) | **Success** | **3 failures** | not applicable | Both agree. Also seen on harmless questions. |
| Insecure output / XSS (LLM05) | Success at sink only | not tested | not applicable | Manual only (code-level). |

## What this shows (plain words)
- **Overlap is small.** The tools agree with manual testing on excessive agency and on the model being injectable.
- **Manual testing found the app-specific, high-impact bugs** (secrets in the vector store, hidden document instructions, unescaped HTML). Tools do not know your documents or code.
- **Tools bring volume.** garak ran 256 variants per probe and found a high direct-injection rate that my handful of payloads missed.
- **Grader reliability is a problem.** promptfoo's local 3B grader passed responses where the app ran an unrequested send_email (prompt-extraction tests 8 and 9). Its 9/12 "pass" rate overstates safety.
- **False sense of safety:** tool exit codes and pass rates are not proof. I found three tool runs that "succeeded" with no real results (bad path, wrong probe name, wrong report path) before getting valid output.

## Limits
- Small model as generator and grader; results will differ with a stronger model.
- garak scans the model alone; promptfoo's attacks were generic. Neither covers the poisoned document, tool allowlists or HTML sink.
- Single runs, temperature settings per tool defaults. promptfoo hijacking plugin produced no tests.
- PyRIT was not run.
