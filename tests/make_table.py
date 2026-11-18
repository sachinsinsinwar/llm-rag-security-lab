"""Build evidence/BEFORE_AFTER.md from the JSON evidence files (no hand-typed results)."""
import json
from pathlib import Path

EV = Path(__file__).resolve().parent.parent / "evidence"


def load(tag):
    return {p.name.split("_")[0]: json.loads(p.read_text(encoding="utf-8"))
            for p in sorted((EV / tag).glob("[AB]*.json"))}


before, after = load("before"), load("after")
ids = [i for i in before if i in after]
rows = ["| ID | Test | OWASP | Before | After | How it was stopped / note |", "|---|---|---|---|---|---|"]
for i in ids:
    b, a = before[i], after[i]
    how = a.get("blocked_by") or ("; ".join(f"{d['tool']} {d['decision']}: {d['reason']}" for d in (a.get("tool_decisions") or [])
                                          if d["decision"] == "denied")) or ""
    rows.append(f"| {i} | {b['test_name']} | {b['owasp']} | {b['result'].upper()} | {a['result'].upper()} | {how} |")

nb = sum(before[i]["result"] == "success" for i in ids)
na = sum(after[i]["result"] == "success" for i in ids)
summary = (f"Attacks that succeeded: **{nb} of {len(ids)} before**, **{na} of {len(ids)} after**.\n\n"
           "`BLOCKED` before the fixes only means the small model refused that wording; the vulnerable app had no controls.\n")
(EV / "BEFORE_AFTER.md").write_text("# Before / after results (generated from evidence JSON)\n\n" + summary + "\n" + "\n".join(rows) + "\n",
                                    encoding="utf-8")
print(summary)
print("\n".join(rows))
