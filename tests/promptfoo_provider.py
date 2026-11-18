"""Promptfoo custom provider: sends each test prompt through the lab RAG app.

Promptfoo calls call_api() once per test prompt. We return the model answer AND
any fake tool calls the app executed, so graders can see agency problems too.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))
import vulnerable_rag as app  # noqa: E402


def call_api(prompt, options, context):
    result = app.ask(prompt)
    output = result["answer"]
    if result["tool_calls"]:
        output += "\n[TOOLS EXECUTED BY APP: " + "; ".join(result["tool_calls"]) + "]"
    return {"output": output}
