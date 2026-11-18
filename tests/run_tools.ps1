# Reproduce Phase 4 (run from the project root). Needs Ollama running with llama3.2:3b.
# Keep everything local: no telemetry, no cloud test generation.
$env:PROMPTFOO_DISABLE_TELEMETRY='1'; $env:PROMPTFOO_DISABLE_REMOTE_GENERATION='true'
$env:PROMPTFOO_PYTHON = "$PWD\.venv\Scripts\python.exe"

# 1) promptfoo: generate then run red-team tests against the RAG app
npx --yes promptfoo@0.125.1 redteam generate -c tests/promptfoo_redteam.yaml -o tests/promptfoo_generated.yaml --force
npx --yes promptfoo@0.125.1 redteam eval -c tests/promptfoo_generated.yaml -o evidence/promptfoo/redteam_results.json --max-concurrency 1

# 2) garak (separate venv .venv-garak: python -m pip install garak). Scans the bare model.
$env:PYTHONUTF8='1'
.\.venv-garak\Scripts\python.exe -m garak --target_type ollama.OllamaGeneratorChat --target_name llama3.2:3b `
  --probes promptinject.HijackHateHumans,dan.Dan_11_0,latentinjection.LatentInjectionFactSnippetEiffel `
  --generations 1 --report_prefix model_scan
# garak writes reports to ~\.local\share\garak\garak_runs\ - copy them into evidence/garak/
