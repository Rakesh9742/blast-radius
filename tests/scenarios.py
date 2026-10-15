"""Scenario harness: runs the agent on the demo prompts and checks the answer against graph-derived expectations.
usage: .venv/bin/python -m tests.scenarios [name ...]   (needs ANTHROPIC_API_KEY)"""
from __future__ import annotations
import json, re, subprocess, sys, time, pathlib
from dotenv import load_dotenv
load_dotenv()
from agent.loop import Agent

REPO = "data/repos/mealie"
SCENARIOS = {
    "pillow": {
        "prompt": "Pillow (PIL) has new vulnerabilities in our lockfile. Which of our HTTP endpoints are actually exposed through image handling, who owns that code, and apply the fix.",
        "must_mention": ["/api/recipes/{slug}/image", "minify", "12.", "Hayden"],
        "tools_expected": {"reachability", "who_owns", "plan_fix", "verify_fix", "apply_dependency_fix"},
        "verdict": "EXPLOITABLE",
    },
    "multipart": {
        "prompt": "python-multipart has a denial-of-service vulnerability. Which endpoints accept uploads or forms and are therefore exposed? Who owns them?",
        "must_mention": ["/api/", "python-multipart"],
        "tools_expected": {"reachability", "who_owns"},
        "verdict": None,
    },
    "pyjwt": {
        "prompt": "Is the pyjwt vulnerability reachable in our authentication flow? Show the path from the login endpoints to the jwt calls and tell me the owners.",
        "must_mention": ["/api/auth", "jwt"],
        "tools_expected": {"reachability"},
        "verdict": None,
    },
    "starlette": {
        "prompt": "We do not import starlette directly. Are the starlette vulnerabilities still a problem for us? Explain the dependency chain.",
        "must_mention": ["fastapi", "starlette"],
        "tools_expected": {"transitive_exposure"},
        "verdict": None,
    },
}


def reset_repo():
    subprocess.run(["git", "-C", REPO, "checkout", "-q", "--", "."], check=False)
    subprocess.run(["git", "-C", REPO, "checkout", "-q", "v3.0.0"], check=False)
    out = subprocess.run(["git", "-C", REPO, "branch", "--list", "blast-radius/*"], capture_output=True, text=True).stdout.split()
    for b in out:
        subprocess.run(["git", "-C", REPO, "branch", "-q", "-D", b], check=False)


def main():
    names = sys.argv[1:] or list(SCENARIOS)
    results = []
    for name in names:
        sc = SCENARIOS[name]
        reset_repo()
        calls = []
        agent = Agent("mealie", REPO, on_event=lambda e: calls.append(e["name"]) if e["type"] == "tool_call" else None)
        t0 = time.time()
        out = agent.run(sc["prompt"])
        agent.close()
        ans = out["answer"]
        missing = [m for m in sc["must_mention"] if m.lower() not in ans.lower()]
        missing_tools = sc["tools_expected"] - set(calls)
        verdict_ok = sc["verdict"] is None or sc["verdict"] in ans.upper()
        ok = not missing and not missing_tools and verdict_ok
        results.append({"scenario": name, "ok": ok, "missing_text": missing, "missing_tools": sorted(missing_tools), "verdict_ok": verdict_ok,
                        "tool_calls": calls, "cypher_steps": len(out["trace"]), "seconds": round(time.time() - t0, 1), "usage": out["usage"]})
        pathlib.Path("data/reports").mkdir(exist_ok=True, parents=True)
        pathlib.Path(f"data/reports/scenario-{name}.md").write_text(f"# {name}\n\n> {sc['prompt']}\n\n{ans}\n\n---\ntools: {calls}\n")
        print(f"{'PASS' if ok else 'FAIL'} {name:<10} {results[-1]['seconds']}s  tools={len(calls)} cypher={len(out['trace'])} "
              f"in={out['usage']['input']} out={out['usage']['output']}" + (f"  missing={missing} {sorted(missing_tools)}" if not ok else ""), flush=True)
    reset_repo()
    print(json.dumps(results, indent=1))
    sys.exit(0 if all(r["ok"] for r in results) else 1)


if __name__ == "__main__":
    main()
