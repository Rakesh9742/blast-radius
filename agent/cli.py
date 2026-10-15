"""Terminal runner: python -m agent.cli "Is CVE-2025-48379 (pillow) reachable? Fix it."  """
import argparse, json, sys
from dotenv import load_dotenv
load_dotenv()
from agent.loop import Agent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("prompt", nargs="+")
    ap.add_argument("--graph", default="mealie")
    ap.add_argument("--repo", default="data/repos/mealie")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    def on_event(e):
        if a.json: return
        if e["type"] == "tool_call": print(f"\n> {e['name']}({json.dumps(e['input'])[:160]})", flush=True)
        elif e["type"] == "tool_result":
            for s in e["steps"]: print(f"    [{s['type']}] {s['label']}: {s['rows']} rows, {s['ms']} ms", flush=True)
        elif e["type"] == "thinking": print(f"  ~ {e['text'][:200].strip()}", flush=True)

    out = Agent(a.graph, a.repo, on_event).run(" ".join(a.prompt))
    if a.json: print(json.dumps(out, indent=2, default=str))
    else:
        print("\n" + "=" * 80 + "\n" + out["answer"]); print(f"\n[{out['model']}] tokens in={out['usage']['input']} out={out['usage']['output']}, cypher steps={len(out['trace'])}")


if __name__ == "__main__":
    main()
