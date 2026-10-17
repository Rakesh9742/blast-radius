.PHONY: setup db ingest serve demo cli stop forget-decisions restart

PY=.venv/bin/python
REPO?=data/repos/mealie
GRAPH?=mealie

setup:            ## create venv + install deps
	python3 -m venv .venv && .venv/bin/pip install -q -r requirements.txt

db:               ## start FalkorDB (ports 6379 + browser 3000)
	docker compose up -d 2>/dev/null || docker start blast-radius-falkordb >/dev/null
	sleep 2 && docker exec blast-radius-falkordb redis-cli ping

clone:            ## clone the target repo at the analysed release
	@test -d $(REPO) || git clone -q --branch v3.0.0 https://github.com/mealie-recipes/mealie.git $(REPO)
	@cd $(REPO) && git fetch -q --unshallow 2>/dev/null || true

ingest: clone     ## build the code graph (parse + OSV + git blame + load)
	$(PY) -m ingest.run --repo $(REPO) --graph $(GRAPH) --source-dirs mealie --route-prefix /api --url https://github.com/mealie-recipes/mealie

serve:            ## run the web UI on http://localhost:8000
	.venv/bin/uvicorn server.app:app --port 8000

demo: setup db ingest serve   ## everything, one command

cli:              ## terminal agent: make cli Q="pillow: what is exposed?"
	$(PY) -m agent.cli "$(Q)"

stop:
	docker compose down

reset-repo:       ## put the analysed repo back to v3.0.0 and drop agent branches
	cd $(REPO) && git checkout -q -- . && git checkout -q v3.0.0 && (git branch --list 'blast-radius/*' | xargs -r git branch -q -D)

test:             ## parser unit test
	$(PY) -m tests.test_parse

scenarios:        ## run the agent on the demo scenarios and check expectations (needs ANTHROPIC_API_KEY)
	$(PY) -m tests.scenarios

forget-decisions: ## delete the agent's recorded triage decisions in the current demo graph
	$(PY) -c "import sys; sys.path.insert(0,'.'); from core.db import get_graph; get_graph('$(GRAPH)').query('MATCH (d:Decision) DETACH DELETE d'); print('decisions cleared')"

restart:          ## restart the web console on :8000
	-lsof -ti :8000 -sTCP:LISTEN | xargs kill 2>/dev/null; sleep 1
	nohup .venv/bin/uvicorn server.app:app --port 8000 > /tmp/blast-radius.log 2>&1 &
	@sleep 3 && curl -s http://localhost:8000/api/health | cut -c1-60 && echo
