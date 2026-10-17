# Re-rendering the demo video

The demo video is produced automatically: a browser driver performs the demo on the local console, shows each narration line as a caption while macOS text-to-speech reads it, records the screen, and ffmpeg mixes the speech onto the recording. Scenes and narration are listed in `docs/demo-scenes.md` and defined in `scripts/demo/record.js`.

Requirements: macOS (for the `say` voice), Google Chrome, ffmpeg (`brew install ffmpeg`), Node 18+, the console running on http://localhost:8000 with the `mealie` graph selected and the fork configured in `.env` (`GITHUB_TOKEN`, `GITHUB_REPO`).

```bash
make reset-repo && make forget-decisions && make restart      # clean starting state
cd scripts/demo && npm install
OUT=/tmp/demo node record.js                                  # ~4 minutes, runs one real agent scenario
OUT=/tmp/demo DEST=$HOME/Desktop/blast-radius-demo.mp4 ./assemble.sh
```

`OUT/timeline.json` records when each narration clip started; `assemble.sh` delays each clip to that time and mixes them. Change `VOICE` or `RATE` in the environment to use another voice or speed.
