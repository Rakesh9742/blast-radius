#!/bin/bash
# Mix the narration clips onto the screen recording at their recorded start times and export an MP4.
set -e
OUT=${OUT:-/tmp/demo}; DEST=${DEST:-$HOME/Desktop/blast-radius-demo.mp4}
cd "$OUT"
python3 - <<'PY'
import json, shlex
d = json.load(open("timeline.json"))
inputs = ["-i", "raw.webm"]; filters = []; labels = []
for i, c in enumerate(d["timeline"], start=1):
    inputs += ["-i", f"{c['key']}.aiff"]
    filters.append(f"[{i}:a]aformat=sample_rates=44100:channel_layouts=stereo,adelay={c['startMs']}|{c['startMs']}[a{i}]")
    labels.append(f"[a{i}]")
n = len(labels)
filters.append("".join(labels) + f"amix=inputs={n}:normalize=0:dropout_transition=0,volume=1.0[aout]")
open("ffmpeg_args.txt", "w").write(" ".join(shlex.quote(x) for x in inputs) + "\n" + ";".join(filters) + "\n")
print("clips:", n, "| video ms:", d["totalMs"])
PY
INPUTS=$(sed -n 1p ffmpeg_args.txt); FILTER=$(sed -n 2p ffmpeg_args.txt)
# Chrome's screencast is written at a nominal 25 fps regardless of the real capture rate: rescale video time to the wall clock
RAW_S=$(ffprobe -v error -select_streams v -show_entries packet=pts_time -of csv=p=0 raw.webm | tail -1)
WALL_S=$(python3 -c "import json; print(json.load(open('timeline.json'))['totalMs']/1000)")
F=$(python3 -c "print(round($WALL_S/$RAW_S, 6))"); echo "video time factor: $F (raw ${RAW_S}s -> wall ${WALL_S}s)"
FILTER="[0:v]setpts=PTS*$F[vout];$FILTER"
eval ffmpeg -v error -y $INPUTS -filter_complex "'$FILTER'" -map "'[vout]'" -map "'[aout]'" -c:v libx264 -preset medium -crf 20 -pix_fmt yuv420p -r 25 -c:a aac -b:a 160k -movflags +faststart "$DEST"
ffprobe -v error -show_entries format=duration:stream=codec_name,width,height -of default=nw=1 "$DEST"
ls -la "$DEST" | awk '{print $5/1048576 " MB"}'
