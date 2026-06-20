#!/usr/bin/env python3
"""
TikTok MP4 Patcher — Self-hosted VPS tool
Web frontend for patcher_core.
"""

import uuid, threading, queue, os, time
from pathlib import Path
from flask import (
    Flask, request, render_template, jsonify,
    send_from_directory, Response, stream_with_context
)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500 MB

AUTH_TOKEN = os.environ.get("PATCHER_AUTH_TOKEN", "")

BASE_DIR   = Path(__file__).parent
UPLOAD_DIR = BASE_DIR / "uploads"
OUTPUT_DIR = BASE_DIR / "outputs"
UPLOAD_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

JOB_TTL = 24 * 3600  # 24 hours

_job_logs:   dict[str, queue.Queue] = {}
_job_status: dict[str, str]         = {}
_job_output: dict[str, str]         = {}
_job_created: dict[str, float]      = {}


def require_auth():
    if not AUTH_TOKEN:
        return None
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    if token != AUTH_TOKEN:
        return jsonify({"error": "Unauthorized"}), 401
    return None


def run_job(job_id: str, src: Path, original_name: str, comment: str):
    log = _job_logs[job_id]
    _job_status[job_id] = "running"

    stem     = Path(original_name).stem
    out_name = f"{stem}_patched.mp4"
    out_path = OUTPUT_DIR / f"{job_id}_{out_name}"

    try:
        log.put(f"[JOB]  {job_id[:8]}... started")
        log.put(f"[JOB]  input: {original_name}  ({src.stat().st_size:,} bytes)")

        from patcher_core import patch_all

        def log_func(msg):
            log.put(msg)

        success = patch_all(src, out_path, comment=comment, log_func=log_func, method='balanced-sync')

        if success:
            _job_output[job_id] = f"{job_id}_{out_name}"
            _job_status[job_id] = "done"
        else:
            _job_status[job_id] = "error"

    except Exception as exc:
        log.put(f"[ERROR] {exc}")
        _job_status[job_id] = "error"
    finally:
        try: src.unlink(missing_ok=True)
        except: pass
        log.put(None)


def _cleanup_jobs():
    now = time.time()
    expired = [jid for jid, t in _job_created.items() if now - t > JOB_TTL]
    for jid in expired:
        _job_logs.pop(jid, None)
        _job_status.pop(jid, None)
        out_name = _job_output.pop(jid, None)
        _job_created.pop(jid, None)
        if out_name:
            try: (OUTPUT_DIR / out_name).unlink(missing_ok=True)
            except: pass


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/")
def index(): return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():
    resp = require_auth()
    if resp:
        return resp

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    f = request.files["file"]
    if not f.filename.lower().endswith(".mp4"):
        return jsonify({"error": "Only .mp4 files accepted"}), 400

    comment = request.form.get("comment", "")
    job_id  = str(uuid.uuid4())
    dest    = UPLOAD_DIR / f"{job_id}_input.mp4"
    f.save(dest)

    _cleanup_jobs()
    _job_logs[job_id] = queue.Queue()
    _job_created[job_id] = time.time()
    threading.Thread(target=run_job, args=(job_id, dest, f.filename, comment), daemon=True).start()
    return jsonify({"job_id": job_id})


@app.route("/stream/<job_id>")
def stream(job_id: str):
    def generate():
        q = _job_logs.get(job_id)
        if q is None: yield "data: [ERROR] Unknown job\n\n"; return
        while True:
            try: line = q.get(timeout=60)
            except queue.Empty: yield ": keepalive\n\n"; continue
            if line is None:
                status = _job_status.get(job_id, "error")
                out    = _job_output.get(job_id, "")
                yield f"data: __STATUS__{status}|{out}\n\n"; return
            yield f"data: {line}\n\n"
    return Response(stream_with_context(generate()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/download/<filename>")
def download(filename: str):
    if filename not in set(_job_output.values()): return "Not found", 404
    return send_from_directory(OUTPUT_DIR, filename, as_attachment=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
