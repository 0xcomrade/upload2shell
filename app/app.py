#!/usr/bin/env python3
"""
GhostView thumbnail service - intentionally vulnerable lab application.

This small Flask app mimics a very common production pattern:
a web application accepts an image upload and generates a thumbnail with
Pillow. When the uploaded bytes are actually PostScript/EPS content
(regardless of the file extension), Pillow hands them to the system
Ghostscript binary with -dSAFER. On Ghostscript < 10.08.0 that interpreter
is vulnerable to CVE-2026-125396 ("Upload2Shell"), so a crafted upload
escapes the sandbox and executes commands as this process's user.

!!! AUTHORIZED LAB USE ONLY !!!
Run this only inside the provided Docker lab or an isolated test network.
"""
import io
import os
import time
import uuid

from flask import Flask, request, jsonify, send_from_directory, render_template
from PIL import Image

UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "/app/uploads")
THUMB_DIR = os.path.join(UPLOAD_DIR, "thumbs")
os.makedirs(THUMB_DIR, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024


def safe_name(name: str) -> str:
    base = os.path.basename(name or "").strip() or "upload.bin"
    return "".join(c for c in base if c.isalnum() or c in "._-")[:80] or "upload.bin"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return jsonify(error="no file part"), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify(error="empty filename"), 400

    name = f"{uuid.uuid4().hex[:8]}_{safe_name(f.filename)}"
    path = os.path.join(UPLOAD_DIR, name)
    f.save(path)

    t0 = time.time()
    thumb_url = None
    error = None
    try:
        # The vulnerable step: Pillow sniffs the CONTENT (not the extension).
        # EPS/PostScript bytes dispatched here end up running `gs -dSAFER`.
        with Image.open(path) as im:
            im.load()                      # pixel decode -> Ghostscript for EPS
            im.thumbnail((160, 160))
            thumb_name = f"{os.path.splitext(name)[0]}.png"
            im.save(os.path.join(THUMB_DIR, thumb_name), "PNG")
            thumb_url = f"/uploads/thumbs/{thumb_name}"
    except Exception as exc:               # noqa: BLE001 - lab app: report all
        error = f"{type(exc).__name__}: {exc}"

    return jsonify(
        file=name,
        thumbnail=thumb_url,
        elapsed_ms=int((time.time() - t0) * 1000),
        error=error,
    )


@app.route("/uploads/<path:filename>")
def uploads(filename):
    return send_from_directory(UPLOAD_DIR, filename)


@app.route("/healthz")
def healthz():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
