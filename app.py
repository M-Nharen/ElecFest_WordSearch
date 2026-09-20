"""
Tech Events Word Search - Flask backend (Vercel-ready)

Server-only secrets: the answer key (where each word is) and SECRET_KEY.
The browser gets the letters, the number of words, and a yes/no per selection.

Vercel functions are stateless, so progress travels in an HMAC-signed token
that the browser sends back with each /api/verify call.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import secrets

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# Set SECRET_KEY in Vercel -> Project -> Settings -> Environment Variables.
_secret = os.environ.get("SECRET_KEY")
if not _secret:
    _secret = "dev-only-secret-change-me"
    print("WARNING: SECRET_KEY is not set. Using an insecure development key.")
SECRET = _secret.encode()

# --------------------------------------------------------------------------
# Hardcoded 18x18 grid. (row, col), zero-based, top-left is (0, 0).
# 18 is the smallest size that fits "Reverse engineering" (18 letters).
# --------------------------------------------------------------------------
GRID = [
    "ZHVERILOGWARSEBALT",
    "REVERSEENGINEERING",
    "UXXDJKPAJORYTXBIYM",
    "TWPCBWORKSHOPEPHAC",
    "VVKDAOZESQSYMPQKNE",
    "KIITNUAWIREVBIBEAF",
    "FDOUHQWBGHHWOCICLS",
    "HTZZTWLINVNIQYAEOB",
    "MNFDQXCHADDAFYHDGG",
    "AQVOOJRULMGVYGXZCN",
    "NQASSBNQQSFDVZPLHA",
    "QDTLJWLJUAVNDDJGAY",
    "VIAZOBNUEPOGSTCALJ",
    "AOLJXCHYSPGDSLMWLO",
    "EHYLMDIDTDCTKUMGEW",
    "DATVPYBXWPJLOEZLNI",
    "ELECKARTPQPXXZNPGV",
    "JMHFPTIRNWVWCSXSED",
]
SIZE = len(GRID)

# Secret answer key (label is only used for the startup self-check).
ANSWER_KEY = [
    {"label": "Eleckart",            "start": (16, 0), "end": (16, 7)},
    {"label": "Signal quest",        "start": (4, 8),  "end": (14, 8)},
    {"label": "Reverse engineering", "start": (1, 0),  "end": (1, 17)},
    {"label": "Analog challenge",    "start": (3, 16), "end": (17, 16)},
    {"label": "Verilog wars",        "start": (0, 2),  "end": (0, 12)},
    {"label": "IOH",                 "start": (12, 1), "end": (14, 1)},
    {"label": "PCB workshop",        "start": (3, 2),  "end": (3, 12)},
]
TOTAL = len(ANSWER_KEY)


def _line_cells(start, end):
    """Every (row, col) from start to end, or None if not a straight line."""
    dr, dc = end[0] - start[0], end[1] - start[1]
    if not (dr == 0 or dc == 0 or abs(dr) == abs(dc)):
        return None
    steps = max(abs(dr), abs(dc))
    sr = (dr > 0) - (dr < 0)
    sc = (dc > 0) - (dc < 0)
    return [(start[0] + sr * i, start[1] + sc * i) for i in range(steps + 1)]


def _self_check():
    """Fail at startup if the key and grid ever drift apart."""
    for entry in ANSWER_KEY:
        cells = _line_cells(entry["start"], entry["end"])
        spelled = "".join(GRID[r][c] for r, c in cells)
        expected = "".join(ch for ch in entry["label"].upper() if ch.isalpha())
        assert spelled == expected, f"{entry['label']}: grid spells {spelled}"


_self_check()


# --------------------------------------------------------------------------
# Signed tokens and per-progress codes
# --------------------------------------------------------------------------
def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _sign(message: str) -> str:
    return _b64(hmac.new(SECRET, message.encode(), hashlib.sha256).digest()[:16])


def make_token(found: set, nonce: str) -> str:
    body = _b64(json.dumps({"f": sorted(found), "n": nonce}).encode())
    return f"{body}.{_sign(body)}"


def read_token(token):
    """Return (found_ids, nonce). Invalid or tampered tokens count as fresh."""
    try:
        body, sig = token.split(".", 1)
        if not hmac.compare_digest(sig, _sign(body)):
            return set(), None
        data = json.loads(_unb64(body))
        found = {i for i in data["f"] if isinstance(i, int) and 0 <= i < TOTAL}
        return found, str(data["n"])
    except Exception:
        return set(), None


def make_code(count: int, nonce: str) -> str:
    """A different code for every count, e.g. TE3-1B1CA8-9F2C41AA (3 words found)."""
    sig = hmac.new(SECRET, f"code:{count}:{nonce}".encode(), hashlib.sha256).hexdigest()[:8]
    return f"TE{count}-{nonce}-{sig.upper()}"


_CODE_RE = re.compile(r"^TE([1-9]\d*)-([0-9A-F]{6})-([0-9A-F]{8})$")


def check_code(code: str):
    """Return the number of words the code represents, or None if it's not genuine."""
    m = _CODE_RE.match(code.strip().upper())
    if not m:
        return None
    count = int(m.group(1))
    if count > TOTAL:
        return None
    return count if hmac.compare_digest(make_code(count, m.group(2)), m.group(0)) else None


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _point(raw):
    """Parse {"r": int, "c": int} into a bounds-checked tuple, else None."""
    try:
        r, c = raw["r"], raw["c"]
        if isinstance(r, int) and isinstance(c, int) and 0 <= r < SIZE and 0 <= c < SIZE:
            return (r, c)
    except Exception:
        pass
    return None


def _match(start, end):
    """Index of the word this selection spells (either direction), else None."""
    for i, w in enumerate(ANSWER_KEY):
        if (start, end) == (w["start"], w["end"]) or (end, start) == (w["start"], w["end"]):
            return i
    return None


def _cells_json(word_id):
    w = ANSWER_KEY[word_id]
    return [list(cell) for cell in _line_cells(w["start"], w["end"])]


@app.after_request
def no_store(resp):
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/puzzle")
def puzzle():
    """Letters and word count only. Word names and positions are never sent."""
    return jsonify(size=SIZE, grid=GRID, total=TOTAL)


@app.post("/api/verify")
def verify():
    data = request.get_json(silent=True) or {}
    start, end = _point(data.get("start")), _point(data.get("end"))
    if not start or not end:
        return jsonify(error="start and end must be {r, c} within the grid"), 400

    found, nonce = read_token(data.get("token") or "")
    nonce = nonce or secrets.token_hex(3).upper()

    word_id = _match(start, end)
    if word_id is None:
        return jsonify(correct=False, found_count=len(found), total=TOTAL)

    already = word_id in found
    found.add(word_id)
    count = len(found)
    return jsonify(
        correct=True,
        already_found=already,
        word_id=word_id,
        cells=_cells_json(word_id),
        found_count=count,
        total=TOTAL,
        token=make_token(found, nonce),
        complete=count == TOTAL,
        code=make_code(count, nonce),
    )


@app.post("/api/restore")
def restore():
    """Lets a returning player pick up where they left off (token must be valid)."""
    data = request.get_json(silent=True) or {}
    found, nonce = read_token(data.get("token") or "")
    count = len(found)
    return jsonify(
        found=[{"word_id": i, "cells": _cells_json(i)} for i in sorted(found)],
        found_count=count,
        total=TOTAL,
        complete=count == TOTAL,
        code=make_code(count, nonce) if count and nonce else None,
    )


@app.post("/api/check-code")
def check_code_route():
    """For organizers: is this code genuine, and how many words does it stand for?"""
    data = request.get_json(silent=True) or {}
    count = check_code(str(data.get("code", "")))
    return jsonify(valid=count is not None, words_found=count)


if __name__ == "__main__":
    app.run(port=5000)