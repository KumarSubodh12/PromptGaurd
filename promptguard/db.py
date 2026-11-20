"""SQLite storage for scan history, reports and settings."""
from __future__ import annotations

import json
import secrets
import sqlite3
from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .config import CATEGORIES, DB_PATH, METHODS, risk_band

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY, created_at TEXT NOT NULL, name TEXT, source TEXT, kind TEXT,
    risk_score INTEGER, content_score INTEGER, category TEXT, n_findings INTEGER, confidence REAL,
    status TEXT, profile TEXT, custom_caps TEXT, chars INTEGER, text TEXT, result TEXT
);
CREATE INDEX IF NOT EXISTS scans_created ON scans(created_at);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
"""
DEFAULT_SETTINGS = {"store_text": True, "default_profile": "unknown"}


class Database:
    def __init__(self, path: Path = DB_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.conn() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def conn(self):
        c = sqlite3.connect(self.path)
        c.row_factory = sqlite3.Row
        try:
            yield c
            c.commit()
        finally:
            c.close()

    # ---------------------------------------------------------------- settings
    def get_settings(self) -> dict:
        out = dict(DEFAULT_SETTINGS)
        with self.conn() as c:
            for r in c.execute("SELECT key, value FROM settings"):
                out[r["key"]] = json.loads(r["value"])
        return out

    def set_settings(self, values: dict) -> dict:
        with self.conn() as c:
            for k, v in values.items():
                if k in DEFAULT_SETTINGS:
                    c.execute("INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                              (k, json.dumps(v)))
        return self.get_settings()

    # ---------------------------------------------------------------- scans
    def save_scan(self, result: dict, text: str, *, source: str, kind: str, profile: str, custom_caps: list[str]) -> str:
        sid = secrets.token_hex(6)
        store = self.get_settings()["store_text"]
        with self.conn() as c:
            c.execute(
                "INSERT INTO scans(id, created_at, name, source, kind, risk_score, content_score, category, n_findings, confidence,"
                " status, profile, custom_caps, chars, text, result) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (sid, datetime.now(timezone.utc).isoformat(timespec="seconds"), result["name"], source, kind,
                 result["risk"]["score"], result["content_threat"]["score"], result["risk"]["category"],
                 result["stats"]["visible_findings"], result["confidence"], "completed", profile,
                 json.dumps(custom_caps), len(text), text if store else None, json.dumps(result)))
        return sid

    def get_scan(self, sid: str) -> dict | None:
        with self.conn() as c:
            r = c.execute("SELECT * FROM scans WHERE id = ?", (sid,)).fetchone()
        if not r:
            return None
        d = dict(r)
        d["result"] = json.loads(d["result"])
        d["custom_caps"] = json.loads(d["custom_caps"] or "[]")
        d["text_stored"] = d["text"] is not None
        return d

    def list_scans(self, q: str = "", limit: int = 200, offset: int = 0) -> list[dict]:
        sql = ("SELECT id, created_at, name, source, kind, risk_score, content_score, category, n_findings, confidence, status, profile, chars "
               "FROM scans")
        args: list = []
        if q:
            sql += " WHERE name LIKE ?"
            args.append(f"%{q}%")
        sql += " ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?"
        args += [limit, offset]
        with self.conn() as c:
            return [dict(r) for r in c.execute(sql, args)]

    def delete_scan(self, sid: str) -> bool:
        with self.conn() as c:
            return c.execute("DELETE FROM scans WHERE id = ?", (sid,)).rowcount > 0

    def delete_all(self) -> int:
        with self.conn() as c:
            n = c.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            c.execute("DELETE FROM scans")
        return n

    # ---------------------------------------------------------------- statistics
    def stats(self) -> dict:
        """Everything on the dashboard is computed from real scans."""
        with self.conn() as c:
            rows = [dict(r) for r in c.execute(
                "SELECT id, created_at, name, risk_score, category, n_findings, confidence, status, result FROM scans "
                "ORDER BY created_at DESC, rowid DESC")]
        total = len(rows)
        suspicious = sum(1 for r in rows if r["risk_score"] >= 30)
        high = 0
        conf, cats, methods = [], Counter(), Counter()
        bands = Counter()
        by_day: dict[str, list[int]] = defaultdict(list)
        for r in rows:
            res = json.loads(r["result"])
            bands[r["category"]] += 1
            for f in res["findings"]:
                if f["discounted"]:
                    continue
                cats[f["category"]] += 1
                methods[f["method"]] += 1
                if f["band"] in ("High", "Critical"):
                    high += 1
            if r["n_findings"]:
                conf.append(r["confidence"])
            by_day[r["created_at"][:10]].append(r["risk_score"])
        today = datetime.now(timezone.utc).date()
        trend = []
        for k in range(29, -1, -1):
            day = (today - timedelta(days=k)).isoformat()
            vals = by_day.get(day, [])
            trend.append({"date": day, "scans": len(vals), "avg_score": round(sum(vals) / len(vals), 1) if vals else None})
        return {
            "total_scans": total,
            "suspicious_documents": suspicious,
            "high_risk_findings": high,
            "avg_confidence": round(sum(conf) / len(conf), 3) if conf else None,
            "benign_vs_suspicious": {"benign": total - suspicious, "suspicious": suspicious},
            "risk_distribution": {b: bands.get(b, 0) for b in ("Low", "Medium", "High", "Critical")},
            "categories": {CATEGORIES[k][0]: v for k, v in cats.items()},
            "category_keys": dict(cats),
            "methods": {METHODS.get(k, k): v for k, v in methods.items()},
            "trend": trend,
            "recent": [{k: r[k] for k in ("id", "created_at", "name", "risk_score", "category", "n_findings", "status")}
                       for r in rows[:8]],
        }
