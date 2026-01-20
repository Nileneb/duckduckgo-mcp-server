from __future__ import annotations

import aiosqlite
from pathlib import Path
from typing import Dict, List, Optional


RULE_KINDS = ("allow_domain", "deny_domain", "allow_pattern", "deny_pattern")


class PolicyStore:
    """
    SQLite-backed store for allow/deny rules + settings.
    """

    def __init__(self, db_path: Path):
        self.db_path = db_path

    async def init(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("PRAGMA journal_mode=WAL;")
            await db.execute("PRAGMA synchronous=NORMAL;")
            await db.execute("PRAGMA busy_timeout=5000;")
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    kind TEXT NOT NULL,
                    value TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                    UNIQUE(kind, value)
                );
                """
            )
            await db.execute("CREATE INDEX IF NOT EXISTS idx_rules_kind ON rules(kind);")
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            await db.commit()

    async def list_rules(self, kind: str) -> List[str]:
        if kind not in RULE_KINDS:
            return []
        async with aiosqlite.connect(self.db_path) as db:
            cur = await db.execute("SELECT value FROM rules WHERE kind=? ORDER BY value ASC;", (kind,))
            rows = await cur.fetchall()
            return [r[0] for r in rows]

    async def add_rule(self, kind: str, value: str) -> bool:
        if kind not in RULE_KINDS:
            return False
        value = value.strip()
        if not value:
            return False
        async with aiosqlite.connect(self.db_path) as db:
            try:
                await db.execute("INSERT OR IGNORE INTO rules(kind, value) VALUES(?, ?);", (kind, value))
                await db.commit()
                # if it already existed, changes() will be 0
                cur = await db.execute("SELECT changes();")
                row = await cur.fetchone()
                changed = row[0] if row else 0
                return changed == 1
            except Exception:
                return False

    async def remove_rule(self, kind: str, value: str) -> bool:
        if kind not in RULE_KINDS:
            return False
        value = value.strip()
        if not value:
            return False
        async with aiosqlite.connect(self.db_path) as db:
            cur = await db.execute("DELETE FROM rules WHERE kind=? AND value=?;", (kind, value))
            await db.commit()
            return cur.rowcount > 0

    async def get_setting(self, key: str) -> Optional[str]:
        async with aiosqlite.connect(self.db_path) as db:
            cur = await db.execute("SELECT value FROM settings WHERE key=?;", (key,))
            row = await cur.fetchone()
            if row is None:
                return None
            return row[0]

    async def set_setting(self, key: str, value: str) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO settings(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value;",
                (key, value),
            )
            await db.commit()

    async def get_all_settings(self) -> Dict[str, str]:
        async with aiosqlite.connect(self.db_path) as db:
            cur = await db.execute("SELECT key, value FROM settings;")
            rows = await cur.fetchall()
            return {k: v for (k, v) in rows}
