import sqlite3
import json
from datetime import datetime
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'cyberguard.db')


class Database:
    def init(self):
        with self._connect() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS analyses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    indicators TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    summary TEXT,
                    created_at TEXT NOT NULL
                )
            ''')

    def _connect(self):
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

    def save(self, analysis_type, target, indicators, risk_level, summary=''):
        with self._connect() as conn:
            cursor = conn.execute(
                'INSERT INTO analyses (type, target, indicators, risk_level, summary, created_at) VALUES (?, ?, ?, ?, ?, ?)',
                (analysis_type, target, json.dumps(indicators), risk_level, summary, datetime.now().isoformat())
            )
            return cursor.lastrowid

    def get_all(self):
        with self._connect() as conn:
            rows = conn.execute('SELECT * FROM analyses ORDER BY created_at DESC').fetchall()
            return [self._row_to_dict(r) for r in rows]

    def get_recent(self, limit=5):
        with self._connect() as conn:
            rows = conn.execute(
                'SELECT * FROM analyses ORDER BY created_at DESC LIMIT ?', (limit,)
            ).fetchall()
            return [self._row_to_dict(r) for r in rows]

    def get_stats(self):
        with self._connect() as conn:
            total = conn.execute('SELECT COUNT(*) FROM analyses').fetchone()[0]
            high_risk = conn.execute(
                "SELECT COUNT(*) FROM analyses WHERE risk_level = 'alto'"
            ).fetchone()[0]
            by_type = conn.execute(
                'SELECT type, COUNT(*) as count FROM analyses GROUP BY type'
            ).fetchall()
            return {
                'total': total,
                'high_risk': high_risk,
                'by_type': {row['type']: row['count'] for row in by_type}
            }

    def clear(self):
        with self._connect() as conn:
            conn.execute('DELETE FROM analyses')

    def _row_to_dict(self, row):
        d = dict(row)
        d['indicators'] = json.loads(d['indicators'])
        return d
