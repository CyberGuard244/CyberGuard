import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cyberguard.db')


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS analyses (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_type TEXT NOT NULL,
            content     TEXT NOT NULL,
            risk_level  TEXT NOT NULL,
            indicators  TEXT,
            ai_explanation TEXT,
            created_at  TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


def save_analysis(analysis_type, content, risk_level, indicators, ai_explanation):
    conn = get_connection()
    conn.execute(
        '''INSERT INTO analyses
           (analysis_type, content, risk_level, indicators, ai_explanation, created_at)
           VALUES (?, ?, ?, ?, ?, ?)''',
        (analysis_type, content, risk_level, str(indicators), ai_explanation,
         datetime.now().isoformat())
    )
    conn.commit()
    conn.close()


def get_all_analyses(limit=50):
    conn = get_connection()
    rows = conn.execute(
        'SELECT * FROM analyses ORDER BY created_at DESC LIMIT ?', (limit,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def clear_all_analyses():
    conn = get_connection()
    conn.execute('DELETE FROM analyses')
    conn.commit()
    conn.close()
