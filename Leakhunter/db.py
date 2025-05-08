# db.py
import sqlite3, datetime, os
from config import DB_PATH

DDL = """
CREATE TABLE IF NOT EXISTS leaks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_url TEXT,
    keyword     TEXT,
    data_type   TEXT,
    match       TEXT,
    line        TEXT,
    ts          TEXT
);
"""

class LeakDB:
    def __init__(self, path: str = DB_PATH):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.execute(DDL)
        self.conn.commit()

    def insert(self, finding, source_url: str):
        self.conn.execute(
            "INSERT INTO leaks (source_url, keyword, data_type, match, line, ts) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (source_url, finding.keyword, finding.data_type,
             finding.match, finding.line, datetime.datetime.utcnow().isoformat())
        )
        self.conn.commit()

    def close(self):
        self.conn.close()
