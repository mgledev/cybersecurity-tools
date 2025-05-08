# config.py
from pathlib import Path

DEFAULT_KEYWORDS = ["password", "apikey", "secret", "token"]

# ← ustaw None, jeśli wolisz działać przez VPN zamiast TOR-a
TOR_PROXY = {
    "http":  "socks5h://127.0.0.1:9150",
    "https": "socks5h://127.0.0.1:9150",
}

# (url, typ_parsera, wymaga_tor?)
PASTE_SOURCES = [
    ("https://pastebin.com/archive",          "pastebin",  False),
    ("https://controlc.com/feeds/recent",     "rss",       False),
    ("https://ghostbin.com/archive",          "ghostbin",  False),
    ("https://throwbin.io/recent",            "throwbin",  False),
    ("https://paste.ee/latest",               "pasteee",   False),
    ("https://dpaste.org/api/drafts/",        "dpaste",    False),
    # — dark-web — wymaga TOR
    ("http://pastej7szrq5m7fi4.onion",        "onionpb",   True),
    ("http://controlc3xh6phtkw.onion/rss",    "rss_onion", True),
    ("http://ghostbin6ajz3lyq.onion/archive", "ghost_on",  True),
]

DB_PATH     = "leakhunter.db"
EXPORT_DIR  = Path("exports")
EXPORT_DIR.mkdir(exist_ok=True)
MAX_PASTES  = 200
REQUEST_TIMEOUT = 12
