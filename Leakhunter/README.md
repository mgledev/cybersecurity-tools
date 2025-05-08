# LeakHunter Async • OMN1 module

> Ultra-fast OSINT scanner for paste-sites (Pastebin, ControlC, paste.ee, *.onion).  
> **Python 3.10+ • asyncio + aiohttp • fuzzy matching • TOR/No-TOR switch • CSV/HTML export • interactive menu 1-2-3-4.**

---

## ✨ Features

| ⚡ | **Asynchronous** – 50-200 RAW fetches in ~3 s |
| 🛡 | **TOR / VPN toggle** |
| 🔍 | **Regex & fuzzy detection** – e-mails, hashes, JWT, AWS keys, tokens |
| 💾 | **CSV / HTML** report + SQLite history, zero duplikatów (cache) |
| 🔁 | **Continuous monitor** (`--watch`) |
| 🖥 | **Simple menu** 1 (quick) · 2 (custom) · 3 (monitor) · 4 (exit) |

---

## 🚀 Quick Start

```bash
git clone https://github.com/mgledev/leakhunter.git
cd leakhunter
python -m venv .venv && . .venv/Scripts/activate   # Windows
pip install -r requirements.txt

# uruchom menu
python leakhunter_async.py
