"""
LeakHunter Async – OMN1 module
Version: 2025-05-08
"""

import argparse, asyncio, aiohttp, json, logging, os, re, sys, time
from pathlib import Path
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from rapidfuzz import fuzz

from detectors import classify_line, REGEX_PATTERNS
from exporter import display_table, export_csv, export_html
from config import (
    PASTE_SOURCES,
    TOR_PROXY,
    MAX_PASTES,
    REQUEST_TIMEOUT,
    DEFAULT_KEYWORDS,
)

# ───────────────────────────── logging ─────────────────────────────
LOG = logging.getLogger("LeakHunterAsync")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[logging.FileHandler("leakhunter_async.log"), logging.StreamHandler()],
)

ua = UserAgent()

# ──────────────────────────── cache seen ───────────────────────────
CACHE_FILE = Path("cache_seen.json")
SEEN: set[str] = set(json.loads(CACHE_FILE.read_text())) if CACHE_FILE.exists() else set()


def save_cache() -> None:
    CACHE_FILE.write_text(json.dumps(list(SEEN)))


# ───────────────────── aiohttp helpers / headers ───────────────────
def make_headers() -> dict:
    return {"User-Agent": ua.random}


def make_connector(use_tor: bool):
    proxy = TOR_PROXY["http"] if (use_tor and TOR_PROXY) else None
    return aiohttp.TCPConnector(ssl=False), proxy


# ─────────────────────── fetch list of links (sync) ────────────────
def fetch_html_links(url: str, selector: str, use_tor: bool) -> list[str]:
    try:
        html = requests.get(
            url,
            proxies=TOR_PROXY if use_tor else None,
            headers=make_headers(),
            timeout=REQUEST_TIMEOUT,
        ).text
        soup = BeautifulSoup(html, "html.parser")
        return [urljoin(url, a["href"]) for a in soup.select(selector)][:MAX_PASTES]
    except Exception as exc:
        LOG.warning("%s parse error: %s", url, exc)
        return []


# ───────────────────── source-specific generators ──────────────────
def gen_pastebin(url: str, use_tor: bool):
    for link in fetch_html_links(url, "table a", use_tor):
        if "/archive/" in link:
            continue
        yield link, link.replace("pastebin.com/", "pastebin.com/raw/")


def gen_ghostbin(url: str, use_tor: bool):
    for link in fetch_html_links(url, "table.archive-list a.title", use_tor):
        yield link, urljoin(link, "raw")


def gen_rss(url: str, use_tor: bool):
    import feedparser

    feed = feedparser.parse(
        requests.get(
            url,
            proxies=TOR_PROXY if use_tor else None,
            headers=make_headers(),
            timeout=REQUEST_TIMEOUT,
        ).text
    )
    for entry in feed.entries[:MAX_PASTES]:
        link = entry.link
        yield link, link if link.endswith("/raw") else link + "/raw"


GEN_MAP = {
    "pastebin": gen_pastebin,
    "ghostbin": gen_ghostbin,
    "throwbin": lambda u, t: ((l, l) for l in fetch_html_links(u, "table a", t)),
    "pasteee": lambda u, t: ((l, l.replace("/p/", "/r/")) for l in fetch_html_links(u, "a.card-link", t)),
    "dpaste": lambda *_: (),  # niestabilne API
    "rss": gen_rss,
    "rss_onion": gen_rss,
    "onionpb": gen_pastebin,
    "ghost_on": gen_ghostbin,
}

# ─────────────────────── fuzzy-matching helpers ────────────────────
ALIASES = {
    "password": ["pass", "passwd", "pwd"],
    "token": ["access_token", "auth_token", "bearer"],
}


def expand_keywords(base_kw: list[str]) -> list[str]:
    ks = set(base_kw)
    for kw in base_kw:
        ks.update(ALIASES.get(kw.lower(), []))
    return list(ks)


def fuzzy_hit(line: str, keywords: list[str], thresh: int = 80):
    lower = line.lower()
    for kw in keywords:
        if kw.lower() in lower or fuzz.partial_ratio(kw.lower(), lower) >= thresh:
            return kw
    return None


# ───────────────────────── async worker core ───────────────────────
SEM_LIMIT = 15  # równoległe zapytania


async def fetch_raw(session: aiohttp.ClientSession, url: str) -> str:
    try:
        async with session.get(url, timeout=REQUEST_TIMEOUT) as resp:
            return await resp.text()
    except Exception:
        return ""


async def worker(
    link: str,
    raw: str,
    session: aiohttp.ClientSession,
    keywords: list[str],
    rows: list[list],
    sem: asyncio.Semaphore,
):
    if link in SEEN:
        return
    async with sem:
        text = await fetch_raw(session, raw)
    if not text:
        return
    for line in text.splitlines():
        kw = fuzzy_hit(line, keywords)
        if kw or any(re.search(rx, line, flags=re.I) for rx in REGEX_PATTERNS.values()):
            for finding in classify_line(line, keywords):
                rows.append(
                    [
                        link,
                        finding.keyword or finding.data_type,
                        finding.data_type,
                        finding.match,
                        finding.line.strip(),
                        time.strftime("%Y-%m-%d %H:%M:%S"),
                    ]
                )
                LOG.info("[MATCH] %-6s %-30s %s", finding.data_type, finding.match[:30], link)
                SEEN.add(link)
                break


async def run_async(keywords: list[str], use_tor: bool = False) -> list[list]:
    conn, _proxy = make_connector(use_tor)
    rows: list[list] = []
    async with aiohttp.ClientSession(connector=conn, headers=make_headers()) as session:
        sem = asyncio.Semaphore(SEM_LIMIT)
        tasks = []
        for src_url, stype, tor_only in PASTE_SOURCES:
            if tor_only and not use_tor:
                continue
            gen = GEN_MAP.get(stype)
            if not gen:
                continue
            for link, raw in gen(src_url, use_tor):
                tasks.append(worker(link, raw, session, keywords, rows, sem))
        await asyncio.gather(*tasks, return_exceptions=True)
    save_cache()
    return rows


# ──────────────────────────── menu helpers ──────────────────────────
def ask_tor() -> bool:
    ans = input("Używać TOR? [y/N]: ").lower().startswith("y")
    if ans and not TOR_PROXY:
        print("⚠  TOR_PROXY nie skonfigurowano – przełączam na No-TOR.")
        return False
    return ans


def run_scan(keywords: list[str]):
    use_tor = ask_tor()
    print("⏳ Skanuję…")
    rows = asyncio.run(run_async(expand_keywords(keywords), use_tor))
    if rows:
        display_table(rows)
        export_csv(rows, "last_scan.csv")
        print("\n📄  Wyniki ➜ exports/last_scan.csv")
    else:
        print("Brak dopasowań.")
    input("\n⏎  ENTER, aby wrócić do menu…")


def monitor(keywords: list[str], interval: int):
    use_tor = ask_tor()
    print("⏲  Monitoring – Ctrl+C, aby przerwać.")
    try:
        while True:
            print(f"\n▶ {time.strftime('%H:%M:%S')} – skan…")
            rows = asyncio.run(run_async(expand_keywords(keywords), use_tor))
            if rows:
                display_table(rows)
                filename = f"monitor_{int(time.time())}.html"
                export_html(rows, filename)
                print(f"💾 HTML ➜ exports/{filename}")
            else:
                print("Brak dopasowań.")
            time.sleep(interval * 60)
    except KeyboardInterrupt:
        print("\nMonitoring przerwany.")
        time.sleep(1)


def show_menu():
    while True:
        os.system("cls" if os.name == "nt" else "clear")
        print(r"""
     _                _    _                 _            
    | |              | |  | |               | |           
    | |     ___  __ _| | _| |__  _   _ _ __ | |_ ___ _ __ 
    | |    / _ \/ _` | |/ / '_ \| | | | '_ \| __/ _ \ '__|
    | |___|  __/ (_| |   <| | | | |_| | | | | ||  __/ |   
    |______\___|\__,_|_|\_\_| |_|\__,_|_| |_|\__\___|_|   
                                                        (OMN1)
        """)
        print("1) Quick Scan – domyślne słowa kluczowe")
        print("2) Custom Scan – własne słowa kluczowe")
        print("3) Continuous Monitor – co X minut")
        print("4) Exit")
        choice = input("\nWybierz 1-4: ").strip()
        if choice == "1":
            run_scan(DEFAULT_KEYWORDS)
        elif choice == "2":
            kw = input("Frazy (przecinki): ")
            run_scan([k.strip() for k in kw.split(",") if k.strip()])
        elif choice == "3":
            kw = input("Frazy (przecinki): ")
            mins = int(input("Interwał w minutach: "))
            monitor([k.strip() for k in kw.split(",") if k.strip()], mins)
        elif choice == "4":
            sys.exit(0)


# ───────────────────────────── entry-point ─────────────────────────
if __name__ == "__main__":
    if len(sys.argv) > 1:
        # tryb „stary” – flagami CLI
        parser = argparse.ArgumentParser()
        parser.add_argument("-k", "--keywords", nargs="+", default=DEFAULT_KEYWORDS)
        parser.add_argument("--no-tor", action="store_true")
        parser.add_argument("--watch", type=int, help="continuous mode (minutes)")
        args = parser.parse_args()
        if args.watch:
            monitor(args.keywords, args.watch)
        else:
            run_scan(args.keywords if args.keywords else DEFAULT_KEYWORDS)
    else:
        # brak argumentów -> interaktywne menu 1/2/3/4
        show_menu()
