#!/usr/bin/env python3
"""
DumpFerret v2 – Red/Blue Team IOC scanner with cracking, VT, HIBP, PDF and GUI
"""

import re, os, hashlib, shutil, tempfile, magic, subprocess, csv, json
from pathlib import Path
from typing import Dict, Set

from modules import hash_cracker, pdf_reporter, hash_identifier

IOC_REGEX = {
    "email": re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "ipv4":  re.compile(rb"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
    "url":   re.compile(rb"https?://[\w\-\.?\&=/%#]+"),
    "btc":   re.compile(rb"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
    "md5":   re.compile(rb"\b[a-fA-F0-9]{32}\b"),
    "sha1":  re.compile(rb"\b[a-fA-F0-9]{40}\b"),
    "sha256":re.compile(rb"\b[a-fA-F0-9]{64}\b"),
    "iban":  re.compile(rb"\b[A-Z]{2}[0-9]{2}[ ]?([0-9]{4}[ ]?){3,6}[0-9]{0,4}\b"),
    "cc":    re.compile(rb"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),
    "pesel": re.compile(rb"\b\d{11}\b")
}

class DumpFerret:
    def __init__(self, yara_path=None, use_bulk=False, keep_tmp=False):
        self.yara = None
        self.use_bulk = use_bulk
        self.keep_tmp = keep_tmp
        if yara_path:
            import yara
            self.yara = yara.compile(filepath=yara_path)

    def _sha256(self, fpath: Path) -> str:
        h = hashlib.sha256()
        with open(fpath, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    def _stream_scan(self, fpath: Path) -> Dict[str, Set[str]]:
        hits = {k: set() for k in IOC_REGEX}
        try:
            with open(fpath, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    for k, rx in IOC_REGEX.items():
                        hits[k].update(m.decode(errors="ignore") for m in rx.findall(chunk))
        except Exception as e:
            print(f"[!] Failed to read {fpath}: {e}")
        return hits

    def _bulk_extract(self, fpath: Path, outdir: Path):
        subprocess.run(["bulk_extractor", "-o", str(outdir), str(fpath)],
                       check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _write_csv(self, data: Dict[str, Set[str]], out: Path) -> Path:
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["type", "value"])
            for k, values in data.items():
                for v in values:
                    w.writerow([k, v])
        return out

    def scan(self, input_path: str) -> Dict[str, any]:
        src = Path(input_path)
        mime = magic.from_file(str(src), mime=True)
        tmp = Path(tempfile.mkdtemp(prefix="dumpferret_"))
        print(f"[+] MIME: {mime}")

        try:
            target = src
            if mime in {"application/zip", "application/x-7z-compressed"}:
                shutil.unpack_archive(src, tmp)
                target = tmp

            iocs = {k: set() for k in IOC_REGEX}
            yara_hits = {}
            paths = list(target.rglob("*") if target.is_dir() else [target])
            for p in paths:
                if not p.is_file():
                    continue
                res = self._stream_scan(p)
                for k, vals in res.items():
                    iocs[k].update(vals)
                if self.yara:
                    matches = self.yara.match(str(p))
                    if matches:
                        yara_hits[str(p)] = [m.rule for m in matches]

            if self.use_bulk:
                self._bulk_extract(target, tmp / "bulk")

            sha256 = self._sha256(src)
            out_csv = Path("summary.csv")
            self._write_csv(iocs, out_csv)

            print(f"[+] SHA256: {sha256}")
            for k, v in iocs.items():
                print(f"[+] {k}: {len(v)}")

            if iocs.get("md5") or iocs.get("sha1") or iocs.get("sha256"):
                all_hashes = list(iocs.get("md5", set()) | iocs.get("sha1", set()) | iocs.get("sha256", set()))
                detected = hash_identifier.batch_identify(all_hashes)
                print("[+] Hash type identification:")
                for h, t in detected.items():
                    print(f"    {h[:10]}... → {t}")

            if yara_hits:
                print("[+] YARA matches:")
                for f, rules in yara_hits.items():
                    print(f"    {f} -> {rules}")

            print(f"[+] Output written to: {out_csv}")

            return {
                "sha256": sha256,
                "ioc_counts": {k: len(v) for k, v in iocs.items()},
                "yara_hits": yara_hits,
                "csv": str(out_csv),
                "iocs": iocs
            }

        finally:
            if not self.keep_tmp:
                shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    def banner():
        print(r"""
   ____                        ______                    __ 
  / __ \__  ______ ___  ____  / ____/__  _____________  / /_
 / / / / / / / __ `__ \/ __ \/ /_  / _ \/ ___/ ___/ _ \/ __/
/ /_/ / /_/ / / / / / / /_/ / __/ /  __/ /  / /  /  __/ /_  
\_____/\__,_/_/ /_/ /_/ .___/_/    \___/_/  /_/   \___/\__/  
                     /_/           (OMN1: mgledev) 
[1] Scan dump and extract IOCs
[2] Crack hashes using John the Ripper
[3] Generate PDF report
[4] Exit
[5] IOC enrichment (AbuseIPDB / HIBP - requires API keys)
""")

    banner()

    while True:
        choice = input("Select option: ").strip()

        if choice == "1":
            path = input("Enter path to file: ").strip()
            ferret = DumpFerret()
            result = ferret.scan(path)
        elif choice == "2":
            print("[!] Using summary.csv → hashes.txt → John")
            import pandas as pd
            df = pd.read_csv("summary.csv")
            iocs = {k: set(df[df["type"] == k]["value"]) for k in df["type"].unique()}
            hf = hash_cracker.extract_hashes(iocs, "hashes.txt")
            if hf:
                print("[+] Cracking hashes with John...")
                cracked = hash_cracker.run_john(hf)
                print(f"[+] Cracked hashes written to {cracked}")
        elif choice == "3":
            print("[!] Using summary.csv → PDF")
            import pandas as pd
            df = pd.read_csv("summary.csv")
            iocs = {k: set(df[df["type"] == k]["value"]) for k in df["type"].unique()}
            sha256 = "manual-mode"
            pdf = pdf_reporter.PDFReport()
            pdf.generate(sha256, iocs, {})
            print("[+] summary.pdf generated")
        elif choice == "4":
            print("Bye!")
            break
        elif choice == "5":
            print("[!] Enrichment not available – API keys missing. Set them in modules/enricher.py")
        else:
            print("[!] Invalid option")
