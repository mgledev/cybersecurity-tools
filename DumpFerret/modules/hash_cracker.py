import subprocess
from pathlib import Path
import csv
import re

JTR_PATH = "john/run/john.exe"  # lokalny John the Ripper

def extract_hashes(ioc_dict, outfile="hashes.txt"):
    known_types = {"md5", "sha1", "sha256"}
    hashes = set()
    for htype in known_types:
        for h in ioc_dict.get(htype, set()):
            # tylko czyste heksadecymalne ciągi, bez spacji, komentarzy
            clean = re.match(r"^[a-fA-F0-9]{32,64}$", h.strip())
            if clean:
                hashes.add(h.strip())

    with open(outfile, "w") as f:
        for h in hashes:
            f.write(h + "\n")
    return outfile if hashes else None

def run_john(hashfile: str) -> Path:
    cracked_out = Path("cracked.csv")
    try:
        subprocess.run([JTR_PATH, "--format=Raw-MD5", hashfile], check=True)
        result = subprocess.run([JTR_PATH, "--format=Raw-MD5", "--show", hashfile], capture_output=True, text=True)
        lines = result.stdout.strip().splitlines()
        with open(cracked_out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["hash", "plaintext"])
            for line in lines:
                if ":" in line:
                    parts = line.split(":", 1)
                    w.writerow([parts[0].strip(), parts[1].strip()])
    except Exception as e:
        print(f"[!] John error: {e}")
    return cracked_out
