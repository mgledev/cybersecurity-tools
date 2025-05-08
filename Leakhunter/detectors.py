# detectors.py
import re
from collections import namedtuple

Finding = namedtuple("Finding",
                     ["keyword", "line", "data_type", "match", "source_url"])

REGEX_PATTERNS = {
    "EMAIL"   : r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "HASH"    : r"\b[a-fA-F0-9]{32,64}\b",
    "JWT"     : r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
    "AWS_KEY" : r"AKIA[0-9A-Z]{16}",
    "RSA_KEY" : r"-----BEGIN\sRSA\sPRIVATE\sKEY-----",
}

def classify_line(line: str, keywords: list[str]) -> list[Finding]:
    findings = []
    lower = line.lower()
    for kw in keywords:
        if kw.lower() in lower:
            findings.append(Finding(kw, line.strip(), "KEYWORD", kw, None))
    for dtype, rx in REGEX_PATTERNS.items():
        for m in re.findall(rx, line, flags=re.I):
            findings.append(Finding(dtype, line.strip(), dtype, m, None))
    return findings
