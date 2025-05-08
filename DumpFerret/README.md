# 🦝 DumpFerret

> Red & Blue Team IOC scanner with hash cracking, PDF reporting, and modular enrichment.

---

## 🔍 What is DumpFerret?

**DumpFerret** is a professional IOC dump analyzer built for red/blue teams, CTFers and incident responders. It scans dump archives, detects sensitive data (IOCs), cracks password hashes using John the Ripper, and generates clean PDF reports.

---

## 🚀 Features

- 🔎 IOC extraction (emails, IPs, hashes, URLs, credit cards, etc.)
- 🔐 Hash cracking via John the Ripper
- 📄 PDF report generation
- 📦 Supports `.zip`, `.7z`, `.txt`, `.log`, `.csv`
- 🧠 Modular enrichment via HIBP / AbuseIPDB (optional)
- 🔍 YARA support (optional)
- 👨‍💻 Clean CLI with ASCII banner

---

## 🛠 Installation

```bash
git clone https://github.com/mgledev/DumpFerret.git
cd DumpFerret
pip install -r requirements.txt
