# exporter.py
import csv, pandas as pd
from prettytable import PrettyTable
from config import EXPORT_DIR

def export_csv(rows, filename="leakhunter_export.csv"):
    path = EXPORT_DIR / filename
    with open(path, "w", newline="", encoding="utf-8") as f:
        cw = csv.writer(f)
        cw.writerow(["source_url", "keyword", "data_type",
                     "match", "line", "timestamp"])
        cw.writerows(rows)
    return path

def display_table(rows):
    table = PrettyTable(
        ["Source", "Keyword/Type", "Match", "Line"])
    for r in rows:
        table.add_row([
            r[0][:30] + "…",
            f"{r[1]} / {r[2]}",
            (r[3][:25] + "…") if len(r[3]) > 28 else r[3],
            (r[4][:40] + "…") if len(r[4]) > 43 else r[4]])
    print(table)

def export_html(rows, filename="leakhunter_report.html"):
    df = pd.DataFrame(rows, columns=[
        "source_url", "keyword", "data_type",
        "match", "line", "timestamp"])
    path = EXPORT_DIR / filename
    df.to_html(path, index=False, escape=False)
    return path
