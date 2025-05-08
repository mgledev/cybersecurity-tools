from fpdf import FPDF
from datetime import datetime

class PDFReport:
    def __init__(self, title="DumpFerret Report"):
        self.pdf = FPDF()
        self.title = title
        self.pdf.set_auto_page_break(auto=True, margin=15)

    def add_title(self):
        self.pdf.set_font("Arial", "B", 16)
        self.pdf.cell(0, 10, self.title, ln=True, align="C")
        self.pdf.ln(10)

    def add_section(self, header: str, content: list[str]):
        self.pdf.set_font("Arial", "B", 12)
        self.pdf.cell(0, 10, header, ln=True)
        self.pdf.set_font("Arial", "", 10)
        for line in content:
            self.pdf.multi_cell(0, 8, line)
        self.pdf.ln(5)

    def generate(self, sha256: str, iocs: dict, yara: dict, outfile="summary.pdf"):
        self.pdf.add_page()
        self.add_title()
        self.add_section("Report Generated", [datetime.now().isoformat()])
        self.add_section("SHA256 of Source", [sha256])

        for k, v in iocs.items():
            self.add_section(f"IOC: {k}", list(v))

        if yara:
            yara_lines = [f"{k}: {', '.join(rules)}" for k, rules in yara.items()]
            self.add_section("YARA Matches", yara_lines)

        self.pdf.output(outfile)
        return outfile
