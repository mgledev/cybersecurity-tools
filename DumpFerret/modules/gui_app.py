import streamlit as st
from dumpferret import DumpFerret

st.set_page_config(page_title="DumpFerret GUI", layout="wide")
st.title("🦡 DumpFerret – IOC Extractor")

uploaded_file = st.file_uploader("Upload a dump file (.zip, .sql, .txt)", type=["zip", "7z", "sql", "txt"])

use_yara = st.checkbox("Enable YARA scanning")
yara_path = st.text_input("YARA rules path", "rules.yar")
use_bulk = st.checkbox("Enable bulk_extractor")
run_scan = st.button("Run Analysis")

if uploaded_file and run_scan:
    with open("temp_input", "wb") as f:
        f.write(uploaded_file.read())

    df = DumpFerret(yara_path=yara_path if use_yara else None, use_bulk=use_bulk)
    result = df.scan("temp_input")

    st.success("Scan complete!")
    st.json(result)

    with open(result["csv"], "r", encoding="utf-8") as f:
        st.download_button("Download CSV", f, file_name="summary.csv")
