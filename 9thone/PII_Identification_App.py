import streamlit as st
import pandas as pd
import re

# -------------------------------------------------------------
# Streamlit App: PII Data Identification and Classification
# -------------------------------------------------------------
st.set_page_config(page_title="PII Identifier", page_icon="🔍", layout="wide")
st.title("🔍 PII Data Identification & Classification Tool")

st.markdown("""
Upload a dataset (CSV or TXT) and this app will:
1. Detect **Personally Identifiable Information (PII)** such as Email, Phone, Aadhaar, etc.  
2. Classify your data as **Structured** or **Unstructured**  
3. Explain **Data States** – At-Rest, In-Transit, and In-Use  
""")

# -------------------------------------------------------------
# File upload
# -------------------------------------------------------------
uploaded_file = st.file_uploader("📂 Upload dataset", type=["csv", "txt"])

def detect_pii(text):
    """Detect possible PII using regex patterns"""
    patterns = {
        "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "Phone": r"\b\d{10}\b",
        "Aadhaar/SSN": r"\b\d{12}\b|\b\d{3}-\d{2}-\d{4}\b",
        "Credit Card": r"\b\d{4}-\d{4}-\d{4}-\d{4}\b",
        "IP Address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    }

    found = []
    for label, pattern in patterns.items():
        if re.search(pattern, text):
            found.append(label)
    return found


def highlight_pii(text):
    """Highlights detected PII patterns in red"""
    patterns = {
        "Email": r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        "Phone": r"(\b\d{10}\b)",
        "Aadhaar/SSN": r"(\b\d{12}\b|\b\d{3}-\d{2}-\d{4}\b)",
        "Credit Card": r"(\b\d{4}-\d{4}-\d{4}-\d{4}\b)",
        "IP Address": r"((?:\d{1,3}\.){3}\d{1,3})"
    }

    highlighted_text = text
    for label, pattern in patterns.items():
        highlighted_text = re.sub(pattern, r'<span style="color:red; font-weight:bold;">\1</span>', highlighted_text)
    return highlighted_text


# -------------------------------------------------------------
# File Processing
# -------------------------------------------------------------
if uploaded_file:
    filename = uploaded_file.name.lower()
    st.success(f"✅ File uploaded: {uploaded_file.name}")

    # ---------------------------------------------------------
    # Structured Data (CSV)
    # ---------------------------------------------------------
    if filename.endswith(".csv"):
        try:
            # try utf-8 first; fallback to latin1
            try:
                df = pd.read_csv(uploaded_file, encoding="utf-8")
            except UnicodeDecodeError:
                uploaded_file.seek(0)
                df = pd.read_csv(uploaded_file, encoding="latin1")

            st.write("### 🧾 Dataset Preview")
            st.dataframe(df.head())

            st.markdown("### 🔎 Detected PII Fields")
            pii_report = []

            for col in df.columns:
                sample_text = " ".join(df[col].astype(str).values[:100])
                pii_found = detect_pii(sample_text)
                if pii_found:
                    st.write(f"**{col}** → {', '.join(pii_found)}")
                    pii_report.append({"Column": col, "Detected PII": ", ".join(pii_found)})

            if not pii_report:
                st.info("No PII detected in this dataset.")
            else:
                report_df = pd.DataFrame(pii_report)
                st.download_button(
                    "📥 Download PII Report (CSV)",
                    report_df.to_csv(index=False).encode("utf-8"),
                    "pii_report.csv",
                    "text/csv"
                )

            st.markdown("### 📊 Data Classification: **Structured Data**")

        except Exception as e:
            st.error(f"Error reading CSV file: {e}")

    # ---------------------------------------------------------
    # Unstructured Data (TXT)
    # ---------------------------------------------------------
    elif filename.endswith(".txt"):
        try:
            try:
                text = uploaded_file.read().decode("utf-8")
            except UnicodeDecodeError:
                uploaded_file.seek(0)
                text = uploaded_file.read().decode("latin1")

            st.markdown("### 📄 Uploaded Text Preview")
            st.code(text[:500])

            pii_found = detect_pii(text)
            if pii_found:
                st.markdown("### 🔎 Detected PII Elements:")
                st.success(", ".join(pii_found))

                st.markdown("### 🟥 Highlighted PII in Text")
                st.markdown(highlight_pii(text), unsafe_allow_html=True)
            else:
                st.info("No PII detected in this text.")

            st.markdown("### 📊 Data Classification: **Unstructured Data**")

        except Exception as e:
            st.error(f"Error reading text file: {e}")

    # ---------------------------------------------------------
    # Data States Info
    # ---------------------------------------------------------
    st.markdown("---")
    st.markdown("### 🔐 Data States")
    st.markdown("""
    - **At-Rest:** Data stored on disk, file, or database.  
    - **In-Transit:** Data moving through a network or API.  
    - **In-Use:** Data currently processed or accessed in memory.
    """)

else:
    st.info("Please upload a dataset (.csv or .txt) to start analysis.")

