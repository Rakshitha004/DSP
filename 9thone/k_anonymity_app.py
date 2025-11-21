# -------------------------------------------------------------
# Streamlit App : k-Anonymity Based Data Anonymization (Final)
# -------------------------------------------------------------
import streamlit as st
import pandas as pd
import math

# -------------------------------------------------------------
# Page Setup
# -------------------------------------------------------------
st.set_page_config(page_title="🧩 k-Anonymity Tool", page_icon="🧩", layout="wide")

st.markdown("<h1 style='text-align:center;color:#2F6B6B;'>🧩 Data Anonymization using k-Anonymity</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align:center;color:#555;'>Protect sensitive data by generalizing quasi-identifiers to achieve k-anonymity.</p>", unsafe_allow_html=True)
st.write("---")

# -------------------------------------------------------------
# File Upload Section
# -------------------------------------------------------------
uploaded_file = st.file_uploader("📂 Upload your dataset (CSV only)", type=["csv"])

if uploaded_file:
    # Safe CSV reading with proper delimiter and encoding
    try:
        df = pd.read_csv(uploaded_file, encoding="utf-8", sep=",")
    except UnicodeDecodeError:
        uploaded_file.seek(0)
        df = pd.read_csv(uploaded_file, encoding="latin1", sep=",")

    # Clean up column names
    df.columns = df.columns.str.strip()

    st.subheader("📄 Original Dataset")
    st.dataframe(df.head())

    # ---------------------------------------------------------
    # k-Anonymity Settings
    # ---------------------------------------------------------
    st.subheader("⚙️ k-Anonymity Settings")

    quasi_cols = st.multiselect(
        "Select Quasi-Identifier Columns (attributes that could indirectly identify a person):",
        options=df.columns.tolist(),
        help="Examples: Name, Email, Phone, Aadhaar, Address, Age, etc."
    )

    k_value = st.number_input(
        "Enter desired k-value:",
        min_value=2, value=3, step=1,
        help="Higher k means stronger privacy but more data generalization."
    )

    # ---------------------------------------------------------
    # Helper Functions
    # ---------------------------------------------------------
    def compute_k(data, cols):
        """Compute minimum group size (k)"""
        if len(cols) == 0:
            return 0
        return data.groupby(cols).size().min()

    def generalize_value(val):
        """Simple generalization logic"""
        if pd.isna(val):
            return val
        if isinstance(val, str) and val.isdigit() and len(val) == 6:
            return val[:3] + "XXX"  # Example: 560034 → 560XXX
        if isinstance(val, (int, float)):
            grp = math.floor(val / 5) * 5
            return f"{grp}-{grp+4}"  # Example: 27 → 25-29
        if isinstance(val, str) and "@" in val:
            # Generalize email → hide username
            return val.split("@")[0][:2] + "***@" + val.split("@")[1]
        if isinstance(val, str) and len(val) > 4:
            # Mask last few characters for other strings
            return val[:3] + "***"
        return val

    # ---------------------------------------------------------
    # Apply Anonymization
    # ---------------------------------------------------------
    if st.button("🔐 Apply k-Anonymization"):
        if not quasi_cols:
            st.warning("⚠️ Please select at least one quasi-identifier column.")
        else:
            current_k = compute_k(df, quasi_cols)
            st.info(f"📊 Current dataset k = **{current_k}**")

            if current_k >= k_value:
                st.success(f"✅ Dataset already satisfies {k_value}-Anonymity.")
                st.dataframe(df.head())
            else:
                st.warning("⚠️ Dataset does NOT satisfy desired k-Anonymity.")
                st.info("Applying generalization to quasi-identifier columns...")

                anon_df = df.copy()
                for col in quasi_cols:
                    anon_df[col] = anon_df[col].apply(generalize_value)

                new_k = compute_k(anon_df, quasi_cols)
                st.success(f"✅ After generalization, new k = {new_k}")

                st.markdown("---")
                st.subheader("🔍 Before Anonymization")
                st.dataframe(df.head())

                st.subheader("🔒 After Anonymization")
                st.dataframe(anon_df.head())

                st.download_button(
                    label="📥 Download Anonymized Dataset",
                    data=anon_df.to_csv(index=False).encode("utf-8"),
                    file_name="anonymized_data.csv",
                    mime="text/csv"
                )

else:
    st.info("Please upload a CSV dataset to begin.")

# -------------------------------------------------------------
# Footer
# -------------------------------------------------------------
st.markdown("---")
st.caption("Developed for Data Security & Privacy Lab | Educational Version | Demonstrates k-Anonymity with safe generalization.")
