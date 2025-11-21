# phishing_detector.py
import pandas as pd
import streamlit as st
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
import time

# ---------------- Feature Extraction ----------------
def extract_features(url: str):
    if not isinstance(url, str):
        url = str(url)
    return {
        "url_length": len(url),
        "has_at": 1 if "@" in url else 0,
        "has_https": 1 if url.lower().startswith("https") else 0,
        "num_digits": sum(c.isdigit() for c in url),
        "num_hyphen": url.count("-"),
        "num_subdir": url.count("/")  # crude approximation of subdirectories
    }

# ---------------- Example Training Dataset ----------------
# small sample dataset (replace with real dataset for better results)
data = {
    "url": [
        "https://www.google.com",
        "http://phishing-site.com/login@secure",
        "https://secure-bank.com/account",
        "http://fake-update.com/install",
        "https://amazon.com/payment",
        "http://paypal.verify-account.com"
    ],
    "label": [0, 1, 0, 1, 0, 1]  # 0 = legitimate, 1 = phishing
}
df = pd.DataFrame(data)

# Extract features for training
feature_df = pd.DataFrame([extract_features(u) for u in df["url"]])
X = feature_df
y = df["label"]

# Train/Test Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Model Training (increase max_iter to avoid convergence warnings on small data)
model = LogisticRegression(max_iter=200, solver="liblinear")
model.fit(X_train, y_train)

# Accuracy
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)

# ---------------- Streamlit UI ----------------
st.set_page_config(page_title="Phishing Detector", page_icon="🛡️", layout="wide")

st.markdown(
    """
    <style>
    .main-title {text-align:center; color:#8E44AD; font-size:42px; font-weight:bold;}
    .sub-text {text-align:center; color:#7F8C8D; font-size:18px;}
    .container {padding: 1rem 2rem;}
    </style>
    """,
    unsafe_allow_html=True
)
st.markdown("<div class='main-title'>Batch Phishing Website Detection</div>", unsafe_allow_html=True)
st.markdown("<div class='sub-text'>Upload a file with URLs or check a single URL. (Demo model trained with tiny sample)</div>", unsafe_allow_html=True)
st.info(f"Model trained (demo) — accuracy on small holdout: **{acc*100:.2f}%**")

# ---------------- Single URL Check ----------------
st.subheader("Check a Single URL")
user_url = st.text_input("Enter a website URL:")

if st.button("Check Now"):
    if user_url.strip() == "":
        st.warning("Please enter a valid URL.")
    else:
        features = pd.DataFrame([extract_features(user_url)])
        try:
            prediction = model.predict(features)[0]
            result = "Phishing Website" if prediction == 1 else "Legitimate Website"
            st.success(f"Result: {result}")
        except Exception as e:
            st.error(f"Error making prediction: {e}")

st.markdown("---")

# ---------------- Batch URL Check ----------------
st.subheader("Upload File with URLs (CSV or TXT)")
uploaded_file = st.file_uploader("Upload your file (CSV: first column = URLs or plain TXT lines)", type=["csv", "txt"])

if uploaded_file is not None:
    try:
        # Read uploaded file robustly
        if uploaded_file.name.lower().endswith(".csv"):
            url_df = pd.read_csv(uploaded_file, header=None, encoding="utf-8", engine="python")
            urls = url_df.iloc[:, 0].astype(str).tolist()
        else:  # TXT file
            content = uploaded_file.read()
            # attempt decode in fallback-safe way
            if isinstance(content, bytes):
                try:
                    text = content.decode("utf-8")
                except Exception:
                    text = content.decode("latin-1", errors="ignore")
            else:
                text = str(content)
            urls = [line.strip() for line in text.splitlines() if line.strip()]

        if not urls:
            st.warning("No URLs found in the uploaded file.")
        else:
            st.write("File uploaded successfully. Running detection...")

            # Progress simulation
            progress = st.progress(0)
            for i in range(100):
                time.sleep(0.004)
                progress.progress(i + 1)

            # Extract features & predict
            batch_features = pd.DataFrame([extract_features(u) for u in urls])
            batch_preds = model.predict(batch_features)

            # Create results table
            results = pd.DataFrame({
                "URL": urls,
                "Prediction": ["Phishing" if p == 1 else "Legitimate" for p in batch_preds]
            })

            st.subheader("Results Table")
            st.dataframe(results, use_container_width=True)

            # Allow download
            csv_bytes = results.to_csv(index=False).encode("utf-8")
            st.download_button("Download results CSV", data=csv_bytes, file_name="phishing_detection_results.csv", mime="text/csv")

    except Exception as e:
        st.error(f"Error processing file: {e}")

st.markdown("---")
st.caption("Demo Phishing Detector — replace the example dataset with a larger labeled dataset for production use.")
