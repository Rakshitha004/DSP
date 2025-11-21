import streamlit as st
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import jwt
import datetime

# ---------------- RSA Digital Signature ----------------
def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(private_key, message):
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# ---------------- Authentication & JWT ----------------
SECRET_KEY = "my_super_secret_key"

USERS_DB = {
    "alice": "alice123",
    "bob": "bob123",
    "nakul": "nakul123&&"
}

def authenticate(username, password):
    if username in USERS_DB and USERS_DB[username] == password:
        token = jwt.encode(
            {"user": username, "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=10)},
            SECRET_KEY,
            algorithm="HS256"
        )
        return token
    else:
        return None

def verify_token(token):
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return True, data["user"]
    except Exception:
        return False, None

# ---------------- Streamlit UI ----------------
st.set_page_config(page_title="Digital Signatures & Auth Lab", page_icon="🔑", layout="wide")

st.markdown("<h1 style='text-align:center; color:#FF5722;'>Digital Signatures & Auth Lab Demo</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align:center;'>Interactive demo for signing transactions and secure login with JWT</p>", unsafe_allow_html=True)
st.markdown("---")

# ---------------- Columns Layout ----------------
col1, col2 = st.columns(2)

# -------- Column 1: Digital Signature --------
with col1:
    st.markdown("### 🖊 Digital Signature")
    message = st.text_area("Enter transaction/message:", value="Payment of $100 to Bob", key="ds_message")
    if st.button("Generate Keys & Sign", key="ds_sign_btn"):
        private_key, public_key = generate_keys()
        signature = sign_message(private_key, message)
        st.success("Message signed successfully!")
        st.code(signature.hex(), language="bash")

        verified = verify_signature(public_key, message, signature)
        st.info(f"Signature Verified: {'Valid' if verified else 'Invalid'}")

        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        st.text_area("Public Key (share with recipient):", pem.decode(), height=150)

# -------- Column 2: Authentication & Authorization --------
with col2:
    st.markdown("### 🔐 Authentication & Authorization")
    username = st.text_input("Username", key="auth_user")
    password = st.text_input("Password", type="password", key="auth_pass")

    if st.button("Login & Get JWT Token", key="auth_login_btn"):
        token = authenticate(username, password)
        if token:
            st.success("Login successful!")
            st.code(token, language="bash")

            if st.button("Simulate Secure API Call", key="api_call_btn"):
                valid, user = verify_token(token)
                if valid:
                    st.info(f"API Access Granted for user: {user}")
                else:
                    st.error("Invalid or expired token")
        else:
            st.error("Invalid credentials")

st.markdown("---")
st.caption("Case Study: Digital signatures in e-commerce/banking secure transactions and prevent tampering.")
