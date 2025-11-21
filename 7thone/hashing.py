# encrypt_run_streamlit.py
import streamlit as st
import base64
import json
import os
import io
import contextlib
from datetime import datetime

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken
import secrets

# ------------------ Helpers ------------------

def derive_fernet_key(password: str, salt: bytes, iterations: int = 390000) -> bytes:
    """
    Derive a 32-byte key for Fernet using PBKDF2-HMAC-SHA256.
    Returns a urlsafe-base64-encoded key (as bytes) usable by cryptography.Fernet.
    """
    pwd = password.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    key = kdf.derive(pwd)
    return base64.urlsafe_b64encode(key)

def encrypt_code_bytes(code_bytes: bytes, password: str) -> bytes:
    """
    Encrypt code bytes with a password.
    Returns a JSON bytes: {"salt": base64..., "ct": base64..., "iters": N}
    """
    salt = secrets.token_bytes(16)
    key = derive_fernet_key(password, salt)
    f = Fernet(key)
    token = f.encrypt(code_bytes)
    payload = {"salt": base64.b64encode(salt).decode("ascii"),
               "ct": base64.b64encode(token).decode("ascii"),
               "iters": 390000}
    return json.dumps(payload).encode("utf-8")

def decrypt_code_bytes(encrypted_json_bytes: bytes, password: str) -> bytes:
    """
    Decrypt JSON blob produced by encrypt_code_bytes.
    Raises InvalidToken on wrong password / corrupted blob.
    """
    payload = json.loads(encrypted_json_bytes.decode("utf-8"))
    salt = base64.b64decode(payload["salt"])
    token = base64.b64decode(payload["ct"])
    iterations = int(payload.get("iters", 390000))
    key = derive_fernet_key(password, salt, iterations)
    f = Fernet(key)
    plain = f.decrypt(token)  # may raise InvalidToken
    return plain

def make_download_bytesio(content_bytes: bytes, filename: str, mime="application/octet-stream"):
    st.download_button("Download " + filename, data=content_bytes, file_name=filename, mime=mime)

# ------------------ Streamlit UI ------------------

st.set_page_config(page_title="Encrypt & Run Python (Demo)", layout="wide", page_icon="🔐")
st.title("🔐 Encrypt Python Source & Run (Demo)")
st.markdown(
    """
This app demonstrates password-based encryption of Python source and runtime decryption/execution.
**DO NOT run untrusted code.** Use only simple trusted examples (e.g., a greet function).
"""
)

tab_encrypt, tab_run = st.tabs(["🔏 Encrypt Code", "▶️ Decrypt & Run"])

# ---------- Encrypt Tab ----------
with tab_encrypt:
    st.subheader("Encrypt a Python snippet")
    mode = st.radio("Provide source via", ["Paste code", "Upload file (.py)"], index=0, horizontal=True)

    code_bytes = None
    if mode == "Paste code":
        code_text = st.text_area("Paste Python code (trusted)", value='''def greet(name):\n    print(f"Hello, {name}")\n\nif __name__ == "__main__":\n    greet("World")\n''', height=220)
        if code_text and code_text.strip():
            code_bytes = code_text.encode("utf-8")
    else:
        uploaded = st.file_uploader("Upload .py file", type=["py"], accept_multiple_files=False)
        if uploaded is not None:
            uploaded.seek(0)
            raw = uploaded.read()
            code_bytes = raw if isinstance(raw, bytes) else raw.encode("utf-8")

    password = st.text_input("Encryption password (choose a strong one)", type="password")
    password_confirm = st.text_input("Confirm password", type="password")

    if st.button("Encrypt"):
        if not code_bytes:
            st.warning("Please provide some Python code (paste or upload).")
        elif not password:
            st.warning("Password is required.")
        elif password != password_confirm:
            st.warning("Passwords do not match.")
        else:
            enc_blob = encrypt_code_bytes(code_bytes, password)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"encrypted_code_{ts}.json"
            st.success("Encryption successful.")
            st.write("You can download the encrypted file and give it + the password to someone who can decrypt & run it.")
            make_download_bytesio(enc_blob, filename)
            st.code(enc_blob.decode("utf-8")[:1000] + ("\n... (truncated)" if len(enc_blob) > 1000 else ""), language="json")
            st.info("Keep the password safe. Without it the code cannot be decrypted.")

# ---------- Decrypt & Run Tab ----------
with tab_run:
    st.subheader("Decrypt an encrypted snippet and run it")
    uploaded_enc = st.file_uploader("Upload encrypted JSON file (from 'Encrypt' tab)", type=["json"], accept_multiple_files=False)
    enc_text = st.text_area("Or paste encrypted JSON (from 'Encrypt' tab)", height=150)
    pw = st.text_input("Decryption password", type="password", key="pw_run")
    show_decoded = st.checkbox("Show decrypted source (before running)", value=False)
    run_button = st.button("Decrypt & Run")

    enc_bytes = None
    if uploaded_enc is not None:
        uploaded_enc.seek(0)
        raw = uploaded_enc.read()
        enc_bytes = raw if isinstance(raw, bytes) else raw.encode("utf-8")
    elif enc_text and enc_text.strip():
        enc_bytes = enc_text.encode("utf-8")

    if run_button:
        if not enc_bytes:
            st.warning("Please upload or paste the encrypted JSON blob.")
        elif not pw:
            st.warning("Please provide the decryption password.")
        else:
            try:
                plain = decrypt_code_bytes(enc_bytes, pw)
            except InvalidToken:
                st.error("Decryption failed — wrong password or corrupted file.")
            except Exception as e:
                st.error(f"Decryption error: {e}")
            else:
                try:
                    decoded_text = plain.decode("utf-8")
                except Exception:
                    decoded_text = None

                if show_decoded:
                    st.subheader("Decrypted source")
                    if decoded_text is not None:
                        st.code(decoded_text, language="python")
                    else:
                        st.write("Binary content (not text).")

                # Execute the decrypted code safely (trusted only). Capture stdout.
                st.info("Executing decrypted code (trusted only). Output below:")
                buf = io.StringIO()
                # Minimal execution context providing builtins so print works
                exec_globals = {"__builtins__": __builtins__}
                with contextlib.redirect_stdout(buf):
                    try:
                        exec(plain, exec_globals)
                    except Exception as e:
                        st.error(f"Error during execution: {e}")
                out = buf.getvalue()
                if out.strip():
                    st.subheader("Program output")
                    st.code(out)
                else:
                    st.info("Program executed but produced no stdout output.")

st.markdown("---")
st.caption("Demo: password-based encryption (PBKDF2 + Fernet). Executing decrypted code is potentially dangerous — only run trusted snippets.")



