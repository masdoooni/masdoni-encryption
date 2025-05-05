import streamlit as st
import streamlit.components.v1 as components
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Random import get_random_bytes
import base64
import io
import json
import os

# Utility functions

def generate_rsa_keys(key_size: int):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem.decode(), public_pem.decode()


def encrypt_message_aes(message: bytes, key: bytes, iv: bytes):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    pad_len = 16 - len(message) % 16
    padded = message + bytes([pad_len] * pad_len)
    return encryptor.update(padded) + encryptor.finalize()


def decrypt_message_aes(encrypted: bytes, key: bytes, iv: bytes):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(encrypted) + decryptor.finalize()
    pad_len = padded[-1]
    return padded[:-pad_len]


def rsa_encrypt_key(key_iv: bytes, public_key):
    return public_key.encrypt(
        key_iv,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )


def rsa_decrypt_key(encrypted_key: bytes, private_key):
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )


def rsa_sign_message(message: bytes, private_key):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    hashed = digest.finalize()
    return private_key.sign(
        hashed,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )


def rsa_verify_signature(message: bytes, signature: bytes, public_key):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    hashed = digest.finalize()
    public_key.verify(
        signature,
        hashed,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

# Tab 1: Key Generation

def tab1_keygen():
    st.header("🔐 RSA Key Pair Generator")
    key_size = st.selectbox("Pilih panjang kunci (bit):", [1024, 2048, 4096], index=1)

    if 'generated_keys' not in st.session_state:
        st.session_state['generated_keys'] = None

    if st.button("🔁 Generate Key Pair"):
        private_key, public_key = generate_rsa_keys(key_size)
        st.session_state['generated_keys'] = (private_key, public_key)

    if st.session_state['generated_keys']:
        private_key, public_key = st.session_state['generated_keys']
        # Private Key
        with st.expander("🔓 Private Key"):
            st.text_area("Private Key", private_key, height=250)
            col1, col2 = st.columns(2)
            with col1:
                st.download_button("⬇️ Download Private Key", private_key, file_name=f"private_key_{key_size}.pem")
            with col2:
                components.html(
                    f"""
                    <button onclick="navigator.clipboard.writeText(`{private_key}`)">📋 Copy Private Key</button>
                    """, height=30
                )
        # Public Key
        with st.expander("🔑 Public Key"):
            st.text_area("Public Key", public_key, height=250)
            col1, col2 = st.columns(2)
            with col1:
                st.download_button("⬇️ Download Public Key", public_key, file_name=f"public_key_{key_size}.pem")
            with col2:
                components.html(
                    f"""
                    <button onclick="navigator.clipboard.writeText(`{public_key}`)">📋 Copy Public Key</button>
                    """, height=30
                )
        st.info("💡 Simpan private key di tempat aman dan jangan dibagikan ke siapa pun.")

# Tab 2: Encrypt + Sign

def tab2_encrypt_sign():
    st.header("✉️ Kirim Pesan Aman (Encrypt + Sign)")
    input_mode = st.radio("Pilih input:", ["Teks", "File"])
    message_bytes, filename = None, ""

    if input_mode == "Teks":
        message = st.text_area("Tulis pesan:")
        if message:
            message_bytes = message.encode()
    else:
        uploaded_file = st.file_uploader("Upload file untuk dienkripsi")
        if uploaded_file:
            message_bytes = uploaded_file.read()
            filename = uploaded_file.name

    pub_method = st.radio("Public Key Penerima:", ["Upload File", "Paste Manual"], key="pub_sign")
    if pub_method == "Upload File":
        pub_key_file = st.file_uploader("Public Key Penerima (.pem)", type=["pem"], key="pub2")
        pub_key_data = pub_key_file.read() if pub_key_file else None
    else:
        pub_key_text = st.text_area("Tempelkan isi public key penerima (.pem):")
        pub_key_data = pub_key_text.encode() if pub_key_text else None

    priv_method = st.radio("Private Key Pengirim:", ["Upload File", "Paste Manual"], key="priv_sign")
    if priv_method == "Upload File":
        priv_key_file = st.file_uploader("Private Key Pengirim (.pem)", type=["pem"], key="priv2_")
        priv_key_data = priv_key_file.read() if priv_key_file else None
    else:
        priv_key_text = st.text_area("Tempelkan isi private key pengirim (.pem):")
        priv_key_data = priv_key_text.encode() if priv_key_text else None

    if st.button("🔒 Enkripsi & Tanda Tangan"):
        if message_bytes and priv_key_data and pub_key_data:
            public_key = serialization.load_pem_public_key(pub_key_data)
            private_key = serialization.load_pem_private_key(priv_key_data, password=None)

            aes_key = get_random_bytes(32)
            iv = get_random_bytes(16)
            encrypted_msg = encrypt_message_aes(message_bytes, aes_key, iv)
            encrypted_key = rsa_encrypt_key(aes_key + iv, public_key)
            signature = rsa_sign_message(message_bytes, private_key)

            payload = {
                "encrypted_key": base64.b64encode(encrypted_key).decode(),
                "signature": base64.b64encode(signature).decode(),
                "encrypted_message": base64.b64encode(encrypted_msg).decode(),
                "filename": filename or None
            }

            if input_mode == "Teks":
                st.success("✅ Pesan berhasil dienkripsi dan ditandatangani!")
                st.text_area("📦 Encrypted Message (JSON)", value=json.dumps(payload, indent=2), height=300)
            else:
                enc_filename = f"{filename}.enc"
                memfile = io.BytesIO()
                memfile.write(json.dumps(payload).encode())
                memfile.seek(0)
                st.download_button("⬇️ Download File Terenkripsi", memfile, file_name=enc_filename)

            st.info("💡 Kirim file `.enc` ini ke penerima TANPA mengubah isinya. Pastikan penerima memiliki private key yang sesuai.")

# Tab 3: Decrypt + Verify

def tab3_decrypt_verify():
    st.header("📥 Terima Pesan Aman (Decrypt + Verify)")
    input_mode = st.radio("Pilih input:", ["Teks", "File"], key="input_recv")
    payload = None

    if input_mode == "Teks":
        raw = st.text_area("Tempelkan pesan terenkripsi (JSON):", height=200)
        if raw:
            try:
                payload = json.loads(raw)
            except Exception as e:
                st.error(f"Format JSON tidak valid: {e}")
    else:
        uploaded = st.file_uploader("Upload file `.enc`")
        if uploaded:
            try:
                raw = uploaded.read().decode()
                payload = json.loads(raw)
            except Exception as e:
                st.error(f"Gagal membaca file: {e}")

    # Private Key for decryption
    priv_method = st.radio("Private Key (decrypt):", ["Upload File", "Paste Manual"], key="priv_recv")
    if priv_method == "Upload File":
        priv_key_file = st.file_uploader("Private Key (.pem)", type=["pem"], key="priv3")
        priv_key_data = priv_key_file.read() if priv_key_file else None
    else:
        priv_key_text = st.text_area("Tempelkan isi private key (.pem):", height=200)
        priv_key_data = priv_key_text.encode() if priv_key_text else None

    # Public Key for verification
    pub_method = st.radio("Public Key (verify):", ["Upload File", "Paste Manual"], key="pub_recv")
    if pub_method == "Upload File":
        pub_key_file = st.file_uploader("Public Key (.pem)", type=["pem"], key="pub4")
        pub_key_data = pub_key_file.read() if pub_key_file else None
    else:
        pub_key_text = st.text_area("Tempelkan isi public key (.pem):", height=200)
        pub_key_data = pub_key_text.encode() if pub_key_text else None

    if st.button("🔓 Dekripsi & Verifikasi"):
        if payload and priv_key_data and pub_key_data:
            try:
                private_key = serialization.load_pem_private_key(priv_key_data, password=None)
                public_key = serialization.load_pem_public_key(pub_key_data)

                encrypted_key = base64.b64decode(payload["encrypted_key"])
                key_iv = rsa_decrypt_key(encrypted_key, private_key)
                aes_key, iv = key_iv[:32], key_iv[32:]
                encrypted_msg = base64.b64decode(payload["encrypted_message"])
                decrypted = decrypt_message_aes(encrypted_msg, aes_key, iv)

                # Verify signature
                try:
                    signature = base64.b64decode(payload["signature"])
                    rsa_verify_signature(decrypted, signature, public_key)
                    st.success("✅ Signature valid")
                except Exception:
                    st.error("❌ Signature tidak valid")

                if input_mode == "Teks":
                    txt = decrypted.decode()
                    st.text_area("📨 Decrypted Message", txt, height=300)
                else:
                    orig_filename = payload.get("filename") or "decrypted_file"
                    memfile = io.BytesIO()
                    memfile.write(decrypted)
                    memfile.seek(0)
                    st.download_button("⬇️ Download Decrypted File", memfile, file_name=orig_filename)

            except Exception as e:
                st.error(f"Proses gagal: {e}")

# Sidebar

tab = st.sidebar.radio("Navigasi", ["🔐 Generate Key", "✉️ Kirim Pesan", "📥 Terima Pesan"])

if tab == "🔐 Generate Key":
    tab1_keygen()
elif tab == "✉️ Kirim Pesan":
    tab2_encrypt_sign()
elif tab == "📥 Terima Pesan":
    tab3_decrypt_verify()
