import streamlit as st
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Random import get_random_bytes
import base64
import io
import ast

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

# UI Functions

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
        with st.expander("🔓 Private Key"):
            st.text_area("Private Key", private_key, height=250)
            st.download_button("⬇️ Download Private Key", private_key, file_name=f"private_key_{key_size}.pem")
            st.button("📋 Salin Private Key", on_click=lambda: st.session_state.update({"copy_private": private_key}))

        with st.expander("🔑 Public Key"):
            st.text_area("Public Key", public_key, height=250)
            st.download_button("⬇️ Download Public Key", public_key, file_name=f"public_key_{key_size}.pem")
            st.button("📋 Salin Public Key", on_click=lambda: st.session_state.update({"copy_public": public_key}))

        st.info("💡 Simpan private key di tempat aman dan jangan dibagikan ke siapa pun.")

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

    pub_method = st.radio("Public Key Penerima:", ["Upload File", "Paste Manual"])
    if pub_method == "Upload File":
        pub_key_file = st.file_uploader("Public Key Penerima (.pem)", type=["pem"], key="pub")
        pub_key_data = pub_key_file.read() if pub_key_file else None
    else:
        pub_key_text = st.text_area("Tempelkan isi public key penerima (.pem):")
        pub_key_data = pub_key_text.encode() if pub_key_text else None

    priv_method = st.radio("Private Key Pengirim:", ["Upload File", "Paste Manual"])
    if priv_method == "Upload File":
        priv_key_file = st.file_uploader("Private Key Pengirim (.pem)", type=["pem"], key="priv")
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
                "encrypted_message": base64.b64encode(encrypted_msg).decode()
            }

            if input_mode == "Teks":
                st.success("✅ Pesan berhasil dienkripsi dan ditandatangani!")
                st.text_area("📦 Encrypted Message (JSON)", value=str(payload), height=300)
            else:
                enc_filename = f"{filename}.enc"
                memfile = io.BytesIO()
                memfile.write(str(payload).encode())
                memfile.seek(0)
                st.download_button("⬇️ Download File Terenkripsi", memfile, file_name=enc_filename)

            st.info("💡 Kirim file `.enc` ini ke penerima TANPA mengubah isinya. Pastikan penerima memiliki private key yang sesuai.")


def tab3_decrypt_verify():
    st.header("📥 Terima Pesan (Decrypt + Optional Verify)")
    
    input_mode = st.radio("Pilih input terenkripsi:", ["Teks", "File"])
    encrypted_data = None

    if input_mode == "Teks":
        encrypted_text = st.text_area("Tempelkan pesan terenkripsi (JSON):")
        if encrypted_text:
            try:
                encrypted_data = ast.literal_eval(encrypted_text)
            except:
                st.error("❌ Format pesan tidak valid.")
                return
    else:
        uploaded_enc_file = st.file_uploader("Upload file terenkripsi (.enc)", type=["enc"])
        if uploaded_enc_file:
            try:
                encrypted_data = ast.literal_eval(uploaded_enc_file.read().decode())
            except:
                st.error("❌ Format file tidak valid.")
                return

    priv_method = st.radio("Private Key Anda:", ["Upload File", "Paste Manual"])
    if priv_method == "Upload File":
        priv_key_file = st.file_uploader("Private Key Anda (.pem)", type=["pem"], key="dec_priv")
        priv_key_data = priv_key_file.read() if priv_key_file else None
    else:
        priv_key_text = st.text_area("Tempelkan isi private key Anda (.pem):")
        priv_key_data = priv_key_text.encode() if priv_key_text else None

    st.markdown("### (Opsional) Public Key Pengirim")
    pub_method = st.radio("Pilih metode input:", ["Tidak Diisi", "Upload File", "Paste Manual"])
    pub_key_data = None

    if pub_method == "Upload File":
        pub_key_file = st.file_uploader("Public Key Pengirim (.pem)", type=["pem"], key="dec_pub")
        pub_key_data = pub_key_file.read() if pub_key_file else None
    elif pub_method == "Paste Manual":
        pub_key_text = st.text_area("Tempelkan isi public key pengirim (.pem):")
        pub_key_data = pub_key_text.encode() if pub_key_text else None

    if st.button("🔓 Dekripsi"):
        if encrypted_data and priv_key_data:
            try:
                private_key = serialization.load_pem_private_key(priv_key_data, password=None)
            except:
                st.error("❌ Private key tidak valid.")
                return

            try:
                encrypted_key = base64.b64decode(encrypted_data["encrypted_key"])
                signature = base64.b64decode(encrypted_data["signature"])
                encrypted_message = base64.b64decode(encrypted_data["encrypted_message"])

                key_iv = rsa_decrypt_key(encrypted_key, private_key)
                aes_key, iv = key_iv[:32], key_iv[32:]
                decrypted = decrypt_message_aes(encrypted_message, aes_key, iv)

                st.success("✅ Pesan berhasil didekripsi!")

                if input_mode == "Teks":
                    try:
                        st.text_area("📄 Pesan Terdekripsi", decrypted.decode(), height=300)
                    except:
                        st.error("🔍 Tidak dapat menampilkan sebagai teks. Ini kemungkinan file.")
                else:
                    st.download_button("⬇️ Download File Terdekripsi", decrypted, file_name="decrypted_output")

                if pub_key_data:
                    try:
                        public_key = serialization.load_pem_public_key(pub_key_data)
                        rsa_verify_signature(decrypted, signature, public_key)
                        st.success("✅ Tanda tangan berhasil diverifikasi.")
                    except Exception:
                        st.warning("⚠️ Verifikasi gagal: tanda tangan tidak cocok dengan public key.")
                else:
                    st.info("ℹ️ Pesan tidak diverifikasi karena public key tidak tersedia.")
            except Exception as e:
                st.error(f"❌ Terjadi kesalahan saat dekripsi/verifikasi: {str(e)}")

# Sidebar router
tab = st.sidebar.radio("Navigasi", ["🔐 Generate Key", "✉️ Kirim Pesan", "📥 Terima Pesan"])

if tab == "🔐 Generate Key":
    tab1_keygen()
elif tab == "✉️ Kirim Pesan":
    tab2_encrypt_sign()
elif tab == "📥 Terima Pesan":
    tab3_decrypt_verify()
