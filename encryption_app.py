
import streamlit as st
import json
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

# Tab 1: Key Generator
def tab1_keygen():
    st.header("🔐 RSA Key Pair Generator")
    key_size = st.selectbox("Pilih panjang kunci (bit):", [1024, 2048, 4096], index=1)

    if 'keys' not in st.session_state:
        st.session_state.keys = None

    if st.button("🔁 Generate Key Pair"):
        private_pem, public_pem = generate_rsa_keys(key_size)
        st.session_state.keys = (private_pem, public_pem)

    if st.session_state.keys:
        private_pem, public_pem = st.session_state.keys
        with st.expander("🔓 Private Key"):
            st.code(private_pem)
            st.download_button("⬇️ Download Private Key", private_pem, file_name=f"private_key_{key_size}.pem")
            st.markdown(
                f"<button onclick="navigator.clipboard.writeText(`{private_pem}`)">📋 Copy Private Key</button>",
                unsafe_allow_html=True
            )
        with st.expander("🔑 Public Key"):
            st.code(public_pem)
            st.download_button("⬇️ Download Public Key", public_pem, file_name=f"public_key_{key_size}.pem")
            st.markdown(
                f"<button onclick="navigator.clipboard.writeText(`{public_pem}`)">📋 Copy Public Key</button>",
                unsafe_allow_html=True
            )
        st.info("💡 Simpan private key di tempat aman dan jangan dibagikan.")

# Tab 2: Encrypt + Sign
def tab2_encrypt_sign():
    st.header("✉️ Kirim Pesan Aman (Encrypt + Sign)")
    input_mode = st.radio("Pilih input:", ["Teks", "File"])
    message_bytes, filename = None, None

    if input_mode == "Teks":
        message = st.text_area("Tulis pesan:")
        if message:
            message_bytes = message.encode()
    else:
        uploaded = st.file_uploader("Upload file untuk dienkripsi", type=None)
        if uploaded:
            message_bytes = uploaded.read()
            filename = uploaded.name

    # Public key recipient
    pub_method = st.radio("Public Key Penerima:", ["Upload File", "Paste Manual"])
    if pub_method == "Upload File":
        pub_file = st.file_uploader("Public Key (.pem)", type=["pem"], key="pub2")
        pub_data = pub_file.read() if pub_file else None
    else:
        pub_text = st.text_area("Paste isi public key (.pem):")
        pub_data = pub_text.encode() if pub_text else None

    # Private key sender
    priv_method = st.radio("Private Key Pengirim:", ["Upload File", "Paste Manual"])
    if priv_method == "Upload File":
        priv_file = st.file_uploader("Private Key (.pem)", type=["pem"], key="priv2")
        priv_data = priv_file.read() if priv_file else None
    else:
        priv_text = st.text_area("Paste isi private key (.pem):")
        priv_data = priv_text.encode() if priv_text else None

    if st.button("🔒 Enkripsi & Tanda Tangan"):
        if message_bytes and pub_data and priv_data:
            public_key = serialization.load_pem_public_key(pub_data)
            private_key = serialization.load_pem_private_key(priv_data, password=None)
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
                st.success("✅ Pesan terenkripsi dan ditandatangani!")
                st.text_area("Encrypted Payload (JSON)", json.dumps(payload), height=300)
            else:
                out_name = filename + ".enc"
                bio = io.BytesIO()
                bio.write(json.dumps(payload).encode())
                bio.seek(0)
                st.download_button("⬇️ Download File .enc", bio, file_name=out_name)
            st.info("💡 Kirim data di atas tanpa mengubah isinya. Pastikan penerima punya private key yang sesuai.")
        else:
            st.warning("Lengkapi semua input dan kunci.")

# Tab 3: Decrypt + Verify
def tab3_decrypt_verify():
    st.header("📥 Terima Pesan Aman (Decrypt & Verify)")
    input_mode = st.radio("Pilih input terenkripsi:", ["Upload File .enc", "Paste Encrypted Text"])
    enc_data = None
    enc_filename = None

    if input_mode == "Upload File .enc":
        enc_file = st.file_uploader("Upload .enc file", type=["enc"])
        if enc_file:
            enc_filename = enc_file.name
            enc_data = enc_file.read().decode()
    else:
        enc_data = st.text_area("Paste encrypted JSON:")

    # Private key recipient
    priv_method = st.radio("Private Key Anda:", ["Upload File", "Paste Manual"])
    if priv_method == "Upload File":
        priv_file = st.file_uploader("Private Key (.pem)", type=["pem"], key="priv3")
        priv_data = priv_file.read() if priv_file else None
    else:
        priv_text = st.text_area("Paste isi private key (.pem):")
        priv_data = priv_text.encode() if priv_text else None

    # Public key sender (optional)
    pub_opt = st.radio("Public Key Pengirim (opsional):", ["Tidak diberikan", "Upload File", "Paste Manual"])
    pub_data = None
    if pub_opt == "Upload File":
        pubf = st.file_uploader("Public Key (.pem)", type=["pem"], key="pub3")
        if pubf: pub_data = pubf.read()
    elif pub_opt == "Paste Manual":
        pubt = st.text_area("Paste isi public key pengirim (.pem):")
        if pubt: pub_data = pubt.encode()

    if st.button("🔓 Dekripsi & Verifikasi"):
        if enc_data and priv_data:
            try:
                payload = json.loads(enc_data)
                encrypted_key = base64.b64decode(payload["encrypted_key"])
                signature = base64.b64decode(payload["signature"])
                encrypted_message = base64.b64decode(payload["encrypted_message"])

                private_key = serialization.load_pem_private_key(priv_data, password=None)
                key_iv = rsa_decrypt_key(encrypted_key, private_key)
                aes_key, iv = key_iv[:32], key_iv[32:]
                decrypted = decrypt_message_aes(encrypted_message, aes_key, iv)

                st.success("✅ Pesan berhasil didekripsi!")

                # Verify signature
                if pub_data:
                    try:
                        public_key = serialization.load_pem_public_key(pub_data)
                        rsa_verify_signature(decrypted, signature, public_key)
                        st.success("✅ Signature VALID")
                    except:
                        st.error("❌ Signature INVALID")
                else:
                    st.warning("⚠️ Public key pengirim tidak diberikan, verifikasi signature dilewati.")

                # Output decrypted
                try:
                    text = decrypted.decode()
                    st.text_area("📝 Pesan Asli:", text, height=250)
                except:
                    # file
                    name = enc_filename.rsplit(".enc",1)[0] if enc_filename else "decrypted_file"
                    st.download_button("⬇️ Download Decrypted File", decrypted, file_name=name)
            except Exception as e:
                st.error(f"Gagal memproses: {e}")
        else:
            st.warning("Tambahkan encrypted data dan private key Anda.")

# Sidebar navigation
tab = st.sidebar.radio("Navigasi", ["🔐 Generate Key", "✉️ Kirim Pesan", "📥 Terima Pesan"])
if tab == "🔐 Generate Key":
    tab1_keygen()
elif tab == "✉️ Kirim Pesan":
    tab2_encrypt_sign()
elif tab == "📥 Terima Pesan":
    tab3_decrypt_verify()
