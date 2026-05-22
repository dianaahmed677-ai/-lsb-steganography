"""
LSB Steganography Web App — enhanced UI
Run: streamlit run app.py
"""

import cv2
import numpy as np
import streamlit as st
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

from LSBSteg import LSBSteg, SteganographyException

_SALT_LEN = 16
_NONCE_LEN = 16
_TAG_LEN = 16
_PBKDF2_ITERATIONS = 100_000
_AES_OVERHEAD = _SALT_LEN + _NONCE_LEN + _TAG_LEN + 16  # approximate GCM overhead
_HEADER_BITS = 64  # encode_binary length prefix


def inject_custom_css():
    st.markdown(
        """
        <style>
        .main-header {
            background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 50%, #2563eb 100%);
            padding: 1.5rem 2rem;
            border-radius: 12px;
            margin-bottom: 1.5rem;
            color: white;
        }
        .main-header h1 { color: white !important; margin: 0; font-size: 1.75rem; }
        .main-header p { color: #e0e7ff !important; margin: 0.5rem 0 0 0; opacity: 0.95; }
        .metric-card {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 10px;
            padding: 0.75rem 1rem;
        }
        div[data-testid="stSidebar"] {
            background: linear-gradient(180deg, #0f172a 0%, #1e293b 100%);
        }
        .stDownloadButton button {
            background: linear-gradient(90deg, #059669, #10b981) !important;
            color: white !important;
            border: none !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def encrypt_message(message: str, password: str) -> bytes:
    if not password:
        raise ValueError("Password is required.")
    salt = get_random_bytes(_SALT_LEN)
    key = PBKDF2(password.encode("utf-8"), salt, dkLen=32, count=_PBKDF2_ITERATIONS, hmac_hash_module=SHA256)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode("utf-8"))
    return salt + cipher.nonce + tag + ciphertext


def decrypt_message(data: bytes, password: str) -> str:
    if not password:
        raise ValueError("Password is required.")
    min_len = _SALT_LEN + _NONCE_LEN + _TAG_LEN
    if len(data) < min_len:
        raise ValueError("Hidden data is too short or corrupted.")
    salt = data[:_SALT_LEN]
    nonce = data[_SALT_LEN : _SALT_LEN + _NONCE_LEN]
    tag = data[_SALT_LEN + _NONCE_LEN : min_len]
    ciphertext = data[min_len:]
    key = PBKDF2(password.encode("utf-8"), salt, dkLen=32, count=_PBKDF2_ITERATIONS, hmac_hash_module=SHA256)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")


def read_uploaded_image(uploaded_file) -> np.ndarray:
    raw = uploaded_file.getvalue()
    arr = np.frombuffer(raw, dtype=np.uint8)
    image = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if image is None:
        raise ValueError("Could not read the image. Use PNG or BMP.")
    return image


def estimate_capacity_bytes(image: np.ndarray) -> int:
    """Rough max payload (1 LSB per channel bit) minus header."""
    h, w, c = image.shape
    total_bits = w * h * c
    return max(0, (total_bits - _HEADER_BITS) // 8)


def encode_into_image(carrier: np.ndarray, payload: bytes) -> np.ndarray:
    steg = LSBSteg(carrier.copy())
    return steg.encode_binary(payload)


def decode_from_image(stego: np.ndarray) -> bytes:
    steg = LSBSteg(stego)
    return steg.decode_binary()


def image_to_png_bytes(image: np.ndarray) -> bytes:
    ok, buf = cv2.imencode(".png", image)
    if not ok:
        raise ValueError("Failed to encode output image as PNG.")
    return buf.tobytes()


def bgr_to_rgb(img: np.ndarray) -> np.ndarray:
    return cv2.cvtColor(img, cv2.COLOR_BGR2RGB)


def render_header():
    st.markdown(
        """
        <div class="main-header">
            <h1>🔐 LSB Steganography Studio</h1>
            <p>Hide AES-encrypted secrets inside images · إخفاء رسائل مشفّرة داخل الصور</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def show_image_metrics(image: np.ndarray, label: str):
    h, w, c = image.shape
    cap = estimate_capacity_bytes(image)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Width", f"{w} px")
    c2.metric("Height", f"{h} px")
    c3.metric("Channels", c)
    c4.metric("Max capacity", f"~{cap:,} B", help="Approx. for 1 LSB per channel")


def sidebar_content():
    st.header("📖 Guide")
    st.markdown(
        """
        **Steps**
        1. Encrypt message (AES + password)
        2. Embed in image (LSB)
        3. Download **PNG**
        4. Later: upload PNG + password → extract

        **Rules**
        - Use **PNG** for output
        - Same password to decrypt
        - Larger image = more capacity
        """
    )
    with st.expander("FAQ"):
        st.markdown(
            """
            **Why PNG?**  
            JPEG compression destroys hidden bits.

            **Wrong password?**  
            Decryption fails — you will see an error.

            **Image too small?**  
            Use a bigger carrier or shorter message.
            """
        )
    st.divider()
    st.caption("Core: `LSBSteg` class (unchanged algorithm)")


def tab_hide():
    st.markdown("### 📥 Hide secret message")
    carrier_file = st.file_uploader(
        "Carrier image",
        type=["png", "bmp", "jpg", "jpeg"],
        help="Original image that will hold the secret",
    )

    if carrier_file:
        carrier = read_uploaded_image(carrier_file)
        st.session_state["carrier_preview"] = carrier
        show_image_metrics(carrier, "carrier")
        st.image(bgr_to_rgb(carrier), caption="Carrier preview", use_container_width=True)
        if carrier_file.name.lower().endswith((".jpg", ".jpeg")):
            st.warning("JPEG input is OK for encoding, but always **download PNG** as output.")

    message = st.text_area(
        "Secret message",
        height=120,
        placeholder="Type your secret message here...",
        max_chars=50000,
    )
    if message:
        st.caption(f"Characters: {len(message)}")

    password = st.text_input("Encryption password", type="password", key="pw_hide")
    if password:
        strength = "Strong" if len(password) >= 8 else "Weak — use 8+ characters"
        st.caption(f"Password: {strength}")

    col_btn, col_clr = st.columns([3, 1])
    with col_btn:
        hide_clicked = st.button("🔒 Hide message in image", type="primary", use_container_width=True)
    with col_clr:
        if st.button("Clear", use_container_width=True):
            for k in ("stego_png", "stego_preview", "carrier_preview", "last_message"):
                st.session_state.pop(k, None)
            st.rerun()

    if hide_clicked:
        if not carrier_file:
            st.error("Upload a carrier image first.")
        elif not message.strip():
            st.error("Enter a secret message.")
        elif not password:
            st.error("Enter a password.")
        else:
            try:
                carrier = read_uploaded_image(carrier_file)
                encrypted = encrypt_message(message.strip(), password)
                cap = estimate_capacity_bytes(carrier)
                if len(encrypted) > cap:
                    st.error(
                        f"Payload too large ({len(encrypted):,} bytes). "
                        f"Image capacity ~{cap:,} bytes. Use a larger image or shorter message."
                    )
                else:
                    with st.spinner("Encrypting and embedding..."):
                        stego = encode_into_image(carrier, encrypted)
                        png_bytes = image_to_png_bytes(stego)
                    st.session_state["stego_png"] = png_bytes
                    st.session_state["stego_preview"] = stego
                    st.session_state["last_message"] = message.strip()
                    st.session_state["payload_size"] = len(encrypted)
                    st.success("Done! Message hidden and encrypted inside the image.")
            except SteganographyException as e:
                st.error(f"Image capacity exceeded: {e}")
            except Exception as e:
                st.error(str(e))

    if "stego_preview" in st.session_state:
        st.divider()
        st.markdown("#### ✅ Result")
        m1, m2, m3 = st.columns(3)
        m1.metric("Payload size", f"{st.session_state.get('payload_size', 0):,} B")
        m2.metric("Format", "PNG")
        m3.metric("Status", "Ready")

        c_before, c_after = st.columns(2)
        if "carrier_preview" in st.session_state:
            with c_before:
                st.image(bgr_to_rgb(st.session_state["carrier_preview"]), caption="Before", use_container_width=True)
        with c_after:
            st.image(bgr_to_rgb(st.session_state["stego_preview"]), caption="After (stego)", use_container_width=True)

        st.download_button(
            label="⬇️ Download stego image (PNG)",
            data=st.session_state["stego_png"],
            file_name="stego_secret.png",
            mime="image/png",
            use_container_width=True,
        )


def tab_extract():
    st.markdown("### 📤 Extract secret message")
    stego_file = st.file_uploader(
        "Stego image (PNG)",
        type=["png", "bmp"],
        help="The image you downloaded after hiding data",
    )

    if stego_file:
        stego = read_uploaded_image(stego_file)
        show_image_metrics(stego, "stego")
        st.image(bgr_to_rgb(stego), caption="Stego preview", use_container_width=True)

    password_extract = st.text_input("Decryption password", type="password", key="pw_extract")

    if st.button("🔓 Extract message", type="primary", use_container_width=True):
        if not stego_file:
            st.error("Upload the stego image.")
        elif not password_extract:
            st.error("Enter the password.")
        else:
            try:
                with st.spinner("Extracting and decrypting..."):
                    stego = read_uploaded_image(stego_file)
                    raw = decode_from_image(stego)
                    plain = decrypt_message(raw, password_extract)
                st.success("Message recovered successfully!")
                st.text_area("Extracted message", value=plain, height=180)
                st.download_button(
                    "⬇️ Download message as .txt",
                    data=plain.encode("utf-8"),
                    file_name="extracted_message.txt",
                    mime="text/plain",
                )
            except ValueError as e:
                st.error(str(e))
            except SteganographyException as e:
                st.error(f"Could not read hidden data: {e}")
            except Exception:
                st.error("Decryption failed. Check password and use the correct PNG file.")


def tab_about():
    st.markdown("### About this project")
    st.markdown(
        """
        This web app extends the **LSB Steganography** project with:

        | Layer | Technology |
        |-------|------------|
        | Hiding | Least Significant Bit (`LSBSteg`) |
        | Encryption | AES-GCM + PBKDF2 password key |
        | Interface | Streamlit |

        **Pipeline:** Message → AES encrypt → LSB embed → PNG image → (reverse to read)

        **Academic use:** Cyber security / information hiding coursework.
        """
    )
    st.info("For CLI usage: `python LSBSteg.py encode ...` / `decode ...` — see README.md")


def main():
    st.set_page_config(
        page_title="LSB Steganography Studio",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    inject_custom_css()
    sidebar_content()
    render_header()

    tab1, tab2, tab3 = st.tabs(["🔒 Hide", "🔓 Extract", "ℹ️ About"])

    with tab1:
        tab_hide()
    with tab2:
        tab_extract()
    with tab3:
        tab_about()

    st.divider()
    st.caption("LSB Steganography · Diana Ahmed Ramadan · TM471 · Educational project")


if __name__ == "__main__":
    main()
