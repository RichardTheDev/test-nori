import streamlit as st
import requests
import hashlib
import base64
from io import BytesIO
from PIL import Image
import subprocess
import tempfile
import os

# URL de l'API Certigna
BASE_URL = "https://timestamp.dhimyotis.com/api/v1/"

st.set_page_config(page_title="Horodatage Certigna d'images", layout="centered")

st.title("Horodatage d’images avec Certignaa")
st.markdown(
    """
Cette interface envoie vos données à l’API **Certigna Horodatage** via HTTPS en utilisant 
l’authentification Basic (identifiant + mot de passe de votre **crédentiel**, et non du compte admin).
"""
)

# --- Identifiants Certigna ---
st.subheader("Identifiants Certigna")
username = st.text_input("Identifiant du crédentiel")
password = st.text_input("Mot de passe du crédentiel", type="password")

st.caption(
    "Les identifiants sont ceux du **crédentiel** créé dans l’espace Certigna (menu « Crédentiels »)."
)

# --- Choix de la méthode ---
st.subheader("Type de certification")
mode = st.radio(
    "Choisissez ce que vous souhaitez obtenir :",
    (
        "Jeton d’horodatage du hash de l’image (.tsr)",
        "PDF horodaté généré à partir de l’image",
    ),
)

# --- Upload fichier ---
st.subheader("Image à horodater")
uploaded_file = st.file_uploader(
    "Déposez une image (PNG, JPG, etc.)", type=["png", "jpg", "jpeg", "tiff", "bmp", "gif"]
)

algo = "SHA256"  # SHA-256

def compute_hash(file_bytes: bytes, algorithm: str = "SHA256") -> str:
    if algorithm.upper() == "SHA256":
        return hashlib.sha256(file_bytes).hexdigest().upper()
    elif algorithm.upper() == "SHA384":
        return hashlib.sha384(file_bytes).hexdigest().upper()
    elif algorithm.upper() == "SHA512":
        return hashlib.sha512(file_bytes).hexdigest().upper()
    else:
        raise ValueError("Algorithme non supporté par cette interface.")

def decode_tsr_with_openssl(tsr_bytes: bytes) -> str:
    """
    Décode un token TSA (.tsr) via openssl ts -reply -text
    (si openssl n'est pas installé, on retourne un message clair)
    """
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".tsr") as f:
            f.write(tsr_bytes)
            tsr_path = f.name

        result = subprocess.run(
            ["openssl", "ts", "-reply", "-in", tsr_path, "-text"],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            return f"[OpenSSL ERROR]\n{result.stderr}"

        return result.stdout
    except FileNotFoundError:
        return "[OpenSSL] Commande 'openssl' introuvable sur la machine."
    except Exception as e:
        return f"[OpenSSL] Erreur pendant le décodage: {e}"
    finally:
        try:
            if "tsr_path" in locals() and os.path.exists(tsr_path):
                os.remove(tsr_path)
        except Exception:
            pass

def print_certigna_response(resp: requests.Response):
    """
    Affiche 'tout' ce que l'on peut afficher côté client :
    status, headers, content-type, taille, body texte (si lisible), body base64.
    """
    st.subheader("📡 Réponse Certigna (brute)")

    st.markdown("**Status code**")
    st.code(str(resp.status_code), language="text")

    st.markdown("**Headers**")
    st.json(dict(resp.headers))

    st.markdown("**Content-Type**")
    st.code(resp.headers.get("Content-Type", ""), language="text")

    st.markdown("**Body size (bytes)**")
    st.code(str(len(resp.content)), language="text")

    # Tentative d'affichage texte (si réponse textuelle)
    st.markdown("**Body (texte si décodable)**")
    try:
        txt = resp.content.decode("utf-8", errors="strict")
        st.text_area("Body texte", txt, height=140)
    except Exception:
        st.info("Body non UTF-8 (binaire) — normal pour TSR / PDF.")

    st.markdown("**Body (Base64)**")
    st.text_area(
        "Body base64",
        base64.b64encode(resp.content).decode("ascii"),
        height=180
    )

def timestamp_hash(hashed_message: str, algorithm: str, username: str, password: str) -> requests.Response:
    data = {
        "certReq": "true",
        "hashAlgorithm": algorithm,
        "hashedMessage": hashed_message,
    }

    resp = requests.post(
        BASE_URL,
        data=data,
        auth=(username, password),
        timeout=30,
    )
    return resp

def image_to_pdf_bytes(image_bytes: bytes) -> bytes:
    image = Image.open(BytesIO(image_bytes)).convert("RGB")
    buf = BytesIO()
    image.save(buf, format="PDF")
    return buf.getvalue()

def timestamp_pdf(pdf_bytes: bytes, username: str, password: str) -> requests.Response:
    files = {"file": ("document.pdf", pdf_bytes, "application/pdf")}

    resp = requests.post(
        BASE_URL,
        files=files,
        auth=(username, password),
        timeout=60,
    )
    return resp

st.write("---")

if st.button("Horodater l’image", disabled=not uploaded_file or not username or not password):
    if not uploaded_file:
        st.error("Merci de sélectionner une image.")
    elif not username or not password:
        st.error("Merci de saisir vos identifiants Certigna (crédentiel).")
    else:
        try:
            file_bytes = uploaded_file.read()

            st.info(f"Fichier reçu : **{uploaded_file.name}** – taille : {len(file_bytes)} octets")
            st.image(file_bytes, caption="Aperçu de l’image", use_column_width=True)

            if mode.startswith("Jeton"):
                # --- Horodatage du hash ---
                st.subheader("1. Calcul du hash de l’image")
                hashed = compute_hash(file_bytes, algo)
                st.code(hashed, language="text")

                st.subheader("2. Envoi à l’API Certigna (horodatage du hash)")
                resp = timestamp_hash(hashed, algo, username, password)

                # Affiche TOUT ce que Certigna renvoie côté HTTP
                print_certigna_response(resp)

                if resp.status_code != 200:
                    raise RuntimeError(f"Erreur API Certigna (hash) : {resp.status_code} - {resp.text}")

                token_bytes = resp.content
                st.success("Horodatage réussi – jeton d’horodatage reçu ✅")

                st.download_button(
                    label="📥 Télécharger le jeton d’horodatage (.tsr)",
                    data=token_bytes,
                    file_name=f"{uploaded_file.name}.tsr",
                    mime=resp.headers.get("Content-Type", "application/timestamp-reply"),
                )

                # Décodage OpenSSL (infos internes du token)
                st.subheader("🔎 Jeton TSA décodé (OpenSSL)")
                decoded = decode_tsr_with_openssl(token_bytes)
                st.text_area("Décodage OpenSSL", decoded, height=380)

            else:
                # --- Horodatage via PDF ---
                st.subheader("1. Conversion de l’image en PDF")
                pdf_bytes = image_to_pdf_bytes(file_bytes)
                st.write(f"PDF généré en mémoire – taille : {len(pdf_bytes)} octets")

                st.subheader("2. Envoi à l’API Certigna (PDF à horodater)")
                resp = timestamp_pdf(pdf_bytes, username, password)

                # Affiche TOUT ce que Certigna renvoie côté HTTP
                print_certigna_response(resp)

                if resp.status_code != 200:
                    raise RuntimeError(f"Erreur API Certigna (PDF) : {resp.status_code} - {resp.text}")

                stamped_pdf_bytes = resp.content
                st.success("Horodatage réussi – PDF horodaté reçu ✅")

                st.download_button(
                    label="📥 Télécharger le PDF horodaté",
                    data=stamped_pdf_bytes,
                    file_name=f"{uploaded_file.name.rsplit('.',1)[0]}_horodate.pdf",
                    mime=resp.headers.get("Content-Type", "application/pdf"),
                )

                st.markdown(
                    """
                    Ouvrez ce PDF dans **Adobe Acrobat Reader** ou un autre lecteur supportant
                    les signatures / tampons temporels pour visualiser les informations
                    de certification.
                    """
                )

        except Exception as e:
            st.error(f"Une erreur s’est produite : {e}")