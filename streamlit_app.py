import streamlit as st
import requests
import hashlib
import base64
from io import BytesIO
from PIL import Image

# URL de l'API Certigna (doc PDF)
BASE_URL = "https://timestamp.dhimyotis.com/api/v1/"

st.set_page_config(page_title="Horodatage Certigna d'images", layout="centered")

st.title("Horodatage d’images avec Certigna")
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

algo = "SHA256"  # on fixe SHA-256 (supporté par l’API)  [oai_citation:2‡API_Service_Horodatage_Certigna_2024 (1) 3.pdf](sediment://file_0000000053247243b39141f74aa493f4)

def compute_hash(file_bytes: bytes, algorithm: str = "SHA256") -> str:
    """Calcule le hash hexadécimal du fichier."""
    if algorithm.upper() == "SHA256":
        return hashlib.sha256(file_bytes).hexdigest().upper()
    elif algorithm.upper() == "SHA384":
        return hashlib.sha384(file_bytes).hexdigest().upper()
    elif algorithm.upper() == "SHA512":
        return hashlib.sha512(file_bytes).hexdigest().upper()
    else:
        raise ValueError("Algorithme non supporté par cette interface.")


def timestamp_hash(hashed_message: str, algorithm: str, username: str, password: str) -> bytes:
    """
    Appelle l'API Certigna pour horodater un hash.
    Envoie une requête x-www-form-urlencoded comme indiqué dans la doc.  [oai_citation:3‡API_Service_Horodatage_Certigna_2024 (1) 3.pdf](sediment://file_0000000053247243b39141f74aa493f4)
    """
    data = {
        "certReq": "true",          # on demande l'inclusion du certificat de l’UH
        "hashAlgorithm": algorithm, # SHA256 / SHA384 / SHA512
        "hashedMessage": hashed_message,
    }

    response = requests.post(
        BASE_URL,
        data=data,
        auth=(username, password),  # Basic Auth
        timeout=30,
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"Erreur API Certigna (hash) : {response.status_code} - {response.text}"
        )

    # Contenu de type application/timestamp-reply (jeton .tsr)  [oai_citation:4‡API_Service_Horodatage_Certigna_2024 (1) 3.pdf](sediment://file_0000000053247243b39141f74aa493f4)
    return response.content


def image_to_pdf_bytes(image_bytes: bytes) -> bytes:
    """Convertit une image en PDF (une page) en mémoire."""
    image = Image.open(BytesIO(image_bytes)).convert("RGB")
    buf = BytesIO()
    image.save(buf, format="PDF")
    return buf.getvalue()


def timestamp_pdf(pdf_bytes: bytes, username: str, password: str) -> bytes:
    """
    Appelle l'API Certigna pour horodater un PDF.
    Envoie un multipart/form-data avec le champ 'file', comme dans l’exemple curl.  [oai_citation:5‡API_Service_Horodatage_Certigna_2024 (1) 3.pdf](sediment://file_0000000053247243b39141f74aa493f4)
    """
    files = {
        "file": ("document.pdf", pdf_bytes, "application/pdf")
    }

    response = requests.post(
        BASE_URL,
        files=files,
        auth=(username, password),
        timeout=60,
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"Erreur API Certigna (PDF) : {response.status_code} - {response.text}"
        )

    # Contenu : le PDF horodaté (application/pdf)  [oai_citation:6‡API_Service_Horodatage_Certigna_2024 (1) 3.pdf](sediment://file_0000000053247243b39141f74aa493f4)
    return response.content


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
                token_bytes = timestamp_hash(hashed, algo, username, password)

                st.success("Horodatage réussi – jeton d’horodatage reçu ✅")

                st.download_button(
                    label="📥 Télécharger le jeton d’horodatage (.tsr)",
                    data=token_bytes,
                    file_name=f"{uploaded_file.name}.tsr",
                    mime="application/timestamp-reply",
                )

                st.subheader("Jeton encodé en Base64 (pour archivage / logs)")
                st.text_area(
                    "Jeton (.tsr) encodé en Base64",
                    value=base64.b64encode(token_bytes).decode("ascii"),
                    height=150,
                )

                st.subheader("Vérifier le jeton avec OpenSSL (optionnel)")
                st.markdown(
                    """
                    Exemple de commande (si vous avez `openssl` installé) :

                    ```bash
                    # Vérifier que le jeton correspond bien au fichier original
                    openssl ts -verify \\
                        -CAfile trusted_certs.pem \\
                        -data IMAGE_ORIGINALE.ext \\
                        -in JETON.tsr -token_in
                    ```
                    """
                )

            else:
                # --- Horodatage via PDF ---
                st.subheader("1. Conversion de l’image en PDF")
                pdf_bytes = image_to_pdf_bytes(file_bytes)
                st.write(f"PDF généré en mémoire – taille : {len(pdf_bytes)} octets")

                st.subheader("2. Envoi à l’API Certigna (PDF à horodater)")
                stamped_pdf_bytes = timestamp_pdf(pdf_bytes, username, password)

                st.success("Horodatage réussi – PDF horodaté reçu ✅")

                st.download_button(
                    label="📥 Télécharger le PDF horodaté",
                    data=stamped_pdf_bytes,
                    file_name=f"{uploaded_file.name.rsplit('.',1)[0]}_horodate.pdf",
                    mime="application/pdf",
                )

                st.markdown(
                    """
                    Ouvrez ce PDF dans **Adobe Acrobat Reader** ou un autre lecteur supportant
                    les signatures / tampons temporels pour visualiser les informations
                    de certification de l’horodatage.
                    """
                )

        except Exception as e:
            st.error(f"Une erreur s’est produite : {e}")