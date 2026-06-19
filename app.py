from urllib.parse import urlparse
from email import message_from_bytes
from email.policy import default
from bs4 import BeautifulSoup
import tempfile
import os
import time
import base64
import requests
import re
from bs4 import BeautifulSoup

try:
    import extract_msg
@@ -36,7 +36,7 @@
VT_API_KEY = (os.getenv("VIRUSTOTAL_API_KEY") or "").strip()
URLSCAN_API_KEY = (os.getenv("URLSCAN_API_KEY") or "").strip()

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
MAX_FILE_SIZE = 5 * 1024 * 1024

ALLOWED_EXTENSIONS = {".pdf", ".jpg", ".jpeg", ".png", ".eml", ".msg"}
ALLOWED_CONTENT_TYPES = {
@@ -59,8 +59,10 @@ def normalizar_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    if url.startswith(("http://", "https://")):
        return url
    if url.startswith("www."):
        return "http://" + url
    return url


@@ -77,13 +79,34 @@ def extraer_urls(texto: Optional[str]) -> List[str]:
    for item in encontrados:
        url = item.strip().rstrip(".,;)")
        url = normalizar_url(url)
        if url and url not in vistos:
        if url.startswith(("http://", "https://")) and url not in vistos:
            vistos.add(url)
            urls_limpias.append(url)

    return urls_limpias


def extraer_links_html(html: str) -> List[str]:
    if not html:
        return []

    links = []
    vistos = set()

    try:
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            href = (a.get("href") or "").strip()
            href = normalizar_url(href)
            if href.startswith(("http://", "https://")) and href not in vistos:
                vistos.add(href)
                links.append(href)
    except Exception:
        pass

    return links


def extraer_dominio_de_email(remitente: Optional[str]) -> Optional[str]:
    if not remitente:
        return None
@@ -114,7 +137,9 @@ def limpiar_texto_html(texto: str) -> str:
    texto = re.sub(r"(?is)<style.*?>.*?</style>", " ", texto)
    texto = re.sub(r"(?is)<br\s*/?>", "\n", texto)
    texto = re.sub(r"(?is)</p>", "\n", texto)
    texto = re.sub(r"(?is)</div>", "\n", texto)
    texto = re.sub(r"(?is)<.*?>", " ", texto)
    texto = re.sub(r"&nbsp;", " ", texto)
    texto = re.sub(r"\s+", " ", texto)
    return texto.strip()

@@ -134,6 +159,7 @@ def extraer_texto_eml_desde_bytes(contenido: bytes) -> Dict[str, Any]:
        resultado["from"] = str(msg.get("from") or "").strip()

        partes_texto = []
        urls_html = []

        if msg.is_multipart():
            for part in msg.walk():
@@ -148,18 +174,23 @@ def extraer_texto_eml_desde_bytes(contenido: bytes) -> Dict[str, Any]:
                        texto = part.get_content()
                        if texto:
                            partes_texto.append(str(texto))

                    elif content_type == "text/html":
                        html = part.get_content()
                        if html:
                            partes_texto.append(limpiar_texto_html(str(html)))
                            html_str = str(html)
                            partes_texto.append(limpiar_texto_html(html_str))
                            urls_html.extend(extraer_links_html(html_str))
                except Exception:
                    continue
        else:
            try:
                contenido_simple = msg.get_content()
                if contenido_simple:
                    if msg.get_content_type() == "text/html":
                        partes_texto.append(limpiar_texto_html(str(contenido_simple)))
                        html_str = str(contenido_simple)
                        partes_texto.append(limpiar_texto_html(html_str))
                        urls_html.extend(extraer_links_html(html_str))
                    else:
                        partes_texto.append(str(contenido_simple))
            except Exception:
@@ -168,7 +199,7 @@ def extraer_texto_eml_desde_bytes(contenido: bytes) -> Dict[str, Any]:
        body = "\n".join([p for p in partes_texto if p]).strip()
        resultado["body"] = body

        urls = extraer_urls(
        urls_texto = extraer_urls(
            " ".join(
                [
                    resultado["subject"],
@@ -177,14 +208,23 @@ def extraer_texto_eml_desde_bytes(contenido: bytes) -> Dict[str, Any]:
                ]
            )
        )
        resultado["urls"] = urls

        urls_finales = []
        vistos = set()

        for u in urls_html + urls_texto:
            if u and u not in vistos:
                vistos.add(u)
                urls_finales.append(u)

        resultado["urls"] = urls_finales

        dominios = set()
        dom_from = extraer_dominio_de_email(resultado["from"])
        if dom_from:
            dominios.add(dom_from)

        for u in urls:
        for u in urls_finales:
            dom = extraer_dominio_de_url(u)
            if dom:
                dominios.add(dom)
@@ -196,7 +236,7 @@ def extraer_texto_eml_desde_bytes(contenido: bytes) -> Dict[str, Any]:
        return resultado


def extraer_texto_msg_desde_bytes(contenido: bytes, filename: str) -> Dict[str, Any]:
def extraer_texto_msg_desde_bytes(contenido: bytes) -> Dict[str, Any]:
    resultado = {
        "subject": "",
        "from": "",
@@ -221,7 +261,7 @@ def extraer_texto_msg_desde_bytes(contenido: bytes, filename: str) -> Dict[str,
        resultado["from"] = str(getattr(msg, "sender", "") or "").strip()
        resultado["body"] = str(getattr(msg, "body", "") or "").strip()

        urls = extraer_urls(
        urls_texto = extraer_urls(
            " ".join(
                [
                    resultado["subject"],
@@ -230,14 +270,15 @@ def extraer_texto_msg_desde_bytes(contenido: bytes, filename: str) -> Dict[str,
                ]
            )
        )
        resultado["urls"] = urls

        resultado["urls"] = urls_texto

        dominios = set()
        dom_from = extraer_dominio_de_email(resultado["from"])
        if dom_from:
            dominios.add(dom_from)

        for u in urls:
        for u in urls_texto:
            dom = extraer_dominio_de_url(u)
            if dom:
                dominios.add(dom)
@@ -268,7 +309,7 @@ async def extraer_datos_desde_archivo_correo(archivo: Optional[UploadFile]) -> O
        return extraer_texto_eml_desde_bytes(contenido)

    if filename.endswith(".msg"):
        return extraer_texto_msg_desde_bytes(contenido, archivo.filename)
        return extraer_texto_msg_desde_bytes(contenido)

    return None

@@ -838,10 +879,10 @@ async def analizar_correo(
            puntos += 2
            motivos.append(f"La URL {u} usa http en lugar de https.")

        if any(p in u_lower for p in ["login", "verifica", "cuenta"]):
        if any(p in u_lower for p in ["login", "verifica", "cuenta", "confirm"]):
            puntos += 2
            motivos.append(
                f"La URL {u} parece relacionada con inicio de sesión o verificación de cuenta."
                f"La URL {u} parece relacionada con inicio de sesión, verificación o confirmación."
            )

    for dominio in dominios_detectados:
