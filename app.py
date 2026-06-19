from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List, Dict, Any, Set
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

try:
    import extract_msg
except ImportError:
    extract_msg = None

app = FastAPI()

origins = [
    "https://analizador-correos.pracegar.vercel.app",
    "http://localhost:3000",
    "http://localhost:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

VT_API_KEY = (os.getenv("VIRUSTOTAL_API_KEY") or "").strip()
URLSCAN_API_KEY = (os.getenv("URLSCAN_API_KEY") or "").strip()

MAX_FILE_SIZE = 5 * 1024 * 1024

ALLOWED_EXTENSIONS = {".pdf", ".jpg", ".jpeg", ".png", ".eml", ".msg"}
ALLOWED_CONTENT_TYPES = {
    "application/pdf",
    "image/jpeg",
    "image/jpg",
    "image/png",
    "message/rfc822",
    "application/vnd.ms-outlook",
    "application/octet-stream",
}


def obtener_url_id_vt(url: str) -> str:
    url_bytes = url.encode("utf-8")
    return base64.urlsafe_b64encode(url_bytes).decode("utf-8").strip("=")


def normalizar_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if url.startswith(("http://", "https://")):
        return url
    if url.startswith("www."):
        return "http://" + url
    return url


def extraer_urls(texto: Optional[str]) -> List[str]:
    if not texto:
        return []

    patron = r'(https?://[^\s<>"\'()]+|www\.[^\s<>"\'()]+)'
    encontrados = re.findall(patron, texto, flags=re.IGNORECASE)

    urls_limpias = []
    vistos = set()

    for item in encontrados:
        url = item.strip().rstrip(".,;)")
        url = normalizar_url(url)
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

    match = re.search(r'([a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}))', remitente)
    if not match:
        return None

    dominio = match.group(2).lower().strip()
    return dominio or None


def extraer_dominio_de_url(url: str) -> Optional[str]:
    try:
        parsed = urlparse(url)
        dominio = (parsed.netloc or "").lower().strip()
        if dominio.startswith("www."):
            dominio = dominio[4:]
        return dominio or None
    except Exception:
        return None


def limpiar_texto_html(texto: str) -> str:
    if not texto:
        return ""
    texto = re.sub(r"(?is)<script.*?>.*?</script>", " ", texto)
    texto = re.sub(r"(?is)<style.*?>.*?</style>", " ", texto)
    texto = re.sub(r"(?is)<br\s*/?>", "\n", texto)
    texto = re.sub(r"(?is)</p>", "\n", texto)
    texto = re.sub(r"(?is)</div>", "\n", texto)
    texto = re.sub(r"(?is)<.*?>", " ", texto)
    texto = re.sub(r"&nbsp;", " ", texto)
    texto = re.sub(r"\s+", " ", texto)
    return texto.strip()


def recortar_texto(texto: str, max_len: int = 140) -> str:
    texto = (texto or "").strip()
    if len(texto) <= max_len:
        return texto
    return texto[:max_len].rstrip() + "..."


def generar_resumen_usuario(
    riesgo: str,
    remitente: str,
    urls_detectadas: List[str],
    archivo_info: Optional[Dict[str, Any]],
    archivo_extraido: Optional[Dict[str, Any]],
    puntos: int
) -> List[str]:
    resumen = []

    if riesgo == "alto":
        resumen.append("Este correo presenta varias señales de riesgo y se recomienda no interactuar con enlaces ni adjuntos.")
    elif riesgo == "medio":
        resumen.append("Este correo presenta algunas señales de precaución y conviene revisarlo antes de confiar en su contenido.")
    else:
        resumen.append("No se detectaron señales fuertes de riesgo, pero igual conviene revisar el mensaje con atención.")

    dominio_remitente = extraer_dominio_de_email(remitente)
    if dominio_remitente:
        resumen.append(f"El remitente visible pertenece al dominio {dominio_remitente}.")

    if urls_detectadas:
        if len(urls_detectadas) == 1:
            resumen.append("Se detectó 1 enlace en el correo o en el adjunto.")
        else:
            resumen.append(f"Se detectaron {len(urls_detectadas)} enlaces en el correo o en el adjunto.")

        url_sospechosa = next(
            (
                u for u in urls_detectadas
                if any(p in u.lower() for p in ["login", "verifica", "cuenta", "confirm"])
            ),
            None
        )
        if url_sospechosa:
            resumen.append("Al menos uno de los enlaces parece de confirmación, verificación o acceso a cuenta.")

    if archivo_info:
        resumen.append(f"Se analizó un archivo adjunto válido: {archivo_info.get('filename', 'archivo')}.")

    if archivo_extraido and archivo_extraido.get("from"):
        resumen.append("Se pudo extraer información interna del correo adjunto para enriquecer el análisis.")

    if puntos >= 6:
        resumen.append("La recomendación es tratar este mensaje como sospechoso hasta validarlo por otro medio.")

    return resumen[:5]


def analizar_url_con_virustotal(url: str) -> Dict[str, Any]:
    resultado = {
        "usada": False,
        "ok": False,
        "detalle": "",
        "motivos": [],
        "stats": {},
        "risk_points": 0,
    }

    if not VT_API_KEY:
        resultado["detalle"] = "No existe VIRUSTOTAL_API_KEY en variables de entorno."
        return resultado

    headers = {
        "x-apikey": VT_API_KEY,
        "accept": "application/json",
    }

    try:
        submit = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=30,
        )

        resultado["usada"] = True

        if submit.status_code not in [200, 202]:
            resultado["detalle"] = f"VirusTotal devolvió status {submit.status_code} al enviar la URL."
            return resultado

        url_id = obtener_url_id_vt(url)

        for _ in range(5):
            report = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
                timeout=30,
            )

            if report.status_code == 200:
                data = report.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)

                resultado["ok"] = True
                resultado["stats"] = stats
                resultado["detalle"] = "VirusTotal respondió correctamente para la URL."

                if malicious > 0:
                    resultado["risk_points"] = 6
                    resultado["motivos"].append(
                        f"VirusTotal marcó la URL como maliciosa en {malicious} motores."
                    )
                elif suspicious > 0:
                    resultado["risk_points"] = 3
                    resultado["motivos"].append(
                        f"VirusTotal marcó la URL como sospechosa en {suspicious} motores."
                    )
                else:
                    resultado["risk_points"] = 0
                    resultado["motivos"].append(
                        f"VirusTotal respondió sin detecciones claras para la URL (harmless: {harmless}, undetected: {undetected})."
                    )

                return resultado

            time.sleep(3)

        resultado["detalle"] = "VirusTotal aceptó la URL, pero no devolvió reporte listo a tiempo."
        return resultado

    except Exception as e:
        resultado["detalle"] = f"Error consultando VirusTotal URL: {str(e)}"
        return resultado


def analizar_dominio_con_virustotal(dominio: str) -> Dict[str, Any]:
    resultado = {
        "usada": False,
        "ok": False,
        "detalle": "",
        "motivos": [],
        "stats": {},
        "risk_points": 0,
    }

    if not VT_API_KEY:
        resultado["detalle"] = "No existe VIRUSTOTAL_API_KEY en variables de entorno."
        return resultado

    headers = {
        "x-apikey": VT_API_KEY,
        "accept": "application/json",
    }

    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{dominio}",
            headers=headers,
            timeout=30,
        )

        resultado["usada"] = True

        if resp.status_code != 200:
            resultado["detalle"] = f"VirusTotal devolvió status {resp.status_code} al consultar el dominio."
            return resultado

        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        resultado["ok"] = True
        resultado["stats"] = stats
        resultado["detalle"] = "VirusTotal respondió correctamente para el dominio."

        if malicious > 0:
            resultado["risk_points"] = 4
            resultado["motivos"].append(
                f"VirusTotal marcó el dominio {dominio} como malicioso en {malicious} motores."
            )
        elif suspicious > 0:
            resultado["risk_points"] = 2
            resultado["motivos"].append(
                f"VirusTotal marcó el dominio {dominio} como sospechoso en {suspicious} motores."
            )
        else:
            resultado["risk_points"] = 0
            resultado["motivos"].append(
                f"VirusTotal respondió sin detecciones claras para el dominio {dominio} (harmless: {harmless}, undetected: {undetected})."
            )

        return resultado

    except Exception as e:
        resultado["detalle"] = f"Error consultando VirusTotal dominio: {str(e)}"
        return resultado


def analizar_url_con_urlscan(url: str) -> Dict[str, Any]:
    resultado = {
        "usada": False,
        "ok": False,
        "detalle": "",
        "motivos": [],
        "uuid": None,
        "score": None,
        "risk_points": 0,
    }

    if not URLSCAN_API_KEY:
        resultado["detalle"] = "No existe URLSCAN_API_KEY en variables de entorno."
        return resultado

    headers = {
        "API-Key": URLSCAN_API_KEY,
        "Content-Type": "application/json",
    }

    try:
        submit = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json={
                "url": url,
                "visibility": "public",
            },
            timeout=30,
        )

        resultado["usada"] = True

        if submit.status_code != 200:
            resultado["detalle"] = f"urlscan.io devolvió status {submit.status_code} al enviar la URL."
            return resultado

        submit_data = submit.json()
        uuid = submit_data.get("uuid")
        resultado["uuid"] = uuid

        if not uuid:
            resultado["detalle"] = "urlscan.io no devolvió UUID."
            return resultado

        for _ in range(8):
            result = requests.get(
                f"https://urlscan.io/api/v1/result/{uuid}/",
                headers={"API-Key": URLSCAN_API_KEY},
                timeout=30,
            )

            if result.status_code == 200:
                data = result.json()
                verdicts = data.get("verdicts", {})
                overall = verdicts.get("overall", {})
                brands = verdicts.get("brands", [])
                malicious = overall.get("malicious", False)
                score = overall.get("score", 0)

                resultado["ok"] = True
                resultado["score"] = score
                resultado["detalle"] = "urlscan.io respondió correctamente."

                if malicious:
                    resultado["risk_points"] = 5
                    resultado["motivos"].append(
                        f"urlscan.io marcó la página como potencialmente maliciosa (score {score})."
                    )
                elif score and score > 0:
                    resultado["risk_points"] = 2
                    resultado["motivos"].append(
                        f"urlscan.io detectó señales de riesgo en la página (score {score})."
                    )
                else:
                    resultado["risk_points"] = 0
                    resultado["motivos"].append(
                        "urlscan.io respondió sin señales fuertes de riesgo."
                    )

                if brands:
                    resultado["motivos"].append(
                        f"urlscan.io detectó posible relación con marcas: {', '.join(brands[:3])}."
                    )

                return resultado

            time.sleep(5)

        resultado["detalle"] = "urlscan.io aceptó la URL, pero no devolvió resultado listo a tiempo."
        return resultado

    except Exception as e:
        resultado["detalle"] = f"Error consultando urlscan.io: {str(e)}"
        return resultado


async def analizar_archivo_con_virustotal(archivo: UploadFile) -> Dict[str, Any]:
    resultado = {
        "usada": False,
        "ok": False,
        "detalle": "",
        "motivos": [],
        "analysis_id": None,
        "sha256": None,
        "stats": {},
        "risk_points": 0,
        "status": None,
        "intentos": 0,
    }

    if not VT_API_KEY:
        resultado["detalle"] = "No existe VIRUSTOTAL_API_KEY en variables de entorno."
        return resultado

    headers = {
        "x-apikey": VT_API_KEY,
        "accept": "application/json",
    }

    try:
        contenido = await archivo.read()
        await archivo.seek(0)

        files = {
            "file": (
                archivo.filename,
                contenido,
                archivo.content_type or "application/octet-stream",
            )
        }

        submit = requests.post(
            "https://www.virustotal.com/api/v3/files",
            headers=headers,
            files=files,
            timeout=60,
        )

        resultado["usada"] = True

        if submit.status_code not in [200, 202]:
            resultado["detalle"] = f"VirusTotal devolvió status {submit.status_code} al subir el archivo."
            return resultado

        submit_data = submit.json()
        analysis_id = submit_data.get("data", {}).get("id")
        resultado["analysis_id"] = analysis_id

        if not analysis_id:
            resultado["detalle"] = "VirusTotal no devolvió analysis_id para el archivo."
            return resultado

        max_intentos = 15
        espera_segundos = 6

        for intento in range(1, max_intentos + 1):
            resultado["intentos"] = intento

            analysis_resp = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=30,
            )

            if analysis_resp.status_code != 200:
                resultado["detalle"] = (
                    f"VirusTotal devolvió status {analysis_resp.status_code} al consultar "
                    f"el análisis del archivo."
                )
                return resultado

            analysis_data = analysis_resp.json()
            attrs = analysis_data.get("data", {}).get("attributes", {})
            status = attrs.get("status")
            resultado["status"] = status

            if status == "completed":
                item_resp = requests.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}/item",
                    headers=headers,
                    timeout=30,
                )

                if item_resp.status_code != 200:
                    resultado["detalle"] = (
                        "VirusTotal completó el análisis del archivo, pero no devolvió "
                        "el reporte final."
                    )
                    return resultado

                item_data = item_resp.json()
                item_attrs = item_data.get("data", {}).get("attributes", {})
                stats = item_attrs.get("last_analysis_stats", {})
                sha256 = item_attrs.get("sha256")
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)

                resultado["ok"] = True
                resultado["sha256"] = sha256
                resultado["stats"] = stats
                resultado["detalle"] = "VirusTotal respondió correctamente para el archivo."

                if malicious > 0:
                    resultado["risk_points"] = 6
                    resultado["motivos"].append(
                        f"VirusTotal marcó el archivo como malicioso en {malicious} motores."
                    )
                elif suspicious > 0:
                    resultado["risk_points"] = 3
                    resultado["motivos"].append(
                        f"VirusTotal marcó el archivo como sospechoso en {suspicious} motores."
                    )
                else:
                    resultado["risk_points"] = 0
                    resultado["motivos"].append(
                        f"VirusTotal respondió sin detecciones claras para el archivo "
                        f"(harmless: {harmless}, undetected: {undetected})."
                    )

                return resultado

            if status in ["queued", "in-progress"]:
                if intento < max_intentos:
                    time.sleep(espera_segundos)
                    continue

                resultado["detalle"] = (
                    "VirusTotal aceptó el archivo, pero el análisis sigue pendiente "
                    f"({status}) después de varios intentos."
                )
                resultado["motivos"].append(
                    "El archivo fue enviado a VirusTotal, pero el análisis aún no finaliza."
                )
                return resultado

            resultado["detalle"] = (
                f"VirusTotal devolvió un estado no esperado para el archivo: {status}"
            )
            return resultado

        resultado["detalle"] = "VirusTotal no devolvió un resultado final para el archivo."
        return resultado

    except Exception as e:
        resultado["detalle"] = f"Error consultando VirusTotal archivo: {str(e)}"
        return resultado


def construir_motivos_visibles(
    riesgo: str,
    resumen_usuario: List[str],
    urls_detectadas: List[str],
    archivo_info: Optional[Dict[str, Any]],
) -> List[str]:
    visibles = []

    if riesgo == "alto":
        visibles.append("Se detectaron varias señales de riesgo en este correo.")
    elif riesgo == "medio":
        visibles.append("Se detectaron algunas señales que ameritan precaución.")
    else:
        visibles.append("No se detectaron señales fuertes de riesgo, pero conviene revisar el mensaje.")

    for linea in resumen_usuario:
        if linea not in visibles:
            visibles.append(linea)

    if urls_detectadas:
        visibles.append("Los detalles técnicos de enlaces y análisis externos están disponibles en Ver detalles.")

    if archivo_info:
        visibles.append("Los detalles técnicos del archivo adjunto están disponibles en Ver detalles.")

    return visibles[:5]


async def extraer_datos_desde_archivo_correo(archivo: Optional[UploadFile]) -> Optional[Dict[str, Any]]:
    if not archivo or not archivo.filename:
        return None

    filename = archivo.filename.lower().strip()
    contenido = await archivo.read()
    await archivo.seek(0)

    if filename.endswith(".eml"):
        return extraer_texto_eml_desde_bytes(contenido)

    if filename.endswith(".msg"):
        return extraer_texto_msg_desde_bytes(contenido)

    return None


async def validar_archivo(archivo: Optional[UploadFile]) -> Optional[Dict[str, Any]]:
    if not archivo or not archivo.filename:
        return None

    filename = archivo.filename.strip()
    filename_lower = filename.lower()

    extension = ""
    if "." in filename_lower:
        extension = "." + filename_lower.split(".")[-1]

    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Tipo de archivo no permitido. Solo se aceptan PDF, JPG, JPEG, PNG, EML o MSG."
        )

    content_type = (archivo.content_type or "").lower().strip()
    if content_type and content_type not in ALLOWED_CONTENT_TYPES:
        if extension != ".msg":
            raise HTTPException(
                status_code=400,
                detail=f"Tipo MIME no permitido: {content_type}"
            )

    contenido = await archivo.read()
    tamano = len(contenido)

    if tamano > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=400,
            detail="El archivo excede el tamaño máximo permitido de 5 MB."
        )

    await archivo.seek(0)

    return {
        "filename": filename,
        "content_type": content_type,
        "size_bytes": tamano,
        "extension": extension,
    }


@app.get("/")
async def root():
    return {"mensaje": "API de análisis de correos funcionando"}


@app.post("/analizar-correo")
async def analizar_correo(
    remitente: Optional[str] = Form(None),
    asunto: Optional[str] = Form(None),
    cuerpo: Optional[str] = Form(None),
    url: Optional[str] = Form(None),
    archivo: Optional[UploadFile] = File(None),
):
    motivos: List[str] = []
    puntos = 0

    urls_detectadas: List[str] = []
    dominios_detectados: Set[str] = set()

    debug_vt_urls = []
    debug_vt_dominios = []
    debug_urlscan_urls = []
    debug_vt_archivo = None
    debug_archivo_extraido = None

    dominios_internos = ["pracegar.com", "haceb.com"]

    remitente_limpio = (remitente or "").strip()
    asunto_limpio = (asunto or "").strip()
    cuerpo_limpio = (cuerpo or "").strip()
    url_limpia = normalizar_url((url or "").strip()) if url else ""

    archivo_info = await validar_archivo(archivo)
    archivo_extraido = await extraer_datos_desde_archivo_correo(archivo)
    debug_archivo_extraido = archivo_extraido

    if archivo_extraido:
        remitente_extraido = (archivo_extraido.get("from") or "").strip()
        asunto_extraido = (archivo_extraido.get("subject") or "").strip()
        cuerpo_extraido = (archivo_extraido.get("body") or "").strip()

        if not remitente_limpio and remitente_extraido:
            remitente_limpio = remitente_extraido

        if not asunto_limpio and asunto_extraido:
            asunto_limpio = asunto_extraido

        if not cuerpo_limpio and cuerpo_extraido:
            cuerpo_limpio = cuerpo_extraido

    dominio_remitente = extraer_dominio_de_email(remitente_limpio)
    if dominio_remitente:
        dominios_detectados.add(dominio_remitente)

        if dominio_remitente not in dominios_internos:
            puntos += 2
            motivos.append("El remitente no parece ser del dominio de la empresa.")

    if asunto_limpio:
        asunto_lower = asunto_limpio.lower()
        palabras_peligrosas = [
            "urgente",
            "bloqueo",
            "pago",
            "factura",
            "seguridad",
            "clave",
            "contraseña",
            "transferencia",
        ]
        if any(p in asunto_lower for p in palabras_peligrosas):
            puntos += 2
            motivos.append(
                "El asunto contiene palabras de urgencia o relacionadas con pagos/seguridad."
            )

    if cuerpo_limpio:
        cuerpo_lower = cuerpo_limpio.lower()
        if (
            "cambiar cuenta" in cuerpo_lower
            or "número de cuenta" in cuerpo_lower
            or "datos bancarios" in cuerpo_lower
            or "tarjeta de crédito" in cuerpo_lower
            or "credenciales" in cuerpo_lower
            or "usuario y contraseña" in cuerpo_lower
        ):
            puntos += 3
            motivos.append(
                "El cuerpo menciona cambios de cuenta o datos financieros/sensibles."
            )

    if url_limpia:
        urls_detectadas.append(url_limpia)

    urls_en_cuerpo = extraer_urls(cuerpo_limpio)
    for u in urls_en_cuerpo:
        if u not in urls_detectadas:
            urls_detectadas.append(u)

    if archivo_extraido:
        for u in archivo_extraido.get("urls", []):
            if u not in urls_detectadas:
                urls_detectadas.append(u)

        for d in archivo_extraido.get("dominios", []):
            if d:
                dominios_detectados.add(d)

    for u in urls_detectadas:
        dominio = extraer_dominio_de_url(u)
        if dominio:
            dominios_detectados.add(dominio)

    for u in urls_detectadas:
        u_lower = u.lower()

        if u_lower.startswith("http://"):
            puntos += 2
            motivos.append(f"La URL {recortar_texto(u, 120)} usa http en lugar de https.")

        if any(p in u_lower for p in ["login", "verifica", "cuenta", "confirm"]):
            puntos += 2
            motivos.append(
                f"La URL {recortar_texto(u, 120)} parece relacionada con inicio de sesión, verificación o confirmación."
            )

    for dominio in dominios_detectados:
        vt_dominio = analizar_dominio_con_virustotal(dominio)
        debug_vt_dominios.append(
            {
                "dominio": dominio,
                "resultado": vt_dominio,
            }
        )
        motivos.extend(vt_dominio.get("motivos", []))
        puntos += vt_dominio.get("risk_points", 0)

    for u in urls_detectadas:
        vt_url = analizar_url_con_virustotal(u)
        debug_vt_urls.append(
            {
                "url": u,
                "resultado": vt_url,
            }
        )
        motivos.extend(vt_url.get("motivos", []))
        puntos += vt_url.get("risk_points", 0)

        urlscan_url = analizar_url_con_urlscan(u)
        debug_urlscan_urls.append(
            {
                "url": u,
                "resultado": urlscan_url,
            }
        )
        motivos.extend(urlscan_url.get("motivos", []))
        puntos += urlscan_url.get("risk_points", 0)

    if archivo_info and archivo:
        vt_archivo = await analizar_archivo_con_virustotal(archivo)
        debug_vt_archivo = vt_archivo
        motivos.append(f"Hay un archivo adjunto válido ({archivo_info['filename']}).")
        motivos.extend(vt_archivo.get("motivos", []))
        puntos += vt_archivo.get("risk_points", 0)

        if archivo_extraido:
            if archivo_extraido.get("urls"):
                motivos.append(
                    f"Se extrajeron {len(archivo_extraido.get('urls', []))} URL(s) desde el archivo adjunto para análisis."
                )
            if archivo_extraido.get("from"):
                motivos.append("Se extrajo información del remitente desde el archivo adjunto.")

    if puntos <= 2:
        riesgo = "bajo"
    elif puntos <= 5:
        riesgo = "medio"
    else:
        riesgo = "alto"

    if not motivos:
        motivos.append(
            "No se detectaron señales fuertes, pero siempre verifica con atención, sobre todo si hay enlaces o adjuntos."
        )

    resumen_usuario = generar_resumen_usuario(
        riesgo=riesgo,
        remitente=remitente_limpio,
        urls_detectadas=urls_detectadas,
        archivo_info=archivo_info,
        archivo_extraido=archivo_extraido,
        puntos=puntos,
    )

    motivos_visibles = construir_motivos_visibles(
        riesgo=riesgo,
        resumen_usuario=resumen_usuario,
        urls_detectadas=urls_detectadas,
        archivo_info=archivo_info,
    )

    return {
        "riesgo": riesgo,
        "resumen_usuario": resumen_usuario,
        "motivos": motivos_visibles,
        "debug": {
            "motivos_completos": motivos,
            "urls_detectadas": urls_detectadas,
            "dominios_detectados": sorted(list(dominios_detectados)),
            "vt_urls": debug_vt_urls,
            "vt_dominios": debug_vt_dominios,
            "urlscan_urls": debug_urlscan_urls,
            "vt_archivo": debug_vt_archivo,
            "archivo_extraido": debug_archivo_extraido,
            "vt_key_cargada": bool(VT_API_KEY),
            "urlscan_key_cargada": bool(URLSCAN_API_KEY),
            "archivo_info": archivo_info,
            "puntos_totales": puntos,
        },
    }
