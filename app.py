from fastapi import FastAPI, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List, Dict, Any, Set
from urllib.parse import urlparse
import os
import time
import base64
import requests
import re

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


def obtener_url_id_vt(url: str) -> str:
    url_bytes = url.encode("utf-8")
    return base64.urlsafe_b64encode(url_bytes).decode("utf-8").strip("=")


def normalizar_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
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
        if url and url not in vistos:
            vistos.add(url)
            urls_limpias.append(url)

    return urls_limpias


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


def analizar_url_con_virustotal(url: str) -> Dict[str, Any]:
    resultado = {
        "usada": False,
        "ok": False,
        "detalle": "",
        "motivos": [],
        "stats": {},
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
                    resultado["motivos"].append(
                        f"VirusTotal marcó la URL como maliciosa en {malicious} motores."
                    )
                elif suspicious > 0:
                    resultado["motivos"].append(
                        f"VirusTotal marcó la URL como sospechosa en {suspicious} motores."
                    )
                else:
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
            resultado["motivos"].append(
                f"VirusTotal marcó el dominio {dominio} como malicioso en {malicious} motores."
            )
        elif suspicious > 0:
            resultado["motivos"].append(
                f"VirusTotal marcó el dominio {dominio} como sospechoso en {suspicious} motores."
            )
        else:
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
                    resultado["motivos"].append(
                        f"urlscan.io marcó la página como potencialmente maliciosa (score {score})."
                    )
                elif score and score > 0:
                    resultado["motivos"].append(
                        f"urlscan.io detectó señales de riesgo en la página (score {score})."
                    )
                else:
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

    dominios_internos = ["pracegar.com", "haceb.com"]

    remitente_limpio = (remitente or "").strip()
    asunto_limpio = (asunto or "").strip()
    cuerpo_limpio = (cuerpo or "").strip()
    url_limpia = normalizar_url((url or "").strip()) if url else ""

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

    for u in urls_detectadas:
        dominio = extraer_dominio_de_url(u)
        if dominio:
            dominios_detectados.add(dominio)

        u_lower = u.lower()

        if u_lower.startswith("http://"):
            puntos += 3
            motivos.append(f"La URL {u} usa http en lugar de https.")

        if "login" in u_lower or "verifica" in u_lower or "cuenta" in u_lower:
            puntos += 2
            motivos.append(
                f"La URL {u} parece relacionada con inicio de sesión o verificación de cuenta."
            )

    for dominio in dominios_detectados:
        vt_dominio = analizar_dominio_con_virustotal(dominio)
        debug_vt_dominios.append({
            "dominio": dominio,
            "resultado": vt_dominio,
        })

        motivos.extend(vt_dominio.get("motivos", []))

        for m in vt_dominio.get("motivos", []):
            m_lower = m.lower()
            if "malicioso" in m_lower:
                puntos += 4
            elif "sospechoso" in m_lower:
                puntos += 2

    for u in urls_detectadas:
        vt_url = analizar_url_con_virustotal(u)
        debug_vt_urls.append({
            "url": u,
            "resultado": vt_url,
        })

        motivos.extend(vt_url.get("motivos", []))

        for m in vt_url.get("motivos", []):
            m_lower = m.lower()
            if "maliciosa" in m_lower:
                puntos += 4
            elif "sospechosa" in m_lower:
                puntos += 2

        urlscan_url = analizar_url_con_urlscan(u)
        debug_urlscan_urls.append({
            "url": u,
            "resultado": urlscan_url,
        })

        motivos.extend(urlscan_url.get("motivos", []))

        for m in urlscan_url.get("motivos", []):
            m_lower = m.lower()
            if "maliciosa" in m_lower:
                puntos += 4
            elif "riesgo" in m_lower:
                puntos += 2

    if archivo is not None and archivo.filename:
        puntos += 1
        motivos.append(
            f"Hay un archivo adjunto ({archivo.filename}). Esta versión aún no analiza el archivo con motores externos."
        )

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

    return {
        "riesgo": riesgo,
        "motivos": motivos,
        "debug": {
            "urls_detectadas": urls_detectadas,
            "dominios_detectados": sorted(list(dominios_detectados)),
            "vt_urls": debug_vt_urls,
            "vt_dominios": debug_vt_dominios,
            "urlscan_urls": debug_urlscan_urls,
            "vt_key_cargada": bool(VT_API_KEY),
            "urlscan_key_cargada": bool(URLSCAN_API_KEY),
        },
    }
