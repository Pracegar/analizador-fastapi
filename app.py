from fastapi import FastAPI, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List

app = FastAPI()

# Orígenes permitidos
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

    # Regla 1: remitente externo raro
    dominios_internos = ["@pracegar.com", "@haceb.com"]
    if remitente and not any(d in remitente.lower() for d in dominios_internos):
        puntos += 2
        motivos.append("El remitente no parece ser del dominio de la empresa.")

    # Regla 2: palabras peligrosas en el asunto
    if asunto:
        asunto_lower = asunto.lower()
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

    # Regla 3: URL sospechosa
    if url:
        url_lower = url.lower()
        if url_lower.startswith("http://"):
            puntos += 3
            motivos.append("La URL usa http en lugar de https.")
        if "login" in url_lower or "verifica" in url_lower or "cuenta" in url_lower:
            puntos += 2
            motivos.append(
                "La URL parece relacionada con inicio de sesión o verificación de cuenta."
            )

    # Regla 4: cuerpo con cambios de cuenta o datos sensibles
    if cuerpo:
        cuerpo_lower = cuerpo.lower()
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

    # Regla 5: archivo adjunto presente
    if archivo is not None and archivo.filename:
        motivos.append(
            f"Hay un archivo adjunto ({archivo.filename}). Esta versión todavía no lo analiza automáticamente."
        )

    # Asignar nivel de riesgo
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

    return {"riesgo": riesgo, "motivos": motivos}
