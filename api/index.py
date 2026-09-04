"""
Backend de LiquidaYa.pe — funciones serverless para Vercel.

Reemplaza al backend de Render (FastAPI + Culqi). Vive en el MISMO proyecto
de Vercel que el frontend (index.html), así que no hay CORS que configurar
ni "cold start" de 35 segundos.

Pasarela: Izipay (api.micuentaweb.pe), usando el flujo oficial de
"Formulario incrustado" documentado en:
  https://github.com/izipay-pe/Embedded-PaymentForm-JavaScript
  https://github.com/izipay-pe/Server-PaymentForm-Python-Flask

Variables de entorno que debes configurar en Vercel (Project Settings ->
Environment Variables) con las credenciales de tu Back Office Vendedor
de Izipay (primero en modo TEST, luego en modo PRODUCCION):

  IZIPAY_USERNAME    -> "Nro de tienda" / shopId del Back Office
  IZIPAY_PASSWORD    -> clave de la API REST (test o producción)
  IZIPAY_PUBLIC_KEY  -> llave pública (test o producción)
  IZIPAY_HMAC_KEY    -> clave SHA-256 HMAC (Back Office > Configuración > Claves)

Guía para obtener credenciales: https://github.com/izipay-pe/obtener-credenciales-de-conexion
"""

import base64
import hashlib
import hmac
import json as json_lib
import os
from decimal import Decimal

import requests
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

IZIPAY_USERNAME = os.environ.get("IZIPAY_USERNAME", "")
IZIPAY_PASSWORD = os.environ.get("IZIPAY_PASSWORD", "")
IZIPAY_PUBLIC_KEY = os.environ.get("IZIPAY_PUBLIC_KEY", "")
IZIPAY_HMAC_KEY = os.environ.get("IZIPAY_HMAC_KEY", "")

CREATE_PAYMENT_URL = "https://api.micuentaweb.pe/api-payment/V4/Charge/CreatePayment"

# El precio se fija aquí, en el servidor — nunca se confía en un monto
# que venga del navegador del cliente.
PRECIO_SOLES = "9.90"


@app.get("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "servicio": "LiquidaYa backend (Vercel + Izipay)",
        "izipay_configurado": bool(IZIPAY_USERNAME and IZIPAY_PASSWORD and IZIPAY_PUBLIC_KEY),
    })


@app.post("/api/formtoken")
def formtoken():
    """
    El frontend llama aquí ANTES de mostrar el formulario de pago.
    Crea la orden en Izipay y devuelve el formToken + la llave pública
    que el widget de Izipay (classic.js) necesita para renderizarse.
    """
    body = request.get_json(silent=True) or {}

    requeridos = ["firstName", "lastName", "email", "phoneNumber", "identityCode", "orderId"]
    faltantes = [campo for campo in requeridos if not body.get(campo)]
    if faltantes:
        return jsonify({"error": f"Faltan datos obligatorios: {', '.join(faltantes)}"}), 400

    if not (IZIPAY_USERNAME and IZIPAY_PASSWORD and IZIPAY_PUBLIC_KEY):
        return jsonify({"error": "El servidor no tiene configuradas las credenciales de Izipay (variables de entorno)."}), 500

    auth = "Basic " + base64.b64encode(f"{IZIPAY_USERNAME}:{IZIPAY_PASSWORD}".encode("utf-8")).decode("utf-8")

    payload = {
        "amount": int(Decimal(PRECIO_SOLES) * 100),  # Izipay recibe el monto en centimos
        "currency": "PEN",
        "orderId": body["orderId"],
        "customer": {
            "email": body["email"],
            "billingDetails": {
                "firstName": body["firstName"],
                "lastName": body["lastName"],
                "phoneNumber": body["phoneNumber"],
                "identityType": body.get("identityType", "DNI"),
                "identityCode": body["identityCode"],
                "address": body.get("address", "Sin direccion"),
                "country": "PE",
                "state": body.get("state", "Lima"),
                "city": body.get("city", "Lima"),
                "zipCode": body.get("zipCode", "15001"),
            },
        },
    }

    headers = {"Content-Type": "application/json", "Authorization": auth}

    try:
        r = requests.post(CREATE_PAYMENT_URL, json=payload, headers=headers, timeout=15)
        data = r.json()
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": f"No se pudo contactar a Izipay: {exc}"}), 502

    if data.get("status") == "SUCCESS":
        return jsonify({
            "formToken": data["answer"]["formToken"],
            "publicKey": IZIPAY_PUBLIC_KEY,
        }), 200

    mensaje = data.get("answer", {}).get("errorMessage") or data.get("answer", {}).get("_type") or "Izipay rechazo la solicitud"
    return jsonify({"error": mensaje, "detalle": data}), 502


def _firma_valida(texto: str, hash_recibido: str, clave: str) -> bool:
    if not (texto and hash_recibido and clave):
        return False
    calculado = hmac.new(clave.encode("utf-8"), texto.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(calculado, hash_recibido)


@app.post("/api/validar")
def validar():
    """
    El frontend llama aquí justo despues de que Izipay le devuelve una
    respuesta de pago (KR.onSubmit), ANTES de desbloquear el expediente.

    Esta es la pieza que arregla el bug critico que tenia el sitio con
    Culqi: aqui SI se verifica de verdad, con la clave HMAC, que el pago
    fue aprobado -- no se confia en lo que diga el navegador del cliente.
    """
    body = request.get_json(silent=True) or {}
    kr_answer = body.get("krAnswer", "")
    kr_hash = body.get("krHash", "")

    if not _firma_valida(kr_answer, kr_hash, IZIPAY_HMAC_KEY):
        return jsonify({"pagado": False, "motivo": "firma_invalida"}), 400

    try:
        respuesta = json_lib.loads(kr_answer)
        pagado = respuesta.get("orderStatus") == "PAID"
    except Exception:  # noqa: BLE001
        pagado = False

    return jsonify({"pagado": bool(pagado)}), 200


@app.post("/api/ipn")
def ipn():
    """
    Notificacion servidor-a-servidor de Izipay (IPN). Configura esta URL
    en tu Back Office Vendedor: Configuracion > Notificaciones de reglas.
    Sirve de respaldo por si el navegador del cliente se cierra antes de
    llegar a /api/validar. La firma del IPN se calcula con el PASSWORD
    de la tienda (no con la clave HMAC), asi lo define Izipay.
    """
    kr_answer = request.form.get("kr-answer", "")
    kr_hash = request.form.get("kr-hash", "")

    if not _firma_valida(kr_answer, kr_hash, IZIPAY_PASSWORD):
        return "Firma invalida", 400

    try:
        respuesta = json_lib.loads(kr_answer)
        order_id = respuesta.get("orderDetails", {}).get("orderId")
        estado = respuesta.get("orderStatus")
        # Vercel guarda esto en los logs de la funcion (Project > Logs).
        # Si mas adelante quieres guardar las ventas en una base de datos,
        # este es el lugar para escribir ahi.
        print(f"[IPN LiquidaYa] orden={order_id} estado={estado}")
    except Exception:  # noqa: BLE001
        pass

    return "OK", 200
