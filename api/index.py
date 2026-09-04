"""
Backend de LiquidaYa.pe — funciones serverless para Vercel.
Compatible con enrutamiento relativo (/api/... y /...).
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

CREATE_PAYMENT_URL = "https://api.micuentaweb.pe/api-payment/V4/Charge/CreatePayment"
PRECIO_SOLES = "9.90"


def _get_env():
    return {
        "username": os.environ.get("IZIPAY_USERNAME", "").strip(),
        "password": os.environ.get("IZIPAY_PASSWORD", "").strip(),
        "public_key": os.environ.get("IZIPAY_PUBLIC_KEY", "").strip(),
        "hmac_key": os.environ.get("IZIPAY_HMAC_KEY", "").strip(),
    }


# Ruta de verificación (soporta /, /health y /api/health)
@app.route("/", methods=["GET"])
@app.route("/health", methods=["GET"])
@app.route("/api/health", methods=["GET"])
def health():
    env = _get_env()
    configurado = bool(env["username"] and env["password"] and env["public_key"])
    return jsonify({
        "status": "ok",
        "servicio": "LiquidaYa backend (Vercel + Izipay)",
        "izipay_configurado": configurado,
        "ruta_detectada": request.path
    }), 200


# Endpoint para generar formToken de Izipay
@app.route("/formtoken", methods=["POST"])
@app.route("/api/formtoken", methods=["POST"])
def formtoken():
    env = _get_env()
    body = request.get_json(silent=True) or {}

    requeridos = ["firstName", "lastName", "email", "phoneNumber", "identityCode", "orderId"]
    faltantes = [campo for campo in requeridos if not body.get(campo)]
    if faltantes:
        return jsonify({"error": f"Faltan datos obligatorios: {', '.join(faltantes)}"}), 400

    if not (env["username"] and env["password"] and env["public_key"]):
        return jsonify({"error": "El servidor no tiene configuradas las credenciales de Izipay en Vercel."}), 500

    auth = "Basic " + base64.b64encode(f"{env['username']}:{env['password']}".encode("utf-8")).decode("utf-8")

    payload = {
        "amount": int(Decimal(PRECIO_SOLES) * 100),
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
    except Exception as exc:
        return jsonify({"error": f"No se pudo contactar a Izipay: {exc}"}), 502

    if data.get("status") == "SUCCESS":
        return jsonify({
            "formToken": data["answer"]["formToken"],
            "publicKey": env["public_key"],
        }), 200

    mensaje = data.get("answer", {}).get("errorMessage") or data.get("answer", {}).get("_type") or "Izipay rechazo la solicitud"
    return jsonify({"error": mensaje, "detalle": data}), 502


def _firma_valida(texto: str, hash_recibido: str, clave: str) -> bool:
    if not (texto and hash_recibido and clave):
        return False
    calculado = hmac.new(clave.encode("utf-8"), texto.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(calculado, hash_recibido)


# Endpoint de validación criptográfica post-pago
@app.route("/validar", methods=["POST"])
@app.route("/api/validar", methods=["POST"])
def validar():
    env = _get_env()
    body = request.get_json(silent=True) or {}
    kr_answer = body.get("krAnswer", "")
    kr_hash = body.get("krHash", "")

    if not _firma_valida(kr_answer, kr_hash, env["hmac_key"]):
        return jsonify({"pagado": False, "motivo": "firma_invalida"}), 400

    try:
        respuesta = json_lib.loads(kr_answer)
        pagado = respuesta.get("orderStatus") == "PAID"
    except Exception:
        pagado = False

    return jsonify({"pagado": bool(pagado)}), 200


# Endpoint IPN de respaldo servidor a servidor
@app.route("/ipn", methods=["POST"])
@app.route("/api/ipn", methods=["POST"])
def ipn():
    env = _get_env()
    kr_answer = request.form.get("kr-answer", "")
    kr_hash = request.form.get("kr-hash", "")

    if not _firma_valida(kr_answer, kr_hash, env["password"]):
        return "Firma invalida", 400

    try:
        respuesta = json_lib.loads(kr_answer)
        order_id = respuesta.get("orderDetails", {}).get("orderId")
        estado = respuesta.get("orderStatus")
        print(f"[IPN LiquidaYa] orden={order_id} estado={estado}")
    except Exception:
        pass

    return "OK", 200


@app.errorhandler(404)
def page_not_found(e):
    return jsonify({
        "status": "error",
        "mensaje": f"Ruta no encontrada en Flask: {request.path}",
        "metodo": request.method
    }), 404
