from flask import Flask, request, jsonify
from app.service.whatsapp import WhatsAppService
from flask import Blueprint, request, jsonify, current_app


whatsapp_bp = Blueprint("whatsapp_bp", __name__)
whatsapp = WhatsAppService()

@whatsapp_bp.route('/send_whatsapp', methods=['POST'])
def send_whatsapp():
    try:
        data = request.get_json()
        to_number = data.get("to_number")
        message = data.get("message")

        if not to_number or not message:
            return jsonify({"status": "error", "error": "Faltan datos"}), 400

        response = whatsapp.send_message(to_number, message)

        return jsonify(response)

    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


