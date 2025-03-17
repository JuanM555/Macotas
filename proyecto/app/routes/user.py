# app/routes/user.py

from flask import Blueprint, request, jsonify

bp = Blueprint('user', __name__, url_prefix='/user')

@bp.route('/profile', methods=['GET'])
def profile():
    # Lógica para el perfil de usuario
    return jsonify({"message": "Perfil de usuario"})
