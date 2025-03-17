import logging
import bcrypt
import jwt
from flask import Blueprint, request, jsonify, current_app
from app.service.db_service import get_db_connection
from app.service.email_service import send_verification_email
from app.service.email_service import send_password_reset_email
from datetime import datetime, timedelta
from marshmallow import Schema, fields, ValidationError, validate
from flask import render_template
import time

# Configurar Blueprint
auth_bp = Blueprint('auth', __name__)

# Configuración de logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Esquema de validación para los datos del usuario
class UserSchema(Schema):
    username = fields.Str(required=True, validate=validate.Length(min=3, max=50))
    email = fields.Email(required=True,validate=validate.Regexp(r'^[a-zA-Z0-9._%+-]+@(outlook\.com|hotmail\.com|gmail\.com)$'))
    password = fields.Str(required=True, validate=validate.Length(min=8))
    user_type = fields.Str(validate=validate.OneOf(['user'])) 


# Ruta para registrar usuario
@auth_bp.route('/register', methods=['POST'])
def register_user():
    try:
        # Validamos los datos con el esquema
        data = request.get_json()
        schema = UserSchema()
        validated_data = schema.load(data)

        #validar que el usuario sea de tipo 'usuario'
        validated_data['user_type'] = 'user'
        
        # Conexión a la base de datos
        connection = get_db_connection()
        if not connection:
            return jsonify({'code': 'DB001', 'message': 'Error al conectar con la base de datos'}), 500

        cursor = connection.cursor()
        # Verificamos si el nombre de usuario ya está registrado
        cursor.execute("SELECT id FROM user WHERE username = %s", (validated_data['username'],))
        if cursor.fetchone():
            return jsonify({'code': 'REG006', 'message': 'El nombre de usuario ya está en uso. Intenta con otro.'}), 400
            
        # Verificamos si el correo ya está registrado
        cursor.execute("SELECT id FROM user WHERE email = %s", (validated_data['email'],))
        if cursor.fetchone():
            return jsonify({'code': 'REG004', 'message': 'El correo ingresado ya se encuentra registrado.'}), 400

        
        # Hasheamos la contraseña
        hashed_password = bcrypt.hashpw(validated_data['password'].encode('utf-8'), bcrypt.gensalt())
        
        # Generamos el token de verificación
        secret_key = current_app.config.get('JWT_SECRET_KEY', 'default_secret')
        token = jwt.encode({'email': validated_data['email'], 'exp': datetime.utcnow() + timedelta(hours=1)}, secret_key, algorithm='HS256')

        # Enviamos el correo de verificación
        verification_url = f"http://127.0.0.1:5000/verify?token={token}"

        # Intentamos enviar el correo y verificamos si fue exitoso
        email_sent = send_verification_email(validated_data['email'], verification_url)
        
        if not email_sent:
            return jsonify({'code': 'REG005', 'message': 'Error al enviar el correo de verificación.'}), 500
        
        # Si el correo se envió correctamente, registramos al usuario en la base de datos
        cursor.execute(
            "INSERT INTO user (username, email, password, user_type, email_verified) VALUES (%s, %s, %s, %s, %s)",
            (validated_data['username'], validated_data['email'], hashed_password, 'user', False)
        )
        connection.commit()

        return jsonify({'message': 'Usuario registrado exitosamente. Por favor, verifica en tu correo electrónico (SPAM).'})

    except ValidationError as e:
        # Capturamos errores de validación
        errors = e.messages
        logging.warning(f"[VAL001] Errores de validación: {errors}")
        return jsonify({'code': 'VAL001', 'errors': errors}), 400

    except Exception as e:
        logging.error(f"[REG003] Error inesperado: {e}")
        return jsonify({'code': 'REG003', 'message': 'Error inesperado durante el registro'}), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


# Ruta para verificar el correo electrónico
@auth_bp.route('/verify', methods=['GET'])
def verify_email():
    token = request.args.get('token')
    if not token:
        logging.warning("[VER001] Token de verificación no proporcionado.")
        return render_template('verification_error.html', message='Token no proporcionado')

    try:
        secret_key = current_app.config.get('JWT_SECRET_KEY', 'default_secret')
        decoded_token = jwt.decode(token, secret_key, algorithms=['HS256'])
        email = decoded_token['email']

        connection = get_db_connection()
        if not connection:
            return render_template('verification_error.html', message='Error al conectar con la base de datos')

        cursor = connection.cursor()
        cursor.execute("UPDATE user SET email_verified = TRUE WHERE email = %s", (email,))
        connection.commit()
        logging.info(f"Correo electrónico {email} verificado exitosamente.")

        return render_template('verification_success.html')

    except jwt.ExpiredSignatureError:
        logging.error("[VER002] El token de verificación ha expirado.")
        return render_template('verification_error.html', message='El token de verificación ha expirado')

    except jwt.InvalidTokenError as e:
        logging.error(f"[VER003] Token inválido: {e}")
        return render_template('verification_error.html', message='Token inválido')

    except Exception as e:
        logging.error(f"[VER004] Error inesperado durante la verificación: {e}")
        return render_template('verification_error.html', message='Error inesperado durante la verificación')

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


# Ruta para solicitar recuperación de contraseña
@auth_bp.route('/recover_password', methods=['POST'])
def recover_password():
    data = request.get_json()
    email = data.get('email')
    
    if not email:
        return jsonify({'code': 'REC001', 'message': 'El correo electrónico es obligatorio'}), 400

    connection = get_db_connection()
    cursor = connection.cursor()

    # Verificar si el usuario existe y si su correo está verificado
    cursor.execute("SELECT id, email_verified, last_reset_request FROM user WHERE email = %s", (email,))
    user = cursor.fetchone()

    if not user:
        return jsonify({'code': 'REC002', 'message': 'El correo no está registrado'}), 404

    user_id, is_verified, last_reset_request = user

    # Si el usuario no ha verificado su correo, no permitir la recuperación de contraseña
    if not is_verified:
        return jsonify({'code': 'REC004', 'message': 'Debes verificar tu correo antes de recuperar tu contraseña'}), 403

    # Verificar si el usuario ya solicitó un cambio de contraseña recientemente (ej. 3 min)
    min_wait_time = timedelta(minutes=3)
    if last_reset_request and datetime.utcnow() - last_reset_request < min_wait_time:
        return jsonify({'code': 'REC003', 'message': 'Ya solicitaste un cambio de contraseña. Espera antes de intentarlo de nuevo'}), 429

    # Generar el token de recuperación
    secret_key = current_app.config.get('JWT_SECRET_KEY', 'default_secret')
    token = jwt.encode({'email': email, 'exp': datetime.utcnow() + timedelta(minutes=5)},secret_key,algorithm='HS256')

    # Actualizar la última solicitud de cambio de contraseña
    cursor.execute("UPDATE user SET last_reset_request = %s WHERE id = %s", (datetime.utcnow(), user_id))
    connection.commit()

    # Enviar correo con el enlace de recuperación
    reset_url = f"http://127.0.0.1:5000/reset-password?token={token}"
    send_password_reset_email(email, reset_url)

    return jsonify({'message': 'Se ha enviado un enlace de recuperación de contraseña a tu correo electrónico. (SPAM)'})


# Ruta para mostrar el formulario de cambio de contraseña
@auth_bp.route('/reset-password', methods=['GET'])
def show_reset_password_form():
    token = request.args.get('token')

    if not token:
        return "Token no válido o faltante", 400

    return render_template('reset_password.html', token=token)


# Ruta para resetear la contraseña
@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')

    if not token or not new_password:
        return jsonify({'code': 'RST001', 'message': 'Token y nueva contraseña son obligatorios'}), 400

    secret_key = current_app.config.get('JWT_SECRET_KEY', 'default_secret')

    try:
        decoded_token = jwt.decode(token, secret_key, algorithms=['HS256'])
        email = decoded_token['email']
    except jwt.ExpiredSignatureError:
        return jsonify({'code': 'RST002', 'message': 'El token ha expirado'}), 400
    except jwt.InvalidTokenError:
        return jsonify({'code': 'RST003', 'message': 'Token inválido'}), 400

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT id, password FROM user WHERE email = %s", (email,))
    user = cursor.fetchone()

    if not user:
        return jsonify({'code': 'RST004', 'message': 'Usuario no encontrado'}), 404

    user_id, current_password = user

    # Comparar con la contraseña actual
    if bcrypt.checkpw(new_password.encode('utf-8'), current_password.encode('utf-8')):
        return jsonify({'code': 'RST005', 'message': 'No puedes utilizar estra contraseña, debes elegir una nueva contraseña'}), 400

    # Verificar historial de contraseñas
    cursor.execute("SELECT password_hash FROM password_history WHERE user_id = %s ORDER BY created_at DESC LIMIT 5", (user_id,))
    previous_passwords = [row[0] for row in cursor.fetchall()]

    for old_password in previous_passwords:
        if bcrypt.checkpw(new_password.encode('utf-8'), old_password.encode('utf-8')):
            return jsonify({'code': 'RST006', 'message': 'Esta contraseña se encontro en el historial de contraseña, debes elegir una nueva contraseña'}), 400

    # Hashear la nueva contraseña y actualizar
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

    cursor.execute("UPDATE user SET password = %s WHERE id = %s", (hashed_password, user_id))
    cursor.execute("INSERT INTO password_history (user_id, password_hash) VALUES (%s, %s)", (user_id, hashed_password))

    connection.commit()
    return jsonify({'message': 'Contraseña actualizada exitosamente.'})


# Ruta para mostrar el resultado de la verificación
@auth_bp.route('/verification_result', methods=['GET'])
def verification_result():
    result = request.args.get('result')
    if result == 'success':
        return jsonify({'message': 'Verificación completada exitosamente.'})
    elif result == 'failure':
        return jsonify({'message': 'Hubo un problema con la verificación.'})
    else:
        return jsonify({'message': 'Resultado de verificación no especificado.'}), 400


# Ruta para solicitar reenvío de verificación
@auth_bp.route('/resend-verification', methods=['POST'])
def resend_verification():
    try:
        # Obtener datos del JSON
        data = request.get_json()
        if not data or not data.get('email'):
            return jsonify({'code': 'RESEND002', 'message': 'El correo es requerido'}), 400

        email = data.get('email').strip()

        # Conexión a la base de datos
        connection = get_db_connection()
        if not connection:
            return jsonify({'code': 'DB001', 'message': 'Error al conectar con la base de datos'}), 500
        
        cursor = connection.cursor()
        cursor.execute("SELECT id, email_verified, last_verification_resend FROM user WHERE email = %s", (email,))
        user = cursor.fetchone()

        # Validaciones
        if not user:
            return jsonify({'code': 'RESEND003', 'message': 'El correo no está registrado'}), 404
        
        if user[1]:  # Si el usuario ya está verificado
            return jsonify({'code': 'RESEND004', 'message': 'Este correo ya está verificado'}), 400

        # Validación de tiempo para reenvío
        last_resend_time = user[2]  # Puede ser NULL
        current_time = datetime.utcnow()

        if last_resend_time:
            time_difference = current_time - last_resend_time
            if time_difference < timedelta(minutes=3):
                remaining_time = 180 - int(time_difference.total_seconds())  # Tiempo restante en segundos
                return jsonify({
                    'code': 'RESEND005',
                    'message': f'Debes esperar {remaining_time} segundos antes de solicitar otro correo de verificación.'
                }), 429

        # Generar nuevo token de verificación
        secret_key = current_app.config.get('JWT_SECRET_KEY', 'default_secret')
        token = jwt.encode({'email': email, 'exp': current_time + timedelta(hours=1)}, secret_key, algorithm='HS256')

        verification_url = f"http://127.0.0.1:5000/verify?token={token}"

        # Intentar enviar el correo
        email_sent = send_verification_email(email, verification_url)

        if not email_sent:
            return jsonify({'code': 'SV001', 'message': 'Error al enviar el correo de verificación.'}), 500

        # Actualizar el tiempo de reenvío en la base de datos
        cursor.execute("UPDATE user SET last_verification_resend = %s WHERE email = %s", (current_time, email))
        connection.commit()

        return jsonify({'message': 'Correo de verificación enviado nuevamente.'}), 200

    except Exception as e:
        logging.error(f"[RESEND001] Error inesperado: {e}")
        return jsonify({'code': 'RESEND001', 'message': 'Error inesperado durante el proceso de reenvío de verificación'}), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


#Ruta para solicitar el ingreso (LOGIN)
@auth_bp.route('/login', methods=['POST'])
def login():
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_TIME = timedelta(minutes=5)
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'code': 'LOGIN001', 'message': 'El correo y la contraseña son obligatorios'}), 400

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("SELECT id, password, email_verified, failed_attempts, lock_until, user_type FROM user WHERE email = %s", (email,))
        user = cursor.fetchone()

        if not user:
            return jsonify({'code': 'LOGIN002', 'message': 'Usuario no registrado'}), 404

        user_id, hashed_password, email_verified, failed_attempts, lock_until, user_type = user

        now = datetime.utcnow()
        if lock_until and now < lock_until:
            remaining_time = int((lock_until - now).total_seconds() / 60)
            return jsonify({'code': 'LOGIN003', 'message': f'Tu cuenta está bloqueada "temporalmente". Intenta nuevamente en {remaining_time} minutos.'}), 403

        if not email_verified:
            return jsonify({'code': 'LOGIN004', 'message': 'Debes verificar tu correo antes de iniciar sesión.', 'resend_verification_link': '/resend-verification'}), 403

        if not bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
            failed_attempts += 1
            if failed_attempts >= MAX_FAILED_ATTEMPTS:
                lock_until = now + LOCKOUT_TIME
                cursor.execute("UPDATE user SET failed_attempts = %s, lock_until = %s WHERE id = %s", (failed_attempts, lock_until, user_id))
                connection.commit()
                return jsonify({'code': 'LOGIN005', 'message': f'Demasiados intentos fallidos. Tu cuenta ha sido bloqueada "temporalmente" por {LOCKOUT_TIME.seconds // 60} minutos.'}), 403
            else:
                cursor.execute("UPDATE user SET failed_attempts = %s WHERE id = %s", (failed_attempts, user_id))
                connection.commit()
                return jsonify({'code': 'LOGIN006', 'message': f'Contraseña incorrecta. Te quedan {MAX_FAILED_ATTEMPTS - failed_attempts} intentos antes de ser bloqueado "temporalmente".'}), 401

        cursor.execute("UPDATE user SET failed_attempts = 0, lock_until = NULL WHERE id = %s", (user_id,))
        connection.commit()

        secret_key = current_app.config.get('JWT_SECRET_KEY')
        token = jwt.encode({'user_id': user_id, 'email': email, 'user_type': user_type, 'exp': now + timedelta(hours=2)}, secret_key, algorithm='HS256')

        response = jsonify({'message': 'Inicio de sesión exitoso', 'token': token})
        response.set_cookie('jwt', token, httponly=True, secure=True, samesite='Lax') 

        return response
    finally:
        cursor.close()
        connection.close()

# Ruta para obtener el rol del usuario
@auth_bp.route("/get_user_role", methods=["GET"])
def get_user_role():
    token = request.headers.get("Authorization")

    if not token or "Bearer " not in token:
        return jsonify({"message": "Token no proporcionado o incorrecto"}), 401

    try:
        secret_key = current_app.config.get("JWT_SECRET_KEY")
        token = token.split(" ")[1]  # Extraer el token sin "Bearer"
        decoded_token = jwt.decode(token, secret_key, algorithms=["HS256"])

        user_role = decoded_token.get("user_type")  # Obtener el rol del usuario

        if user_role:
            return jsonify({"role": user_role})
        else:
            return jsonify({"message": "Rol no encontrado"}), 404

    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Token inválido"}), 401