import logging
import jwt
import bcrypt
from app.service.db_service import get_db_connection
from app.service.email_service import send_verification_email
from flask import Blueprint, request, jsonify, g
from functools import wraps
from app.config import Config  
from datetime import datetime, timezone, timedelta
from marshmallow import Schema, fields, ValidationError, validate

dash_bp = Blueprint('dash', __name__, url_prefix="/dashboard")

# Esquema de validación de usuario
class UserSchema(Schema):
    username = fields.Str(required=True, validate=validate.Length(min=3, max=50))
    email = fields.Email(required=True, validate=validate.Regexp(r'^[a-zA-Z0-9._%+-]+@(outlook\.com|hotmail\.com|gmail\.com)$'))
    password = fields.Str(required=True, validate=validate.Length(min=8))
    user_type = fields.Str(required=True, validate=validate.OneOf(['user', 'admin', 'cura']))

# Esquema para actualización de usuario (password opcional)
class UserUpdateSchema(Schema):
    username = fields.Str(required=True, validate=validate.Length(min=3, max=50))
    email = fields.Email(required=True, validate=validate.Regexp(r'^[a-zA-Z0-9._%+-]+@(outlook\.com|hotmail\.com|gmail\.com)$'))
    password = fields.Str(required=False, validate=validate.Length(min=8))
    user_type = fields.Str(required=True, validate=validate.OneOf(['user', 'admin', 'cura']))


# Middleware general para verificar autenticación
@dash_bp.before_request
def verify_token():
    if request.method == 'OPTIONS':
        response = jsonify({})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
        return response, 200
    
    # Excluir rutas públicas si las hay
    if request.endpoint and 'public' in request.endpoint:
        return
        
    token = request.headers.get("Authorization")
    
    if not token:
        return jsonify({"error": "Token requerido"}), 401
        
    try:
        token = token.split("Bearer ")[1]
        data = jwt.decode(token, Config.JWT_SECRET_KEY, algorithms=["HS256"])
        
        # Validar si el token ha expirado manualmente
        if datetime.now(timezone.utc).timestamp() > data["exp"]:
            return jsonify({"error": "El token ha expirado"}), 401
            
        # Guardar datos de usuario en el contexto de la solicitud
        g.user = data
        
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "El token ha expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Token inválido"}), 401
    except Exception as e:
        return jsonify({"error": f"Error al verificar el token: {str(e)}"}), 401

# Endpoint para validar si el usuario está autenticado y obtener su rol
@dash_bp.route("/validate_session", methods=["GET"])
def validate_session():
    # Los datos de usuario ya están disponibles en g.user  al middleware
    return jsonify({
        "message": "Usuario autenticado",
        "user_id": g.user["user_id"],
        "email": g.user["email"],
        "role": g.user["user_type"]
    })

# Endpoint para validar si el usuario puede acceder a un dashboard
@dash_bp.route("/validate_dashboard", methods=["POST"])
def validate_dashboard():
    data = request.get_json()
    current_dashboard = data.get("dashboard")

    if not current_dashboard:
        return jsonify({"error": "Dashboard no especificado"}), 400

    # Definir qué dashboard le corresponde a cada rol
    allowed_dashboards = {
        "admin": "dash_admin",
        "user": "dash_user",
        "cura": "dash_cura"
    }

    # Verificar si el usuario está en el dashboard correcto
    if allowed_dashboards.get(g.user["user_type"]) != current_dashboard:
        return jsonify({"error": "Acceso no autorizado"}), 403

    return jsonify({"message": "Acceso permitido"})


# Función ejemplo de registrar usuario actualizada para usar g.user
@dash_bp.route('/register', methods=['POST'])
def register_user():
    try:
        # Verificar si el usuario autenticado es un admin
        if g.user["user_type"] != "admin":
            return jsonify({'code': 'AUTH001', 'message': 'Acceso no autorizado'}), 403

        # Obtener datos del request
        data = request.get_json()
        schema = UserSchema()
        validated_data = schema.load(data)

        # Conectar a la base de datos
        connection = get_db_connection()
        if not connection:
            return jsonify({'code': 'DB001', 'message': 'Error al conectar con la base de datos'}), 500

        cursor = connection.cursor()

        # Verificar si el nombre de usuario ya está registrado
        cursor.execute("SELECT id FROM user WHERE username = %s", (validated_data['username'],))
        if cursor.fetchone():
            return jsonify({'code': 'REG006', 'message': 'El nombre de usuario ya está en uso. Intenta con otro.'}), 400

        # Verificar si el correo ya está registrado
        cursor.execute("SELECT id FROM user WHERE email = %s", (validated_data['email'],))
        if cursor.fetchone():
            return jsonify({'code': 'REG004', 'message': 'El correo ingresado ya se encuentra registrado.'}), 400

        # Hashear la contraseña
        hashed_password = bcrypt.hashpw(validated_data['password'].encode('utf-8'), bcrypt.gensalt())

        # Generar token de verificación
        secret_key = Config.JWT_SECRET_KEY
        verification_token = jwt.encode(
            {'email': validated_data['email'], 'exp': datetime.utcnow() + timedelta(hours=1)},
            secret_key, 
            algorithm='HS256'
        )

        # Enviar correo de verificación
        verification_url = f"http://127.0.0.1:5000/verify?token={verification_token}"
        email_sent = send_verification_email(validated_data['email'], verification_url)

        if not email_sent:
            return jsonify({'code': 'REG005', 'message': 'Error al enviar el correo de verificación.'}), 500

        # Insertar usuario en la base de datos
        cursor.execute(
            "INSERT INTO user (username, email, password, user_type, email_verified) VALUES (%s, %s, %s, %s, %s)",
            (validated_data['username'], validated_data['email'], hashed_password, validated_data['user_type'], False)
        )
        connection.commit()

        return jsonify({'message': f"Usuario {validated_data['user_type']} registrado exitosamente. Por favor, verifica tu correo."})

    except ValidationError as e:
        return jsonify({'code': 'VAL001', 'errors': e.messages}), 400
    except Exception as e:
        logging.error(f"[REG003] Error inesperado: {e}")
        return jsonify({'code': 'REG003', 'message': 'Error inesperado durante el registro'}), 500
    finally:
        # Cerrar cursor y conexión si fueron creados
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

# mostrar usuarios en la tabla, ordenar, buscar y paginar
@dash_bp.route('/users', methods=['GET'])
def get_users():
    try:
        # Verificar si el usuario autenticado es un admin
        if g.user["user_type"] != "admin":
            return jsonify({'code': 'AUTH001', 'message': 'Acceso no autorizado'}), 403

        # Obtener parámetros de paginación y búsqueda
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 10, type=int)
        search = request.args.get('search', '')
        sort_by = request.args.get('sort', 'username')
        sort_order = request.args.get('order', 'ASC')
        
        # Validar parámetros
        if page < 1:
            page = 1
        if limit < 1 or limit > 100:
            limit = 10
        
        # Calcular offset para paginación
        offset = (page - 1) * limit
        
        # Conectar a la base de datos
        connection = get_db_connection()
        if not connection:
            return jsonify({'code': 'DB001', 'message': 'Error al conectar con la base de datos'}), 500

        cursor = connection.cursor(dictionary=True)
        
        # Construir la consulta base
        query = "SELECT id, username, email, user_type, email_verified FROM user"
        count_query = "SELECT COUNT(*) as total FROM user"
        
        # Agregar filtro de búsqueda si existe
        params = []
        if search:
            search_term = f"%{search}%"
            query += " WHERE (username LIKE %s OR email LIKE %s)"
            count_query += " WHERE (username LIKE %s OR email LIKE %s)"
            params.extend([search_term, search_term])
            
        # Agregar ordenamiento
        if sort_by in ['username', 'email', 'user_type']:
            if sort_order.upper() not in ['ASC', 'DESC']:
                sort_order = 'ASC'
            query += f" ORDER BY {sort_by} {sort_order}"
        else:
            query += " ORDER BY username ASC"
            
        # Agregar paginación
        query += " LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        
        # Ejecutar consulta para obtener total de registros
        if search:
            cursor.execute(count_query, [search_term, search_term])
        else:
            cursor.execute(count_query)
        total_count = cursor.fetchone()['total']
        
        # Ejecutar consulta principal
        cursor.execute(query, params)
        users = cursor.fetchall()
        
        # Calcular total de páginas
        total_pages = (total_count + limit - 1) // limit
        
        # Preparar respuesta
        return jsonify({
            'users': users,
            'pagination': {
                'total': total_count,
                'page': page,
                'limit': limit,
                'pages': total_pages
            }
        })

    except Exception as e:
        logging.error(f"[USR001] Error al obtener usuarios: {e}")
        return jsonify({'code': 'USR001', 'message': 'Error al obtener la lista de usuarios'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

# Endpoint para obtener información de un usuario específico
@dash_bp.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    try:
        # Verificar si el usuario autenticado es un admin
        if g.user["user_type"] != "admin":
            return jsonify({'code': 'AUTH001', 'message': 'Acceso no autorizado'}), 403

        # Conectar a la base de datos
        connection = get_db_connection()
        if not connection:
            return jsonify({'code': 'DB001', 'message': 'Error al conectar con la base de datos'}), 500

        cursor = connection.cursor(dictionary=True)

        # Obtener datos del usuario
        cursor.execute("SELECT id, username, email, user_type, email_verified FROM user WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        if not user:
            return jsonify({'code': 'USR004', 'message': 'Usuario no encontrado'}), 404

        return jsonify({'user': user})

    except Exception as e:
        logging.error(f"[USR005] Error al obtener usuario: {e}")
        return jsonify({'code': 'USR005', 'message': 'Error al obtener información del usuario'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

# Endpoint para actualizar un usuario
@dash_bp.route('/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    try:
        # Verificar si el usuario autenticado es un admin
        if g.user["user_type"] != "admin":
            return jsonify({'code': 'AUTH001', 'message': 'Acceso no autorizado'}), 403

        # Obtener datos del request
        data = request.get_json()
        schema = UserUpdateSchema()
        validated_data = schema.load(data)

        # Conectar a la base de datos
        connection = get_db_connection()
        if not connection:
            return jsonify({'code': 'DB001', 'message': 'Error al conectar con la base de datos'}), 500

        cursor = connection.cursor()

        # Verificar si el usuario existe
        cursor.execute("SELECT id FROM user WHERE id = %s", (user_id,))
        if not cursor.fetchone():
            return jsonify({'code': 'USR004', 'message': 'Usuario no encontrado'}), 404

        # Verificar si el nombre de usuario ya está en uso por otro usuario
        cursor.execute("SELECT id FROM user WHERE username = %s AND id != %s", 
                       (validated_data['username'], user_id))
        if cursor.fetchone():
            return jsonify({'code': 'USR006', 'message': 'El nombre de usuario ya está en uso por otro usuario'}), 400

        # Verificar si el correo ya está en uso por otro usuario
        cursor.execute("SELECT id FROM user WHERE email = %s AND id != %s", 
                       (validated_data['email'], user_id))
        if cursor.fetchone():
            return jsonify({'code': 'USR007', 'message': 'El correo electrónico ya está en uso por otro usuario'}), 400

        # Preparar la consulta de actualización
        if 'password' in validated_data and validated_data['password']:
            # Si se proporciona contraseña, actualizarla también
            hashed_password = bcrypt.hashpw(validated_data['password'].encode('utf-8'), bcrypt.gensalt())
            cursor.execute(
                "UPDATE user SET username = %s, email = %s, password = %s, user_type = %s WHERE id = %s",
                (validated_data['username'], validated_data['email'], hashed_password, 
                 validated_data['user_type'], user_id)
            )
        else:
            # Si no se proporciona contraseña, actualizar solo los otros campos
            cursor.execute(
                "UPDATE user SET username = %s, email = %s, user_type = %s WHERE id = %s",
                (validated_data['username'], validated_data['email'], validated_data['user_type'], user_id)
            )

        connection.commit()

        return jsonify({'message': 'Usuario actualizado exitosamente'})

    except ValidationError as e:
        return jsonify({'code': 'VAL001', 'errors': e.messages}), 400
    except Exception as e:
        logging.error(f"[USR008] Error al actualizar usuario: {e}")
        return jsonify({'code': 'USR008', 'message': 'Error inesperado al actualizar el usuario'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

# Endpoint para eliminar un usuario
@dash_bp.route('/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    try:
        # Verificar si el usuario autenticado es un admin
        if g.user["user_type"] != "admin":
            return jsonify({'code': 'AUTH001', 'message': 'Acceso no autorizado'}), 403

        # Verificar que no se esté eliminando a sí mismo
        if g.user["user_id"] == user_id:
            return jsonify({'code': 'USR008', 'message': 'No puedes eliminar tu propia cuenta'}), 400

        # Conectar a la base de datos
        connection = get_db_connection()
        if not connection:
            return jsonify({'code': 'DB001', 'message': 'Error al conectar con la base de datos'}), 500

        cursor = connection.cursor()

        # Verificar si el usuario existe
        cursor.execute("SELECT id FROM user WHERE id = %s", (user_id,))
        if not cursor.fetchone():
            return jsonify({'code': 'USR004', 'message': 'Usuario no encontrado'}), 404

        # Eliminar usuario
        cursor.execute("DELETE FROM user WHERE id = %s", (user_id,))
        connection.commit()

        return jsonify({'message': 'Usuario eliminado exitosamente'})

    except Exception as e:
        logging.error(f"[USR009] Error al eliminar usuario: {e}")
        return jsonify({'code': 'USR009', 'message': 'Error al eliminar el usuario'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

