# app/routes/profile_routes.py
from flask import Blueprint, request, jsonify
from app.service.db_service import get_db_connection
from app.service.media import upload_profile_image, get_profile_image_url, delete_all_versions
import logging
from datetime import datetime
import jwt
from app.config import Config  


profile_bp = Blueprint('profile', __name__)


@profile_bp.route('/status', methods=['GET'])
def check_profile_status():
    try:
        # Extraer el token del encabezado Authorization
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'success': False, 'message': 'Token no proporcionado'}), 401
        
        token = auth_header.split(' ')[1]
        
        # Decodificar el token para obtener el user_id
        try:
            payload = jwt.decode(token, Config.JWT_SECRET_KEY, algorithms=['HS256'])
            user_id = payload.get('user_id')
        except jwt.ExpiredSignatureError:
            return jsonify({'success': False, 'message': 'Token expirado'}), 401
        except jwt.InvalidTokenError as e:
            logging.error(f"Error al decodificar token: {str(e)}")
            return jsonify({'success': False, 'message': 'Token inválido'}), 401
        
        if not user_id:
            return jsonify({'success': False, 'message': 'ID de usuario no encontrado en el token'}), 400
        
        # Consultar si el perfil está completo
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT profile_completed FROM user_profile 
            WHERE user_id = %s
        """, (user_id,))
        
        result = cursor.fetchone()
        
        # Log para depuración
        logging.info(f"Resultado de consulta de perfil para user_id {user_id}: {result}")
        
        cursor.close()
        conn.close()
        
        if result:
            profile_completed = bool(result[0])
        else:
            profile_completed = False
        
        return jsonify({
            'success': True, 
            'profile_completed': profile_completed
        })
        
    except Exception as e:
        logging.error(f"[PROFILE003] Error al verificar estado del perfil: {e}")
        return jsonify({
            'success': False, 
            'message': 'Error al procesar la solicitud', 
            'debug_error': str(e)
        }), 500


# Endpoint de actualización para extraer el user_id del token
@profile_bp.route('/update', methods=['POST'])
def update_profile():
    try:
        # Extraer el token del encabezado Authorization
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'success': False, 'message': 'Token no proporcionado'}), 401
        
        token = auth_header.split(' ')[1]
        
        # Decodificar el token para obtener el user_id
        try:
            payload = jwt.decode(token, Config.JWT_SECRET_KEY, algorithms=['HS256'])
            user_id = payload.get('user_id')
        except jwt.ExpiredSignatureError:
            return jsonify({'success': False, 'message': 'Token expirado'}), 401
        except jwt.InvalidTokenError as e:
            logging.error(f"Error al decodificar token: {str(e)}")
            return jsonify({'success': False, 'message': 'Token inválido'}), 401
        
        # Obtener datos del formulario
        full_name = request.form.get('full_name')
        phone = request.form.get('phone')
        
        # Verificación básica
        if not user_id or not full_name or not phone:
            return jsonify({'success': False, 'message': 'Información incompleta'}), 400
        
        # Inicializar variables
        profile_picture_url = None
        profile_picture_version = None
        
        # Verificar si hay archivo de imagen
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and file.filename != '':
                # Depuración: Imprimir información del archivo
                logging.info(f"Archivo recibido: {file.filename}, {file.content_type}, {file.mimetype}")
                
                try:
                    # Verificar si el usuario ya tenía una imagen en Cloudinary
                    conn = get_db_connection()
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT profile_picture_url FROM user_profile 
                        WHERE user_id = %s AND profile_picture_url IS NOT NULL 
                        AND profile_picture_url NOT LIKE '/SkillSwap/%'
                    """, (user_id,))
                    existing_image = cursor.fetchone()
                    cursor.close()
                    conn.close()
                    
                    # Si existe una imagen anterior en Cloudinary, eliminar todas sus versiones
                    if existing_image and existing_image[0]:
                        try:
                            logging.info(f"Eliminando versiones anteriores de la imagen para user_id {user_id}")
                            delete_all_versions(existing_image[0], resource_type="image")
                        except Exception as delete_error:
                            logging.error(f"Error al eliminar versiones antiguas: {str(delete_error)}")
                            # Continuamos con la subida aunque falle la eliminación
                    
                    # Subir la imagen a Cloudinary
                    image_result = upload_profile_image(file, user_id)
                    profile_picture_url = image_result["public_id"]
                    profile_picture_version = image_result["version"]
                    
                    # Log para depuración
                    logging.info(f"URL de imagen obtenida después de la carga: {profile_picture_url}, versión: {profile_picture_version}")
                    
                    if not profile_picture_url:
                        logging.error("Error: No se pudo obtener URL después de la carga")
                        return jsonify({'success': False, 'message': 'Error al cargar la imagen'}), 500
                except Exception as upload_error:
                    logging.error(f"Error al subir imagen: {str(upload_error)}")
                    return jsonify({'success': False, 'message': f'Error al cargar la imagen: {str(upload_error)}'}), 500
        
        # Para imágenes predefinidas, asegurarse de guardar solo la ruta relativa
        elif 'profile_picture_url' in request.form:
            # Obtener la URL original
            original_url = request.form.get('profile_picture_url')
            
            # Extraer solo la ruta relativa si contiene la base URL
            if original_url:
                # Si es una URL completa que contiene 'http://' o la ruta base
                if original_url.startswith('http://') or original_url.startswith('https://'):
                    # Buscar la parte de la ruta que corresponde a /SkillSwap/
                    start_index = original_url.find('/SkillSwap/')
                    if start_index != -1:
                        # Extraer solo desde /SkillSwap/ en adelante
                        profile_picture_url = original_url[start_index:]
                    else:
                        # Si no se encuentra el patrón, usar la URL original
                        profile_picture_url = original_url
                else:
                    # Si ya es una ruta relativa, usarla tal cual
                    profile_picture_url = original_url
                
        
        # Conectar a la base de datos
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verificar si ya existe un perfil para este usuario
        cursor.execute("SELECT id FROM user_profile WHERE user_id = %s", (user_id,))
        existing_profile = cursor.fetchone()
        
        if existing_profile:
            # Actualizar el perfil existente
            update_query = """
                UPDATE user_profile SET 
                full_name = %s, 
                phone = %s,
                profile_completed = 1
            """
            
            params = [full_name, phone]
            
            # Solo actualizar la URL de la imagen si se proporcionó una nueva
            if profile_picture_url:
                if profile_picture_version:
                    update_query += ", profile_picture_url = %s, profile_picture_version = %s"
                    params.extend([profile_picture_url, profile_picture_version])
                else:
                    update_query += ", profile_picture_url = %s"
                    params.append(profile_picture_url)
            
            update_query += " WHERE user_id = %s"
            params.append(user_id)
            
            cursor.execute(update_query, tuple(params))
            logging.info(f"Perfil actualizado para user_id {user_id}")
        else:
            # Crear un nuevo perfil
            if profile_picture_version:
                cursor.execute("""
                    INSERT INTO user_profile 
                    (user_id, full_name, phone, profile_picture_url, profile_picture_version, profile_completed) 
                    VALUES (%s, %s, %s, %s, %s, 1)
                """, (user_id, full_name, phone, profile_picture_url, profile_picture_version))
            else:
                cursor.execute("""
                    INSERT INTO user_profile 
                    (user_id, full_name, phone, profile_picture_url, profile_completed) 
                    VALUES (%s, %s, %s, %s, 1)
                """, (user_id, full_name, phone, profile_picture_url))
            logging.info(f"Nuevo perfil creado para user_id {user_id}")
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Perfil actualizado correctamente'})
    
    except Exception as e:
        logging.error(f"[PROFILE002] Error al actualizar perfil: {e}")
        return jsonify({
            'success': False, 
            'message': 'Error al procesar la solicitud', 
            'debug_error': str(e)
        }), 500


@profile_bp.route('/picture', methods=['GET'])
def get_profile_picture():
    try:
        # Extraer el token del encabezado Authorization
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'success': False, 'message': 'Token no proporcionado'}), 401
        
        token = auth_header.split(' ')[1]
        
        # Decodificar el token para obtener el user_id
        try:
            payload = jwt.decode(token, Config.JWT_SECRET_KEY, algorithms=['HS256'])
            user_id = payload.get('user_id')
        except jwt.ExpiredSignatureError:
            return jsonify({'success': False, 'message': 'Token expirado'}), 401
        except jwt.InvalidTokenError as e:
            logging.error(f"Error al decodificar token: {str(e)}")
            return jsonify({'success': False, 'message': 'Token inválido'}), 401
        
        if not user_id:
            return jsonify({'success': False, 'message': 'ID de usuario no encontrado en el token'}), 400
        
        # Consultar la URL de la imagen de perfil y su versión
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT profile_picture_url, profile_picture_version FROM user_profile 
            WHERE user_id = %s
        """, (user_id,))
        
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        
        # Obtener URL base para imágenes relativas
        base_url = request.host_url.rstrip('/')
        
        if result and result[0]:
            profile_picture_url = result[0]
            profile_picture_version = result[1] if len(result) > 1 else None
            
            logging.info(f"URL recuperada de la BD: {profile_picture_url}, versión: {profile_picture_version}")
            
            # Usar el nuevo servicio para determinar la URL correcta
            final_url = get_profile_image_url(
                profile_picture_url, 
                profile_picture_version, 
                base_url
            )
            
            return jsonify({
                'success': True,
                'profile_picture_url': final_url
            })
        else:
            # Si no hay imagen, usar el servicio para obtener la URL predeterminada
            default_url = get_profile_image_url(None, None, base_url)
            
            return jsonify({
                'success': True,
                'profile_picture_url': default_url
            })
            
    except Exception as e:
        logging.error(f"[PROFILE004] Error al recuperar imagen de perfil: {e}")
        return jsonify({
            'success': False, 
            'message': 'Error al procesar la solicitud', 
            'debug_error': str(e)
        }), 500