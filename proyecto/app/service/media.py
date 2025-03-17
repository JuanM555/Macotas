import cloudinary
import cloudinary.uploader
import cloudinary.api
import cloudinary.utils
import logging
import time
from app.config import Config

# Configurar Cloudinary 
cloudinary.config(
    cloud_name=Config.CLOUDINARY_CLOUD_NAME,
    api_key=Config.CLOUDINARY_API_KEY,
    api_secret=Config.CLOUDINARY_API_SECRET
)


def upload_profile_image(file_data, user_id):
    """
    Sube una imagen de perfil y sobrescribe versiones anteriores.
    
    Args:
        file_data: Datos del archivo a subir
        user_id: ID del usuario
        
    Returns:
        dict: Información de la imagen subida con public_id y version
    """
    try:
        logging.info(f"Intentando subir imagen para user_id: {user_id}")
        
        # Subir con invalidate=true para eliminar versiones en caché
        upload_result = cloudinary.uploader.upload(
            file_data,
            folder="profiles",
            public_id=f"user_{user_id}",
            overwrite=True,
            invalidate=True,
            resource_type="auto",
            type="authenticated"
        )
        
        logging.info(f"Resultado de carga: {upload_result}")
        
        # Devolver public_id y version como un diccionario
        return {
            "public_id": upload_result["public_id"],
            "version": upload_result["version"]
        }
    
    except Exception as e:
        logging.error(f"[CLOUDINARY001] Error en Cloudinary: {str(e)}")
        raise


def upload_document(file_data, folder, custom_id=None, overwrite=True, invalidate=True):
    """
    Sube un documento u otro archivo a Cloudinary.
    
    Args:
        file_data: Datos del archivo a subir
        folder: Carpeta donde guardar el archivo
        custom_id: ID personalizado para el archivo (opcional)
        overwrite: Si se debe sobrescribir archivos existentes
        invalidate: Si se deben invalidar versiones en caché
        
    Returns:
        dict: Información completa del archivo subido
    """
    try:
        logging.info(f"Subiendo archivo a carpeta {folder}")
        
        upload_params = {
            "folder": folder,
            "resource_type": "auto",
            "type": "authenticated",
            "overwrite": overwrite,
            "invalidate": invalidate
        }
        
        if custom_id:
            upload_params["public_id"] = custom_id
            
        upload_result = cloudinary.uploader.upload(
            file_data,
            **upload_params
        )
        
        logging.info(f"Archivo subido exitosamente: {upload_result['public_id']}")
        return upload_result
    
    except Exception as e:
        logging.error(f"[CLOUDINARY004] Error al subir archivo: {str(e)}")
        raise


def delete_resource(public_id, resource_type="image", invalidate=True):
    """
    Elimina un recurso de Cloudinary.
    
    Args:
        public_id: ID público del recurso a eliminar
        resource_type: Tipo de recurso (image, raw, video, etc.)
        invalidate: Si se debe invalidar en CDN también
        
    Returns:
        dict: Resultado de la operación de eliminación
    """
    try:
        logging.info(f"Eliminando recurso: {public_id}")
        
        result = cloudinary.uploader.destroy(
            public_id,
            resource_type=resource_type,
            invalidate=invalidate
        )
        
        logging.info(f"Resultado de eliminación: {result}")
        return result
    
    except Exception as e:
        logging.error(f"[CLOUDINARY005] Error al eliminar recurso: {str(e)}")
        raise


def delete_all_versions(public_id, resource_type="image"):
    """
    Elimina todas las versiones de un recurso de Cloudinary.
    
    Args:
        public_id: ID público del recurso
        resource_type: Tipo de recurso
        
    Returns:
        dict: Resultado de la operación
    """
    try:
        logging.info(f"Eliminando todas las versiones de: {public_id}")
        
        result = cloudinary.api.delete_resources_by_prefix(
            f"{public_id}",
            resource_type=resource_type
        )
        
        logging.info(f"Resultado de eliminación masiva: {result}")
        return result
    
    except Exception as e:
        logging.error(f"[CLOUDINARY006] Error al eliminar versiones: {str(e)}")
        raise


def list_resource_versions(public_id, resource_type="image"):
    """
    Lista todas las versiones disponibles de un recurso.
    
    Args:
        public_id: ID público del recurso
        resource_type: Tipo de recurso
        
    Returns:
        list: Lista de versiones disponibles
    """
    try:
        logging.info(f"Listando versiones para: {public_id}")
        
        result = cloudinary.api.resources_by_ids(
            [public_id],
            resource_type=resource_type,
            versions=True
        )
        
        if 'resources' in result and result['resources']:
            versions = [{'version': item['version'], 'url': item['url']} 
                       for item in result['resources']]
            return versions
        
        return []
    
    except Exception as e:
        logging.error(f"[CLOUDINARY007] Error al listar versiones: {str(e)}")
        raise


def get_authenticated_image_url(public_id, version=None):
    """
    Genera una URL autenticada para Cloudinary con o sin versión específica.
    
    Args:
        public_id (str): El public_id de Cloudinary
        version (str, optional): La versión específica de la imagen
        
    Returns:
        str: URL autenticada para la imagen
    """
    try:
        # Definir parámetros base
        params = {
            "type": "authenticated",
            "secure": True,
            "sign_url": True,
            "resource_type": "image",
            "sign_url_expiration": int(time.time()) + 3600  # 1 hora
        }
        
        # Añadir versión específica o force_version según corresponda
        if version:
            params["version"] = version
        else:
            params["force_version"] = True
            
        authenticated_url = cloudinary.utils.cloudinary_url(
            public_id,
            **params
        )[0]
        
        logging.info(f"URL autenticada generada: {authenticated_url}")
        return authenticated_url
    except Exception as e:
        logging.error(f"[CLOUDINARY002] Error al generar URL autenticada: {str(e)}")
        raise


def get_profile_image_url(profile_picture_url, profile_picture_version=None, base_url=None):
    """
    Determina y genera la URL correcta para una imagen de perfil
    dependiendo de su tipo (Cloudinary, ruta relativa, URL completa).
    
    Args:
        profile_picture_url (str): URL o public_id de la imagen
        profile_picture_version (str, optional): La versión de la imagen Cloudinary
        base_url (str, optional): URL base para imágenes relativas
        
    Returns:
        str: URL final para la imagen de perfil
    """
    try:
        if not profile_picture_url:
            # Si no hay imagen de perfil, devolver una URL predeterminada
            default_image_url = "/SkillSwap/static/images/default-profile.png"
            if base_url:
                return f"{base_url.rstrip('/')}{default_image_url}"
            return default_image_url
            
        # Para rutas relativas de la aplicación
        if profile_picture_url.startswith('/SkillSwap/'):
            return profile_picture_url
            
        # Para public_id de Cloudinary (no comienza con 'http' ni con '/')
        if not profile_picture_url.startswith(('http://', 'https://', '/')):
            logging.info(f"Generando URL autenticada para public_id: {profile_picture_url}")
            return get_authenticated_image_url(profile_picture_url, profile_picture_version)
            
        # Para cualquier otro tipo de URL
        return profile_picture_url
            
    except Exception as e:
        logging.error(f"[CLOUDINARY003] Error al procesar URL de imagen: {str(e)}")
        raise