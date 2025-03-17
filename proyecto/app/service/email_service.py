import yagmail
import logging
from app.config import Config  # Importar la configuración desde config.py

def send_verification_email(email, verification_url):
    """Envía un correo de verificación al usuario."""
    try:
        # Crear una instancia de SMTP con las credenciales del archivo Config
        yag = yagmail.SMTP(Config.MAIL_USERNAME, Config.MAIL_PASSWORD)
        yag.send(
            to=email,
            subject="¡Bienvenido a nuestro software de gestion sacramental, Completa tu registro",
            contents=f"Haz clic en el siguiente enlace para verificar tu correo:  {verification_url}"
        )   
        logging.info(f"Correo de verificación enviado a {email}.")
        return True
    except Exception as email_error:
        logging.error(f"[EMAIL001] Error al enviar el correo: {email_error}")
        return False
        
def send_password_reset_email(email, verification_url):
    """Envía un correo de verificación al usuario."""
    try:
        # Crear una instancia de SMTP con las credenciales del archivo Config
        yag = yagmail.SMTP(Config.MAIL_USERNAME, Config.MAIL_PASSWORD)

        # Convertir el contenido en UTF-8 explícitamente
        contenido = f"Haz clic en el siguiente enlace para recuperar tu contrasena: {verification_url}"

        # Enviar el correo con el contenido en UTF-8
        yag.send(
            to=email,
            subject="¡Bienvenido! Recupera tu contrasena de nuestro software de gestion sacramental",
            contents=[contenido]  # Pasar como lista para que yagmail lo interprete bien
        )   
        logging.info(f"Correo de verificación enviado a {email}.")
        return True
    except Exception as email_error:
        logging.error(f"[EMAIL001] Error al enviar el correo: {email_error}")
        return False
