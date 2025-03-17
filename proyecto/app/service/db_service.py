import mysql.connector
import logging
from mysql.connector import Error
from app.config import Config  # Importar la configuración centralizada

def get_db_connection():
    """Establece la conexión con la base de datos."""
    try:
        connection = mysql.connector.connect(
            host=Config.DB_HOST,
            user=Config.DB_USER,
            password=Config.DB_PASSWORD,
            database=Config.DB_NAME
        )
        if connection.is_connected():
            logging.info("Conexión a la base de datos establecida.")
            return connection
    except Error as e:
        logging.error(f"[DB001] Error al conectar con la base de datos: {e}")
        return None
