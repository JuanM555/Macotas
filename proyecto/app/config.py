import os
from dotenv import load_dotenv


# Cargar el archivo .env
load_dotenv()

class Config:
    # Base de datos
    DB_HOST = os.getenv("DB_HOST")
    DB_NAME = os.getenv("DB_NAME")
    DB_USER = os.getenv("DB_USER")
    DB_PASSWORD = os.getenv("DB_PASSWORD")
    
    SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Correo
    MAIL_USERNAME = os.getenv("EMAIL_USER")
    MAIL_PASSWORD = os.getenv("EMAIL_PASS")
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True

    # JWT
    JWT_SECRET_KEY = os.getenv("JWT_SECRET")

    # Cloudinary
    CLOUDINARY_CLOUD_NAME = os.getenv("cloud_name")
    CLOUDINARY_API_KEY = os.getenv("api_key")
    CLOUDINARY_API_SECRET = os.getenv("api_secret")