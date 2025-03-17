from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_cors import CORS

# Instancia de las extensiones
db = SQLAlchemy()
mail = Mail()

def create_app():
    app = Flask(__name__)
    app.config.from_object('app.config.Config')

    # Habilitar CORS
    CORS(app)

    # Inicializar las extensiones
    db.init_app(app)
    mail.init_app(app)

    # Registrar los Blueprints
    from app.routes import auth, user  
    app.register_blueprint(auth.bp)  # Registro de 'auth'
    app.register_blueprint(user.bp)  # Registro de 'user'

    return app
