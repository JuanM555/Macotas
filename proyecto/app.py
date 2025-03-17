from flask import Flask
from flask_cors import CORS
from app.config import Config  
from app.routes.auth import auth_bp
from app.routes.dash import dash_bp 
from app.routes.whatsapp import whatsapp_bp
from app.routes.media import profile_bp

# Crear la aplicación Flask
app = Flask(__name__, template_folder="app/templates", static_folder="app/static")

# Cargar la configuración desde Config
app.config.from_object(Config)

# Configurar CORS
CORS(app, resources={r"/*": {"origins": "*"}})


# Registrar las rutas
app.register_blueprint(auth_bp)
app.register_blueprint(dash_bp, url_prefix="/dashboard")
app.register_blueprint(whatsapp_bp, url_prefix="/api")
app.register_blueprint(profile_bp)

if __name__ == '__main__':
    app.run(debug=True)
