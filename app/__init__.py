from flask import Flask, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from .models import db, User
from itsdangerous import URLSafeTimedSerializer

login_manager = LoginManager()
migrate = Migrate()

# Initialize the serializer globally (used for URL token generation)
URL_SERIALIZER = None


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def create_app(config_class="Config"):
    """Create and configure the Flask application."""
    app = Flask(__name__)
    
    # Load the configuration from config.py
    app.config.from_object(f"config.{config_class}")

    # Initialize extensions with the app
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'  # Set the login view for flask-login
    
    # Initialize migration
    migrate.init_app(app, db)
    
    # Initialize URL serializer (used for token generation)
    global URL_SERIALIZER
    URL_SERIALIZER = URLSafeTimedSerializer(app.config['SECRET_KEY'])

    # Register Blueprints
    from .views import bp as views_bp
    from .auth import auth as auth_bp
    from .admin import admin as admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(views_bp)
    app.register_blueprint(admin_bp, url_prefix='/admin')

    # Create the tables (if needed)
    with app.app_context():
        db.create_all()

    return app
