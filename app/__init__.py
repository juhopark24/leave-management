from flask import Flask
from app.config import Config
from app.extensions import db
from app.utils.logger import setup_logger
from app.routes import auth, main, system

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize extensions
    db.init_app(app)
    
    # Setup logging
    setup_logger(app)
    
    # Register blueprints
    app.register_blueprint(auth.bp)
    app.register_blueprint(main.bp)
    app.register_blueprint(system.bp)
    
    # Create database tables
    with app.app_context():
        db.create_all()
        
    return app
