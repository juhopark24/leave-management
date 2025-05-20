from flask import Flask
from app.config import Config
from app.extensions import db
from app.models.employee import Employee
from datetime import datetime
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

        # Create default admin account
        if not Employee.query.filter_by(user_id='admin').first():
            admin = Employee(
                name='Administrator',
                department='Admin',
                position='Manager',
                join_date=datetime.now().date(),
                annual_leave=0,
                user_id='admin',
                role='admin'
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()

    return app
