import logging
from logging.handlers import RotatingFileHandler
import os
from datetime import datetime
from app.extensions import db
from app.models.system_log import SystemLog

def setup_logger(app):
    if not os.path.exists('logs'):
        os.mkdir('logs')
        
    file_handler = RotatingFileHandler('logs/leave_tracker.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Leave Tracker startup')

def log_system_action(action, details, employee_id=None):
    try:
        log = SystemLog(
            action=action,
            details=details,
            employee_id=employee_id,
            timestamp=datetime.now()
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to log system action: {str(e)}")

def log_employee_change(employee, old_values, new_values):
    changes = []
    for key, old_value in old_values.items():
        if old_value != new_values.get(key):
            changes.append(f"{key}: {old_value} → {new_values.get(key)}")
    
    if changes:
        log_system_action(
            action='edit_employee',
            details=f"Employee {employee.name} updated: {', '.join(changes)}",
            employee_id=employee.id
        )

def log_leave_request(leave_request, action):
    log_system_action(
        action=action,
        details=f"Leave request {leave_request.id} for {leave_request.employee.name}: "
                f"{leave_request.start_date} to {leave_request.end_date} ({leave_request.days} days)",
        employee_id=leave_request.employee_id
    ) 