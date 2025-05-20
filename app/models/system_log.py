from datetime import datetime
from . import db

class SystemLog(db.Model):
    __tablename__ = 'system_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    action = db.Column(db.String(50), nullable=False)  # 'add', 'edit', 'delete', 'cancel_request'
    employee_name = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    
    def to_dict(self):
        return {
            'id': self.id,
            'action': self.action,
            'details': self.details,
            'employee_name': self.employee_name,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        } 