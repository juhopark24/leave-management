from datetime import datetime
from app.extensions import db

class SystemLog(db.Model):
    __tablename__ = 'system_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'))
    timestamp = db.Column(db.DateTime, default=datetime.now)
    
    def to_dict(self):
        return {
            'id': self.id,
            'action': self.action,
            'details': self.details,
            'employee_id': self.employee_id,
            'employee_name': self.employee.name if self.employee else None,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        } 