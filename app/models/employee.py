from datetime import datetime
from . import db
from werkzeug.security import generate_password_hash, check_password_hash

class Employee(db.Model):
    __tablename__ = 'employees'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    eng_name = db.Column(db.String(100))
    department = db.Column(db.String(100))
    position = db.Column(db.String(100))
    join_date = db.Column(db.DateTime, nullable=False)
    annual_leave = db.Column(db.Float, default=15)
    used_leave = db.Column(db.Float, default=0)
    remaining_leave = db.Column(db.Float, default=15)
    user_id = db.Column(db.String(50), unique=True, nullable=False)
    user_pw_hash = db.Column(db.LargeBinary(128), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'admin' or 'user'
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    
    leave_requests = db.relationship('LeaveRequest', 
                                   foreign_keys='LeaveRequest.target_id',
                                   backref='employee', 
                                   lazy=True)
    applied_requests = db.relationship('LeaveRequest',
                                     foreign_keys='LeaveRequest.applicant_id',
                                     backref='applicant',
                                     lazy=True)
    
    def set_password(self, password):
        self.user_pw_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.user_pw_hash, password)
    
    def update_leave_days(self, annual_leave=None, used_leave=None):
        if annual_leave is not None:
            self.annual_leave = annual_leave
        if used_leave is not None:
            self.used_leave = used_leave
        self.remaining_leave = self.annual_leave - self.used_leave
        self.updated_at = datetime.now()
        
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'department': self.department,
            'position': self.position,
            'join_date': self.join_date.strftime('%Y-%m-%d'),
            'annual_leave': self.annual_leave,
            'used_leave': self.used_leave,
            'remaining_leave': self.remaining_leave,
            'user_id': self.user_id,
            'role': self.role
        } 