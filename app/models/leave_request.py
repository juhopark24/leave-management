from datetime import datetime
from . import db

class LeaveRequest(db.Model):
    __tablename__ = 'leave_requests'
    
    id = db.Column(db.Integer, primary_key=True)
    applicant_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    target_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # '연차', '반차(오전)', '반차(오후)', '출장'
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    reason = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'approved', 'rejected', 'cancelled', 'cancel_pending'
    created_at = db.Column(db.DateTime, default=datetime.now)
    processed_at = db.Column(db.DateTime)
    cancel_requested = db.Column(db.Boolean, default=False)
    cancel_reason = db.Column(db.Text)
    cancel_at = db.Column(db.DateTime)
    leave_days = db.Column(db.Float, default=0)
    
    def to_dict(self):
        return {
            'id': self.id,
            'applicant_id': self.applicant_id,
            'applicant_name': self.applicant.name,
            'target_id': self.target_id,
            'target_name': self.target.name,
            'type': self.type,
            'start_date': self.start_date.strftime('%Y-%m-%d %H:%M:%S'),
            'end_date': self.end_date.strftime('%Y-%m-%d %H:%M:%S'),
            'reason': self.reason,
            'status': self.status,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'processed_at': self.processed_at.strftime('%Y-%m-%d %H:%M:%S') if self.processed_at else None,
            'cancel_requested': self.cancel_requested,
            'cancel_reason': self.cancel_reason,
            'cancel_at': self.cancel_at.strftime('%Y-%m-%d %H:%M:%S') if self.cancel_at else None,
            'leave_days': self.leave_days
        }
    
    def update_status(self, status, cancel_reason=None):
        self.status = status
        if cancel_reason:
            self.cancel_reason = cancel_reason
        self.updated_at = datetime.now()
        
    def is_cancellable(self):
        return self.status in ['pending', 'approved'] 