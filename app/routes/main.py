from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app.models.employee import Employee
from app.models.leave_request import LeaveRequest
from app.utils.security import login_required, admin_required, csrf_protect
from app.utils.logger import log_system_action
from app.utils.date_utils import get_kst_now, format_date, is_holiday, count_weekdays, round_to_half
from app.extensions import db

bp = Blueprint('main', __name__)

@bp.route('/')
@login_required
def index():
    employee = Employee.query.get(session['user_id'])
    leave_requests = LeaveRequest.query.filter_by(employee_id=employee.id).order_by(LeaveRequest.created_at.desc()).all()
    return render_template('index.html', employee=employee, leave_requests=leave_requests)

@bp.route('/request', methods=['GET', 'POST'])
@login_required
@csrf_protect
def request_leave():
    if request.method == 'POST':
        employee = Employee.query.get(session['user_id'])
        leave_type = request.form['leave_type']
        start_date = request.form['start_date']
        end_date = request.form['end_date']
        reason = request.form['reason'].strip()
        
        if not all([leave_type, start_date, end_date, reason]):
            flash('모든 필드를 입력해주세요.')
            return redirect(url_for('main.request_leave'))
            
        if len(reason) < 5:
            flash('사유는 5자 이상 입력해주세요.')
            return redirect(url_for('main.request_leave'))
            
        start_date = format_date(start_date)
        end_date = format_date(end_date)
        
        if start_date < get_kst_now().date():
            flash('시작일은 오늘 이후여야 합니다.')
            return redirect(url_for('main.request_leave'))
            
        if end_date < start_date:
            flash('종료일은 시작일 이후여야 합니다.')
            return redirect(url_for('main.request_leave'))
            
        if leave_type in ['annual', 'half_day']:
            if is_holiday(start_date) or is_holiday(end_date):
                flash('주말 및 공휴일에는 연차를 사용할 수 없습니다.')
                return redirect(url_for('main.request_leave'))
                
        if leave_type == 'half_day' and start_date != end_date:
            flash('반차는 하루만 신청 가능합니다.')
            return redirect(url_for('main.request_leave'))
            
        days = count_weekdays(start_date, end_date)
        if leave_type == 'half_day':
            days = 0.5
            
        if days > employee.remaining_leave:
            flash('남은 연차 일수가 부족합니다.')
            return redirect(url_for('main.request_leave'))
            
        existing_requests = LeaveRequest.query.filter(
            LeaveRequest.employee_id == employee.id,
            LeaveRequest.status.in_(['pending', 'approved']),
            ((LeaveRequest.start_date <= start_date <= LeaveRequest.end_date) |
             (LeaveRequest.start_date <= end_date <= LeaveRequest.end_date))
        ).first()
        
        if existing_requests:
            flash('해당 기간에 이미 신청된 휴가가 있습니다.')
            return redirect(url_for('main.request_leave'))
            
        leave_request = LeaveRequest(
            employee_id=employee.id,
            leave_type=leave_type,
            start_date=start_date,
            end_date=end_date,
            days=days,
            reason=reason
        )
        
        db.session.add(leave_request)
        db.session.commit()
        
        log_system_action('request_leave', f"Leave request created: {days} days", employee.id)
        flash('휴가가 신청되었습니다.')
        return redirect(url_for('main.index'))
        
    return render_template('request.html') 