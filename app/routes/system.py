from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app.models.employee import Employee
from app.models.leave_request import LeaveRequest
from app.models.system_log import SystemLog
from app.utils.security import admin_required, csrf_protect
from app.utils.logger import log_system_action, log_employee_change
from app.utils.date_utils import format_date, parse_date, round_to_half
from app.extensions import db

bp = Blueprint('system', __name__)

@bp.route('/system')
@admin_required
def system():
    employees = Employee.query.all()
    leave_requests = LeaveRequest.query.filter_by(status='pending').all()
    system_logs = SystemLog.query.order_by(SystemLog.timestamp.desc()).limit(100).all()
    return render_template('system.html', employees=employees, leave_requests=leave_requests, system_logs=system_logs)

@bp.route('/system/employee/add', methods=['POST'])
@admin_required
@csrf_protect
def add_employee():
    name = request.form['name'].strip()
    department = request.form['department'].strip()
    position = request.form['position'].strip()
    join_date = request.form['join_date']
    annual_leave = request.form['annual_leave']
    user_id = request.form['user_id'].strip()
    user_pw = request.form['user_pw'].strip()
    
    if not all([name, join_date, user_id, user_pw]):
        flash('필수 항목을 모두 입력해주세요.')
        return redirect(url_for('system.system'))
        
    if len(user_id) < 4 or len(user_pw) < 4:
        flash('아이디와 비밀번호는 4자 이상이어야 합니다.')
        return redirect(url_for('system.system'))
        
    if Employee.query.filter_by(user_id=user_id).first():
        flash('이미 사용 중인 아이디입니다.')
        return redirect(url_for('system.system'))
        
    try:
        annual_leave = round_to_half(float(annual_leave))
        if annual_leave < 0:
            raise ValueError()
    except ValueError:
        flash('연차 일수는 0 이상의 숫자여야 합니다.')
        return redirect(url_for('system.system'))
        
    employee = Employee(
        name=name,
        department=department,
        position=position,
        join_date=parse_date(join_date),
        annual_leave=annual_leave,
        user_id=user_id
    )
    employee.set_password(user_pw)
    
    db.session.add(employee)
    db.session.commit()
    
    log_system_action('add_employee', f"New employee added: {name}", employee.id)
    flash('직원이 추가되었습니다.')
    return redirect(url_for('system.system'))

@bp.route('/system/employee/edit/<int:employee_id>', methods=['POST'])
@admin_required
@csrf_protect
def edit_employee(employee_id):
    employee = Employee.query.get_or_404(employee_id)
    old_values = employee.to_dict()
    
    name = request.form['name'].strip()
    department = request.form['department'].strip()
    position = request.form['position'].strip()
    join_date = request.form['join_date']
    annual_leave = request.form['annual_leave']
    used_leave = request.form['used_leave']
    user_id = request.form['user_id'].strip()
    user_pw = request.form['user_pw'].strip()
    role = request.form['role']
    
    if not all([name, join_date, user_id]):
        flash('필수 항목을 모두 입력해주세요.')
        return redirect(url_for('system.system'))
        
    if len(user_id) < 4:
        flash('아이디는 4자 이상이어야 합니다.')
        return redirect(url_for('system.system'))
        
    existing_employee = Employee.query.filter_by(user_id=user_id).first()
    if existing_employee and existing_employee.id != employee.id:
        flash('이미 사용 중인 아이디입니다.')
        return redirect(url_for('system.system'))
        
    try:
        annual_leave = round_to_half(float(annual_leave))
        used_leave = round_to_half(float(used_leave))
        if annual_leave < 0 or used_leave < 0 or used_leave > annual_leave:
            raise ValueError()
    except ValueError:
        flash('연차 일수는 0 이상이어야 하며, 사용한 연차는 총 연차를 초과할 수 없습니다.')
        return redirect(url_for('system.system'))
        
    if role == 'user' and employee.role == 'admin':
        admin_count = Employee.query.filter_by(role='admin').count()
        if admin_count <= 1:
            flash('마지막 관리자 계정은 일반 사용자로 변경할 수 없습니다.')
            return redirect(url_for('system.system'))
            
    employee.name = name
    employee.department = department
    employee.position = position
    employee.join_date = parse_date(join_date)
    employee.annual_leave = annual_leave
    employee.used_leave = used_leave
    employee.remaining_leave = annual_leave - used_leave
    employee.user_id = user_id
    employee.role = role
    
    if user_pw:
        if len(user_pw) < 4:
            flash('비밀번호는 4자 이상이어야 합니다.')
            return redirect(url_for('system.system'))
        employee.set_password(user_pw)
        
    db.session.commit()
    
    new_values = employee.to_dict()
    log_employee_change(employee, old_values, new_values)
    flash('직원 정보가 수정되었습니다.')
    return redirect(url_for('system.system'))

@bp.route('/system/employee/delete/<int:employee_id>', methods=['POST'])
@admin_required
@csrf_protect
def delete_employee(employee_id):
    employee = Employee.query.get_or_404(employee_id)
    
    if employee.role == 'admin':
        admin_count = Employee.query.filter_by(role='admin').count()
        if admin_count <= 1:
            flash('마지막 관리자 계정은 삭제할 수 없습니다.')
            return redirect(url_for('system.system'))
            
    db.session.delete(employee)
    db.session.commit()
    
    log_system_action('delete_employee', f"Employee deleted: {employee.name}")
    flash('직원이 삭제되었습니다.')
    return redirect(url_for('system.system'))

@bp.route('/system/leave/approve/<int:request_id>', methods=['POST'])
@admin_required
@csrf_protect
def approve_leave(request_id):
    leave_request = LeaveRequest.query.get_or_404(request_id)
    
    if leave_request.status != 'pending':
        flash('이미 처리된 요청입니다.')
        return redirect(url_for('system.system'))
        
    leave_request.update_status('approved')
    employee = leave_request.employee
    employee.update_leave_days(used_leave=employee.used_leave + leave_request.days)
    
    db.session.commit()
    
    log_system_action('approve_leave', f"Leave request approved: {leave_request.days} days", employee.id)
    flash('휴가가 승인되었습니다.')
    return redirect(url_for('system.system'))

@bp.route('/system/leave/reject/<int:request_id>', methods=['POST'])
@admin_required
@csrf_protect
def reject_leave(request_id):
    leave_request = LeaveRequest.query.get_or_404(request_id)
    
    if leave_request.status != 'pending':
        flash('이미 처리된 요청입니다.')
        return redirect(url_for('system.system'))
        
    leave_request.update_status('rejected')
    db.session.commit()
    
    log_system_action('reject_leave', f"Leave request rejected", leave_request.employee_id)
    flash('휴가가 거절되었습니다.')
    return redirect(url_for('system.system')) 
