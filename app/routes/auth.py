from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app.models.employee import Employee
from app.utils.security import generate_csrf_token, csrf_protect
from app.utils.logger import log_system_action

bp = Blueprint('auth', __name__)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_id = request.form['user_id'].strip()
        password = request.form['password']
        
        if not user_id or not password:
            flash('아이디와 비밀번호를 입력해주세요.')
            return render_template('login.html')
            
        employee = Employee.query.filter_by(user_id=user_id).first()
        
        if employee and employee.check_password(password):
            session['user_id'] = employee.id
            session['user_name'] = employee.name
            session['role'] = employee.role
            log_system_action('login', f"User {employee.name} logged in", employee.id)
            return redirect(url_for('main.index'))
            
        flash('아이디 또는 비밀번호가 올바르지 않습니다.')
        
    return render_template('login.html')

@bp.route('/logout')
def logout():
    if 'user_id' in session:
        log_system_action('logout', f"User {session.get('user_name')} logged out", session.get('user_id'))
    session.clear()
    return redirect(url_for('auth.login')) 