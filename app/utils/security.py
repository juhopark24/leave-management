import os
from functools import wraps
from flask import session, redirect, url_for, flash, request
from app.extensions import db
from app.models.employee import Employee

def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = os.urandom(24).hex()
    return session['csrf_token']

def csrf_protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == "POST":
            token = session.get('csrf_token')
            if not token or token != request.form.get('csrf_token'):
                flash('잘못된 요청입니다.')
                return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('auth.login', next=request.endpoint))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('auth.login', next=request.endpoint))
        current_user = Employee.query.get(session['user_id'])
        if not current_user or current_user.role != 'admin':
            flash('권한이 없습니다.')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function 