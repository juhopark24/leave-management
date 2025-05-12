from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file, g
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import bcrypt
import pandas as pd
import io
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
import os
from functools import wraps
from sqlalchemy.exc import SQLAlchemyError
from decimal import Decimal, ROUND_HALF_UP
import pytz
import logging
from logging.handlers import RotatingFileHandler
import json
from sqlalchemy.orm import aliased
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///work_manager.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

db = SQLAlchemy(app)

# 로깅 설정 (app 생성 이후로 이동)
if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('TimeOff Manager startup')

# 한국 시간대 설정
KST = pytz.timezone('Asia/Seoul')

def get_kst_now():
    return datetime.now(KST)

def format_kst_datetime(dt):
    """datetime 객체를 KST 기준 문자열로 변환"""
    if dt is None:
        return ''
    if dt.tzinfo is None:
        dt = KST.localize(dt)
    return dt.strftime('%Y-%m-%d %H:%M:%S')

def format_date(dt):
    """datetime 객체를 'YYYY-MM-DD' 문자열로 변환"""
    if dt is None:
        return ''
    if isinstance(dt, str):
        return dt
    return dt.strftime('%Y-%m-%d')

def parse_date(date_str):
    """문자열을 datetime 객체로 변환"""
    if isinstance(date_str, datetime):
        return date_str
    try:
        return datetime.strptime(date_str, '%Y-%m-%d')
    except (ValueError, TypeError):
        return None

# CSRF 보호를 위한 토큰 생성
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = os.urandom(24).hex()
    return session['csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

# 템플릿 필터 등록
@app.template_filter('format_kst_datetime')
def format_kst_datetime_filter(dt):
    if dt is None:
        return ''
    if dt.tzinfo is None:
        dt = KST.localize(dt)
    return dt.strftime('%Y-%m-%d %H:%M:%S')

# CSRF 보호 데코레이터
def csrf_protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == "POST":
            token = session.get('csrf_token')
            if not token or token != request.form.get('csrf_token'):
                flash('잘못된 요청입니다.')
                return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# 세션 보안 강화
@app.before_request
def before_request():
    session.permanent = True
    g.user = None
    if 'user_id' in session:
        g.user = Employee.query.get(session['user_id'])
        # 세션 하이재킹 방지
        if 'user_agent' not in session:
            session['user_agent'] = request.headers.get('User-Agent')
        elif session['user_agent'] != request.headers.get('User-Agent'):
            session.clear()
            flash('보안을 위해 다시 로그인해주세요.')
            return redirect(url_for('login'))
        
        # 세션 만료 체크 - 로그인 페이지에서는 체크하지 않음
        if request.endpoint != 'login' and 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if get_kst_now() - last_activity > app.config['PERMANENT_SESSION_LIFETIME']:
                session.clear()
                flash('세션이 만료되었습니다. 다시 로그인해주세요.')
                return redirect(url_for('login'))
        
        session['last_activity'] = get_kst_now().isoformat()

# 0.5 단위 반올림 헬퍼 함수
def round_to_half(value):
    return float(Decimal(str(value)).quantize(Decimal('0.5'), rounding=ROUND_HALF_UP))

# 비밀번호 해시 저장용 테이블
class AdminPassword(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pw_hash = db.Column(db.LargeBinary(128), nullable=False)

class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    department = db.Column(db.String(50))
    position = db.Column(db.String(50))
    join_date = db.Column(db.DateTime, nullable=False)
    annual_leave = db.Column(db.Integer, default=15)
    used_leave = db.Column(db.Float, default=0)
    remaining_leave = db.Column(db.Float, default=15)
    user_id = db.Column(db.String(50), unique=True)
    user_pw_hash = db.Column(db.LargeBinary(128))
    role = db.Column(db.String(10), default='user')
    leave_requests = db.relationship(
        'LeaveRequest',
        backref='employee',
        cascade='all, delete-orphan',
        foreign_keys='LeaveRequest.target_id'
    )
    my_requests = db.relationship(
        'LeaveRequest',
        foreign_keys='LeaveRequest.applicant_id',
        backref='applicant'
    )

class LeaveRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    applicant_id = db.Column(db.Integer, db.ForeignKey('employee.id', ondelete='SET NULL'))
    target_id = db.Column(db.Integer, db.ForeignKey('employee.id', ondelete='CASCADE'))
    type = db.Column(db.String(20))
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    reason = db.Column(db.String(200))
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=lambda: get_kst_now())
    processed_at = db.Column(db.DateTime)
    leave_days = db.Column(db.Float, default=0)
    cancel_requested = db.Column(db.Boolean, default=False)
    cancel_reason = db.Column(db.String(200))
    cancel_at = db.Column(db.DateTime)

class SystemLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: get_kst_now())
    action = db.Column(db.String(20))  # add, edit, delete
    employee_name = db.Column(db.String(50))
    details = db.Column(db.String(200))

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': format_kst_datetime(self.timestamp),
            'action': self.action,
            'employee_name': self.employee_name,
            'details': self.details
        }

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_id = request.form['user_id']
        password = request.form['password']
        
        user = Employee.query.filter_by(user_id=user_id).first()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user.user_pw_hash):
            session['user_id'] = user.id
            session['role'] = user.role
            flash('로그인되었습니다.', 'success')
            return redirect(url_for('leave'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        user = Employee.query.get(session['user_id'])
        session.clear()
    flash('로그아웃되었습니다.', 'success')
    return redirect(url_for('login'))

@app.context_processor
def inject_user_role():
    user_id = session.get('user_id')
    is_admin = False
    if user_id:
        emp = Employee.query.get(user_id)
        if emp and emp.role == 'admin':
            is_admin = True
    return dict(user_is_admin=is_admin)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login', next=request.endpoint))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id') or Employee.query.get(session['user_id']).role != 'admin':
            flash('관리자 권한이 필요합니다.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# 공휴일 관리를 위한 클래스 추가
class Holiday(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False, unique=True)
    name = db.Column(db.String(50), nullable=False)
    year = db.Column(db.Integer, nullable=False)

# 공휴일 체크 함수 수정
def is_holiday(date):
    if isinstance(date, str):
        date = datetime.strptime(date, '%Y-%m-%d').date()
    return Holiday.query.filter_by(date=date).first() is not None

# 주말 체크 함수 추가
def is_weekend(date):
    if isinstance(date, str):
        date = datetime.strptime(date, '%Y-%m-%d').date()
    return date.weekday() >= 5  # 5: Saturday, 6: Sunday

# 유효한 휴가 날짜인지 체크하는 함수 추가
def is_valid_leave_date(date):
    if isinstance(date, str):
        date = datetime.strptime(date, '%Y-%m-%d').date()
    return not (is_holiday(date) or is_weekend(date))

@app.route('/', methods=['GET', 'POST'])
@login_required
def leave():
    try:
        employees = Employee.query.all()
        selected_employee = ''
        selected_type = ''
        
        if request.method == 'POST':
            try:
                employee_id = int(request.form['employee_id'])
                type = request.form['type']
                start_date = request.form['start_date']
                end_date = request.form['end_date']
                reason = request.form['reason'].strip()
                created_at = get_kst_now()
                emp = Employee.query.get(employee_id)
                selected_employee = str(employee_id)
                selected_type = type

                # 날짜 검증
                try:
                    sd = datetime.strptime(start_date, '%Y-%m-%d')
                    ed = datetime.strptime(end_date, '%Y-%m-%d')
                    today = get_kst_now().date()
                    
                    if sd.date() < today:
                        flash('휴가 시작일은 오늘 이후여야 합니다.')
                        return render_template('leave_request.html', 
                                             employees=employees, 
                                             requests=get_requests(), 
                                             selected_employee=selected_employee, 
                                             selected_type=selected_type)
                    
                    if ed < sd:
                        flash('종료일은 시작일보다 늦어야 합니다.')
                        return render_template('leave_request.html', 
                                             employees=employees, 
                                             requests=get_requests(), 
                                             selected_employee=selected_employee, 
                                             selected_type=selected_type)
                    
                    # 연차/반차의 경우 주말과 공휴일 제외
                    if type in ['연차', '반차(오전)', '반차(오후)']:
                        if sd.weekday() >= 5 or ed.weekday() >= 5 or is_holiday(start_date) or is_holiday(end_date):
                            flash('연차/반차는 주말과 공휴일에 신청할 수 없습니다.')
                            return render_template('leave_request.html', 
                                                 employees=employees, 
                                                 requests=get_requests(), 
                                                 selected_employee=selected_employee, 
                                                 selected_type=selected_type)
                except ValueError:
                    flash('날짜 형식이 올바르지 않습니다.')
                    return render_template('leave_request.html', 
                                         employees=employees, 
                                         requests=get_requests(), 
                                         selected_employee=selected_employee, 
                                         selected_type=selected_type)

                # 반차 검증
                if type in ['반차(오전)', '반차(오후)']:
                    if sd != ed:
                        flash('반차는 하루만 신청할 수 있습니다.')
                        return render_template('leave_request.html', 
                                             employees=employees, 
                                             requests=get_requests(), 
                                             selected_employee=selected_employee, 
                                             selected_type=selected_type)
                    days = 0.5
                else:
                    days = count_weekdays(sd, ed)

                # 연차 잔여량 검증
                if type in ['연차', '반차(오전)', '반차(오후)']:
                    pending = db.session.query(db.func.sum(LeaveRequest.leave_days)).filter(
                        LeaveRequest.target_id==employee_id,
                        LeaveRequest.status.in_(['pending','approved']),
                        LeaveRequest.type.in_(['연차','반차(오전)','반차(오후)'])
                    ).scalar() or 0
                    
                    if pending + days > emp.annual_leave:
                        flash(f'잔여 연차({emp.annual_leave - pending}일)보다 많은 일수는 신청할 수 없습니다.')
                        return render_template('leave_request.html', 
                                             employees=employees, 
                                             requests=get_requests(), 
                                             selected_employee=selected_employee, 
                                             selected_type=selected_type)

                # 기간 중복 검증
                overlap = LeaveRequest.query.filter(
                    LeaveRequest.target_id==employee_id,
                    LeaveRequest.status.in_(['pending','approved']),
                    LeaveRequest.start_date<=ed,
                    LeaveRequest.end_date>=sd
                ).first()
                if overlap:
                    flash('동일 기간에 이미 신청된 휴가/반차/출장이 있습니다.')
                    return render_template('leave_request.html', 
                                         employees=employees, 
                                         requests=get_requests(), 
                                         selected_employee=selected_employee, 
                                         selected_type=selected_type)

                # 연차 사용량 업데이트
                if type in ['연차','반차(오전)','반차(오후)']:
                    emp.used_leave = round_to_half(emp.used_leave + days)
                    emp.remaining_leave = round_to_half(emp.annual_leave - emp.used_leave)

                # 휴가 신청 생성
                db.session.add(LeaveRequest(
                    applicant_id=session['user_id'],
                    target_id=employee_id,
                    type=type,
                    start_date=sd,
                    end_date=ed,
                    reason=reason,
                    created_at=created_at,
                    leave_days=days
                ))
                db.session.commit()
                
                if type in ['연차', '반차(오전)', '반차(오후)']:
                    flash(f'신청이 완료되었습니다. (연차 소진: {days}일)')
                else:
                    flash('출장 신청이 완료되었습니다.')
                return redirect(url_for('leave'))
                
            except SQLAlchemyError as e:
                db.session.rollback()
                app.logger.error(f'Database error in leave request: {str(e)}')
                flash('데이터베이스 오류가 발생했습니다.')
            except Exception as e:
                db.session.rollback()
                app.logger.error(f'Error in leave request: {str(e)}')
                flash('처리 중 오류가 발생했습니다.')
                
        return render_template('leave_request.html', 
                             employees=employees, 
                             requests=get_requests(), 
                             selected_employee=selected_employee, 
                             selected_type=selected_type)
                             
    except Exception as e:
        app.logger.error(f'Error in leave route: {str(e)}')
        flash('시스템 오류가 발생했습니다.')
        return redirect(url_for('login'))

def get_requests():
    try:
        Target = aliased(Employee)
        Applicant = aliased(Employee)
        return db.session.query(LeaveRequest, Target, Applicant).join(
            Target, 
            LeaveRequest.target_id == Target.id
        ).join(
            Applicant,
            LeaveRequest.applicant_id == Applicant.id
        ).order_by(LeaveRequest.id.desc()).all()
    except Exception as e:
        app.logger.error(f'Error in get_requests: {str(e)}')
        return []

@app.route('/cancel_request/<int:req_id>', methods=['POST'])
@login_required
def cancel_request(req_id):
    req = LeaveRequest.query.get(req_id)
    user_id = session.get('user_id')
    is_admin = Employee.query.get(user_id).role == 'admin'

    # 본인 요청이거나 관리자인 경우만 취소 가능
    if not req or (user_id != req.applicant_id and not is_admin):
        flash('권한이 없습니다.')
        return redirect(url_for('leave'))

    # 대기중(pending) + 본인 요청이면 즉시 취소
    if req.status == 'pending' and user_id == req.applicant_id:
        req.status = 'cancelled'
        req.cancel_at = get_kst_now()
        db.session.commit()
        flash('신청이 즉시 취소되었습니다.')
        return redirect(url_for('leave'))

    # 승인된 경우 등은 기존대로 취소 요청(사유 입력)
    if req.status == 'approved' and not req.cancel_requested:
        cancel_reason = request.form.get('cancel_reason', '').strip()
        if not cancel_reason:
            flash('취소 사유를 입력해주세요.')
            return redirect(url_for('leave'))
        if len(cancel_reason) < 5:
            flash('취소 사유는 5자 이상 입력해주세요.')
            return redirect(url_for('leave'))
        # 취소 요청 처리
        req.cancel_requested = True
        req.cancel_reason = cancel_reason
        req.cancel_at = get_kst_now()
        req.status = 'cancel_pending'
        # 로그 추가
        log = SystemLog(
            timestamp=get_kst_now(),
            action='cancel_request',
            employee_name=req.employee.name,
            details=f'휴가 취소 요청: {req.type} ({req.start_date} ~ {req.end_date}), 사유: {cancel_reason}'
        )
        db.session.add(log)
        db.session.commit()
        flash('취소 요청이 접수되었습니다. 관리자의 승인을 기다려주세요.')
    return redirect(url_for('leave'))

@app.route('/status')
@login_required
def status():
    if not session.get('user_id') or Employee.query.get(session['user_id']).role != 'admin':
        return redirect(url_for('login'))
    requests = db.session.query(LeaveRequest, Employee).join(
        Employee, LeaveRequest.target_id == Employee.id
    ).order_by(LeaveRequest.created_at.desc()).all()
    return render_template('status.html', requests=requests)

@app.route('/approve/<int:req_id>', methods=['POST'])
def approve(req_id):
    if not session.get('user_id') or Employee.query.get(session['user_id']).role != 'admin':
        return redirect(url_for('login', next='status'))
    req = LeaveRequest.query.get(req_id)
    emp = Employee.query.get(req.target_id)
    if req.status in ['pending','cancel_pending']:
        req.status = 'approved'
        req.processed_at = get_kst_now()
        if req.type in ['연차','반차(오전)', '반차(오후)']:
            # 승인 시 used_leave/remaining_leave는 이미 차감되어 있음
            pass
        if req.cancel_requested:
            # 취소 승인 시 연차 원복
            emp.used_leave = round_to_half(emp.used_leave - req.leave_days)
            emp.remaining_leave = round_to_half(emp.annual_leave - emp.used_leave)
            req.status = 'cancelled'
        db.session.commit()
    return redirect(url_for('status'))

@app.route('/reject/<int:req_id>', methods=['POST'])
def reject(req_id):
    if not session.get('user_id') or Employee.query.get(session['user_id']).role != 'admin':
        return redirect(url_for('login', next='status'))
    req = LeaveRequest.query.get(req_id)
    emp = Employee.query.get(req.target_id)
    if req.status in ['pending','cancel_pending']:
        req.status = 'rejected'
        req.processed_at = get_kst_now()
        if req.type in ['연차','반차(오전)', '반차(오후)']:
            # 거절 시 used_leave/remaining_leave 원복
            emp.used_leave = round_to_half(emp.used_leave - req.leave_days)
            emp.remaining_leave = round_to_half(emp.annual_leave - emp.used_leave)
        db.session.commit()
    return redirect(url_for('status'))

@app.route('/approve_cancel/<int:req_id>', methods=['POST'])
def approve_cancel(req_id):
    if not session.get('user_id') or Employee.query.get(session['user_id']).role != 'admin':
        return redirect(url_for('login', next='status'))
    req = LeaveRequest.query.get(req_id)
    emp = Employee.query.get(req.target_id)
    if req.status == 'cancel_pending':
        # 연차/반차라면 연차 복구
        if req.type in ['연차', '반차(오전)', '반차(오후)']:
            emp.used_leave = round_to_half(emp.used_leave - req.leave_days)
            emp.remaining_leave = round_to_half(emp.annual_leave - emp.used_leave)
        req.status = 'cancelled'
        req.processed_at = get_kst_now()
        db.session.commit()
    return redirect(url_for('status'))

@app.route('/reject_cancel/<int:req_id>', methods=['POST'])
def reject_cancel(req_id):
    if not session.get('user_id') or Employee.query.get(session['user_id']).role != 'admin':
        return redirect(url_for('login', next='status'))
    req = LeaveRequest.query.get(req_id)
    if req.status == 'cancel_pending':
        req.status = 'approved'  # 취소 거절 시 다시 승인 상태로
        req.processed_at = get_kst_now()
        db.session.commit()
    return redirect(url_for('status'))

@app.route('/download_history')
def download_history():
    if not session.get('user_id') or Employee.query.get(session['user_id']).role != 'admin':
        return redirect(url_for('login', next='status'))
    requests = db.session.query(LeaveRequest, Employee).join(Employee, LeaveRequest.target_id == Employee.id).all()
    data = [
        {
            '직원명': emp.name,
            '신청구분': req.type,
            '시작일': req.start_date,
            '종료일': req.end_date,
            '신청일시': req.created_at,
            '상태': req.status,
            '사유': req.reason,
            '승인/처리일시': req.processed_at
        }
        for req, emp in requests
    ]
    df = pd.DataFrame(data)
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False)
    output.seek(0)
    return send_file(output, as_attachment=True, download_name='leave_history.xlsx', mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.route('/system', methods=['GET', 'POST'])
@login_required
def system():
    current_user = Employee.query.get(session.get('user_id'))
    if not current_user or current_user.role != 'admin':
        flash('권한이 없습니다.')
        return redirect(url_for('login'))
    
    employees = Employee.query.all()
    system_logs = SystemLog.query.order_by(SystemLog.timestamp.desc()).all()
    admin_count = Employee.query.filter_by(role='admin').count()
    
    if request.method == 'POST':
        try:
            name = request.form['name'].strip()
            department = request.form['department'].strip()
            position = request.form['position'].strip()
            join_date = request.form['join_date'].strip()
            annual_leave = float(request.form.get('annual_leave', 15))
            user_id = request.form['user_id'].strip()
            user_pw = request.form['user_pw'].strip()
            role = request.form.get('role', 'user')

            # 입력값 검증
            if not name or not join_date or not user_id or not user_pw:
                flash('이름, 입사일, ID, PW는 필수입니다.')
                return redirect(url_for('system'))
            
            if len(user_id) < 4:
                flash('ID는 4자 이상이어야 합니다.')
                return redirect(url_for('system'))
                
            if len(user_pw) < 4:
                flash('비밀번호는 4자 이상이어야 합니다.')
                return redirect(url_for('system'))

            # 연차 일수 검증
            try:
                annual_leave = round_to_half(float(annual_leave))
                if annual_leave < 0:
                    flash('연차 일수는 0 이상이어야 합니다.')
                    return redirect(url_for('system'))
            except ValueError:
                flash('연차 일수는 숫자여야 합니다.')
                return redirect(url_for('system'))

            # 중복 검사
            exists = Employee.query.filter_by(name=name, join_date=join_date).first()
            if exists:
                flash('동일한 이름과 입사일을 가진 직원이 이미 존재합니다.')
                return redirect(url_for('system'))
                
            if Employee.query.filter_by(user_id=user_id).first():
                flash('이미 사용중인 ID입니다.')
                return redirect(url_for('system'))

            # 비밀번호 해시 생성
            pw_hash = bcrypt.hashpw(user_pw.encode('utf-8'), bcrypt.gensalt())
            
            # 직원 추가
            emp = Employee(
                name=name,
                department=department,
                position=position,
                join_date=datetime.strptime(join_date, '%Y-%m-%d'),
                annual_leave=annual_leave,
                used_leave=0,
                remaining_leave=annual_leave,
                user_id=user_id,
                user_pw_hash=pw_hash,
                role=role
            )
            db.session.add(emp)
            
            # 로그 추가
            log = SystemLog(
                action='add',
                employee_name=name,
                details=f'부서: {department}, 직급: {position}, 입사일: {join_date}, 연차: {annual_leave}일, ID: {user_id}, 권한: {role}'
            )
            db.session.add(log)
            db.session.commit()
            
            flash('직원이 추가되었습니다.')
            return redirect(url_for('system'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error in system route: {str(e)}')
            flash('처리 중 오류가 발생했습니다.')
            return redirect(url_for('system'))
            
    return render_template('system.html', employees=employees, system_logs=system_logs, admin_count=admin_count)

@app.route('/edit_employee/<int:emp_id>', methods=['POST'])
@login_required
@csrf_protect
def edit_employee(emp_id):
    try:
        current_user = Employee.query.get(session.get('user_id'))
        if not current_user or current_user.role != 'admin':
            flash('권한이 없습니다.')
            return redirect(url_for('login'))
        
        emp = Employee.query.get_or_404(emp_id)
        
        # 관리자 계정 보호
        admin_count = Employee.query.filter_by(role='admin').count()
        if emp.role == 'admin' and admin_count <= 1 and request.form.get('role') != 'admin':
            flash('마지막 관리자 계정은 권한을 변경할 수 없습니다.')
            return redirect(url_for('system'))
        
        # 입력값 검증
        name = request.form['name'].strip()
        join_date = request.form['join_date'].strip()
        user_id = request.form['user_id'].strip()
        user_pw = request.form.get('user_pw', '').strip()
        
        if not all([name, join_date, user_id]):
            flash('필수 항목을 모두 입력해주세요.')
            return redirect(url_for('system'))
        
        if len(user_id) < 4:
            flash('ID는 4자 이상이어야 합니다.')
            return redirect(url_for('system'))
        
        if user_pw and len(user_pw) < 4:
            flash('비밀번호는 4자 이상이어야 합니다.')
            return redirect(url_for('system'))
        
        # 연차 입력값 검증
        try:
            annual_leave = round_to_half(float(request.form['annual_leave']))
            used_leave = round_to_half(float(request.form['used_leave']))
            remaining_leave = round_to_half(float(request.form['remaining_leave']))
            
            if any(x < 0 for x in [annual_leave, used_leave, remaining_leave]):
                flash('연차는 음수일 수 없습니다.')
                return redirect(url_for('system'))
            
            if abs(annual_leave - (used_leave + remaining_leave)) > 0.1:
                flash('연차 합계가 일치하지 않습니다.')
                return redirect(url_for('system'))
        except ValueError:
            flash('연차는 숫자만 입력 가능합니다.')
            return redirect(url_for('system'))
        
        # ID 중복 체크
        existing_emp = Employee.query.filter_by(user_id=user_id).first()
        if existing_emp and existing_emp.id != emp_id:
            flash('이미 사용 중인 ID입니다.')
            return redirect(url_for('system'))
        
        # 직원 정보 업데이트
        old_values = {
            'name': emp.name,
            'department': emp.department,
            'position': emp.position,
            'join_date': emp.join_date,
            'annual_leave': emp.annual_leave,
            'used_leave': emp.used_leave,
            'remaining_leave': emp.remaining_leave,
            'user_id': emp.user_id,
            'role': emp.role
        }
        
        emp.name = name
        emp.department = request.form['department'].strip()
        emp.position = request.form['position'].strip()
        emp.join_date = datetime.strptime(join_date, '%Y-%m-%d')
        emp.annual_leave = annual_leave
        emp.used_leave = used_leave
        emp.remaining_leave = remaining_leave
        emp.user_id = user_id
        emp.role = request.form['role']
        
        if user_pw:
            emp.user_pw_hash = bcrypt.hashpw(user_pw.encode('utf-8'), bcrypt.gensalt())
        
        # 변경사항 로깅
        changes = []
        for key, old_value in old_values.items():
            new_value = getattr(emp, key)
            if old_value != new_value:
                changes.append(f"{key}: {old_value} → {new_value}")
        
        if changes:
            log = SystemLog(
                action='edit',
                employee_name=emp.name,
                details=', '.join(changes)
            )
            db.session.add(log)
        
        db.session.commit()
        flash('직원 정보가 수정되었습니다.')
        
    except SQLAlchemyError as e:
        db.session.rollback()
        flash('데이터베이스 오류가 발생했습니다.')
        app.logger.error(f'Database error in edit_employee: {str(e)}')
    except Exception as e:
        db.session.rollback()
        flash('처리 중 오류가 발생했습니다.')
        app.logger.error(f'Error in edit_employee: {str(e)}')
    
    return redirect(url_for('system'))

@app.route('/delete_employee/<int:emp_id>', methods=['POST'])
@login_required
@csrf_protect
def delete_employee(emp_id):
    try:
        current_user = Employee.query.get(session.get('user_id'))
        if not current_user or current_user.role != 'admin':
            flash('권한이 없습니다.')
            return redirect(url_for('login'))
        
        emp = Employee.query.get_or_404(emp_id)
        
        # 관리자 계정 보호
        admin_count = Employee.query.filter_by(role='admin').count()
        if emp.role == 'admin' and admin_count <= 1:
            flash('마지막 관리자 계정은 삭제할 수 없습니다.')
            return redirect(url_for('system'))
        
        # 관련 데이터 삭제
        LeaveRequest.query.filter_by(target_id=emp_id).delete()
        LeaveRequest.query.filter_by(applicant_id=emp_id).delete()
        
        # 직원 삭제
        db.session.delete(emp)
        
        # 삭제 로그 기록
        log = SystemLog(
            action='delete',
            employee_name=emp.name,
            details=f'직원 삭제: {emp.name}'
        )
        db.session.add(log)
        
        db.session.commit()
        flash('직원이 삭제되었습니다.')
        
    except SQLAlchemyError as e:
        db.session.rollback()
        flash('데이터베이스 오류가 발생했습니다.')
        app.logger.error(f'Database error in delete_employee: {str(e)}')
    except Exception as e:
        db.session.rollback()
        flash('처리 중 오류가 발생했습니다.')
        app.logger.error(f'Error in delete_employee: {str(e)}')
    
    return redirect(url_for('system'))

@app.route('/change_password', methods=['POST'])
def change_password():
    if not session.get('user_id') or Employee.query.get(session['user_id']).role != 'admin':
        return redirect(url_for('login'))
    current_pw = request.form.get('current_password', '').encode('utf-8')
    new_pw = request.form['new_password'].encode('utf-8')
    confirm_pw = request.form['confirm_password'].encode('utf-8')
    pw_row = AdminPassword.query.first()
    if not pw_row or not bcrypt.checkpw(current_pw, pw_row.pw_hash):
        flash('현재 비밀번호가 올바르지 않습니다.')
        return redirect(url_for('system'))
    if new_pw != confirm_pw:
        flash('비밀번호가 일치하지 않습니다.')
        return redirect(url_for('system'))
    pw_hash = bcrypt.hashpw(new_pw, bcrypt.gensalt())
    pw_row.pw_hash = pw_hash
    db.session.commit()
    flash('비밀번호가 변경되었습니다.')
    return redirect(url_for('system'))

@app.context_processor
def inject_now():
    return {'now': get_kst_now()}

@app.route('/employee_history/<int:emp_id>')
@login_required
def employee_history(emp_id):
    # 자신의 이력이거나 관리자인 경우만 접근 가능
    if session.get('user_id') != emp_id and Employee.query.get(session['user_id']).role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    requests = LeaveRequest.query.filter_by(target_id=emp_id).order_by(LeaveRequest.id.desc()).all()
    result = [
        {
            'created_at': req.created_at,
            'type': req.type,
            'start_date': req.start_date,
            'end_date': req.end_date,
            'reason': req.reason,
            'status': req.status
        }
        for req in requests
    ]
    return jsonify(result)

@app.route('/download_approval/<int:req_id>')
def download_approval(req_id):
    if not session.get('user_id') or Employee.query.get(session['user_id']).role != 'admin':
        return redirect(url_for('login', next='status'))
    
    req = LeaveRequest.query.get(req_id)
    emp = Employee.query.get(req.target_id)
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=50, leftMargin=50, topMargin=70, bottomMargin=50)
    styles = getSampleStyleSheet()
    
    # 폰트 등록 (정확한 이름)
    pdfmetrics.registerFont(TTFont('NanumGothic', 'static/fonts/NanumGothic-Regular.ttf'))
    pdfmetrics.registerFont(TTFont('NanumGothic-Bold', 'static/fonts/NanumGothic-Bold.ttf'))
    pdfmetrics.registerFont(TTFont('RobotoCondensed', 'static/fonts/Roboto_Condensed-Regular.ttf'))
    pdfmetrics.registerFont(TTFont('RobotoCondensed-Bold', 'static/fonts/Roboto_Condensed-Bold.ttf'))
    pdfmetrics.registerFont(TTFont('RobotoCondensed-Light', 'static/fonts/Roboto_Condensed-Light.ttf'))
    pdfmetrics.registerFont(TTFont('RobotoCondensed-Medium', 'static/fonts/Roboto_Condensed-Medium.ttf'))
    pdfmetrics.registerFont(TTFont('RobotoCondensed-Thin', 'static/fonts/Roboto_Condensed-Thin.ttf'))
    pdfmetrics.registerFont(TTFont('RobotoCondensed-Italic', 'static/fonts/Roboto_Condensed-Italic.ttf'))
    
    # 스타일 정의 (정확한 폰트명 사용)
    title_style = ParagraphStyle(
        'Title', parent=styles['Normal'], fontName='RobotoCondensed-Bold', fontSize=26, alignment=1, spaceAfter=28, leading=32
    )
    label_style = ParagraphStyle(
        'Label', parent=styles['Normal'], fontName='RobotoCondensed-Bold', fontSize=13, alignment=1, leading=18
    )
    value_style_en = ParagraphStyle(
        'ValueEN', parent=styles['Normal'], fontName='RobotoCondensed', fontSize=13, alignment=1, leading=18, wordWrap='CJK'
    )
    value_style_ko = ParagraphStyle(
        'ValueKO', parent=styles['Normal'], fontName='NanumGothic', fontSize=13, alignment=1, leading=18, wordWrap='CJK'
    )
    sign_label_style = ParagraphStyle(
        'SignLabel', parent=styles['Normal'], fontName='RobotoCondensed-Bold', fontSize=12, alignment=0, leading=16
    )
    sign_value_style = ParagraphStyle(
        'SignValue', parent=styles['Normal'], fontName='NanumGothic', fontSize=12, alignment=0, leading=16
    )
    
    # None/빈값 처리
    type_val = req.type if req.type else 'N/A'
    reason_val = req.reason if req.reason else 'N/A'
    
    elements = []
    # 제목
    elements.append(Paragraph('Leave Application Form', title_style))
    elements.append(Spacer(1, 18))
    
    # 날짜 표기 로직
    start_str = req.start_date.strftime('%Y.%m.%d')
    end_str = req.end_date.strftime('%Y.%m.%d')
    if req.start_date.date() == req.end_date.date():
        date_display = f"{start_str} ({req.start_date.strftime('%a')})"
    else:
        total_days = int(req.leave_days) if req.leave_days == int(req.leave_days) else req.leave_days
        date_display = f"{start_str} ~<br/>{end_str} (total {total_days} days)"
    
    # 표 데이터 (항목은 영어, 값은 한글/영어)
    table_data = [
        [Paragraph('Name', label_style), Paragraph(emp.name, value_style_ko), Paragraph('Position', label_style), Paragraph(emp.position, value_style_ko)],
        [Paragraph('Department', label_style), Paragraph(emp.department, value_style_ko), '', ''],
        [Paragraph('Date', label_style), Paragraph(date_display, value_style_en), Paragraph('Type', label_style), Paragraph(type_val, value_style_en)],
        [Paragraph('Reason', label_style), Paragraph(reason_val, value_style_en), '', '']
    ]
    table = Table(table_data, colWidths=[80, 170, 80, 170], hAlign='CENTER')
    table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, -1), 'RobotoCondensed'),
        ('FONTSIZE', (0, 0), (-1, -1), 13),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID', (0, 0), (-1, -1), 0.8, colors.black),
        ('SPAN', (1, 1), (3, 1)),  # 부서 행 병합
        ('SPAN', (1, 3), (3, 3)),  # Reason 행 병합
        ('BACKGROUND', (0, 0), (-1, 0), colors.whitesmoke),
        ('BACKGROUND', (0, 1), (-1, 1), colors.whitesmoke),
        ('BACKGROUND', (0, 2), (-1, 2), colors.whitesmoke),
        ('BACKGROUND', (0, 3), (-1, 3), colors.whitesmoke),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 50))
    
    # 하단 서명란 (영어)
    sign_table_data = [
        [Paragraph('Date', sign_label_style), Paragraph(req.created_at.strftime('%Y-%m-%d'), sign_value_style), '', ''],
        [Paragraph('Applicant', sign_label_style), Paragraph(emp.name, sign_value_style), Paragraph('Signature', sign_label_style), '________________']
    ]
    sign_table = Table(sign_table_data, colWidths=[70, 150, 70, 170], hAlign='LEFT')
    sign_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, -1), 'RobotoCondensed'),
        ('FONTSIZE', (0, 0), (-1, -1), 12),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('SPAN', (1, 0), (3, 0)),
    ]))
    elements.append(sign_table)
    
    doc.build(elements)
    buffer.seek(0)
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f'leave_form_{req.id}.pdf',
        mimetype='application/pdf'
    )

@app.template_filter('employee_name')
def employee_name(emp_id):
    emp = Employee.query.get(emp_id)
    return emp.name if emp else '-'

@app.route('/get_employee/<int:emp_id>')
@login_required
def get_employee(emp_id):
    # 로그인한 사용자만 접근 가능
    if not session.get('user_id'):
        return jsonify({'error': 'Unauthorized'}), 403
    
    emp = Employee.query.get_or_404(emp_id)
    return jsonify({
        'name': emp.name,
        'department': emp.department,
        'position': emp.position,
        'join_date': emp.join_date,
        'annual_leave': emp.annual_leave,
        'used_leave': emp.used_leave,
        'remaining_leave': emp.remaining_leave,
        'user_id': emp.user_id,
        'role': emp.role
    })

@app.route('/change_language/<language>')
def change_language(language):
    if language in ['ko', 'en']:
        session['language'] = language
    return redirect(request.referrer or url_for('leave'))

# === 사전 기반 다국어 지원 ===
translations = {
    'ko': {
        'login': '로그인',
        'logout': '로그아웃',
        'leave_management': 'leave management',
        'system_management': '시스템 관리',
        'employee_management': '직원 관리',
        'leave_request': '휴가 신청',
        'leave_status': '신청관리',
        'approval': '승인',
        'rejection': '거절',
        'cancel': '취소',
        'submit': '제출',
        'edit': '수정',
        'delete': '삭제',
        'name': '이름',
        'department': '부서',
        'position': '직급',
        'join_date': '입사일',
        'annual_leave': '연차',
        'used_leave': '사용 연차',
        'remaining_leave': '잔여 연차',
        'start_date': '시작일',
        'end_date': '종료일',
        'reason': '사유',
        'status': '상태',
        'created_at': '신청일',
        'processed_at': '승인일시',
        'leave_days': '휴가일수',
        'cancel_request': '취소 요청',
        'cancel_reason': '취소 사유',
        'cancel_at': '취소일시',
        'change_password': '비밀번호 변경',
        'current_password': '현재 비밀번호',
        'new_password': '새 비밀번호',
        'confirm_password': '비밀번호 확인',
        'language': 'language',
        'korean': '한국어',
        'english': 'English',
        'user_id': '아이디',
        'password': '비밀번호',
        'please_sign_in': '계속하려면 로그인하세요',
        'contact_dev': '계정 등록 또는 비밀번호 문의는 아래 메일로 문의해주세요',
        'half_morning_top': '반차',
        'half_morning_bottom': '(오전)',
        'half_afternoon_top': '반차',
        'half_afternoon_bottom': '(오후)',
        'business_trip': '출장',
        'apply': '신청',
        'apply_now': '신청하기',
        'pending': '대기중',
        'approved': '승인',
        'rejected': '거절',
        'cancelled': '취소 완료',
        'cancel_pending': '취소 요청',
        'history': '이력',
        'add': '추가',
        'info': '안내',
        'select_employee': '직원을 선택하세요',
        'select': '선택',
        'close': '닫기',
        'save': '저장',
        'confirm': '확인',
        'delete_confirm': '삭제 확인',
        'no_history': '이력이 없습니다.',
        'apply_guide': '휴가 신청 안내',
        'half_guide1': '반차(오전): 09:00~14:00',
        'half_guide2': '반차(오후): 12:00~18:00',
        'processed': '처리',
        'pdf': 'PDF',
        'select_employee_guide': '직원을 선택하면 휴가 현황이 표시됩니다.',
        'applicant': '신청자',
        'target': '대상자',
        'type': '신청 유형',
        'start_date': '시작일',
        'end_date': '종료일',
        'status': '상태',
        'processed_at': '승인일시',
        'manage': '관리',
        'select_employee': '직원 선택',
        'leave_type': '신청 유형',
        'employee_management': '직원 관리',
        'add_employee': '직원 추가',
        'system_log': '시스템 로그',
        'date': '날짜',
        'action': '작업',
        'edit_employee_info': '직원 정보 수정',
        'delete_employee_confirmation': '직원 삭제 확인',
        'requested_at': '요청일시',
        'type': '유형',
        'no_history': '이력이 없습니다.',
        'history_title': "'s History",
        'start_date': '시작일',
        'end_date': '종료일',
        'reason': '사유',
        'status': '상태',
        'used': '사용',
        'remaining': '잔여',
        'role': '권한',
        'details': '세부 정보',
        'user': '사용자',
        'admin': '관리자',
        'cancel_request_action': '취소 요청',
        'add_action': '추가',
        'edit_action': '수정',
        'delete_action': '삭제',
        'cannot_change_last_admin': '마지막 관리자 계정의 권한을 변경할 수 없습니다.',
        'cannot_delete_last_admin': '마지막 관리자 계정을 삭제할 수 없습니다.',
    },
    'en': {
        'login': 'Login',
        'logout': 'Logout',
        'leave_management': 'Leave Management',
        'system_management': 'System Management',
        'employee_management': 'Employee Management',
        'leave_request': 'Leave Request',
        'leave_status': 'Leave Status',
        'approval': 'Approval',
        'rejection': 'Rejection',
        'cancel': 'Cancel',
        'submit': 'Submit',
        'edit': 'Edit',
        'delete': 'Delete',
        'name': 'Name',
        'department': 'Department',
        'position': 'Position',
        'join_date': 'Join Date',
        'annual_leave': 'Annual Leave',
        'used_leave': 'Used Leave',
        'remaining_leave': 'Remaining Leave',
        'start_date': 'Start Date',
        'end_date': 'End Date',
        'reason': 'Reason',
        'status': 'Status',
        'created_at': 'Request Date',
        'processed_at': 'Processed At',
        'leave_days': 'Leave Days',
        'cancel_request': 'Cancel Request',
        'cancel_reason': 'Cancel Reason',
        'cancel_at': 'Cancel At',
        'change_password': 'Change Password',
        'current_password': 'Current Password',
        'new_password': 'New Password',
        'confirm_password': 'Confirm Password',
        'language': 'Language',
        'korean': 'Korean',
        'english': 'English',
        'user_id': 'User ID',
        'password': 'Password',
        'please_sign_in': 'Please sign in to continue',
        'contact_dev': 'For account registration or password assistance, please contact the Development Team Lead',
        'half_morning_top': 'Half-day',
        'half_morning_bottom': 'Morning',
        'half_afternoon_top': 'Half-day',
        'half_afternoon_bottom': 'Afternoon',
        'business_trip': 'Business Trip',
        'apply': 'Apply',
        'apply_now': 'Apply Now',
        'pending': 'Pending',
        'approved': 'Approved',
        'rejected': 'Rejected',
        'cancelled': 'Cancelled',
        'cancel_pending': 'Cancel Requested',
        'history': 'History',
        'add': 'Add',
        'info': 'Info',
        'select_employee': 'Select Employee',
        'select': 'Select',
        'close': 'Close',
        'save': 'Save',
        'confirm': 'Confirm',
        'delete_confirm': 'Delete Confirm',
        'no_history': 'No history.',
        'apply_guide': 'Leave Application Guide',
        'half_guide1': 'Half-day (Morning): 09:00~14:00',
        'half_guide2': 'Half-day (Afternoon): 12:00~18:00',
        'processed': 'Processed',
        'pdf': 'PDF',
        'select_employee_guide': 'Select an employee to view their leave status.',
        'applicant': 'Applicant',
        'target': 'Target',
        'type': 'Type',
        'start_date': 'Start Date',
        'end_date': 'End Date',
        'status': 'Status',
        'processed_at': 'Processed At',
        'manage': 'Manage',
        'select_employee': 'Select Employee',
        'leave_type': 'Leave Type',
        'employee_management': 'Employee Management',
        'add_employee': 'Add Employee',
        'system_log': 'System Log',
        'date': 'Date',
        'action': 'Action',
        'edit_employee_info': 'Edit Employee Info',
        'delete_employee_confirmation': 'Delete Employee Confirmation',
        'requested_at': 'Requested At',
        'type': 'Type',
        'no_history': 'No history.',
        'history_title': "'s History",
        'start_date': 'Start Date',
        'end_date': 'End Date',
        'reason': 'Reason',
        'status': 'Status',
        'used': 'Used',
        'remaining': 'Remaining',
        'role': 'Role',
        'details': 'Details',
        'user': 'User',
        'admin': 'Admin',
        'cancel_request_action': 'Cancel Request',
        'add_action': 'Add',
        'edit_action': 'Edit',
        'delete_action': 'Delete',
        'cannot_change_last_admin': 'You cannot change the role of the last admin account.',
        'cannot_delete_last_admin': 'You cannot delete the last admin account.',
    }
}

def get_locale():
    return session.get('language') or request.accept_languages.best_match(['ko', 'en']) or 'ko'

@app.context_processor
def inject_translations():
    lang = get_locale()
    return dict(t=translations[lang])

@app.route('/leave/request', methods=['GET', 'POST'])
@login_required
def leave_request():
    if request.method == 'POST':
        try:
            start_date = datetime.strptime(request.form['start_date'], '%Y-%m-%d')
            end_date = datetime.strptime(request.form['end_date'], '%Y-%m-%d')
            
            # 날짜 유효성 검사
            if start_date > end_date:
                flash('종료일은 시작일보다 이후여야 합니다.', 'error')
                return redirect(url_for('leave_request'))
            
            if start_date < get_kst_now().date():
                flash('과거 날짜는 선택할 수 없습니다.', 'error')
                return redirect(url_for('leave_request'))
            
            # 휴가 일수 계산
            leave_days = 0
            current_date = start_date
            while current_date <= end_date:
                if is_valid_leave_date(current_date):
                    leave_days += 1
                current_date += timedelta(days=1)
            
            if leave_days == 0:
                flash('선택한 기간에 유효한 휴가 일수가 없습니다.', 'error')
                return redirect(url_for('leave_request'))
            
            # 잔여 연차 확인
            employee = Employee.query.get(session['user_id'])
            if employee.remaining_leave < leave_days:
                flash('잔여 연차가 부족합니다.', 'error')
                return redirect(url_for('leave_request'))
            
            # 휴가 신청 생성
            leave_request = LeaveRequest(
                applicant_id=session['user_id'],
                target_id=session['user_id'],
                type=request.form['type'],
                start_date=start_date,
                end_date=end_date,
                reason=request.form['reason'],
                leave_days=leave_days
            )
            
            db.session.add(leave_request)
            db.session.commit()
            
            flash('휴가가 신청되었습니다.', 'success')
            return redirect(url_for('leave_status'))
            
        except ValueError as e:
            flash('날짜 형식이 올바르지 않습니다.', 'error')
            return redirect(url_for('leave_request'))
        except Exception as e:
            db.session.rollback()
            flash('휴가 신청 중 오류가 발생했습니다.', 'error')
            return redirect(url_for('leave_request'))
    
    return render_template('leave_request.html')

@app.route('/leave/approve/<int:request_id>', methods=['POST'])
@login_required
@admin_required
def approve_leave(request_id):
    try:
        leave_request = LeaveRequest.query.get_or_404(request_id)
        
        if leave_request.status != 'pending':
            flash('이미 처리된 휴가 신청입니다.', 'error')
            return redirect(url_for('leave_status'))
        
        leave_request.status = 'approved'
        leave_request.processed_at = get_kst_now()
        
        # 연차 사용량 업데이트
        employee = Employee.query.get(leave_request.target_id)
        employee.used_leave += leave_request.leave_days
        employee.remaining_leave -= leave_request.leave_days
        
        db.session.commit()
        flash('휴가가 승인되었습니다.', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash('휴가 승인 중 오류가 발생했습니다.', 'error')
    
    return redirect(url_for('leave_status'))

@app.route('/leave/reject/<int:request_id>', methods=['POST'])
@login_required
@admin_required
def reject_leave(request_id):
    try:
        leave_request = LeaveRequest.query.get_or_404(request_id)
        
        if leave_request.status != 'pending':
            flash('이미 처리된 휴가 신청입니다.', 'error')
            return redirect(url_for('leave_status'))
        
        leave_request.status = 'rejected'
        leave_request.processed_at = get_kst_now()
        
        db.session.commit()
        flash('휴가가 거절되었습니다.', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash('휴가 거절 중 오류가 발생했습니다.', 'error')
    
    return redirect(url_for('leave_status'))

def count_weekdays(start, end):
    """주말과 공휴일을 제외한 평일 수를 계산"""
    days = 0
    current = start
    while current <= end:
        if is_valid_leave_date(current):
            days += 1
        current += timedelta(days=1)
    return days

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id') or Employee.query.get(session['user_id']).role != 'admin':
            flash('관리자 권한이 필요합니다.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

if __name__ == '__main__':
    with app.app_context():
        # 모든 공휴일 데이터 삭제
        Holiday.query.delete()
        db.session.commit()
        db.create_all()
        
        # 기존 데이터 마이그레이션
        try:
            # Employee 모델의 join_date 마이그레이션
            employees = Employee.query.all()
            for emp in employees:
                if isinstance(emp.join_date, str):
                    emp.join_date = datetime.strptime(emp.join_date, '%Y-%m-%d')
            
            # LeaveRequest 모델의 날짜 필드 마이그레이션
            requests = LeaveRequest.query.all()
            for req in requests:
                if isinstance(req.start_date, str):
                    req.start_date = datetime.strptime(req.start_date, '%Y-%m-%d')
                if isinstance(req.end_date, str):
                    req.end_date = datetime.strptime(req.end_date, '%Y-%m-%d')
                if isinstance(req.created_at, str):
                    req.created_at = datetime.strptime(req.created_at, '%Y-%m-%d %H:%M:%S')
                if isinstance(req.processed_at, str) and req.processed_at:
                    req.processed_at = datetime.strptime(req.processed_at, '%Y-%m-%d %H:%M:%S')
                if isinstance(req.cancel_at, str) and req.cancel_at:
                    req.cancel_at = datetime.strptime(req.cancel_at, '%Y-%m-%d %H:%M:%S')
            
            db.session.commit()
        except Exception as e:
            app.logger.error(f'Migration error: {str(e)}')
            db.session.rollback()
        
        # 공휴일 데이터 초기화 코드 완전 주석 처리
        # if Holiday.query.count() == 0:
        #     holidays_2025 = [ ... ]
        #     for date_str, name in holidays_2025:
        #         date = datetime.strptime(date_str, '%Y-%m-%d').date()
        #         holiday = Holiday(date=date, name=name, year=2025)
        #         db.session.add(holiday)
        #     db.session.commit()
        
        # 가상 직원 3명 자동 추가 (중복 방지)
        if Employee.query.count() == 0:
            db.session.add(Employee(
                name='Juho',
                department='Dev team 1',
                position='차장',
                join_date=datetime.strptime('2023-01-01', '%Y-%m-%d'),
                annual_leave=15,
                used_leave=0,
                remaining_leave=15
            ))
            db.session.add(Employee(
                name='Yeseul',
                department='Dev team 1',
                position='대리',
                join_date=datetime.strptime('2022-03-15', '%Y-%m-%d'),
                annual_leave=15,
                used_leave=0,
                remaining_leave=15
            ))
            db.session.add(Employee(
                name='Erdem',
                department='Dev team 1',
                position='사원',
                join_date=datetime.strptime('2021-07-10', '%Y-%m-%d'),
                annual_leave=15,
                used_leave=0,
                remaining_leave=15
            ))
            db.session.commit()
        
        # 비밀번호가 없으면 0000으로 초기화
        if AdminPassword.query.count() == 0:
            pw_hash = bcrypt.hashpw('0000'.encode('utf-8'), bcrypt.gensalt())
            db.session.add(AdminPassword(pw_hash=pw_hash))
            db.session.commit()
        
        # 마스터 계정(admin/admin) 자동 생성
        if Employee.query.filter_by(user_id='admin').first() is None:
            pw_hash = bcrypt.hashpw('admin'.encode('utf-8'), bcrypt.gensalt())
            db.session.add(Employee(
                name='관리자',
                department='관리',
                position='관리자',
                join_date=datetime.strptime('2020-01-01', '%Y-%m-%d'),
                annual_leave=99,
                used_leave=0,
                remaining_leave=99,
                user_id='admin',
                user_pw_hash=pw_hash,
                role='admin'
            ))
            db.session.commit()
    
    app.run(debug=True)