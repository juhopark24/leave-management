import sqlite3
from datetime import datetime

class Database:
    def __init__(self):
        self.conn = sqlite3.connect('work_manager.db')
        self.cursor = self.conn.cursor()
        self.create_tables()

    def create_tables(self):
        # 직원 테이블
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            department TEXT,
            position TEXT,
            join_date TEXT,
            annual_leave INTEGER DEFAULT 15,
            remaining_leave INTEGER DEFAULT 15,
            email TEXT,
            phone TEXT
        )
        ''')

        # 휴가/출장 신청 테이블
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS leave_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER,
            type TEXT NOT NULL,
            start_date TEXT NOT NULL,
            end_date TEXT NOT NULL,
            start_time TEXT,
            end_time TEXT,
            reason TEXT,
            location TEXT,
            status TEXT DEFAULT 'pending',
            created_at TEXT,
            FOREIGN KEY (employee_id) REFERENCES employees (id)
        )
        ''')

        # 휴가 이력 테이블
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS leave_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER,
            type TEXT NOT NULL,
            start_date TEXT NOT NULL,
            end_date TEXT NOT NULL,
            start_time TEXT,
            end_time TEXT,
            days REAL,
            location TEXT,
            FOREIGN KEY (employee_id) REFERENCES employees (id)
        )
        ''')

        self.conn.commit()

    def add_employee(self, name, department, position, join_date, email, phone):
        self.cursor.execute('''
        INSERT INTO employees (name, department, position, join_date, email, phone)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (name, department, position, join_date, email, phone))
        self.conn.commit()

    def get_employees(self):
        self.cursor.execute('SELECT * FROM employees')
        return self.cursor.fetchall()

    def update_employee(self, employee_id, name, department, position, email, phone):
        self.cursor.execute('''
        UPDATE employees 
        SET name = ?, department = ?, position = ?, email = ?, phone = ?
        WHERE id = ?
        ''', (name, department, position, email, phone, employee_id))
        self.conn.commit()

    def delete_employee(self, employee_id):
        self.cursor.execute('DELETE FROM employees WHERE id = ?', (employee_id,))
        self.conn.commit()

    def add_leave_request(self, employee_id, type, start_date, end_date, start_time, end_time, reason, location):
        created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.cursor.execute('''
        INSERT INTO leave_requests (employee_id, type, start_date, end_date, start_time, end_time, reason, location, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (employee_id, type, start_date, end_date, start_time, end_time, reason, location, created_at))
        self.conn.commit()

    def get_leave_requests(self, employee_id=None):
        if employee_id:
            self.cursor.execute('''
                SELECT lr.*, e.name as employee_name 
                FROM leave_requests lr
                JOIN employees e ON lr.employee_id = e.id
                WHERE lr.employee_id = ?
            ''', (employee_id,))
        else:
            self.cursor.execute('''
                SELECT lr.*, e.name as employee_name 
                FROM leave_requests lr
                JOIN employees e ON lr.employee_id = e.id
            ''')
        return self.cursor.fetchall()

    def update_leave_request_status(self, request_id, status):
        self.cursor.execute('''
        UPDATE leave_requests SET status = ? WHERE id = ?
        ''', (status, request_id))
        self.conn.commit()

    def add_leave_history(self, employee_id, type, start_date, end_date, start_time, end_time, days, location):
        self.cursor.execute('''
        INSERT INTO leave_history (employee_id, type, start_date, end_date, start_time, end_time, days, location)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (employee_id, type, start_date, end_date, start_time, end_time, days, location))
        self.conn.commit()

    def get_leave_history(self, employee_id):
        self.cursor.execute('SELECT * FROM leave_history WHERE employee_id = ?', (employee_id,))
        return self.cursor.fetchall()

    def update_annual_leave(self, employee_id, days):
        self.cursor.execute('''
        UPDATE employees 
        SET annual_leave = annual_leave + ?,
            remaining_leave = remaining_leave + ?
        WHERE id = ?
        ''', (days, days, employee_id))
        self.conn.commit()

    def get_remaining_leave(self, employee_id):
        self.cursor.execute('SELECT remaining_leave FROM employees WHERE id = ?', (employee_id,))
        result = self.cursor.fetchone()
        return result[0] if result else 0

    def __del__(self):
        self.conn.close() 