import tkinter as tk
from tkinter import ttk, messagebox
from tkcalendar import DateEntry
from database import Database
from datetime import datetime, timedelta
import pandas as pd
from tkinter import filedialog

class WorkManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("근태 관리 시스템")
        self.root.geometry("1000x700")
        
        # 스타일 설정
        self.style = ttk.Style()
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Arial', 10))
        self.style.configure('TButton', font=('Arial', 10))
        self.style.configure('Header.TLabel', font=('Arial', 12, 'bold'))
        
        self.db = Database()
        
        # 메인 프레임
        self.main_frame = ttk.Frame(self.root, padding="10", style='TFrame')
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 탭 생성
        self.tab_control = ttk.Notebook(self.main_frame)
        
        # 직원 관리 탭
        self.employee_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.employee_tab, text='직원 관리')
        
        # 휴가/출장 신청 탭
        self.leave_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.leave_tab, text='휴가/출장 신청')
        
        # 신청 현황 탭
        self.status_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.status_tab, text='신청 현황')
        
        self.tab_control.pack(expand=1, fill="both")
        
        self.setup_employee_tab()
        self.setup_leave_tab()
        self.setup_status_tab()

    def setup_employee_tab(self):
        # 직원 추가 프레임
        add_frame = ttk.LabelFrame(self.employee_tab, text="직원 추가", padding="5")
        add_frame.grid(row=0, column=0, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        # 첫 번째 행
        ttk.Label(add_frame, text="이름:").grid(row=0, column=0, padx=5, pady=5)
        self.name_entry = ttk.Entry(add_frame)
        self.name_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(add_frame, text="부서:").grid(row=0, column=2, padx=5, pady=5)
        self.department_entry = ttk.Entry(add_frame)
        self.department_entry.grid(row=0, column=3, padx=5, pady=5)
        
        ttk.Label(add_frame, text="직급:").grid(row=0, column=4, padx=5, pady=5)
        self.position_entry = ttk.Entry(add_frame)
        self.position_entry.grid(row=0, column=5, padx=5, pady=5)
        
        # 두 번째 행
        ttk.Label(add_frame, text="이메일:").grid(row=1, column=0, padx=5, pady=5)
        self.email_entry = ttk.Entry(add_frame)
        self.email_entry.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(add_frame, text="전화번호:").grid(row=1, column=2, padx=5, pady=5)
        self.phone_entry = ttk.Entry(add_frame)
        self.phone_entry.grid(row=1, column=3, padx=5, pady=5)
        
        ttk.Button(add_frame, text="추가", command=self.add_employee).grid(row=1, column=5, padx=5, pady=5)
        
        # 직원 목록
        list_frame = ttk.LabelFrame(self.employee_tab, text="직원 목록", padding="5")
        list_frame.grid(row=1, column=0, padx=5, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        columns = ('ID', '이름', '부서', '직급', '이메일', '전화번호', '입사일', '연차', '잔여연차')
        self.employee_tree = ttk.Treeview(list_frame, columns=columns, show='headings')
        
        for col in columns:
            self.employee_tree.heading(col, text=col)
            self.employee_tree.column(col, width=100)
        
        self.employee_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.employee_tree.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.employee_tree.configure(yscrollcommand=scrollbar.set)
        
        # 버튼 프레임
        button_frame = ttk.Frame(list_frame)
        button_frame.grid(row=1, column=0, columnspan=2, pady=5)
        
        ttk.Button(button_frame, text="수정", command=self.edit_employee).grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text="삭제", command=self.delete_employee).grid(row=0, column=1, padx=5)
        ttk.Button(button_frame, text="연차 추가", command=self.add_annual_leave).grid(row=0, column=2, padx=5)
        
        self.refresh_employee_list()

    def setup_leave_tab(self):
        # 휴가/출장 신청 프레임
        request_frame = ttk.LabelFrame(self.leave_tab, text="휴가/출장 신청", padding="5")
        request_frame.grid(row=0, column=0, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        # 첫 번째 행
        ttk.Label(request_frame, text="직원:").grid(row=0, column=0, padx=5, pady=5)
        self.employee_combo = ttk.Combobox(request_frame)
        self.employee_combo.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(request_frame, text="유형:").grid(row=0, column=2, padx=5, pady=5)
        self.type_combo = ttk.Combobox(request_frame, values=['연차', '반차', '출장'])
        self.type_combo.grid(row=0, column=3, padx=5, pady=5)
        self.type_combo.bind('<<ComboboxSelected>>', self.on_type_selected)
        
        # 두 번째 행
        ttk.Label(request_frame, text="시작일:").grid(row=1, column=0, padx=5, pady=5)
        self.start_date = DateEntry(request_frame, width=12, background='darkblue',
                                  foreground='white', borderwidth=2)
        self.start_date.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(request_frame, text="시작시간:").grid(row=1, column=2, padx=5, pady=5)
        self.start_time = ttk.Combobox(request_frame, values=['09:00', '13:00'])
        self.start_time.grid(row=1, column=3, padx=5, pady=5)
        
        # 세 번째 행
        ttk.Label(request_frame, text="종료일:").grid(row=2, column=0, padx=5, pady=5)
        self.end_date = DateEntry(request_frame, width=12, background='darkblue',
                                foreground='white', borderwidth=2)
        self.end_date.grid(row=2, column=1, padx=5, pady=5)
        
        ttk.Label(request_frame, text="종료시간:").grid(row=2, column=2, padx=5, pady=5)
        self.end_time = ttk.Combobox(request_frame, values=['18:00', '13:00'])
        self.end_time.grid(row=2, column=3, padx=5, pady=5)
        
        # 네 번째 행
        ttk.Label(request_frame, text="장소:").grid(row=3, column=0, padx=5, pady=5)
        self.location_entry = ttk.Entry(request_frame, width=50)
        self.location_entry.grid(row=3, column=1, columnspan=3, padx=5, pady=5)
        
        # 다섯 번째 행
        ttk.Label(request_frame, text="사유:").grid(row=4, column=0, padx=5, pady=5)
        self.reason_entry = ttk.Entry(request_frame, width=50)
        self.reason_entry.grid(row=4, column=1, columnspan=3, padx=5, pady=5)
        
        ttk.Button(request_frame, text="신청", command=self.submit_leave_request).grid(row=4, column=4, padx=5, pady=5)
        
        self.refresh_employee_combo()

    def setup_status_tab(self):
        # 신청 현황 프레임
        status_frame = ttk.LabelFrame(self.status_tab, text="신청 현황", padding="5")
        status_frame.grid(row=0, column=0, padx=5, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        columns = ('ID', '직원', '유형', '시작일', '시작시간', '종료일', '종료시간', '장소', '사유', '상태', '신청일')
        self.status_tree = ttk.Treeview(status_frame, columns=columns, show='headings')
        
        for col in columns:
            self.status_tree.heading(col, text=col)
            self.status_tree.column(col, width=100)
        
        self.status_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        scrollbar = ttk.Scrollbar(status_frame, orient=tk.VERTICAL, command=self.status_tree.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.status_tree.configure(yscrollcommand=scrollbar.set)
        
        # 버튼 프레임
        button_frame = ttk.Frame(status_frame)
        button_frame.grid(row=1, column=0, columnspan=2, pady=5)
        
        ttk.Button(button_frame, text="승인", command=lambda: self.update_request_status('approved')).grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text="거절", command=lambda: self.update_request_status('rejected')).grid(row=0, column=1, padx=5)
        ttk.Button(button_frame, text="엑셀 내보내기", command=self.export_to_excel).grid(row=0, column=2, padx=5)
        
        self.refresh_status_list()

    def on_type_selected(self, event):
        type = self.type_combo.get()
        if type == '반차':
            self.start_time['values'] = ['09:00', '13:00']
            self.end_time['values'] = ['13:00', '18:00']
        else:
            self.start_time['values'] = ['09:00']
            self.end_time['values'] = ['18:00']

    def add_employee(self):
        name = self.name_entry.get()
        department = self.department_entry.get()
        position = self.position_entry.get()
        email = self.email_entry.get()
        phone = self.phone_entry.get()
        
        if not all([name, department, position, email, phone]):
            messagebox.showerror("오류", "모든 필드를 입력해주세요.")
            return
        
        join_date = datetime.now().strftime('%Y-%m-%d')
        self.db.add_employee(name, department, position, join_date, email, phone)
        
        self.refresh_employee_list()
        self.refresh_employee_combo()
        
        # 입력 필드 초기화
        self.name_entry.delete(0, tk.END)
        self.department_entry.delete(0, tk.END)
        self.position_entry.delete(0, tk.END)
        self.email_entry.delete(0, tk.END)
        self.phone_entry.delete(0, tk.END)

    def edit_employee(self):
        selected = self.employee_tree.selection()
        if not selected:
            messagebox.showerror("오류", "수정할 직원을 선택해주세요.")
            return
        
        # 수정 다이얼로그 생성
        dialog = tk.Toplevel(self.root)
        dialog.title("직원 정보 수정")
        dialog.geometry("400x300")
        
        employee = self.employee_tree.item(selected[0])['values']
        
        ttk.Label(dialog, text="이름:").grid(row=0, column=0, padx=5, pady=5)
        name_entry = ttk.Entry(dialog)
        name_entry.insert(0, employee[1])
        name_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="부서:").grid(row=1, column=0, padx=5, pady=5)
        dept_entry = ttk.Entry(dialog)
        dept_entry.insert(0, employee[2])
        dept_entry.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="직급:").grid(row=2, column=0, padx=5, pady=5)
        pos_entry = ttk.Entry(dialog)
        pos_entry.insert(0, employee[3])
        pos_entry.grid(row=2, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="이메일:").grid(row=3, column=0, padx=5, pady=5)
        email_entry = ttk.Entry(dialog)
        email_entry.insert(0, employee[4])
        email_entry.grid(row=3, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="전화번호:").grid(row=4, column=0, padx=5, pady=5)
        phone_entry = ttk.Entry(dialog)
        phone_entry.insert(0, employee[5])
        phone_entry.grid(row=4, column=1, padx=5, pady=5)
        
        def save_changes():
            self.db.update_employee(
                employee[0],
                name_entry.get(),
                dept_entry.get(),
                pos_entry.get(),
                email_entry.get(),
                phone_entry.get()
            )
            self.refresh_employee_list()
            dialog.destroy()
        
        ttk.Button(dialog, text="저장", command=save_changes).grid(row=5, column=0, columnspan=2, pady=20)

    def delete_employee(self):
        selected = self.employee_tree.selection()
        if not selected:
            messagebox.showerror("오류", "삭제할 직원을 선택해주세요.")
            return
        
        if messagebox.askyesno("확인", "선택한 직원을 삭제하시겠습니까?"):
            employee_id = self.employee_tree.item(selected[0])['values'][0]
            self.db.delete_employee(employee_id)
            self.refresh_employee_list()
            self.refresh_employee_combo()

    def add_annual_leave(self):
        selected = self.employee_tree.selection()
        if not selected:
            messagebox.showerror("오류", "연차를 추가할 직원을 선택해주세요.")
            return
        
        # 연차 추가 다이얼로그
        dialog = tk.Toplevel(self.root)
        dialog.title("연차 추가")
        dialog.geometry("300x150")
        
        ttk.Label(dialog, text="추가할 연차 일수:").grid(row=0, column=0, padx=5, pady=5)
        days_entry = ttk.Entry(dialog)
        days_entry.grid(row=0, column=1, padx=5, pady=5)
        
        def save_changes():
            try:
                days = int(days_entry.get())
                employee_id = self.employee_tree.item(selected[0])['values'][0]
                self.db.update_annual_leave(employee_id, days)
                self.refresh_employee_list()
                dialog.destroy()
            except ValueError:
                messagebox.showerror("오류", "올바른 숫자를 입력해주세요.")
        
        ttk.Button(dialog, text="저장", command=save_changes).grid(row=1, column=0, columnspan=2, pady=20)

    def refresh_employee_list(self):
        for item in self.employee_tree.get_children():
            self.employee_tree.delete(item)
        
        employees = self.db.get_employees()
        for employee in employees:
            self.employee_tree.insert('', tk.END, values=employee)

    def refresh_employee_combo(self):
        employees = self.db.get_employees()
        self.employee_combo['values'] = [f"{emp[0]}: {emp[1]}" for emp in employees]

    def submit_leave_request(self):
        employee = self.employee_combo.get()
        if not employee:
            messagebox.showerror("오류", "직원을 선택해주세요.")
            return
        
        employee_id = int(employee.split(':')[0])
        type = self.type_combo.get()
        start_date = self.start_date.get_date().strftime('%Y-%m-%d')
        end_date = self.end_date.get_date().strftime('%Y-%m-%d')
        start_time = self.start_time.get()
        end_time = self.end_time.get()
        reason = self.reason_entry.get()
        location = self.location_entry.get()
        
        if not all([type, start_date, end_date, start_time, end_time, reason]):
            messagebox.showerror("오류", "모든 필드를 입력해주세요.")
            return
        
        # 연차 사용량 체크
        if type == '연차':
            remaining = self.db.get_remaining_leave(employee_id)
            if remaining <= 0:
                messagebox.showerror("오류", "잔여 연차가 없습니다.")
                return
        
        self.db.add_leave_request(employee_id, type, start_date, end_date, start_time, end_time, reason, location)
        self.refresh_status_list()
        
        # 입력 필드 초기화
        self.reason_entry.delete(0, tk.END)
        self.location_entry.delete(0, tk.END)

    def refresh_status_list(self):
        for item in self.status_tree.get_children():
            self.status_tree.delete(item)
        
        requests = self.db.get_leave_requests()
        for request in requests:
            self.status_tree.insert('', tk.END, values=request)

    def update_request_status(self, status):
        selected = self.status_tree.selection()
        if not selected:
            messagebox.showerror("오류", "처리할 신청을 선택해주세요.")
            return
        
        request_id = self.status_tree.item(selected[0])['values'][0]
        self.db.update_leave_request_status(request_id, status)
        self.refresh_status_list()

    def export_to_excel(self):
        requests = self.db.get_leave_requests()
        if not requests:
            messagebox.showinfo("알림", "내보낼 데이터가 없습니다.")
            return
        
        # 데이터프레임 생성
        df = pd.DataFrame(requests, columns=['ID', '직원ID', '유형', '시작일', '종료일', '시작시간', '종료시간', '사유', '장소', '상태', '신청일', '직원명'])
        
        # 파일 저장 다이얼로그
        file_path = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel files", "*.xlsx")],
            title="엑셀 파일 저장"
        )
        
        if file_path:
            df.to_excel(file_path, index=False)
            messagebox.showinfo("성공", "파일이 저장되었습니다.")

if __name__ == '__main__':
    root = tk.Tk()
    app = WorkManagerApp(root)
    root.mainloop() 