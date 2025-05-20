import os
from datetime import timedelta

class Config:
    # 기본 설정
    SECRET_KEY = os.urandom(24)
    SQLALCHEMY_DATABASE_URI = 'sqlite:///work_manager.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    
    # 로깅 설정
    LOG_DIR = 'logs'
    LOG_FILE = 'app.log'
    LOG_MAX_BYTES = 10240
    LOG_BACKUP_COUNT = 10
    
    # 공휴일 설정
    HOLIDAYS_2024 = [
        '2024-01-01',  # 신정
        '2024-02-09',  # 설날
        '2024-02-10',  # 설날
        '2024-02-11',  # 설날
        '2024-02-12',  # 대체공휴일
        '2024-03-01',  # 삼일절
        '2024-04-10',  # 국회의원선거일
        '2024-05-05',  # 어린이날
        '2024-05-06',  # 대체공휴일
        '2024-05-15',  # 부처님오신날
        '2024-06-06',  # 현충일
        '2024-08-15',  # 광복절
        '2024-09-16',  # 추석
        '2024-09-17',  # 추석
        '2024-09-18',  # 추석
        '2024-10-03',  # 개천절
        '2024-10-09',  # 한글날
        '2024-12-25',  # 성탄절
    ]
