from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from dotenv import load_dotenv
import os
from flask import Flask
from datetime import timedelta

app = Flask(__name__)
app.secret_key = os.urandom(24)

# 환경 변수 로드
load_dotenv()

# SQLAlchemy 인스턴스 생성
db = SQLAlchemy()

def init_db(app):
    """데이터베이스 초기화 함수"""
    # DB 설정
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///work_manager.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
    
    # Connection Pool 설정
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_size': 10,
        'pool_recycle': 3600,
        'pool_pre_ping': True
    }
    
    # DB 초기화
    db.init_app(app) 