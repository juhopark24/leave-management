from datetime import datetime, timedelta
import pytz
from decimal import Decimal, ROUND_HALF_UP
from app.config import Config

KST = pytz.timezone('Asia/Seoul')


def get_kst_now():
    return datetime.now(KST)


def format_kst_datetime(dt):
    if dt.tzinfo is None:
        dt = KST.localize(dt)
    return dt.strftime('%Y-%m-%d %H:%M:%S')


def is_holiday(date_str):
    return date_str in Config.HOLIDAYS_2024


def count_weekdays(start, end):
    days = 0
    cur = start
    while cur <= end:
        if cur.weekday() < 5 and not is_holiday(cur.strftime('%Y-%m-%d')):
            days += 1
        cur += timedelta(days=1)
    return days


def round_to_half(value):
    return float(Decimal(str(value)).quantize(Decimal('0.5'), rounding=ROUND_HALF_UP))


def format_date(dt):
    """datetime 객체를 'YYYY-MM-DD' 문자열로 변환"""
    return dt.strftime('%Y-%m-%d')


def parse_date(date_str):
    """'YYYY-MM-DD' 문자열을 date 객체로 변환"""
    if isinstance(date_str, datetime):
        return date_str.date()
    return datetime.strptime(date_str, '%Y-%m-%d').date()

