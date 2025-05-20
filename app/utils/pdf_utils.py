import io
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import os

def generate_leave_pdf(req, emp):
    """Return BytesIO buffer and filename for a leave request PDF."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=50, leftMargin=50,
                             topMargin=70, bottomMargin=50)
    styles = getSampleStyleSheet()

    pdfmetrics.registerFont(TTFont('NanumGothic', 'static/fonts/NanumGothic-Regular.ttf'))
    pdfmetrics.registerFont(TTFont('NanumGothic-Bold', 'static/fonts/NanumGothic-Bold.ttf'))
    pdfmetrics.registerFont(TTFont('RobotoCondensed', 'static/fonts/Roboto_Condensed-Regular.ttf'))
    pdfmetrics.registerFont(TTFont('RobotoCondensed-Bold', 'static/fonts/Roboto_Condensed-Bold.ttf'))
    pdfmetrics.registerFont(TTFont('RobotoCondensed-Light', 'static/fonts/Roboto_Condensed-Light.ttf'))
    pdfmetrics.registerFont(TTFont('RobotoCondensed-Medium', 'static/fonts/Roboto_Condensed-Medium.ttf'))
    pdfmetrics.registerFont(TTFont('RobotoCondensed-Thin', 'static/fonts/Roboto_Condensed-Thin.ttf'))
    pdfmetrics.registerFont(TTFont('RobotoCondensed-Italic', 'static/fonts/Roboto_Condensed-Italic.ttf'))
    pdfmetrics.registerFont(TTFont('Inspiration', 'static/fonts/Inspiration-Regular.ttf'))

    title_style = ParagraphStyle('Title', parent=styles['Normal'], fontName='RobotoCondensed-Bold', fontSize=26,
                                   alignment=1, spaceAfter=28, leading=32)
    label_style = ParagraphStyle('Label', parent=styles['Normal'], fontName='RobotoCondensed-Bold', fontSize=13,
                                   alignment=1, leading=18)
    value_style_ko = ParagraphStyle('ValueKO', parent=styles['Normal'], fontName='NanumGothic', fontSize=13,
                                     alignment=1, leading=18, wordWrap='CJK')
    sign_label_style = ParagraphStyle('SignLabel', parent=styles['Normal'], fontName='RobotoCondensed-Bold', fontSize=12,
                                       alignment=0, leading=16)
    sign_value_style = ParagraphStyle('SignValue', parent=styles['Normal'], fontName='NanumGothic', fontSize=12,
                                       alignment=0, leading=16)
    sign_value_italic = ParagraphStyle('SignValueItalic', parent=styles['Normal'], fontName='RobotoCondensed-Italic',
                                        fontSize=12, alignment=0, leading=16)
    signature_style = ParagraphStyle('Signature', parent=styles['Normal'], fontName='Inspiration', fontSize=20,
                                      alignment=0, leading=24)

    start_str = req.start_date.strftime('%Y.%m.%d')
    end_str = req.end_date.strftime('%Y.%m.%d')
    if req.start_date.date() == req.end_date.date():
        date_display = f"{start_str} ({req.start_date.strftime('%a')})"
    else:
        total_days = int(req.leave_days) if req.leave_days == int(req.leave_days) else req.leave_days
        date_display = f"{start_str} ~<br/>{end_str} (total {total_days} days)"

    type_val = getattr(req, 'type', None) or getattr(req, 'leave_type', 'N/A')
    reason_val = req.reason if req.reason else 'N/A'

    elements = [
        Paragraph('Leave Application Form', title_style),
        Spacer(1, 18)
    ]

    table_data = [
        [Paragraph('Name', label_style), Paragraph(emp.name, value_style_ko), Paragraph('Position', label_style), Paragraph(emp.position, value_style_ko)],
        [Paragraph('Department', label_style), Paragraph(emp.department, value_style_ko), '', ''],
        [Paragraph('Date', label_style), Paragraph(date_display, value_style_ko), Paragraph('Type', label_style), Paragraph(type_val, value_style_ko)],
        [Paragraph('Reason', label_style), Paragraph(reason_val, value_style_ko), '', '']
    ]
    table = Table(table_data, colWidths=[80, 170, 80, 170], hAlign='CENTER')
    table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, -1), 'RobotoCondensed'),
        ('FONTSIZE', (0, 0), (-1, -1), 13),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID', (0, 0), (-1, -1), 0.8, colors.black),
        ('SPAN', (1, 1), (3, 1)),
        ('SPAN', (1, 3), (3, 3)),
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

    sign_table_data = [
        [Paragraph('Date', sign_label_style), Paragraph(req.created_at.strftime('%Y-%m-%d'), sign_value_style), '', ''],
        [Paragraph('Applicant', sign_label_style), Paragraph(emp.name, sign_value_style), Paragraph('Signature', sign_label_style), 
         Paragraph(emp.eng_name, signature_style)]
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

    file_date = req.created_at.strftime('%Y%m%d')
    filename = f'leave_request_{file_date}.pdf'

    doc.build(elements)
    buffer.seek(0)
    return buffer, filename

