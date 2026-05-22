# report.py — PDF report generation

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
import io


STRIDE_COLORS = {
    'Elevation of Privilege': colors.HexColor('#A32D2D'),
    'Tampering':              colors.HexColor('#854F0B'),
    'Information Disclosure': colors.HexColor('#185FA5'),
    'Spoofing':               colors.HexColor('#534AB7'),
    'Denial of Service':      colors.HexColor('#3B6D11'),
    'Repudiation':            colors.HexColor('#5F5E5A'),
}

SEV_COLORS = {
    'Critical':    colors.HexColor('#A32D2D'),
    'High':        colors.HexColor('#854F0B'),
    'Medium':      colors.HexColor('#185FA5'),
    'Low':         colors.HexColor('#3B6D11'),
    'Negligible':  colors.HexColor('#5F5E5A'),
    'Unknown':     colors.HexColor('#5F5E5A'),
}


def generate_pdf_report(scan_target, findings, risk_score, counts, scan_type):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'Title',
        parent=styles['Heading1'],
        fontSize=20,
        textColor=colors.HexColor('#1a1a1a'),
        spaceAfter=6,
        alignment=TA_LEFT,
        fontName='Helvetica-Bold'
    )
    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor('#666666'),
        spaceAfter=4,
        fontName='Helvetica'
    )
    section_style = ParagraphStyle(
        'Section',
        parent=styles['Heading2'],
        fontSize=13,
        textColor=colors.HexColor('#1a1a1a'),
        spaceBefore=16,
        spaceAfter=8,
        fontName='Helvetica-Bold'
    )
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor('#333333'),
        spaceAfter=4,
        fontName='Helvetica',
        leading=13
    )
    finding_title_style = ParagraphStyle(
        'FindingTitle',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor('#1a1a1a'),
        fontName='Helvetica-Bold'
    )

    story = []

    # ── Header ─────────────────────────────────────────
    story.append(Paragraph("Docker Security Scanner", title_style))
    story.append(Paragraph("CY256 — Secure Software Design and Development | Air University", subtitle_style))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#dddddd')))
    story.append(Spacer(1, 0.3*cm))

    # ── Scan Info ──────────────────────────────────────
    story.append(Paragraph("Scan Summary", section_style))

    info_data = [
        ['Target', scan_target],
        ['Scan Type', scan_type],
        ['Total Findings', str(len(findings))],
        ['Risk Score', f"{risk_score} / 100"],
        ['Critical', str(counts.get('Critical', 0))],
        ['High', str(counts.get('High', 0))],
        ['Medium', str(counts.get('Medium', 0))],
        ['Low', str(counts.get('Low', 0))],
    ]

    info_table = Table(info_data, colWidths=[4*cm, 13*cm])
    info_table.setStyle(TableStyle([
        ('FONTNAME',    (0,0), (-1,-1), 'Helvetica'),
        ('FONTSIZE',    (0,0), (-1,-1), 9),
        ('FONTNAME',    (0,0), (0,-1), 'Helvetica-Bold'),
        ('TEXTCOLOR',   (0,0), (0,-1), colors.HexColor('#555555')),
        ('BACKGROUND',  (0,0), (-1,0), colors.HexColor('#f5f5f5')),
        ('ROWBACKGROUNDS', (0,0), (-1,-1),
            [colors.HexColor('#ffffff'), colors.HexColor('#f9f9f9')]),
        ('GRID',        (0,0), (-1,-1), 0.5, colors.HexColor('#dddddd')),
        ('PADDING',     (0,0), (-1,-1), 6),
        ('VALIGN',      (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 0.3*cm))

    # ── STRIDE breakdown ───────────────────────────────
    story.append(Paragraph("STRIDE Threat Category Breakdown", section_style))

    stride_counts = {}
    for f in findings:
        s = f.get('stride', 'Unknown')
        stride_counts[s] = stride_counts.get(s, 0) + 1

    if stride_counts:
        stride_data = [['STRIDE Category', 'Count', 'Description']]
        stride_desc = {
            'Spoofing':               'Identity impersonation attacks',
            'Tampering':              'Data or code modification attacks',
            'Repudiation':            'Audit trail and logging issues',
            'Information Disclosure': 'Unauthorized data exposure',
            'Denial of Service':      'Availability disruption attacks',
            'Elevation of Privilege': 'Unauthorized access escalation',
        }
        for stride, count in sorted(stride_counts.items(),
                                     key=lambda x: x[1], reverse=True):
            stride_data.append([
                stride,
                str(count),
                stride_desc.get(stride, '')
            ])

        stride_table = Table(stride_data, colWidths=[5*cm, 2*cm, 10*cm])
        stride_table.setStyle(TableStyle([
            ('FONTNAME',   (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE',   (0,0), (-1,-1), 9),
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a1a1a')),
            ('TEXTCOLOR',  (0,0), (-1,0), colors.white),
            ('ROWBACKGROUNDS', (0,1), (-1,-1),
                [colors.HexColor('#ffffff'), colors.HexColor('#f9f9f9')]),
            ('GRID',       (0,0), (-1,-1), 0.5, colors.HexColor('#dddddd')),
            ('PADDING',    (0,0), (-1,-1), 6),
            ('VALIGN',     (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(stride_table)

    story.append(Spacer(1, 0.3*cm))

    # ── Findings ───────────────────────────────────────
    story.append(Paragraph(
        f"Detailed Findings ({len(findings)} total)", section_style))

    sev_order = ['Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown']
    sorted_findings = sorted(
        findings,
        key=lambda x: sev_order.index(x.get('severity', 'Unknown'))
        if x.get('severity', 'Unknown') in sev_order else 99
    )

    findings_data = [['#', 'Severity', 'Rule / CVE', 'STRIDE', 'Fix']]
    for i, f in enumerate(sorted_findings, 1):
        findings_data.append([
            str(i),
            f.get('severity', 'Unknown'),
            Paragraph(f.get('rule', '')[:60], body_style),
            f.get('stride', ''),
            Paragraph(str(f.get('fix', 'N/A'))[:80], body_style),
        ])

    findings_table = Table(
        findings_data,
        colWidths=[0.7*cm, 2*cm, 6*cm, 4*cm, 4.3*cm]
    )

    table_style = [
        ('FONTNAME',   (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',   (0,0), (-1,-1), 8),
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a1a1a')),
        ('TEXTCOLOR',  (0,0), (-1,0), colors.white),
        ('GRID',       (0,0), (-1,-1), 0.5, colors.HexColor('#dddddd')),
        ('PADDING',    (0,0), (-1,-1), 5),
        ('VALIGN',     (0,0), (-1,-1), 'TOP'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1),
            [colors.HexColor('#ffffff'), colors.HexColor('#f9f9f9')]),
    ]

    for i, f in enumerate(sorted_findings, 1):
        sev = f.get('severity', 'Unknown')
        col = SEV_COLORS.get(sev, colors.HexColor('#333333'))
        table_style.append(('TEXTCOLOR', (1, i), (1, i), col))
        table_style.append(('FONTNAME',  (1, i), (1, i), 'Helvetica-Bold'))

    findings_table.setStyle(TableStyle(table_style))
    story.append(findings_table)

    # ── Footer ─────────────────────────────────────────
    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(
        width="100%", thickness=0.5, color=colors.HexColor('#dddddd')))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        "Docker Security Scanner — CY256 Project | "
        "STRIDE Threat | Air University Islamabad",
        subtitle_style
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer