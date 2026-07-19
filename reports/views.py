from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.http import HttpResponse
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from io import BytesIO

from scanner.models import Scan


@login_required
def history_view(request):
    scans = Scan.objects.filter(user=request.user)

    severity_filter = request.GET.get('severity')
    if severity_filter == 'critical':
        scans = scans.filter(critical_count__gt=0)
    elif severity_filter == 'high':
        scans = scans.filter(high_count__gt=0)

    paginator = Paginator(scans, 10)
    page_obj = paginator.get_page(request.GET.get('page'))

    return render(request, 'reports/history.html', {'page_obj': page_obj})


@login_required
def detail_view(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id, user=request.user)
    issues = scan.issues.all()

    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    issues = sorted(issues, key=lambda i: severity_order.get(i.severity, 5))

    return render(request, 'reports/detail.html', {
        'scan': scan,
        'issues': issues,
        'files': scan.files.all(),
    })


@login_required
def export_pdf(request, scan_id):
    """Generate a downloadable PDF security report for a scan. Pro-only —
    Free-plan users are redirected to the pricing page with an upsell."""
    scan = get_object_or_404(Scan, id=scan_id, user=request.user)

    if request.user.is_on_free_plan:
        messages.info(request, 'PDF export is a Pro feature. Upgrade to download reports.')
        return redirect('subscriptions:pricing')

    issues = list(scan.issues.all())
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    issues.sort(key=lambda i: severity_order.get(i.severity, 5))

    pdf_bytes = _render_scan_pdf(scan, issues)

    response = HttpResponse(pdf_bytes, content_type='application/pdf')
    safe_name = "".join(c for c in scan.project_name if c.isalnum() or c in (' ', '-', '_')).strip() or 'scan'
    response['Content-Disposition'] = f'attachment; filename="fora-ai-report-{safe_name}.pdf"'
    return response


def _render_scan_pdf(scan, issues):
    """Builds the actual PDF bytes using ReportLab. Kept as a plain function
    (not a class-based view) so it's easy to unit test independent of Django's
    request/response cycle."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
    )

    SEVERITY_COLORS = {
        'critical': colors.HexColor('#e5484d'),
        'high': colors.HexColor('#f0883e'),
        'medium': colors.HexColor('#e0b83e'),
        'low': colors.HexColor('#4c8dff'),
        'info': colors.HexColor('#8b8d98'),
    }
    ACCENT = colors.HexColor('#c9891f')  # printable-safe darker shade of the on-screen amber
    DARK = colors.HexColor('#111114')
    MUTED = colors.HexColor('#5b5d66')

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=20 * mm, bottomMargin=18 * mm, leftMargin=18 * mm, rightMargin=18 * mm,
        title=f'Fora AI Security Report — {scan.project_name}',
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('ReportTitle', parent=styles['Heading1'], fontSize=20, textColor=DARK, spaceAfter=4)
    meta_style = ParagraphStyle('Meta', parent=styles['Normal'], fontSize=9.5, textColor=MUTED, spaceAfter=2)
    h2_style = ParagraphStyle('IssueTitle', parent=styles['Heading2'], fontSize=13, textColor=DARK, spaceBefore=14, spaceAfter=4)
    label_style = ParagraphStyle('Label', parent=styles['Normal'], fontSize=8.5, textColor=MUTED, spaceBefore=6, spaceAfter=2)
    body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=10, textColor=DARK, leading=14)
    code_style = ParagraphStyle('Code', parent=styles['Code'], fontSize=8.5, textColor=DARK,
                                 backColor=colors.HexColor('#f4f4f5'), borderPadding=6, leading=11)

    story = []

    story.append(Paragraph('Fora AI — Security Scan Report', title_style))
    story.append(Paragraph(f'Project: {scan.project_name}', meta_style))
    story.append(Paragraph(f'Scanned: {scan.created_at.strftime("%d %b %Y, %H:%M")}', meta_style))
    story.append(Paragraph(f'Language: {scan.language or "Mixed"}', meta_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width='100%', color=colors.HexColor('#e4e4e7'), thickness=1))
    story.append(Spacer(1, 14))

    # Summary table
    summary_data = [
        ['Security Score', 'Critical', 'High', 'Medium', 'Low', 'Info'],
        [
            str(scan.security_score),
            str(scan.critical_count), str(scan.high_count),
            str(scan.medium_count), str(scan.low_count), str(scan.info_count),
        ],
    ]
    summary_table = Table(summary_data, colWidths=[28 * mm] + [23.6 * mm] * 5)
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f4f4f5')),
        ('TEXTCOLOR', (0, 0), (-1, 0), MUTED),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('FONTSIZE', (0, 1), (-1, 1), 14),
        ('FONTNAME', (0, 1), (-1, 1), 'Helvetica-Bold'),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e4e4e7')),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))

    if not issues:
        story.append(Paragraph('No issues found. This scan looks clean.', body_style))
    else:
        story.append(Paragraph(f'{len(issues)} issue(s) found', styles['Heading3']))

        for idx, issue in enumerate(issues, start=1):
            sev_color = SEVERITY_COLORS.get(issue.severity, MUTED)
            sev_label = issue.get_severity_display().upper()

            badge = Table([[sev_label]], colWidths=[24 * mm])
            badge.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, 0), sev_color),
                ('TEXTCOLOR', (0, 0), (0, 0), colors.white),
                ('FONTSIZE', (0, 0), (0, 0), 7.5),
                ('FONTNAME', (0, 0), (0, 0), 'Helvetica-Bold'),
                ('ALIGN', (0, 0), (0, 0), 'CENTER'),
                ('TOPPADDING', (0, 0), (0, 0), 4),
                ('BOTTOMPADDING', (0, 0), (0, 0), 4),
            ]))

            story.append(badge)
            story.append(Paragraph(f'{idx}. {issue.title}', h2_style))
            if issue.line_number:
                story.append(Paragraph(f'{issue.category} · Line {issue.line_number}', meta_style))
            else:
                story.append(Paragraph(issue.category, meta_style))

            story.append(Paragraph('Description', label_style))
            story.append(Paragraph(issue.description or '—', body_style))

            story.append(Paragraph('Why this is dangerous', label_style))
            story.append(Paragraph(issue.why_dangerous or '—', body_style))

            story.append(Paragraph('Recommended fix', label_style))
            story.append(Paragraph(issue.recommended_fix or '—', body_style))

            if issue.code_snippet:
                story.append(Paragraph('Code', label_style))
                escaped = (issue.code_snippet[:600]
                           .replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;'))
                story.append(Paragraph(escaped.replace('\n', '<br/>'), code_style))

            refs = [r for r in (issue.owasp_reference, issue.cwe_reference) if r]
            if refs:
                story.append(Paragraph(' · '.join(refs), meta_style))

            story.append(Spacer(1, 6))
            story.append(HRFlowable(width='100%', color=colors.HexColor('#e4e4e7'), thickness=0.5))

    story.append(Spacer(1, 20))
    footer_style = ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, textColor=MUTED)
    story.append(Paragraph('Generated by Fora AI · by Faizz', footer_style))

    doc.build(story)
    return buffer.getvalue()
