from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.utils import timezone
from django.conf import settings

from .forms import PasteCodeForm, FileUploadForm, ZipUploadForm
from .models import Scan, ScannedFile, Issue
from .engine.analyzer import analyze_single_file, compute_security_score
from .engine.zip_handler import extract_scannable_files, ZipSecurityError
from .engine.providers import get_provider


def _guard_scan_quota(request):
    """Returns a redirect response if the user is out of scans, else None."""
    if not request.user.can_scan():
        messages.warning(request, "You've used all your free scans. Upgrade to continue scanning.")
        return redirect('subscriptions:upgrade')
    return None


def _persist_findings(scan: Scan, language: str, findings: list[dict], scanned_file: ScannedFile = None):
    for f in findings:
        Issue.objects.create(
            scan=scan,
            file=scanned_file,
            title=f['title'],
            category=f['category'],
            severity=f['severity'],
            owasp_reference=f.get('owasp_reference', ''),
            description=f.get('description', ''),
            why_dangerous=f.get('why_dangerous', ''),
            recommended_fix=f.get('recommended_fix', ''),
            secure_code_example=f.get('secure_code_example', ''),
            line_number=f.get('line_number'),
            code_snippet=f.get('code_snippet', ''),
        )


def _finalize_scan(scan: Scan, all_findings: list[dict], use_ai: bool = True):
    from .engine.analyzer import count_by_severity
    counts = count_by_severity(all_findings)
    scan.security_score = compute_security_score(all_findings)
    scan.total_issues = len(all_findings)
    scan.critical_count = counts['critical']
    scan.high_count = counts['high']
    scan.medium_count = counts['medium']
    scan.low_count = counts['low']
    scan.info_count = counts['info']
    scan.status = Scan.Status.COMPLETED
    scan.completed_at = timezone.now()
    scan.ai_provider_used = get_provider().name if use_ai else 'none'
    scan.save()


@login_required
def new_scan_view(request):
    """Landing page for starting a new scan - choose paste / file / zip."""
    guard = _guard_scan_quota(request)
    if guard:
        return guard

    paste_form = PasteCodeForm()
    file_form = FileUploadForm()
    zip_form = ZipUploadForm()

    return render(request, 'scanner/new_scan.html', {
        'paste_form': paste_form,
        'file_form': file_form,
        'zip_form': zip_form,
        'scans_remaining': request.user.scans_remaining,
        'use_ai': not request.user.is_on_free_plan,
    })


@login_required
def scan_paste_view(request):
    guard = _guard_scan_quota(request)
    if guard:
        return guard

    if request.method != 'POST':
        return redirect('scanner:new_scan')

    form = PasteCodeForm(request.POST)
    if not form.is_valid():
        messages.error(request, 'Please provide valid code to scan.')
        return redirect('scanner:new_scan')

    code = form.cleaned_data['code']
    filename_hint = form.cleaned_data.get('filename_hint') or 'pasted_code'
    project_name = form.cleaned_data.get('project_name') or f'Paste - {filename_hint}'

    scan = Scan.objects.create(
        user=request.user,
        project_name=project_name,
        source_type=Scan.SourceType.PASTE,
        raw_code=code,
        status=Scan.Status.RUNNING,
    )

    use_ai = not request.user.is_on_free_plan

    language, findings = analyze_single_file(filename_hint, code, use_ai=use_ai)
    scan.language = language
    scanned_file = ScannedFile.objects.create(
        scan=scan, filename=filename_hint, language=language,
        lines_of_code=len(code.splitlines())
    )
    _persist_findings(scan, language, findings, scanned_file)
    _finalize_scan(scan, findings, use_ai=use_ai)

    request.user.consume_scan()
    messages.success(request, 'Scan complete!')
    return redirect('reports:detail', scan_id=scan.id)


@login_required
def scan_file_view(request):
    guard = _guard_scan_quota(request)
    if guard:
        return guard

    if request.method != 'POST':
        return redirect('scanner:new_scan')

    form = FileUploadForm(request.POST, request.FILES)
    if not form.is_valid():
        for err in form.errors.values():
            messages.error(request, err.as_text())
        return redirect('scanner:new_scan')

    uploaded = form.cleaned_data['file']
    project_name = form.cleaned_data.get('project_name') or uploaded.name

    try:
        raw = uploaded.read(2 * 1024 * 1024)
        code = raw.decode('utf-8', errors='ignore')
    except Exception:
        messages.error(request, 'Could not read the uploaded file as text.')
        return redirect('scanner:new_scan')

    scan = Scan.objects.create(
        user=request.user,
        project_name=project_name,
        source_type=Scan.SourceType.FILE,
        uploaded_file=uploaded if uploaded.size < 5 * 1024 * 1024 else None,
        raw_code=code,
        status=Scan.Status.RUNNING,
    )

    use_ai = not request.user.is_on_free_plan

    language, findings = analyze_single_file(uploaded.name, code, use_ai=use_ai)
    scan.language = language
    scanned_file = ScannedFile.objects.create(
        scan=scan, filename=uploaded.name, language=language,
        lines_of_code=len(code.splitlines())
    )
    _persist_findings(scan, language, findings, scanned_file)
    _finalize_scan(scan, findings, use_ai=use_ai)

    request.user.consume_scan()
    messages.success(request, 'Scan complete!')
    return redirect('reports:detail', scan_id=scan.id)


@login_required
def scan_zip_view(request):
    guard = _guard_scan_quota(request)
    if guard:
        return guard

    if request.method != 'POST':
        return redirect('scanner:new_scan')

    form = ZipUploadForm(request.POST, request.FILES)
    if not form.is_valid():
        for err in form.errors.values():
            messages.error(request, err.as_text())
        return redirect('scanner:new_scan')

    zip_file = form.cleaned_data['zip_file']
    project_name = form.cleaned_data.get('project_name') or zip_file.name.rsplit('.', 1)[0]

    try:
        files = extract_scannable_files(zip_file)
    except ZipSecurityError as exc:
        messages.error(request, f'ZIP rejected: {exc}')
        return redirect('scanner:new_scan')
    except Exception:
        messages.error(request, 'Could not process the ZIP file. Make sure it is a valid archive.')
        return redirect('scanner:new_scan')

    if not files:
        messages.warning(request, 'No scannable source files (.py, .js, .html, .css) were found in the ZIP.')
        return redirect('scanner:new_scan')

    scan = Scan.objects.create(
        user=request.user,
        project_name=project_name,
        source_type=Scan.SourceType.ZIP,
        status=Scan.Status.RUNNING,
    )

    use_ai = not request.user.is_on_free_plan

    all_findings = []
    languages_seen = set()
    for entry in files:
        language, findings = analyze_single_file(entry['filename'], entry['content'], use_ai=use_ai)
        languages_seen.add(language)
        scanned_file = ScannedFile.objects.create(
            scan=scan, filename=entry['filename'], language=language,
            lines_of_code=len(entry['content'].splitlines())
        )
        _persist_findings(scan, language, findings, scanned_file)
        all_findings.extend(findings)

    scan.language = ', '.join(sorted(languages_seen)) if languages_seen else ''
    _finalize_scan(scan, all_findings, use_ai=use_ai)

    request.user.consume_scan()
    messages.success(request, f'Scan complete! Analyzed {len(files)} files.')
    return redirect('reports:detail', scan_id=scan.id)
