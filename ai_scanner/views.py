from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST

from .engine.prompts import TEST_SUITE
from .engine.runner import run_scan
from .engine.target_client import TargetClientError, validate_target_url
from .forms import NewAIScanForm
from .models import AIScan


def _guard_scan_quota(request):
    """Returns a redirect response if the user is out of scans, else None."""
    if not request.user.can_scan():
        messages.warning(request, "You've used all your free scans. Upgrade to continue scanning.")
        return redirect('subscriptions:upgrade')
    return None


@login_required
def new_scan_view(request):
    guard = _guard_scan_quota(request)
    if guard:
        return guard

    form = NewAIScanForm()
    return render(request, 'ai_scanner/new_scan.html', {
        'form': form,
        'scans_remaining': request.user.scans_remaining,
        'test_count': len(TEST_SUITE),
    })


@login_required
@require_POST
def start_scan_view(request):
    guard = _guard_scan_quota(request)
    if guard:
        return guard

    form = NewAIScanForm(request.POST)
    if not form.is_valid():
        for err in form.errors.values():
            messages.error(request, err.as_text())
        return redirect('ai_scanner:new_scan')

    try:
        validate_target_url(form.cleaned_data['target_url'])
    except TargetClientError as exc:
        messages.error(request, str(exc))
        return redirect('ai_scanner:new_scan')

    scan = AIScan.objects.create(
        user=request.user,
        target_name=form.cleaned_data.get('target_name') or 'Untitled AI',
        target_url=form.cleaned_data['target_url'],
        request_field=form.cleaned_data.get('request_field') or 'message',
        response_path=form.cleaned_data.get('response_path') or 'response',
        auth_header=form.cleaned_data.get('auth_header', ''),
    )
    return redirect('ai_scanner:running', scan_id=scan.id)


@login_required
def running_view(request, scan_id):
    scan = get_object_or_404(AIScan, id=scan_id, user=request.user)
    if scan.status == AIScan.Status.COMPLETED:
        return redirect('ai_scanner:report', scan_id=scan.id)
    return render(request, 'ai_scanner/running.html', {'scan': scan, 'test_count': len(TEST_SUITE)})


@login_required
@require_POST
def execute_scan_view(request, scan_id):
    """
    AJAX endpoint the 'running' page calls to actually perform the scan.
    Runs synchronously and returns where to redirect once finished; the
    frontend shows a live thinking/attack-simulation sequence, backed by
    real step progress polled from scan_status_view, for the duration of
    this request.
    """
    scan = get_object_or_404(AIScan, id=scan_id, user=request.user)
    if scan.status == AIScan.Status.COMPLETED:
        return JsonResponse({'ok': True, 'redirect_url': reverse('ai_scanner:report', kwargs={'scan_id': scan.id})})

    try:
        run_scan(scan)
        request.user.consume_scan()
    except Exception as exc:  # noqa: BLE001 - a broken target must not crash the request
        scan.status = AIScan.Status.FAILED
        scan.error_message = str(exc)[:500]
        scan.save(update_fields=['status', 'error_message'])
        return JsonResponse({'ok': False, 'error': 'The scan could not complete. The target may be unreachable.'})

    return JsonResponse({'ok': True, 'redirect_url': reverse('ai_scanner:report', kwargs={'scan_id': scan.id})})


@login_required
def scan_status_view(request, scan_id):
    """Lightweight JSON poll so the running page can show real step progress."""
    scan = get_object_or_404(AIScan, id=scan_id, user=request.user)
    return JsonResponse({
        'status': scan.status,
        'current_step': scan.current_step,
        'total_steps': scan.total_steps,
        'current_step_label': scan.current_step_label,
        'progress_pct': scan.progress_pct,
    })


@login_required
def report_view(request, scan_id):
    scan = get_object_or_404(AIScan, id=scan_id, user=request.user)
    if scan.status not in (AIScan.Status.COMPLETED, AIScan.Status.FAILED):
        return redirect('ai_scanner:running', scan_id=scan.id)

    results = scan.test_results.all()
    return render(request, 'ai_scanner/report.html', {
        'scan': scan,
        'results': results,
        'passed_results': results.filter(passed=True),
        'failed_results': results.filter(passed=False),
    })


@login_required
def history_view(request):
    scans = AIScan.objects.filter(user=request.user)
    paginator = Paginator(scans, 10)
    page_obj = paginator.get_page(request.GET.get('page'))
    return render(request, 'ai_scanner/history.html', {'page_obj': page_obj})


@login_required
@require_POST
def delete_scan_view(request, scan_id):
    scan = get_object_or_404(AIScan, id=scan_id, user=request.user)
    scan.delete()
    messages.success(request, 'Scan deleted.')
    return redirect('ai_scanner:history')


@login_required
@require_POST
def rerun_scan_view(request, scan_id):
    guard = _guard_scan_quota(request)
    if guard:
        return guard

    old = get_object_or_404(AIScan, id=scan_id, user=request.user)
    new_scan = AIScan.objects.create(
        user=request.user,
        target_name=old.target_name,
        target_url=old.target_url,
        request_field=old.request_field,
        response_path=old.response_path,
        auth_header=old.auth_header,
    )
    return redirect('ai_scanner:running', scan_id=new_scan.id)
