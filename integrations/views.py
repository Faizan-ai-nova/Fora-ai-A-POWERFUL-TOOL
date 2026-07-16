import hashlib
import hmac
import io
import json
import logging

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from scanner.engine.analyzer import analyze_single_file
from scanner.engine.zip_handler import ZipSecurityError, extract_scannable_files
from scanner.models import Scan, ScannedFile
from scanner.views import _finalize_scan, _persist_findings

from . import github_client
from .forms import ConnectRepoForm
from .models import GithubRepo

logger = logging.getLogger(__name__)


@login_required
def repo_list_view(request):
    repos = GithubRepo.objects.filter(user=request.user)
    form = ConnectRepoForm()
    return render(request, 'integrations/repo_list.html', {'repos': repos, 'form': form})


@login_required
def connect_repo_view(request):
    if request.method != 'POST':
        return redirect('integrations:list')

    form = ConnectRepoForm(request.POST)
    if not form.is_valid():
        for err in form.errors.values():
            messages.error(request, err.as_text())
        return redirect('integrations:list')

    full_name = form.cleaned_data['repo_full_name']
    token = form.cleaned_data['access_token']

    if GithubRepo.objects.filter(user=request.user, repo_full_name=full_name).exists():
        messages.warning(request, f'{full_name} is already connected.')
        return redirect('integrations:list')

    try:
        info = github_client.get_repo_info(token, full_name)
    except github_client.GithubAPIError as exc:
        messages.error(request, str(exc))
        return redirect('integrations:list')

    default_branch = info.get('default_branch') or 'main'

    repo = GithubRepo.objects.create(
        user=request.user,
        repo_full_name=full_name,
        access_token=token,
        default_branch=default_branch,
    )

    callback_url = request.build_absolute_uri(reverse('integrations:webhook', args=[repo.id]))
    # Force https for the public callback: GitHub's webhook delivery does not follow
    # redirects, and DEBUG=True (or a misconfigured proxy header) can cause Django to
    # think a Railway request came in over plain http, producing a URL that 301s.
    if callback_url.startswith('http://') and request.get_host() not in ('127.0.0.1:8000', 'localhost:8000'):
        callback_url = 'https://' + callback_url[len('http://'):]

    try:
        webhook_id = github_client.create_webhook(token, full_name, callback_url, repo.webhook_secret)
    except github_client.GithubAPIError as exc:
        repo.delete()
        messages.error(request, str(exc))
        return redirect('integrations:list')

    repo.github_webhook_id = webhook_id
    repo.save(update_fields=['github_webhook_id'])

    messages.success(request, f'Connected! Pushes to "{default_branch}" on {full_name} will now be scanned automatically.')
    return redirect('integrations:list')


@login_required
@require_POST
def disconnect_repo_view(request, repo_id):
    repo = get_object_or_404(GithubRepo, id=repo_id, user=request.user)

    if repo.github_webhook_id:
        github_client.delete_webhook(repo.access_token, repo.repo_full_name, repo.github_webhook_id)

    name = repo.repo_full_name
    repo.delete()
    messages.success(request, f'Disconnected {name}.')
    return redirect('integrations:list')


@csrf_exempt
@require_POST
def github_webhook_view(request, repo_id):
    """
    Public endpoint GitHub calls on every push. Auth is via the
    X-Hub-Signature-256 HMAC header (checked against the per-repo secret),
    not a login session — GitHub's servers are the caller.
    """
    repo = get_object_or_404(GithubRepo, id=repo_id, is_active=True)

    raw_body = request.body
    signature_header = request.headers.get('X-Hub-Signature-256', '')
    expected = 'sha256=' + hmac.new(repo.webhook_secret.encode(), raw_body, hashlib.sha256).hexdigest()
    if not signature_header or not hmac.compare_digest(expected, signature_header):
        return HttpResponse('invalid signature', status=401)

    event = request.headers.get('X-GitHub-Event', '')
    if event == 'ping':
        return HttpResponse('pong')
    if event != 'push':
        return HttpResponse(f'ignored ({event} event)')

    try:
        payload = json.loads(raw_body)
    except ValueError:
        return HttpResponse('invalid payload', status=400)

    if payload.get('deleted'):
        return HttpResponse('ignored (branch deleted)')

    ref = payload.get('ref', '')
    branch = ref.rsplit('/', 1)[-1] if ref else ''
    if branch != repo.default_branch:
        return HttpResponse(f'ignored (push to {branch}, watching {repo.default_branch})')

    if not repo.user.can_scan():
        logger.info('GitHub push scan skipped for %s: %s is out of scans.', repo.repo_full_name, repo.user)
        return HttpResponse('skipped: scan quota exhausted')

    try:
        zip_bytes = github_client.fetch_zipball(repo.access_token, repo.repo_full_name, branch)
        files = extract_scannable_files(io.BytesIO(zip_bytes))
    except (github_client.GithubAPIError, ZipSecurityError) as exc:
        logger.error('GitHub push scan failed for %s: %s', repo.repo_full_name, exc)
        return HttpResponse(f'scan failed: {exc}')
    except Exception:
        logger.exception('Unexpected error fetching/extracting push for %s', repo.repo_full_name)
        return HttpResponse('scan failed: unexpected error while reading the repo archive')

    # GitHub zipballs wrap everything in a "{repo}-{sha}/" root folder - strip it for readability.
    for entry in files:
        parts = entry['filename'].split('/', 1)
        entry['filename'] = parts[1] if len(parts) > 1 else entry['filename']

    if not files:
        return HttpResponse('no scannable source files found in this push')

    commit_sha = (payload.get('after') or '')[:7]

    try:
        scan = Scan.objects.create(
            user=repo.user,
            project_name=f'{repo.repo_full_name}@{branch} ({commit_sha})',
            source_type=Scan.SourceType.ZIP,
            status=Scan.Status.RUNNING,
        )

        use_ai = not repo.user.is_on_free_plan
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
        repo.user.consume_scan()

        repo.last_scan = scan
        repo.last_push_sha = payload.get('after', '')
        repo.last_synced_at = timezone.now()
        repo.save(update_fields=['last_scan', 'last_push_sha', 'last_synced_at'])
    except Exception:
        logger.exception('Unexpected error scanning push for %s', repo.repo_full_name)
        return HttpResponse('scan failed: unexpected error during analysis')

    return HttpResponse(f'scan triggered: {scan.id}')
