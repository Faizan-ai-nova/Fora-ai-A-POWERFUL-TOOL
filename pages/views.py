from pathlib import Path

from django.conf import settings
from django.shortcuts import render
from django.views.decorators.http import require_GET
from django.http import HttpResponse, Http404


def about_view(request):
    return render(request, 'pages/about.html')


def privacy_view(request):
    return render(request, 'pages/privacy.html')


def terms_view(request):
    return render(request, 'pages/terms.html')


def github_integration_docs_view(request):
    return render(request, 'pages/github_integration_docs.html')


def offline_view(request):
    """Standalone offline fallback page, served by the service worker when
    the network is unavailable and the requested page isn't cached."""
    return render(request, 'offline.html')


@require_GET
def robots_txt(request):
    lines = [
        'User-agent: *',
        'Allow: /',
        'Disallow: /admin/',
        'Disallow: /dashboard/',
        'Disallow: /scanner/',
        'Disallow: /reports/',
        'Disallow: /accounts/profile/',
        '',
        f'Sitemap: {request.scheme}://{request.get_host()}/sitemap.xml',
    ]
    return HttpResponse('\n'.join(lines), content_type='text/plain')


@require_GET
def sitemap_xml(request):
    """
    Hand-rolled sitemap covering the static/marketing pages and every published
    blog post. Kept dependency-free (no django.contrib.sites/sitemaps) to avoid
    extra required settings for a project this size.
    """
    from django.urls import reverse
    from blog.models import Post

    base = f'{request.scheme}://{request.get_host()}'
    static_urls = [
        (reverse('landing'), 'weekly', '1.0'),
        (reverse('subscriptions:pricing'), 'weekly', '0.9'),
        (reverse('pages:about'), 'monthly', '0.7'),
        (reverse('pages:privacy'), 'yearly', '0.3'),
        (reverse('pages:terms'), 'yearly', '0.3'),
        (reverse('pages:github_integration_docs'), 'monthly', '0.7'),
        (reverse('blog:list'), 'weekly', '0.8'),
    ]

    entries = []
    for path, freq, priority in static_urls:
        entries.append(f'<url><loc>{base}{path}</loc><changefreq>{freq}</changefreq><priority>{priority}</priority></url>')

    for post in Post.objects.filter(is_published=True):
        loc = f'{base}{post.get_absolute_url()}'
        lastmod = post.updated_at.strftime('%Y-%m-%d')
        entries.append(
            f'<url><loc>{loc}</loc><lastmod>{lastmod}</lastmod><changefreq>monthly</changefreq><priority>0.6</priority></url>'
        )

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        + ''.join(entries) +
        '</urlset>'
    )
    return HttpResponse(xml, content_type='application/xml')


@require_GET
def service_worker_view(request):
    """
    Serves /service-worker.js from the site ROOT (not /static/), which is
    required for its scope to cover the whole app rather than just /static/.
    Reads straight from the source static dir so this works identically in
    development and after collectstatic/Whitenoise in production.
    """
    sw_path = Path(settings.BASE_DIR) / 'static' / 'js' / 'service-worker.js'
    if not sw_path.exists():
        raise Http404('service-worker.js not found')

    with open(sw_path, 'r', encoding='utf-8') as f:
        content = f.read()

    response = HttpResponse(content, content_type='application/javascript')
    response['Service-Worker-Allowed'] = '/'
    response['Cache-Control'] = 'no-cache'
    return response
