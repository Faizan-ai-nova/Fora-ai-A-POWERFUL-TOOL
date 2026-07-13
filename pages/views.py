from django.shortcuts import render
from django.views.decorators.http import require_GET
from django.http import HttpResponse


def about_view(request):
    return render(request, 'pages/about.html')


def privacy_view(request):
    return render(request, 'pages/privacy.html')


def terms_view(request):
    return render(request, 'pages/terms.html')


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
