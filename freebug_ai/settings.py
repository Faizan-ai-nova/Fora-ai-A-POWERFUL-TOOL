"""Fora AI URL Configuration."""
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, include
from django.views.generic import TemplateView
from django.http import HttpResponse

from pages.views import robots_txt, sitemap_xml, service_worker_view
def ads_txt(request):
    content = "google.com, pub-8724042466038280, DIRECT, f08c47fec0942fa0"
    return HttpResponse(content, content_type="text/plain")

urlpatterns = [
    path('foraoops8082572326@09/', admin.site.urls),
    path('', TemplateView.as_view(template_name='landing.html'), name='landing'),
    path('accounts/', include('accounts.urls')),
    path('dashboard/', include('dashboard.urls')),
    path('scanner/', include('scanner.urls')),
    path('subscriptions/', include('subscriptions.urls')),
    path('payments/', include('payments.urls')),
    path('reports/', include('reports.urls')),
    path('integrations/', include('integrations.urls')),
    path('blog/', include('blog.urls')),
    path('', include('pages.urls')),
    path('robots.txt', robots_txt, name='robots_txt'),
    path('sitemap.xml', sitemap_xml, name='sitemap_xml'),
    path('service-worker.js', service_worker_view, name='service_worker'),
    path('integrations/', include('integrations.urls')),
    path('ads.txt', ads_txt),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# Custom error handlers
handler404 = 'dashboard.views.error_404'
handler500 = 'dashboard.views.error_500'
