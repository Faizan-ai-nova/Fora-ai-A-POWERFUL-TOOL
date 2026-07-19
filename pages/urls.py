from django.urls import path
from . import views

app_name = 'pages'

urlpatterns = [
    path('about/', views.about_view, name='about'),
    path('features/', views.features_view, name='features'),
    path('privacy/', views.privacy_view, name='privacy'),
    path('terms/', views.terms_view, name='terms'),
     path('docs/github-integration/', views.github_integration_docs_view, name='github_integration_docs'),
     path('offline/', views.offline_view, name='offline'),
]
