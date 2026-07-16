from django.urls import path

from . import views

app_name = 'integrations'

urlpatterns = [
    path('', views.repo_list_view, name='list'),
    path('connect/', views.connect_repo_view, name='connect'),
    path('<uuid:repo_id>/disconnect/', views.disconnect_repo_view, name='disconnect'),
    path('webhook/<uuid:repo_id>/', views.github_webhook_view, name='webhook'),
]
