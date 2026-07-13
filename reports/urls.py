from django.urls import path
from . import views

app_name = 'reports'

urlpatterns = [
    path('', views.history_view, name='history'),
    path('<uuid:scan_id>/', views.detail_view, name='detail'),
    path('<uuid:scan_id>/export/pdf/', views.export_pdf, name='export_pdf'),
]
