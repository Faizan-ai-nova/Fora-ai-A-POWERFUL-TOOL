from django.urls import path

from . import views

app_name = 'ai_scanner'

urlpatterns = [
    path('new/', views.new_scan_view, name='new_scan'),
    path('start/', views.start_scan_view, name='start_scan'),
    path('scan/<uuid:scan_id>/running/', views.running_view, name='running'),
    path('scan/<uuid:scan_id>/execute/', views.execute_scan_view, name='execute_scan'),
    path('scan/<uuid:scan_id>/status/', views.scan_status_view, name='scan_status'),
    path('scan/<uuid:scan_id>/report/', views.report_view, name='report'),
    path('scan/<uuid:scan_id>/delete/', views.delete_scan_view, name='delete_scan'),
    path('scan/<uuid:scan_id>/rerun/', views.rerun_scan_view, name='rerun_scan'),
    path('history/', views.history_view, name='history'),
]
