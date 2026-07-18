from django.urls import path
from . import views
import os

app_name = 'scanner'

urlpatterns = [
    path('new/', views.new_scan_view, name='new_scan'),
    path('scan/paste/', views.scan_paste_view, name='scan_paste'),
    path('scan/file/', views.scan_file_view, name='scan_file'),
    path('scan/zip/', views.scan_zip_view, name='scan_zip'),
    path('badge/<uuid:scan_id>.svg', views.badge_view, name='badge'),
    path('badge/<uuid:scan_id>/toggle/', views.toggle_badge_view, name='toggle_badge'),
]
