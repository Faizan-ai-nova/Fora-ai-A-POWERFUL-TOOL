from django.urls import path

from . import views

app_name = 'agentlab'

urlpatterns = [
    path('', views.new_test_view, name='new_test'),
    path('history/', views.history_view, name='history'),
    path('<uuid:test_id>/', views.detail_view, name='detail'),
]
