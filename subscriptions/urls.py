from django.urls import path
from . import views

app_name = 'subscriptions'

urlpatterns = [
    path('pricing/', views.pricing_view, name='pricing'),
    path('upgrade/', views.upgrade_view, name='upgrade'),
]
