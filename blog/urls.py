from django.urls import path
from . import views

app_name = 'blog'

urlpatterns = [
    path('', views.post_list_view, name='list'),
    path('<slug:slug>/', views.post_detail_view, name='detail'),
]
