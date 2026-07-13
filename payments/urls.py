from django.urls import path
from . import views

app_name = 'payments'

urlpatterns = [
    path('checkout/<str:provider_name>/<slug:plan_slug>/', views.checkout_view, name='checkout'),
    path('upi/checkout/<slug:plan_slug>/',                views.upi_checkout_view, name='upi_checkout'),
    path('upi/pending/',                                  views.upi_pending_view, name='upi_pending'),
    path('success/',                                       views.payment_success_view, name='success'),
    path('razorpay/verify/',                              views.razorpay_verify_view, name='razorpay_verify'),
    path('webhook/paypal/',                               views.paypal_webhook_view, name='paypal_webhook'),
    path('webhook/razorpay/',                             views.razorpay_webhook_view, name='razorpay_webhook'),
]
