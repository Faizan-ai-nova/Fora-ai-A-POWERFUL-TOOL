import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from subscriptions.models import Plan, Subscription
from .models import Payment
from .providers.paypal_provider import PayPalProvider
from .providers.razorpay_provider import RazorpayProvider
from .providers.upi_provider import UPIProvider

PROVIDERS = {
    'paypal':    PayPalProvider(),
    'razorpay':  RazorpayProvider(),
    'upi':       UPIProvider(),
}


@login_required
def checkout_view(request, provider_name, plan_slug):
    plan = get_object_or_404(Plan, slug=plan_slug, is_active=True)
    provider = PROVIDERS.get(provider_name)

    if provider is None:
        messages.error(request, 'Unknown payment provider.')
        return redirect('subscriptions:pricing')

    if not provider.is_configured:
        messages.info(
            request,
           f"{provider.name.title()} is temporarily unavailable right now. Please try another payment method — we're working on getting it fixed soon. Sorry for the inconvenience!"
        )
        return redirect('subscriptions:pricing')

    result = provider.create_checkout_session(request.user, plan)

    if 'error' in result:
        messages.error(request, result['error'])
        return redirect('subscriptions:pricing')

    # Razorpay — render JS widget page instead of redirect
    if result.get('razorpay'):
        return render(request, 'payments/razorpay_checkout.html', {
            'plan': plan,
            'razorpay_data': result,
        })

    # PayPal — redirect to PayPal approval URL
    return redirect(result['checkout_url'])


@login_required
def payment_success_view(request):
    messages.success(request, 'Payment successful! Your plan is now active.')
    return render(request, 'payments/success.html')


@login_required
def upi_checkout_view(request, plan_slug):
    """
    GET  -> show the UPI QR code + 'I've Paid' form.
    POST -> record the payment claim (pending), email the admin, and send
            the user to a 'we're verifying it' page.
    """
    plan = get_object_or_404(Plan, slug=plan_slug, is_active=True)
    provider = PROVIDERS['upi']

    if not provider.is_configured:
        messages.info(
            request,
            'UPI payments are not yet configured. Add UPI_ID in Railway environment variables.'
        )
        return redirect('subscriptions:pricing')

    if request.method == 'POST':
        utr = request.POST.get('utr', '').strip()

        payment = Payment.objects.create(
            user=request.user,
            subscription=None,
            provider=Payment.Provider.UPI,
            provider_transaction_id=utr,
            amount=plan.display_price_inr,
            currency='INR',
            status=Payment.Status.PENDING,
            raw_payload={'plan_id': plan.id, 'plan_slug': plan.slug, 'plan_name': plan.name, 'utr': utr},
        )
        provider.notify_admin(request.user, plan, payment)
        provider.notify_user_pending(request.user, plan)

        return redirect('payments:upi_pending')

    upi_data = provider.create_checkout_session(request.user, plan)
    return render(request, 'payments/upi_checkout.html', {'plan': plan, 'upi_data': upi_data})


@login_required
def upi_pending_view(request):
    return render(request, 'payments/upi_pending.html')


@login_required
@require_POST
def razorpay_verify_view(request):
    """
    Called by Razorpay checkout.js after payment.
    Verifies signature → activates subscription.
    """
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'ok': False, 'error': 'Bad request'}, status=400)

    provider = PROVIDERS['razorpay']
    ok = provider.verify_payment(
        data.get('razorpay_order_id', ''),
        data.get('razorpay_payment_id', ''),
        data.get('razorpay_signature', ''),
    )

    if not ok:
        return JsonResponse({'ok': False, 'error': 'Payment verification failed.'}, status=400)

    # Activate subscription
    plan_id = data.get('plan_id')
    if plan_id:
        try:
            plan = Plan.objects.get(id=plan_id)
            Subscription.objects.filter(user=request.user, status='active').update(status='canceled')
            Subscription.objects.create(
                user=request.user,
                plan=plan,
                status='active',
                provider='razorpay',
                provider_subscription_id=data.get('razorpay_payment_id', ''),
            )
        except Plan.DoesNotExist:
            pass

    return JsonResponse({'ok': True, 'redirect': '/payments/success/'})


@csrf_exempt
def paypal_webhook_view(request):
    provider = PROVIDERS['paypal']
    event = provider.handle_webhook(request)
    if 'error' in event:
        return HttpResponse(status=400)
    # TODO: handle BILLING.SUBSCRIPTION.ACTIVATED etc.
    return JsonResponse({'received': True})


@csrf_exempt
def razorpay_webhook_view(request):
    provider = PROVIDERS['razorpay']
    event = provider.handle_webhook(request)
    if 'error' in event:
        return HttpResponse(status=400)
    # TODO: handle payment.captured, subscription.cancelled etc.
    return JsonResponse({'received': True})
