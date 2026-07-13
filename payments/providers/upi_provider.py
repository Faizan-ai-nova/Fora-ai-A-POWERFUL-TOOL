import logging
from urllib.parse import quote

from django.conf import settings
from django.core.mail import send_mail

from .base import PaymentProvider

logger = logging.getLogger(__name__)


class UPIProvider(PaymentProvider):
    """
    Manual UPI payment flow (no payment gateway / no fees):

    1. User opens checkout -> sees a UPI QR code (+ UPI ID) for the exact
       plan amount, generated on the fly, no API keys needed except the
       UPI ID itself.
    2. User pays via any UPI app (GPay / PhonePe / Paytm / etc.) and clicks
       "I've Paid" on our page, optionally entering the UTR/reference number.
    3. We create a `Payment` row with status=pending and email the admin
       (ADMIN_NOTIFY_EMAIL) with the details so it can be verified manually.
    4. Admin verifies the money actually landed, then approves the payment
       from Django admin (an admin action activates the subscription and
       emails the user).

    This is intentionally provider-agnostic so it's trivial to swap back to
    Razorpay (or add another automated gateway) later - just point the
    pricing page buttons at a different provider key in PROVIDERS.
    """

    name = 'upi'

    @property
    def is_configured(self) -> bool:
        return bool(getattr(settings, 'UPI_ID', ''))

    def build_upi_uri(self, user, plan) -> dict:
        upi_id = settings.UPI_ID
        payee_name = getattr(settings, 'UPI_PAYEE_NAME', 'Fora AI')
        amount = plan.display_price_inr
        note = f'ForaAI {plan.slug} {user.username}'[:50]

        upi_uri = (
            f'upi://pay?pa={quote(upi_id)}&pn={quote(payee_name)}'
            f'&am={amount}&cu=INR&tn={quote(note)}'
        )
        qr_url = (
            'https://api.qrserver.com/v1/create-qr-code/'
            f'?size=280x280&data={quote(upi_uri, safe="")}'
        )
        return {
            'upi_id': upi_id,
            'payee_name': payee_name,
            'amount': amount,
            'upi_uri': upi_uri,
            'qr_url': qr_url,
            'note': note,
        }

    def create_checkout_session(self, user, plan) -> dict:
        if not self.is_configured:
            return {'error': 'UPI payments are not yet configured. Add UPI_ID in your environment variables.'}
        return self.build_upi_uri(user, plan)

    def notify_admin(self, user, plan, payment) -> None:
        """Email the admin that a user claims to have paid via UPI."""
        admin_email = getattr(settings, 'ADMIN_NOTIFY_EMAIL', '')
        if not admin_email:
            logger.warning('ADMIN_NOTIFY_EMAIL not set - skipping UPI payment notification email.')
            return

        subject = f'New UPI payment claim - {user.username} - {plan.name} (₹{plan.display_price_inr})'
        message = (
            f'A user says they just paid via UPI. Please verify in your bank/UPI app, '
            f'then approve it from Django admin.\n\n'
            f'User: {user.username} ({user.email})\n'
            f'Plan: {plan.name} - ₹{plan.display_price_inr} ({plan.billing_period})\n'
            f'UTR / Reference entered by user: {payment.provider_transaction_id or "(not provided)"}\n'
            f'Payment record ID: {payment.id}\n\n'
            f'Approve here: {getattr(settings, "SITE_DOMAIN", "")}/admin/payments/payment/{payment.id}/change/\n'
            f'(Use the "Approve selected UPI payments" action in the Payments list for a one-click activate.)'
        )
        try:
            send_mail(
                subject,
                message,
                getattr(settings, 'DEFAULT_FROM_EMAIL', None),
                [admin_email],
                fail_silently=False,
            )
        except Exception as exc:  # pragma: no cover
            logger.error('UPI admin notification email failed: %s', exc)

    def notify_user_pending(self, user, plan) -> None:
        """Optional confirmation email to the user that their claim was received."""
        if not user.email:
            return
        subject = 'We received your payment - Fora AI'
        message = (
            f'Hi {user.get_full_name() or user.username},\n\n'
            f'We received your UPI payment claim for {plan.name} (₹{plan.display_price_inr}).\n'
            f'Our team verifies UPI payments manually - you will get unlimited access '
            f'within 30 minutes once confirmed.\n\n'
            f'Thanks for your patience,\nFora AI'
        )
        try:
            send_mail(
                subject,
                message,
                getattr(settings, 'DEFAULT_FROM_EMAIL', None),
                [user.email],
                fail_silently=False,
            )
        except Exception as exc:  # pragma: no cover
            logger.error('UPI user notification email failed: %s', exc)

    # --- Required by the PaymentProvider interface, but not used for a manual flow ---

    def verify_payment(self, *args, **kwargs) -> bool:
        return False

    def cancel_subscription(self, subscription) -> bool:
        return False

    def handle_webhook(self, request) -> dict:
        return {'error': 'not_supported'}
