import hashlib
import hmac
import json
import logging
import uuid

from django.conf import settings

from .base import PaymentProvider

logger = logging.getLogger(__name__)


class RazorpayProvider(PaymentProvider):
    name = 'razorpay'

    @property
    def is_configured(self) -> bool:
        return bool(
            getattr(settings, 'RAZORPAY_KEY_ID', '') and
            getattr(settings, 'RAZORPAY_KEY_SECRET', '')
        )

    def create_checkout_session(self, user, plan) -> dict:
        """
        Razorpay works differently — we create an Order server-side
        and pass the order_id + key to the frontend JS widget.
        We return the data needed to render the checkout widget.
        """
        if not self.is_configured:
            return {'error': 'Razorpay is not configured. Add RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET.'}
        try:
            import razorpay
            client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

            # Amount in paise (₹199 = 19900 paise)
            amount_paise = int(float(plan.price_inr or plan.price_monthly) * 100)

            order_data = {
                'amount': amount_paise,
                'currency': 'INR',
                'receipt': f'order_{uuid.uuid4().hex[:12]}',
                'notes': {
                    'user_id': str(user.id),
                    'plan_id': str(plan.id),
                    'plan_slug': plan.slug,
                },
            }
            order = client.order.create(data=order_data)

            return {
                'razorpay': True,          # signal to view that it's widget-based
                'order_id': order['id'],
                'amount': amount_paise,
                'currency': 'INR',
                'key_id': settings.RAZORPAY_KEY_ID,
                'user_name': user.get_full_name() or user.username,
                'user_email': user.email,
                'plan_name': plan.name,
            }
        except Exception as exc:
            logger.error('Razorpay order creation failed: %s', exc)
            return {'error': 'Could not start Razorpay checkout. Please try again.'}

    def verify_payment(self, razorpay_order_id, razorpay_payment_id, razorpay_signature) -> bool:
        """Verify the payment signature from Razorpay callback."""
        try:
            msg = f'{razorpay_order_id}|{razorpay_payment_id}'.encode()
            secret = settings.RAZORPAY_KEY_SECRET.encode()
            expected = hmac.new(secret, msg, hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected, razorpay_signature)
        except Exception as exc:
            logger.error('Razorpay signature verification failed: %s', exc)
            return False

    def cancel_subscription(self, subscription) -> bool:
        # Razorpay subscriptions can be cancelled via API
        if not self.is_configured:
            return False
        try:
            import razorpay
            client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
            client.subscription.cancel(subscription.provider_subscription_id)
            return True
        except Exception as exc:
            logger.error('Razorpay cancellation failed: %s', exc)
            return False

    def handle_webhook(self, request) -> dict:
        if not self.is_configured:
            return {'error': 'not_configured'}
        try:
            payload = request.body
            signature = request.META.get('HTTP_X_RAZORPAY_SIGNATURE', '')
            secret = settings.RAZORPAY_KEY_SECRET.encode()
            expected = hmac.new(secret, payload, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, signature):
                return {'error': 'invalid_signature'}
            data = json.loads(payload)
            return {'type': data.get('event'), 'data': data.get('payload', {})}
        except Exception as exc:
            logger.error('Razorpay webhook failed: %s', exc)
            return {'error': 'invalid_payload'}
