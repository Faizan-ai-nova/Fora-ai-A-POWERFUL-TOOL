import logging

from django.conf import settings

from .base import PaymentProvider

logger = logging.getLogger(__name__)


class StripeProvider(PaymentProvider):
    name = 'stripe'

    @property
    def is_configured(self) -> bool:
        return bool(settings.STRIPE_SECRET_KEY)

    def create_checkout_session(self, user, plan) -> dict:
        if not self.is_configured:
            return {'error': 'Stripe is not configured yet. Add STRIPE_SECRET_KEY to your environment.'}
        try:
            import stripe
            stripe.api_key = settings.STRIPE_SECRET_KEY
            session = stripe.checkout.Session.create(
                mode='subscription',
                customer_email=user.email,
                line_items=[{'price': plan.stripe_price_id or settings.STRIPE_BASIC_PRICE_ID, 'quantity': 1}],
                success_url=f'{settings.SITE_DOMAIN}/payments/success/?session_id={{CHECKOUT_SESSION_ID}}',
                cancel_url=f'{settings.SITE_DOMAIN}/subscriptions/pricing/',
                metadata={'user_id': str(user.id), 'plan_id': str(plan.id)},
            )
            return {'checkout_url': session.url}
        except Exception as exc:  # pragma: no cover - network dependent
            logger.error('Stripe checkout session failed: %s', exc)
            return {'error': 'Could not start Stripe checkout. Please try again later.'}

    def cancel_subscription(self, subscription) -> bool:
        if not self.is_configured:
            return False
        try:
            import stripe
            stripe.api_key = settings.STRIPE_SECRET_KEY
            stripe.Subscription.delete(subscription.provider_subscription_id)
            return True
        except Exception as exc:  # pragma: no cover
            logger.error('Stripe cancellation failed: %s', exc)
            return False

    def handle_webhook(self, request) -> dict:
        if not self.is_configured:
            return {'error': 'not_configured'}
        try:
            import stripe
            payload = request.body
            sig_header = request.META.get('HTTP_STRIPE_SIGNATURE', '')
            event = stripe.Webhook.construct_event(payload, sig_header, settings.STRIPE_WEBHOOK_SECRET)
            return {'type': event['type'], 'data': event['data']['object']}
        except Exception as exc:  # pragma: no cover
            logger.error('Stripe webhook verification failed: %s', exc)
            return {'error': 'invalid_signature'}
