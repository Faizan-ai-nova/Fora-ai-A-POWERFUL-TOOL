import logging

from django.conf import settings

from .base import PaymentProvider

logger = logging.getLogger(__name__)

PAYPAL_API_BASE = {
    'sandbox': 'https://api-m.sandbox.paypal.com',
    'live': 'https://api-m.paypal.com',
}


class PayPalProvider(PaymentProvider):
    name = 'paypal'

    @property
    def is_configured(self) -> bool:
        return bool(settings.PAYPAL_CLIENT_ID and settings.PAYPAL_CLIENT_SECRET)

    @property
    def api_base(self):
        return PAYPAL_API_BASE.get(settings.PAYPAL_MODE, PAYPAL_API_BASE['sandbox'])

    def _get_access_token(self):
        import requests
        resp = requests.post(
            f'{self.api_base}/v1/oauth2/token',
            auth=(settings.PAYPAL_CLIENT_ID, settings.PAYPAL_CLIENT_SECRET),
            data={'grant_type': 'client_credentials'},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()['access_token']

    def _ensure_plan_id(self, plan) -> str:
        """Return plan.paypal_plan_id, creating the PayPal Product + Billing
        Plan on the fly (and saving the ID back to our DB) the first time a
        plan is checked out. This means PayPal works as soon as
        PAYPAL_CLIENT_ID / PAYPAL_CLIENT_SECRET are set - no manual step of
        creating a Product/Plan in the PayPal dashboard first."""
        if plan.paypal_plan_id:
            return plan.paypal_plan_id

        import requests
        token = self._get_access_token()
        headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}

        product_resp = requests.post(
            f'{self.api_base}/v1/catalogs/products',
            headers=headers,
            json={
                'name': f'Fora AI — {plan.name}',
                'description': plan.tagline or f'Fora AI {plan.name} subscription',
                'type': 'SERVICE',
                'category': 'SOFTWARE',
            },
            timeout=10,
        )
        product_resp.raise_for_status()
        product_id = product_resp.json()['id']

        interval_unit = 'YEAR' if plan.billing_period == 'yearly' else 'MONTH'
        plan_resp = requests.post(
            f'{self.api_base}/v1/billing/plans',
            headers=headers,
            json={
                'product_id': product_id,
                'name': f'Fora AI {plan.name} ({plan.billing_period})',
                'billing_cycles': [{
                    'frequency': {'interval_unit': interval_unit, 'interval_count': 1},
                    'tenure_type': 'REGULAR',
                    'sequence': 1,
                    'total_cycles': 0,  # 0 = billed indefinitely until cancelled
                    'pricing_scheme': {
                        'fixed_price': {'value': str(plan.price_monthly), 'currency_code': 'USD'},
                    },
                }],
                'payment_preferences': {
                    'auto_bill_outstanding': True,
                    'payment_failure_threshold': 3,
                },
            },
            timeout=10,
        )
        plan_resp.raise_for_status()
        paypal_plan_id = plan_resp.json()['id']

        plan.paypal_plan_id = paypal_plan_id
        plan.save(update_fields=['paypal_plan_id'])
        return paypal_plan_id

    def create_checkout_session(self, user, plan) -> dict:
        if not self.is_configured:
            return {'error': 'PayPal is not configured yet. Add PAYPAL_CLIENT_ID / PAYPAL_CLIENT_SECRET to your environment.'}
        try:
            import requests
            token = self._get_access_token()
            paypal_plan_id = self._ensure_plan_id(plan)
            resp = requests.post(
                f'{self.api_base}/v1/billing/subscriptions',
                headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'},
                json={
                    'plan_id': paypal_plan_id,
                    'subscriber': {'email_address': user.email},
                    'application_context': {
                        'return_url': f'{settings.SITE_DOMAIN}/payments/success/',
                        'cancel_url': f'{settings.SITE_DOMAIN}/subscriptions/pricing/',
                    },
                },
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
            approve_link = next((l['href'] for l in data.get('links', []) if l['rel'] == 'approve'), None)
            return {'checkout_url': approve_link} if approve_link else {'error': 'No approval link returned by PayPal.'}
        except Exception as exc:  # pragma: no cover - network dependent
            logger.error('PayPal checkout session failed: %s', exc)
            return {'error': 'Could not start PayPal checkout. Please try again later.'}

    def cancel_subscription(self, subscription) -> bool:
        if not self.is_configured:
            return False
        try:
            import requests
            token = self._get_access_token()
            resp = requests.post(
                f'{self.api_base}/v1/billing/subscriptions/{subscription.provider_subscription_id}/cancel',
                headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'},
                json={'reason': 'User requested cancellation'},
                timeout=10,
            )
            return resp.status_code in (204, 200)
        except Exception as exc:  # pragma: no cover
            logger.error('PayPal cancellation failed: %s', exc)
            return False

    def handle_webhook(self, request) -> dict:
        if not self.is_configured:
            return {'error': 'not_configured'}
        import json
        try:
            payload = json.loads(request.body)
            # Full signature verification requires calling PayPal's
            # /v1/notifications/verify-webhook-signature endpoint with the
            # stored webhook ID - wire that in once PAYPAL keys are live.
            return {'type': payload.get('event_type'), 'data': payload.get('resource', {})}
        except Exception as exc:  # pragma: no cover
            logger.error('PayPal webhook parse failed: %s', exc)
            return {'error': 'invalid_payload'}
