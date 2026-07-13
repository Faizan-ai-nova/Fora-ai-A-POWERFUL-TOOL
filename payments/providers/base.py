"""
Modular payment provider interface.

Both Stripe and PayPal implementations follow this contract so views/templates
never need to know which provider is active. Add real API keys via
environment variables (STRIPE_SECRET_KEY, PAYPAL_CLIENT_ID/SECRET) and these
classes light up automatically - no other code changes required.
"""

from abc import ABC, abstractmethod


class PaymentProvider(ABC):
    name = 'base'

    @property
    @abstractmethod
    def is_configured(self) -> bool:
        ...

    @abstractmethod
    def create_checkout_session(self, user, plan) -> dict:
        """
        Start a subscription checkout for the given user/plan.
        Returns {"checkout_url": str} on success, or {"error": str} if the
        provider isn't configured yet / the call failed.
        """
        ...

    @abstractmethod
    def cancel_subscription(self, subscription) -> bool:
        ...

    @abstractmethod
    def handle_webhook(self, request) -> dict:
        """Verify & parse an incoming webhook event. Returns a normalized dict."""
        ...
