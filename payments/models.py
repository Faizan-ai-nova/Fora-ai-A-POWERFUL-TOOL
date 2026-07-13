import uuid

from django.conf import settings
from django.db import models


class Payment(models.Model):
    class Provider(models.TextChoices):
        STRIPE = 'stripe', 'Stripe'
        PAYPAL = 'paypal', 'PayPal'
        UPI = 'upi', 'UPI (Manual)'

    class Status(models.TextChoices):
        PENDING = 'pending', 'Pending'
        SUCCEEDED = 'succeeded', 'Succeeded'
        FAILED = 'failed', 'Failed'
        REFUNDED = 'refunded', 'Refunded'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='payments')
    subscription = models.ForeignKey(
        'subscriptions.Subscription', on_delete=models.SET_NULL, null=True, blank=True, related_name='payments'
    )

    provider = models.CharField(max_length=10, choices=Provider.choices)
    provider_transaction_id = models.CharField(max_length=150, blank=True)
    amount = models.DecimalField(max_digits=8, decimal_places=2)
    currency = models.CharField(max_length=10, default='USD')
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.PENDING)

    raw_payload = models.JSONField(blank=True, null=True, help_text='Raw webhook payload for auditing')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.user.username} - {self.amount} {self.currency} ({self.status})'
