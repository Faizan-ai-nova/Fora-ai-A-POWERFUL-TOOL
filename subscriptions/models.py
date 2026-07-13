import uuid

from django.conf import settings
from django.db import models


class Plan(models.Model):
    slug = models.SlugField(unique=True)
    name = models.CharField(max_length=100)
    tagline = models.CharField(max_length=255, blank=True)

    # USD pricing (kept for reference / international)
    price_monthly = models.DecimalField(max_digits=8, decimal_places=2, default=0)

    # INR pricing for Razorpay
    price_inr = models.DecimalField(
        max_digits=10, decimal_places=2, default=0,
        help_text='Price in INR for Razorpay. e.g. 199 for monthly, 2330 for yearly'
    )
    billing_period = models.CharField(
        max_length=10,
        choices=[('monthly', 'Monthly'), ('yearly', 'Yearly'), ('free', 'Free')],
        default='monthly',
    )

    scan_limit = models.PositiveIntegerField(default=10)
    is_unlimited = models.BooleanField(default=False)
    features = models.JSONField(default=list, blank=True)
    is_active = models.BooleanField(default=True)
    is_featured = models.BooleanField(default=False)
    order = models.PositiveSmallIntegerField(default=0)

    # Payment provider references
    paypal_plan_id = models.CharField(max_length=100, blank=True)
    razorpay_plan_id = models.CharField(max_length=100, blank=True)

    class Meta:
        ordering = ['order', 'price_inr']

    def __str__(self):
        return self.name

    @property
    def display_price_inr(self):
        return int(self.price_inr) if self.price_inr == int(self.price_inr) else self.price_inr


class Subscription(models.Model):
    class Status(models.TextChoices):
        ACTIVE   = 'active',   'Active'
        CANCELED = 'canceled', 'Canceled'
        PAST_DUE = 'past_due', 'Past Due'
        TRIALING = 'trialing', 'Trialing'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='subscriptions')
    plan = models.ForeignKey(Plan, on_delete=models.PROTECT, related_name='subscriptions')
    status = models.CharField(max_length=15, choices=Status.choices, default=Status.ACTIVE)

    provider = models.CharField(
        max_length=20, blank=True,
        choices=[('paypal', 'PayPal'), ('razorpay', 'Razorpay'), ('upi', 'UPI (Manual)'), ('', 'Free / Manual')]
    )
    provider_subscription_id = models.CharField(max_length=150, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    current_period_end = models.DateTimeField(blank=True, null=True)
    canceled_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.user.username} — {self.plan.name} ({self.status})'
