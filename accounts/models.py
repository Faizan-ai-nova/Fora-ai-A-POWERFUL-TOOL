import uuid

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone


class User(AbstractUser):
    """
    Custom user model for Fora AI.

    Extends Django's AbstractUser with SaaS-specific fields:
    subscription tracking, scan quotas, and profile data.
    Keeping this on a custom user model (rather than a separate
    Profile model) makes it trivial to reference from every other
    app without extra joins.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)

    # Profile
    avatar = models.ImageField(upload_to='avatars/', blank=True, null=True)
    company = models.CharField(max_length=150, blank=True)
    job_title = models.CharField(max_length=150, blank=True)
    github_username = models.CharField(max_length=150, blank=True)
    bio = models.TextField(max_length=500, blank=True)

    # Plan / quota (denormalized for fast dashboard reads; source of truth
    # for billing lives in subscriptions.Subscription)
    scans_remaining = models.PositiveIntegerField(default=10)
    total_scans_used = models.PositiveIntegerField(default=0)

    # AI Agent Testing quota (Module 3) — same free-tier shape as scans,
    # kept as a separate counter since a person's plan may grant different
    # amounts of each.
    agent_tests_remaining = models.PositiveIntegerField(default=10)
    total_agent_tests_used = models.PositiveIntegerField(default=0)

    # Preferences - future ready for light/dark toggle & notifications
    dark_mode = models.BooleanField(default=True)
    email_notifications = models.BooleanField(default=True)

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.username

    @property
    def is_on_free_plan(self):
        active_sub = self.subscriptions.filter(status='active').exclude(plan__slug='free').first()
        return active_sub is None

    def can_scan(self):
        """Unlimited plans bypass the scans_remaining counter entirely."""
        active_sub = self.subscriptions.filter(status='active').order_by('-created_at').first()
        if active_sub and active_sub.plan.is_unlimited:
            return True
        return self.scans_remaining > 0

    def consume_scan(self):
        active_sub = self.subscriptions.filter(status='active').order_by('-created_at').first()
        if active_sub and active_sub.plan.is_unlimited:
            self.total_scans_used += 1
            self.save(update_fields=['total_scans_used'])
            return
        if self.scans_remaining > 0:
            self.scans_remaining -= 1
            self.total_scans_used += 1
            self.save(update_fields=['scans_remaining', 'total_scans_used'])

    def can_run_agent_test(self):
        """AI Engineering / Agent Testing (agentlab) is free forever for every
        user - it is never gated behind the scan quota or a paid plan."""
        return True

    def consume_agent_test(self):
        """Still tracked for stats/history, but never decremented - agent
        testing has no quota and can never become a paid feature."""
        self.total_agent_tests_used += 1
        self.save(update_fields=['total_agent_tests_used'])


class PasswordResetToken(models.Model):
    """
    Simple password-reset token model. Django ships with a token
    generator for this already, but a stored token lets us show
    reset history in the admin and expire tokens explicitly.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reset_tokens')
    token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    used = models.BooleanField(default=False)

    def is_valid(self):
        expiry = self.created_at + timezone.timedelta(hours=1)
        return not self.used and timezone.now() < expiry

    def __str__(self):
        return f'Reset token for {self.user.username}'
