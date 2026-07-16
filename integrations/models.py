import secrets
import uuid

from django.conf import settings
from django.db import models


class GithubRepo(models.Model):
    """A GitHub repo connected for automatic scan-on-push."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='github_repos'
    )

    repo_full_name = models.CharField(max_length=255, help_text='e.g. octocat/hello-world')
    access_token = models.CharField(max_length=255, help_text='GitHub Personal Access Token (repo + admin:repo_hook scope)')
    default_branch = models.CharField(max_length=100, default='main')

    github_webhook_id = models.CharField(max_length=50, blank=True)
    webhook_secret = models.CharField(max_length=64, default=secrets.token_hex, editable=False)

    is_active = models.BooleanField(default=True)

    last_scan = models.ForeignKey(
        'scanner.Scan', on_delete=models.SET_NULL, null=True, blank=True, related_name='+'
    )
    last_push_sha = models.CharField(max_length=40, blank=True)
    last_synced_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        unique_together = ('user', 'repo_full_name')

    def __str__(self):
        return self.repo_full_name

    @property
    def masked_token(self):
        if len(self.access_token) <= 4:
            return '••••'
        return f'••••••••{self.access_token[-4:]}'
