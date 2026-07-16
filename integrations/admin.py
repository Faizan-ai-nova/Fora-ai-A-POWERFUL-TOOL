from django.contrib import admin

from .models import GithubRepo


@admin.register(GithubRepo)
class GithubRepoAdmin(admin.ModelAdmin):
    list_display = ('repo_full_name', 'user', 'default_branch', 'is_active', 'last_synced_at', 'created_at')
    list_filter = ('is_active', 'default_branch')
    search_fields = ('repo_full_name', 'user__username', 'user__email')
    readonly_fields = ('id', 'webhook_secret', 'github_webhook_id', 'created_at', 'last_synced_at')
