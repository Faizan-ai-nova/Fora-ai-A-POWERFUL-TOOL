from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, PasswordResetToken

admin.site.site_header = 'Fora AI Admin'
admin.site.site_title = 'Fora AI Admin'
admin.site.index_title = 'Platform Management'


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ('username', 'email', 'scans_remaining', 'total_scans_used', 'is_staff', 'is_active', 'created_at')
    list_filter = ('is_staff', 'is_active', 'created_at')
    search_fields = ('username', 'email', 'company')
    ordering = ('-created_at',)
    fieldsets = BaseUserAdmin.fieldsets + (
        ('Fora AI Profile', {
            'fields': ('avatar', 'company', 'job_title', 'github_username', 'bio')
        }),
        ('Scan Quota', {
            'fields': ('scans_remaining', 'total_scans_used')
        }),
        ('Preferences', {
            'fields': ('dark_mode', 'email_notifications')
        }),
    )


@admin.register(PasswordResetToken)
class PasswordResetTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'token', 'created_at', 'used')
    list_filter = ('used',)
    search_fields = ('user__username', 'user__email')
