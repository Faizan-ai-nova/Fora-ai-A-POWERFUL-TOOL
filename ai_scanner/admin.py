from django.contrib import admin

from .models import AIScan, AITestResult


class AITestResultInline(admin.TabularInline):
    model = AITestResult
    extra = 0
    readonly_fields = ('category', 'test_name', 'passed', 'severity', 'response_time_ms', 'had_error')
    can_delete = False


@admin.register(AIScan)
class AIScanAdmin(admin.ModelAdmin):
    list_display = ('target_name', 'target_url', 'user', 'status', 'security_score', 'risk_level', 'created_at')
    list_filter = ('status', 'risk_level')
    search_fields = ('target_name', 'target_url', 'user__username')
    inlines = [AITestResultInline]


@admin.register(AITestResult)
class AITestResultAdmin(admin.ModelAdmin):
    list_display = ('scan', 'category', 'test_name', 'passed', 'severity')
    list_filter = ('category', 'passed', 'severity')
