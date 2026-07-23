from django.contrib import admin

from .models import AIScan, AITestResult


class AITestResultInline(admin.TabularInline):
    model = AITestResult
    extra = 0
    readonly_fields = ('category', 'owasp_llm_id', 'test_name', 'passed', 'severity', 'response_time_ms', 'had_error')
    can_delete = False


@admin.register(AIScan)
class AIScanAdmin(admin.ModelAdmin):
    # Encrypted credential fields (api_key_encrypted, bearer_token_encrypted,
    # custom_headers_encrypted) are intentionally never listed, searched, or
    # made editable here - they're write-only from every UI, admin included.
    list_display = ('target_name', 'target_url', 'target_type', 'user', 'status', 'security_score', 'security_grade', 'risk_level', 'created_at')
    list_filter = ('status', 'risk_level', 'target_type')
    search_fields = ('target_name', 'target_url', 'user__username')
    readonly_fields = (
        'id', 'created_at', 'completed_at', 'security_score', 'risk_level', 'jailbreak_score',
        'passed_count', 'failed_count', 'avg_response_time_ms', 'error_rate_pct',
        'recommendations', 'owasp_summary', 'target_format', 'error_message',
    )
    exclude = ('api_key_encrypted', 'bearer_token_encrypted', 'custom_headers_encrypted')
    inlines = [AITestResultInline]

    def security_grade(self, obj):
        return obj.security_grade
    security_grade.short_description = 'Grade'


@admin.register(AITestResult)
class AITestResultAdmin(admin.ModelAdmin):
    list_display = ('scan', 'category', 'test_name', 'passed', 'severity')
    list_filter = ('category', 'passed', 'severity')
