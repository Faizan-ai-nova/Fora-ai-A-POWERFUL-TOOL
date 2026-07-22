from django.contrib import admin

from .models import AgentTest


@admin.register(AgentTest)
class AgentTestAdmin(admin.ModelAdmin):
    list_display = ('name', 'user', 'provider', 'model_name', 'status', 'passed', 'total_tokens', 'estimated_cost_usd', 'created_at')
    list_filter = ('provider', 'status', 'passed')
    search_fields = ('name', 'user__username', 'user__email', 'input_prompt')
    readonly_fields = ('id', 'created_at', 'completed_at')
