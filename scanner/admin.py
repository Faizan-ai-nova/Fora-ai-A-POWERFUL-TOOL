from django.contrib import admin
from .models import Scan, ScannedFile, Issue, AIConfiguration


@admin.register(AIConfiguration)
class AIConfigurationAdmin(admin.ModelAdmin):
    list_display = ('active_provider', 'use_database_override', 'updated_at')
    fields = ('use_database_override', 'active_provider', 'notes', 'updated_at')
    readonly_fields = ('updated_at',)

    def has_add_permission(self, request):
        # Singleton - only one AI Settings row should ever exist
        return not AIConfiguration.objects.exists()


class IssueInline(admin.TabularInline):
    model = Issue
    extra = 0
    fields = ('title', 'severity', 'category', 'line_number')
    readonly_fields = ('title', 'severity', 'category', 'line_number')
    can_delete = False


class ScannedFileInline(admin.TabularInline):
    model = ScannedFile
    extra = 0
    fields = ('filename', 'language', 'lines_of_code')
    readonly_fields = ('filename', 'language', 'lines_of_code')
    can_delete = False


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ('project_name', 'user', 'source_type', 'status', 'security_score',
                     'total_issues', 'critical_count', 'high_count', 'created_at')
    list_filter = ('status', 'source_type', 'language', 'created_at')
    search_fields = ('project_name', 'user__username', 'user__email')
    readonly_fields = ('id', 'created_at', 'completed_at')
    inlines = [ScannedFileInline, IssueInline]
    date_hierarchy = 'created_at'


@admin.register(Issue)
class IssueAdmin(admin.ModelAdmin):
    list_display = ('title', 'scan', 'severity', 'category', 'line_number')
    list_filter = ('severity', 'category')
    search_fields = ('title', 'scan__project_name')
