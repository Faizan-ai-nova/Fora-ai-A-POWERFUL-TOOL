from django.contrib import admin
from .models import Plan, Subscription


@admin.register(Plan)
class PlanAdmin(admin.ModelAdmin):
    list_display = ('name', 'slug', 'price_monthly', 'scan_limit', 'is_unlimited', 'is_active', 'is_featured', 'order')
    list_editable = ('price_monthly', 'is_active', 'is_featured', 'order')
    prepopulated_fields = {'slug': ('name',)}


@admin.register(Subscription)
class SubscriptionAdmin(admin.ModelAdmin):
    list_display = ('user', 'plan', 'status', 'provider', 'created_at', 'current_period_end')
    list_filter = ('status', 'provider', 'plan')
    search_fields = ('user__username', 'user__email')
