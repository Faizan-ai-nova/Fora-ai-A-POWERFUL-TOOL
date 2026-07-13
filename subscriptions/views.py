from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from .models import Plan


def pricing_view(request):
    plans = Plan.objects.filter(is_active=True)
    return render(request, 'subscriptions/pricing.html', {'plans': plans})


@login_required
def upgrade_view(request):
    """Shown when a free user runs out of scans - the 'beautiful upgrade page'."""
    plans = Plan.objects.filter(is_active=True).exclude(slug='free')
    return render(request, 'subscriptions/upgrade.html', {'plans': plans})
