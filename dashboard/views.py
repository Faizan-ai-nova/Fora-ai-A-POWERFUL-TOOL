from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.db.models import Avg

from scanner.models import Scan


@login_required
def home_view(request):
    scans = Scan.objects.filter(user=request.user)
    recent_scans = scans[:5]

    total_scans = scans.count()
    avg_score = scans.aggregate(avg=Avg('security_score'))['avg'] or 100

    total_critical = sum(s.critical_count for s in scans)
    total_high = sum(s.high_count for s in scans)

    active_sub = request.user.subscriptions.filter(status='active').order_by('-created_at').first()

    context = {
        'recent_scans': recent_scans,
        'total_scans': total_scans,
        'avg_score': round(avg_score),
        'total_critical': total_critical,
        'total_high': total_high,
        'scans_remaining': request.user.scans_remaining,
        'active_subscription': active_sub,
    }
    return render(request, 'dashboard/dashboard.html', context)


def error_404(request, exception=None):
    return render(request, 'errors/404.html', status=404)


def error_500(request):
    return render(request, 'errors/500.html', status=500)
