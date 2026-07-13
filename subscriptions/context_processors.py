def subscription_context(request):
    """Makes the user's current plan/scan quota available in every template
    (navbar badges, sidebar, upgrade banners) without repeating queries in
    every view."""
    if not request.user.is_authenticated:
        return {}

    active_sub = request.user.subscriptions.filter(status='active').order_by('-created_at').first()
    return {
        'current_plan': active_sub.plan if active_sub else None,
        'current_subscription': active_sub,
        'scans_remaining': request.user.scans_remaining,
    }
