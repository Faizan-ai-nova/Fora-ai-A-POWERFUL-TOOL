"""
Data migration — seeds the Free, Pro Monthly, and Pro Yearly plans.
Run once after initial migration. Safe to re-run (uses get_or_create).
"""
from django.db import migrations


def seed_plans(apps, schema_editor):
    Plan = apps.get_model('subscriptions', 'Plan')

    Plan.objects.get_or_create(
        slug='free',
        defaults=dict(
            name='Free',
            tagline='Get started with no commitment',
            price_monthly=0,
            price_inr=0,
            billing_period='free',
            scan_limit=10,
            is_unlimited=False,
            is_active=True,
            is_featured=False,
            order=0,
            features=[
                '10 scans (lifetime)',
                'Python, Django, JS, HTML, CSS',
                'OWASP Top 10 detection',
                'Secure code examples',
                'Dashboard & scan history',
            ],
        )
    )

    Plan.objects.get_or_create(
        slug='pro-monthly',
        defaults=dict(
            name='Pro — Monthly',
            tagline='Unlimited scans, billed monthly',
            price_monthly=2.49,       # ~$2.49 USD
            price_inr=199,            # ₹199/month
            billing_period='monthly',
            scan_limit=0,
            is_unlimited=True,
            is_active=True,
            is_featured=True,
            order=1,
            features=[
                'Unlimited scans',
                'All 5 languages supported',
                'OWASP Top 10 + CWE mapping',
                'AI-enhanced analysis (optional)',
                'PDF report export',
                'Priority support',
            ],
        )
    )

    Plan.objects.get_or_create(
        slug='pro-yearly',
        defaults=dict(
            name='Pro — Yearly',
            tagline='Unlimited scans, billed yearly — save 2 months',
            price_monthly=1.94,       # ₹2330/12 ≈ $1.94
            price_inr=2330,           # ₹2330/year
            billing_period='yearly',
            scan_limit=0,
            is_unlimited=True,
            is_active=True,
            is_featured=False,
            order=2,
            features=[
                'Everything in Pro Monthly',
                '2 months free vs monthly',
                'Early access to new features',
                'Dedicated support',
            ],
        )
    )


def unseed_plans(apps, schema_editor):
    Plan = apps.get_model('subscriptions', 'Plan')
    Plan.objects.filter(slug__in=['free', 'pro-monthly', 'pro-yearly']).delete()


class Migration(migrations.Migration):
    dependencies = [('subscriptions', '0001_initial')]
    operations = [migrations.RunPython(seed_plans, unseed_plans)]
