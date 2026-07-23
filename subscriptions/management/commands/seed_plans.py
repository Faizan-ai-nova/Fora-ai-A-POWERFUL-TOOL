from django.core.management.base import BaseCommand

from subscriptions.models import Plan


class Command(BaseCommand):
    help = 'Seed the default Free and Basic subscription plans.'

    def handle(self, *args, **options):
        plans = [
            {
                'slug': 'free',
                'name': 'Free',
                'tagline': 'Try Fora AI on your own code',
                'price_monthly': 0,
                'scan_limit': 10,
                'is_unlimited': False,
                'is_featured': False,
                'order': 0,
                'features': [
                    '10 AI security scans',
                    'Paste & file scanning',
                    'Security score & severity breakdown',
                    'Fix recommendations for every issue',
                ],
            },
            {
                'slug': 'basic',
                'name': 'Basic',
                'tagline': 'For developers shipping continuously',
                'price_monthly': 19,
                'scan_limit': 0,
                'is_unlimited': True,
                'is_featured': True,
                'order': 1,
                'features': [
                    'Unlimited AI security scans',
                    'Paste & file scanning',
                    'Full scan history & reports',
                    'Priority support',
                ],
            },
        ]

        for data in plans:
            plan, created = Plan.objects.update_or_create(slug=data['slug'], defaults=data)
            status = 'Created' if created else 'Updated'
            self.stdout.write(self.style.SUCCESS(f'{status} plan: {plan.name}'))
