from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Plan',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('slug', models.SlugField(unique=True)),
                ('name', models.CharField(max_length=100)),
                ('tagline', models.CharField(blank=True, max_length=255)),
                ('price_monthly', models.DecimalField(decimal_places=2, default=0, max_digits=8)),
                ('price_inr', models.DecimalField(decimal_places=2, default=0, max_digits=10, help_text='Price in INR for Razorpay')),
                ('billing_period', models.CharField(choices=[('monthly', 'Monthly'), ('yearly', 'Yearly'), ('free', 'Free')], default='monthly', max_length=10)),
                ('scan_limit', models.PositiveIntegerField(default=6)),
                ('is_unlimited', models.BooleanField(default=False)),
                ('features', models.JSONField(blank=True, default=list)),
                ('is_active', models.BooleanField(default=True)),
                ('is_featured', models.BooleanField(default=False)),
                ('order', models.PositiveSmallIntegerField(default=0)),
                ('paypal_plan_id', models.CharField(blank=True, max_length=100)),
                ('razorpay_plan_id', models.CharField(blank=True, max_length=100)),
            ],
            options={'ordering': ['order', 'price_inr']},
        ),
        migrations.CreateModel(
            name='Subscription',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('status', models.CharField(choices=[('active', 'Active'), ('canceled', 'Canceled'), ('past_due', 'Past Due'), ('trialing', 'Trialing')], default='active', max_length=15)),
                ('provider', models.CharField(blank=True, choices=[('paypal', 'PayPal'), ('razorpay', 'Razorpay'), ('', 'Free / Manual')], max_length=20)),
                ('provider_subscription_id', models.CharField(blank=True, max_length=150)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('current_period_end', models.DateTimeField(blank=True, null=True)),
                ('canceled_at', models.DateTimeField(blank=True, null=True)),
                ('plan', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='subscriptions', to='subscriptions.plan')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='subscriptions', to=settings.AUTH_USER_MODEL)),
            ],
            options={'ordering': ['-created_at']},
        ),
    ]
