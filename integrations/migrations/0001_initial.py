import secrets
import uuid

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('scanner', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='GithubRepo',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('repo_full_name', models.CharField(help_text='e.g. octocat/hello-world', max_length=255)),
                ('access_token', models.CharField(help_text='GitHub Personal Access Token (repo + admin:repo_hook scope)', max_length=255)),
                ('default_branch', models.CharField(default='main', max_length=100)),
                ('github_webhook_id', models.CharField(blank=True, max_length=50)),
                ('webhook_secret', models.CharField(default=secrets.token_hex, editable=False, max_length=64)),
                ('is_active', models.BooleanField(default=True)),
                ('last_push_sha', models.CharField(blank=True, max_length=40)),
                ('last_synced_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('last_scan', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to='scanner.scan')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='github_repos', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-created_at'],
                'unique_together': {('user', 'repo_full_name')},
            },
        ),
    ]
