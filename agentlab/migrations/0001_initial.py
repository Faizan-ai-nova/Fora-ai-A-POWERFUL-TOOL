# Generated for Fora AI — AI Agent Testing (Module 3)

import uuid

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AgentTest',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('name', models.CharField(default='Untitled Test', max_length=255)),
                ('provider', models.CharField(choices=[('groq', 'Groq'), ('openai', 'OpenAI'), ('gemini', 'Google Gemini'), ('claude', 'Anthropic Claude')], default='groq', max_length=10)),
                ('model_name', models.CharField(blank=True, help_text='Overrides the provider default model if set', max_length=100)),
                ('system_prompt', models.TextField(blank=True)),
                ('input_prompt', models.TextField()),
                ('expected_output', models.TextField(blank=True, help_text='Optional. If set, a simple pass/fail match is computed.')),
                ('actual_output', models.TextField(blank=True)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('running', 'Running'), ('completed', 'Completed'), ('failed', 'Failed')], default='pending', max_length=10)),
                ('passed', models.BooleanField(blank=True, help_text='Null when no expected_output was given', null=True)),
                ('error_message', models.TextField(blank=True)),
                ('latency_ms', models.PositiveIntegerField(default=0)),
                ('prompt_tokens', models.PositiveIntegerField(default=0)),
                ('completion_tokens', models.PositiveIntegerField(default=0)),
                ('total_tokens', models.PositiveIntegerField(default=0)),
                ('estimated_cost_usd', models.DecimalField(decimal_places=6, default=0, max_digits=10)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='agent_tests', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
    ]
