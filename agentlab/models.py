import uuid

from django.conf import settings
from django.db import models
from django.urls import reverse


class AgentTest(models.Model):
    """
    A single manual AI-agent/model test run: one prompt sent to one model,
    with the response, latency, token usage, and estimated cost captured.

    This is the "Manual Test" slice of Module 3 (AI Agent Testing) — the
    foundation that Batch/CSV testing and Model Comparison will later build
    on top of, without needing to change this table's shape.
    """

    class Provider(models.TextChoices):
        GROQ = 'groq', 'Groq'
        OPENAI = 'openai', 'OpenAI'
        GEMINI = 'gemini', 'Google Gemini'
        CLAUDE = 'claude', 'Anthropic Claude'
        CUSTOM = 'custom', 'Custom / Other'

    class Status(models.TextChoices):
        PENDING = 'pending', 'Pending'
        RUNNING = 'running', 'Running'
        COMPLETED = 'completed', 'Completed'
        FAILED = 'failed', 'Failed'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='agent_tests')

    name = models.CharField(max_length=255, default='Untitled Test')
    provider = models.CharField(max_length=10, choices=Provider.choices, default=Provider.GROQ)
    model_name = models.CharField(max_length=100, blank=True, help_text='Overrides the provider default model if set')

    system_prompt = models.TextField(blank=True)
    input_prompt = models.TextField()
    expected_output = models.TextField(blank=True, help_text='Optional. If set, a simple pass/fail match is computed.')
    actual_output = models.TextField(blank=True)

    status = models.CharField(max_length=10, choices=Status.choices, default=Status.PENDING)
    passed = models.BooleanField(null=True, blank=True, help_text='Null when no expected_output was given')
    error_message = models.TextField(blank=True)

    latency_ms = models.PositiveIntegerField(default=0)
    prompt_tokens = models.PositiveIntegerField(default=0)
    completion_tokens = models.PositiveIntegerField(default=0)
    total_tokens = models.PositiveIntegerField(default=0)
    estimated_cost_usd = models.DecimalField(max_digits=10, decimal_places=6, default=0)

    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.name} ({self.get_provider_display()})'

    def get_absolute_url(self):
        return reverse('agentlab:detail', kwargs={'test_id': self.id})

    @property
    def status_badge_class(self):
        if self.status == 'completed':
            return 'critical' if self.passed is False else 'success'
        if self.status == 'failed':
            return 'critical'
        if self.status == 'running':
            return 'medium'
        return 'info'
