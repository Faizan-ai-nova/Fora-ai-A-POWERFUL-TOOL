import uuid

from django.conf import settings
from django.db import models
from django.urls import reverse


class AIScan(models.Model):
    """A single AI Security Scanner job: one target chatbot/agent URL, one run."""

    class Status(models.TextChoices):
        PENDING = 'pending', 'Pending'
        RUNNING = 'running', 'Running'
        COMPLETED = 'completed', 'Completed'
        FAILED = 'failed', 'Failed'

    class RiskLevel(models.TextChoices):
        LOW = 'low', 'Low'
        MEDIUM = 'medium', 'Medium'
        HIGH = 'high', 'High'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='ai_scans')

    target_name = models.CharField(max_length=255, default='Untitled AI')
    target_url = models.URLField(max_length=500)

    # How to talk to the target's chat API - kept simple for the MVP but
    # flexible enough to cover most JSON chat endpoints without a custom
    # integration per user.
    request_field = models.CharField(
        max_length=100, default='message',
        help_text="JSON field name the target endpoint expects for the user message"
    )
    response_path = models.CharField(
        max_length=200, default='response',
        help_text="Dot-path to the reply text inside the target's JSON response, e.g. 'data.reply'"
    )
    auth_header = models.CharField(
        max_length=500, blank=True,
        help_text='Optional Authorization header value sent with every test request'
    )

    status = models.CharField(max_length=10, choices=Status.choices, default=Status.PENDING)
    current_step = models.PositiveSmallIntegerField(default=0)
    total_steps = models.PositiveSmallIntegerField(default=0)
    current_step_label = models.CharField(max_length=255, blank=True)

    security_score = models.PositiveSmallIntegerField(default=100)
    risk_level = models.CharField(max_length=10, choices=RiskLevel.choices, default=RiskLevel.LOW)
    jailbreak_score = models.PositiveSmallIntegerField(default=100)

    passed_count = models.PositiveIntegerField(default=0)
    failed_count = models.PositiveIntegerField(default=0)

    avg_response_time_ms = models.PositiveIntegerField(default=0)
    error_rate_pct = models.FloatField(default=0)

    recommendations = models.JSONField(default=list, blank=True)
    error_message = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.target_name} ({self.get_status_display()})'

    def get_absolute_url(self):
        return reverse('ai_scanner:report', kwargs={'scan_id': self.id})

    @property
    def risk_emoji(self):
        return {'low': '🟢', 'medium': '🟡', 'high': '🔴'}.get(self.risk_level, '🟢')

    @property
    def score_color(self):
        if self.security_score >= 90:
            return 'success'
        if self.security_score >= 70:
            return 'info'
        if self.security_score >= 50:
            return 'warning'
        return 'danger'

    @property
    def risk_badge_class(self):
        return {'low': 'badge-success', 'medium': 'badge-medium', 'high': 'badge-critical'}.get(self.risk_level, 'badge-success')

    @property
    def progress_pct(self):
        if not self.total_steps:
            return 0
        return int((self.current_step / self.total_steps) * 100)


class AITestResult(models.Model):
    """A single security test executed against an AIScan's target."""

    class Category(models.TextChoices):
        PROMPT_INJECTION = 'prompt_injection', 'Prompt Injection'
        JAILBREAK = 'jailbreak', 'Jailbreak'
        PROMPT_LEAK = 'prompt_leak', 'Prompt Leak'
        SENSITIVE_DATA = 'sensitive_data', 'Sensitive Data Leak'
        HARMFUL_CONTENT = 'harmful_content', 'Harmful Content'
        RESPONSE_QUALITY = 'response_quality', 'Response Quality'

    scan = models.ForeignKey(AIScan, on_delete=models.CASCADE, related_name='test_results')
    category = models.CharField(max_length=30, choices=Category.choices)
    test_name = models.CharField(max_length=255)
    prompt_sent = models.TextField()
    response_snippet = models.TextField(blank=True)
    passed = models.BooleanField(default=True)
    severity = models.CharField(max_length=10, default='low')
    detail = models.TextField(blank=True)
    response_time_ms = models.PositiveIntegerField(default=0)
    had_error = models.BooleanField(default=False)

    class Meta:
        ordering = ['category', 'id']

    def __str__(self):
        return f'{self.test_name} - {"PASS" if self.passed else "FAIL"}'

    @property
    def badge_class(self):
        return 'badge-success' if self.passed else 'badge-critical'

    @property
    def category_icon(self):
        return {
            'prompt_injection': '🧩',
            'jailbreak': '🔓',
            'prompt_leak': '📄',
            'sensitive_data': '🔑',
            'harmful_content': '☣️',
            'response_quality': '⚡',
        }.get(self.category, '🔍')
