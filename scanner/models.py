import uuid

from django.conf import settings
from django.db import models
from django.urls import reverse


class Scan(models.Model):
    """A single security-scan job: one paste, one file, or one ZIP upload."""

    class SourceType(models.TextChoices):
        PASTE = 'paste', 'Pasted Code'
        FILE = 'file', 'Uploaded File'
        ZIP = 'zip', 'ZIP Project'

    class Status(models.TextChoices):
        PENDING = 'pending', 'Pending'
        RUNNING = 'running', 'Running'
        COMPLETED = 'completed', 'Completed'
        FAILED = 'failed', 'Failed'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='scans')

    project_name = models.CharField(max_length=255, default='Untitled Scan')
    source_type = models.CharField(max_length=10, choices=SourceType.choices, default=SourceType.PASTE)
    language = models.CharField(max_length=30, blank=True, help_text='Detected primary language')

    uploaded_file = models.FileField(upload_to='uploads/%Y/%m/', blank=True, null=True)
    raw_code = models.TextField(blank=True)

    status = models.CharField(max_length=10, choices=Status.choices, default=Status.PENDING)

    # Opt-in toggle: when True, /scanner/badge/<id>.svg is publicly viewable
    # (no login required) so the score can be embedded in a GitHub README or
    # website. Off by default — a scan's score shouldn't be discoverable by
    # anyone who guesses/finds the UUID unless the owner explicitly shares it.
    is_public_badge = models.BooleanField(default=False)

    # Results summary (denormalized for fast dashboard queries)
    security_score = models.PositiveSmallIntegerField(default=100)
    total_issues = models.PositiveIntegerField(default=0)
    critical_count = models.PositiveIntegerField(default=0)
    high_count = models.PositiveIntegerField(default=0)
    medium_count = models.PositiveIntegerField(default=0)
    low_count = models.PositiveIntegerField(default=0)
    info_count = models.PositiveIntegerField(default=0)

    ai_provider_used = models.CharField(max_length=30, default='mock')
    error_message = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.project_name} ({self.get_status_display()})'

    def get_absolute_url(self):
        return reverse('reports:detail', kwargs={'scan_id': self.id})

    @property
    def score_grade(self):
        if self.security_score >= 90:
            return 'A'
        if self.security_score >= 75:
            return 'B'
        if self.security_score >= 50:
            return 'C'
        if self.security_score >= 25:
            return 'D'
        return 'F'

    @property
    def score_color(self):
        if self.security_score >= 90:
            return 'success'
        if self.security_score >= 75:
            return 'info'
        if self.security_score >= 50:
            return 'warning'
        return 'danger'


class ScannedFile(models.Model):
    """Individual file scanned within a Scan (relevant for ZIP project uploads)."""
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='files')
    filename = models.CharField(max_length=500)
    language = models.CharField(max_length=30, blank=True)
    lines_of_code = models.PositiveIntegerField(default=0)

    def __str__(self):
        return self.filename


class AIConfiguration(models.Model):
    """
    Singleton row admins use to control the AI scanning backend from the
    Django admin instead of only via environment variables. If no row
    exists, or use_database_override is False, the analyzer falls back to
    the AI_PROVIDER env var in settings.py.
    """

    PROVIDER_CHOICES = [
        ('mock', 'Rule Engine Only (no AI key required)'),
        ('openai', 'OpenAI'),
        ('gemini', 'Google Gemini'),
        ('claude', 'Anthropic Claude'),
        ('groq', 'Groq'),
    ]

    use_database_override = models.BooleanField(
        default=False,
        help_text='If enabled, the provider selected here overrides the AI_PROVIDER environment variable.'
    )
    active_provider = models.CharField(max_length=20, choices=PROVIDER_CHOICES, default='mock')
    notes = models.TextField(
        blank=True,
        help_text='Internal notes, e.g. rate-limit reminders or which API key is currently active.'
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'AI Settings'
        verbose_name_plural = 'AI Settings'

    def __str__(self):
        return f'AI Settings ({self.get_active_provider_display()})'

    def save(self, *args, **kwargs):
        self.pk = 1  # enforce singleton
        super().save(*args, **kwargs)

    @classmethod
    def get_solo(cls):
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj


class Issue(models.Model):
    """A single detected vulnerability / security issue within a scan."""

    class Severity(models.TextChoices):
        CRITICAL = 'critical', 'Critical'
        HIGH = 'high', 'High'
        MEDIUM = 'medium', 'Medium'
        LOW = 'low', 'Low'
        INFO = 'info', 'Informational'

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='issues')
    file = models.ForeignKey(ScannedFile, on_delete=models.CASCADE, related_name='issues', blank=True, null=True)

    title = models.CharField(max_length=255)
    category = models.CharField(max_length=100, help_text='e.g. SQL Injection, XSS, CSRF')
    severity = models.CharField(max_length=10, choices=Severity.choices)
    owasp_reference = models.CharField(max_length=100, blank=True)
    cwe_reference = models.CharField(max_length=100, blank=True)

    description = models.TextField()
    why_dangerous = models.TextField()
    recommended_fix = models.TextField()
    secure_code_example = models.TextField(blank=True)

    line_number = models.PositiveIntegerField(blank=True, null=True)
    code_snippet = models.TextField(blank=True)

    class Meta:
        ordering = ['severity', 'title']

    def __str__(self):
        return f'[{self.get_severity_display()}] {self.title}'

    SEVERITY_WEIGHT = {
        'critical': 40,
        'high': 20,
        'medium': 10,
        'low': 4,
        'info': 1,
    }

    @property
    def score_weight(self):
        return self.SEVERITY_WEIGHT.get(self.severity, 0)

    @property
    def severity_badge_class(self):
        return {
            'critical': 'badge-critical',
            'high': 'badge-high',
            'medium': 'badge-medium',
            'low': 'badge-low',
            'info': 'badge-info',
        }.get(self.severity, 'badge-info')
