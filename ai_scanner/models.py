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
    # Stores an *encrypted* Authorization header value (legacy single-field
    # credential, kept for backward compatibility - prefer api_key/
    # bearer_token for new scans). See set_auth_header/get_auth_header.
    auth_header = models.TextField(
        blank=True,
        help_text='Optional Authorization header value sent with every test request (encrypted at rest)'
    )

    class TargetFormat(models.TextChoices):
        UNKNOWN = 'unknown', 'Unknown'
        OPENAI_COMPATIBLE = 'openai_compatible', 'OpenAI-compatible chat completions'
        CUSTOM_JSON_CHAT = 'custom_json_chat', 'Custom JSON chat endpoint'
        PLAIN_TEXT_CHAT = 'plain_text_chat', 'Plain-text chat endpoint'

    class TargetType(models.TextChoices):
        AUTO = 'auto', 'Auto-detect'
        WEBSITE = 'website', 'Public AI website / chat interface'
        API_ENDPOINT = 'api_endpoint', 'AI API endpoint'
        AGENT = 'agent', 'Custom AI agent'
        RAG = 'rag', 'RAG application'
        SAAS = 'saas', 'AI SaaS product'

    # --- What kind of target this is, and how to reach it -----------------
    target_type = models.CharField(
        max_length=20, choices=TargetType.choices, default=TargetType.AUTO,
        help_text='What kind of AI target this is. Auto-detect picks the right test profile from the pre-flight probe.'
    )
    model_name = models.CharField(
        max_length=100, blank=True,
        help_text='Optional model identifier to send with each request (e.g. gpt-4o-mini), for API endpoints that require one.'
    )
    request_body_template = models.TextField(
        blank=True,
        help_text='Optional custom JSON request body. Use {{prompt}} where the test prompt should go and, '
                   'optionally, {{model}} for model_name. Leave blank to use request_field/response_path instead.'
    )

    # --- Credentials, stored encrypted at rest, decrypted only in-memory --
    # for the duration of a scan run. Never logged, never rendered back,
    # never included in any report/export. See engine/secret_store.py.
    api_key_encrypted = models.TextField(blank=True)
    bearer_token_encrypted = models.TextField(blank=True)
    custom_headers_encrypted = models.TextField(
        blank=True, help_text='Encrypted JSON blob of extra headers, e.g. {"X-Org-Id": "..."}'
    )

    status = models.CharField(max_length=10, choices=Status.choices, default=Status.PENDING)
    target_format = models.CharField(
        max_length=20, choices=TargetFormat.choices, default=TargetFormat.UNKNOWN,
        help_text='What the pre-flight probe detected the target endpoint to be.'
    )
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
    owasp_summary = models.JSONField(
        default=list, blank=True,
        help_text='Precomputed OWASP LLM Top 10 mapping table for this scan (see engine.scoring.build_owasp_summary).'
    )
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

    @property
    def security_grade(self):
        """Letter grade A+ to F derived from security_score, for report headlines."""
        s = self.security_score
        if s >= 97:
            return 'A+'
        if s >= 93:
            return 'A'
        if s >= 90:
            return 'A-'
        if s >= 87:
            return 'B+'
        if s >= 83:
            return 'B'
        if s >= 80:
            return 'B-'
        if s >= 77:
            return 'C+'
        if s >= 73:
            return 'C'
        if s >= 70:
            return 'C-'
        if s >= 60:
            return 'D'
        return 'F'

    # --- Credential helpers -------------------------------------------------
    # Set* methods encrypt before storing; get* methods decrypt only for the
    # duration of a scan run (engine/target_client.py). Never call the get*
    # methods from a view/template/report - credentials are write-only from
    # the user's point of view.
    def set_auth_header(self, value: str):
        from .engine.secret_store import encrypt
        self.auth_header = encrypt(value or '')

    def get_auth_header(self) -> str:
        from .engine.secret_store import decrypt
        return decrypt(self.auth_header)

    def set_api_key(self, value: str):
        from .engine.secret_store import encrypt
        self.api_key_encrypted = encrypt(value or '')

    def get_api_key(self) -> str:
        from .engine.secret_store import decrypt
        return decrypt(self.api_key_encrypted)

    def set_bearer_token(self, value: str):
        from .engine.secret_store import encrypt
        self.bearer_token_encrypted = encrypt(value or '')

    def get_bearer_token(self) -> str:
        from .engine.secret_store import decrypt
        return decrypt(self.bearer_token_encrypted)

    def set_custom_headers(self, headers_dict: dict):
        import json as _json
        from .engine.secret_store import encrypt
        self.custom_headers_encrypted = encrypt(_json.dumps(headers_dict or {}))

    def get_custom_headers(self) -> dict:
        import json as _json
        from .engine.secret_store import decrypt
        raw = decrypt(self.custom_headers_encrypted)
        if not raw:
            return {}
        try:
            data = _json.loads(raw)
            return data if isinstance(data, dict) else {}
        except ValueError:
            return {}

    @property
    def has_credentials(self) -> bool:
        """For display only - tells the UI a credential is configured, without exposing it."""
        return bool(self.api_key_encrypted or self.bearer_token_encrypted or self.auth_header)


class AITestResult(models.Model):
    """A single security test executed against an AIScan's target."""

    class Category(models.TextChoices):
        PROMPT_INJECTION = 'prompt_injection', 'Prompt Injection'
        JAILBREAK = 'jailbreak', 'Jailbreak'
        PROMPT_LEAK = 'prompt_leak', 'System Prompt Leakage'
        SENSITIVE_DATA = 'sensitive_data', 'Sensitive Data Leakage'
        HARMFUL_CONTENT = 'harmful_content', 'Harmful Content Generation'
        MULTI_TURN = 'multi_turn', 'Multi-turn Attack'
        TOOL_ABUSE = 'tool_abuse', 'Tool / Function Calling Abuse'
        RAG_SECURITY = 'rag_security', 'RAG Security'
        RESPONSE_CONSISTENCY = 'response_consistency', 'Response Consistency'
        CONTEXT_INJECTION = 'context_injection', 'Context Injection'
        ENCODING_ATTACK = 'encoding_attack', 'Encoding & Translation Attack'
        INDIRECT_INJECTION = 'indirect_injection', 'Indirect Prompt Injection'
        HIDDEN_INSTRUCTION = 'hidden_instruction', 'Hidden Instruction Attack'
        AGENT_MANIPULATION = 'agent_manipulation', 'Agent Manipulation'
        API_MISUSE = 'api_misuse', 'API Misuse / Parameter Manipulation'
        UNAUTHORIZED_EXPOSURE = 'unauthorized_exposure', 'Unauthorized Data Exposure'
        MEMORY_LEAKAGE = 'memory_leakage', 'Memory Leakage'
        ALIGNMENT = 'alignment', 'AI Safety & Alignment'
        RESPONSE_QUALITY = 'response_quality', 'Response Quality'

    scan = models.ForeignKey(AIScan, on_delete=models.CASCADE, related_name='test_results')
    category = models.CharField(max_length=30, choices=Category.choices)
    owasp_llm_id = models.CharField(
        max_length=10, blank=True,
        help_text='OWASP LLM Top 10 mapping, e.g. LLM01, LLM06 (blank for tests outside that framework)'
    )
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
            'multi_turn': '🔁',
            'tool_abuse': '🛠️',
            'rag_security': '📚',
            'response_consistency': '🔄',
            'context_injection': '🧬',
            'encoding_attack': '🔡',
            'indirect_injection': '🕵️',
            'hidden_instruction': '🫥',
            'agent_manipulation': '🤖',
            'api_misuse': '⚙️',
            'unauthorized_exposure': '📤',
            'memory_leakage': '🧠',
            'alignment': '🧭',
            'response_quality': '⚡',
        }.get(self.category, '🔍')
