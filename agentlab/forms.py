from django import forms

# Curated models across 3 providers, grouped so the person picks a model
# directly instead of juggling a separate provider dropdown. Provider is
# derived from whichever model is selected (see MODEL_PROVIDER_MAP).
#
# None of these are configured server-side - every model here needs the
# person's own API key, entered in the "Your API key" field below. For any
# other model/provider, use "Custom" and bring your own endpoint + key.
MODEL_CHOICES = [
    ('Google Gemini — needs your own API key', [
        ('gemini-1.5-flash', 'Gemini 1.5 Flash'),
    ]),
    ('Anthropic Claude — needs your own API key', [
        ('claude-sonnet-4-6', 'Claude Sonnet'),
        ('claude-haiku-4-5-20251001', 'Claude Haiku'),
    ]),
    ('ChatGPT (OpenAI) — needs your own API key', [
        ('gpt-4o', 'GPT-4o'),
        ('gpt-4o-mini', 'GPT-4o mini'),
    ]),
    ('Custom — bring any model', [
        ('custom', '🔧 Custom model (any provider, your own API key)'),
    ]),
]

# Flat lookup used by the view to figure out which provider a chosen preset
# model belongs to, so the person doesn't have to pick provider + model
# separately. 'custom' is intentionally absent — its provider is decided by
# custom_provider_type at submit time.
MODEL_PROVIDER_MAP = {
    'gemini-1.5-flash': 'gemini',
    'claude-sonnet-4-6': 'claude',
    'claude-haiku-4-5-20251001': 'claude',
    'gpt-4o': 'openai',
    'gpt-4o-mini': 'openai',
}

CUSTOM_PROVIDER_TYPE_CHOICES = [
    ('openai_compatible', 'OpenAI-compatible (Groq, Together, OpenRouter, Fireworks, self-hosted vLLM, etc.)'),
    ('claude', 'Anthropic Messages API shape'),
    ('gemini', 'Google Gemini generateContent shape'),
]


class AgentTestForm(forms.Form):
    name = forms.CharField(
        max_length=255, required=False,
        widget=forms.TextInput(attrs={'class': 'form-input', 'placeholder': 'e.g. Refund policy Q&A'})
    )
    model_name = forms.ChoiceField(
        choices=MODEL_CHOICES,
        widget=forms.Select(attrs={'class': 'form-input'})
    )
    api_key = forms.CharField(
        required=False,
        widget=forms.PasswordInput(render_value=False, attrs={
            'class': 'form-input', 'placeholder': 'Your API key for the selected model', 'autocomplete': 'off',
        })
    )

    # Only used when model_name == 'custom'
    custom_provider_type = forms.ChoiceField(
        choices=CUSTOM_PROVIDER_TYPE_CHOICES, required=False,
        widget=forms.Select(attrs={'class': 'form-input'})
    )
    custom_model_name = forms.CharField(
        max_length=200, required=False,
        widget=forms.TextInput(attrs={'class': 'form-input', 'placeholder': 'Exact model ID, e.g. meta-llama/Llama-3-70b-chat-hf'})
    )
    custom_api_base = forms.CharField(
        max_length=300, required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': 'Only for OpenAI-compatible — full chat/completions URL, e.g. https://api.together.xyz/v1/chat/completions',
        })
    )

    system_prompt = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={'class': 'form-input code-textarea', 'rows': 6, 'placeholder': 'Optional system / agent instructions'})
    )
    input_prompt = forms.CharField(
        widget=forms.Textarea(attrs={'class': 'form-input code-textarea', 'rows': 6, 'placeholder': 'The message/test input to send'})
    )
    expected_output = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={'class': 'form-input code-textarea', 'rows': 4, 'placeholder': 'Optional — if set, we check the reply contains this'})
    )

    def clean(self):
        cleaned = super().clean()
        if cleaned.get('model_name') == 'custom':
            if not cleaned.get('custom_model_name', '').strip():
                self.add_error('custom_model_name', 'Enter the exact model ID for your custom model.')
            if not cleaned.get('api_key', '').strip():
                self.add_error('api_key', 'A custom model needs an API key.')
            provider_type = cleaned.get('custom_provider_type')
            if provider_type == 'openai_compatible' and not cleaned.get('custom_api_base', '').strip():
                self.add_error('custom_api_base', 'Enter the full chat/completions endpoint URL for this custom model.')
        return cleaned
