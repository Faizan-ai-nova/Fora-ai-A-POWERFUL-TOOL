import json

from django import forms

from .models import AIScan


class NewAIScanForm(forms.Form):
    target_name = forms.CharField(
        max_length=255, required=False,
        widget=forms.TextInput(attrs={'class': 'form-input', 'placeholder': 'e.g. Support Bot v2'})
    )
    target_type = forms.ChoiceField(
        # 'website' is deliberately excluded here: the scanner posts raw JSON
        # to the target URL and reads a JSON/text reply back. It can't drive
        # a browser-rendered chat widget, so offering "website" as a target
        # type overpromises. Keep the model choice (existing rows may still
        # have it) but stop offering it on new scans.
        choices=[c for c in AIScan.TargetType.choices if c[0] != AIScan.TargetType.WEBSITE],
        required=False, initial=AIScan.TargetType.AUTO,
        widget=forms.Select(attrs={'class': 'form-input'})
    )
    target_url = forms.URLField(
        max_length=500,
        widget=forms.URLInput(attrs={'class': 'form-input', 'placeholder': 'https://your-ai-agent.com/api/chat'})
    )
    model_name = forms.CharField(
        max_length=100, required=False,
        widget=forms.TextInput(attrs={'class': 'form-input', 'placeholder': 'e.g. gpt-4o-mini (optional)'})
    )
    request_field = forms.CharField(
        max_length=100, required=False,
        widget=forms.TextInput(attrs={'class': 'form-input', 'placeholder': 'message'})
    )
    response_path = forms.CharField(
        max_length=200, required=False,
        widget=forms.TextInput(attrs={'class': 'form-input', 'placeholder': 'response'})
    )
    auth_header = forms.CharField(
        max_length=500, required=False,
        widget=forms.TextInput(attrs={'class': 'form-input', 'placeholder': 'Bearer sk-... (optional)'})
    )
    api_key = forms.CharField(
        max_length=500, required=False,
        widget=forms.PasswordInput(render_value=False, attrs={'class': 'form-input', 'placeholder': 'API key (optional, encrypted at rest)', 'autocomplete': 'off'})
    )
    bearer_token = forms.CharField(
        max_length=1000, required=False,
        widget=forms.PasswordInput(render_value=False, attrs={'class': 'form-input', 'placeholder': 'Bearer token (optional, encrypted at rest)', 'autocomplete': 'off'})
    )
    custom_headers = forms.CharField(
        max_length=4000, required=False,
        widget=forms.Textarea(attrs={'class': 'form-input', 'rows': 3, 'placeholder': '{"X-Org-Id": "..."}  (optional JSON object)'})
    )
    request_body_template = forms.CharField(
        max_length=4000, required=False,
        widget=forms.Textarea(attrs={'class': 'form-input', 'rows': 3,
                                      'placeholder': '{"messages": [{"role": "user", "content": "{{prompt}}"}], "model": "{{model}}"}  (optional)'})
    )

    def clean_custom_headers(self):
        raw = self.cleaned_data.get('custom_headers', '').strip()
        if not raw:
            return {}
        try:
            data = json.loads(raw)
        except ValueError:
            raise forms.ValidationError('Custom headers must be valid JSON, e.g. {"X-Org-Id": "abc123"}')
        if not isinstance(data, dict):
            raise forms.ValidationError('Custom headers must be a JSON object of header-name/value pairs.')
        return data

    def clean_request_body_template(self):
        raw = self.cleaned_data.get('request_body_template', '').strip()
        if not raw:
            return ''
        probe = raw.replace('{{prompt}}', '""').replace('{{model}}', '""')
        try:
            json.loads(probe)
        except ValueError:
            raise forms.ValidationError('Request body template must be valid JSON once {{prompt}}/{{model}} are filled in.')
        return raw