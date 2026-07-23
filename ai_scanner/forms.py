from django import forms


class NewAIScanForm(forms.Form):
    target_name = forms.CharField(
        max_length=255, required=False,
        widget=forms.TextInput(attrs={'class': 'form-input', 'placeholder': 'e.g. Support Bot v2'})
    )
    target_url = forms.URLField(
        max_length=500,
        widget=forms.URLInput(attrs={'class': 'form-input', 'placeholder': 'https://your-ai-agent.com/api/chat'})
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
