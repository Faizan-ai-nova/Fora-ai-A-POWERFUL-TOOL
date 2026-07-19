import re

from django import forms


class ConnectRepoForm(forms.Form):
    repo_full_name = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs={'class': 'form-input', 'placeholder': 'e.g. Faizz/hello-user'}),
        label='Repository (owner/repo)',
    )
    access_token = forms.CharField(
        max_length=255,
        widget=forms.PasswordInput(attrs={'class': 'form-input', 'placeholder': 'ghp_xxxxxxxxxxxxxxxxxxxx'}, render_value=False),
        label='GitHub Personal Access Token',
        help_text='Needs "repo" and "admin:repo_hook" scopes. We only use it to read this repo and manage its webhook.',
    )

    def clean_repo_full_name(self):
        value = self.cleaned_data['repo_full_name'].strip().strip('/')
        if not re.match(r'^[\w.-]+/[\w.-]+$', value):
            raise forms.ValidationError('Enter the repo as "owner/repo", e.g. octocat/hello-world.')
        return value

    def clean_access_token(self):
        value = self.cleaned_data['access_token'].strip()
        if len(value) < 10:
            raise forms.ValidationError('That doesn\'t look like a valid GitHub token.')
        return value
