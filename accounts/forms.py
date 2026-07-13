from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.core.exceptions import ValidationError

from .models import User


class RegisterForm(UserCreationForm):
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={'placeholder': 'you@example.com', 'class': 'form-input'})
    )
    username = forms.CharField(
        widget=forms.TextInput(attrs={'placeholder': 'yourusername', 'class': 'form-input'})
    )

    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['password1'].widget.attrs.update({'placeholder': '••••••••', 'class': 'form-input'})
        self.fields['password2'].widget.attrs.update({'placeholder': '••••••••', 'class': 'form-input'})

    def clean_email(self):
        email = self.cleaned_data['email'].lower().strip()
        if User.objects.filter(email=email).exists():
            raise ValidationError('An account with this email already exists.')
        return email


class LoginForm(forms.Form):
    username = forms.CharField(
        widget=forms.TextInput(attrs={'placeholder': 'Username or email', 'class': 'form-input', 'autofocus': True})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': '••••••••', 'class': 'form-input'})
    )
    remember_me = forms.BooleanField(required=False, initial=True)


class ForgotPasswordForm(forms.Form):
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={'placeholder': 'you@example.com', 'class': 'form-input'})
    )


class SetNewPasswordForm(forms.Form):
    password1 = forms.CharField(
        label='New password',
        widget=forms.PasswordInput(attrs={'placeholder': '••••••••', 'class': 'form-input'})
    )
    password2 = forms.CharField(
        label='Confirm new password',
        widget=forms.PasswordInput(attrs={'placeholder': '••••••••', 'class': 'form-input'})
    )

    def clean(self):
        cleaned = super().clean()
        p1, p2 = cleaned.get('password1'), cleaned.get('password2')
        if p1 and p2 and p1 != p2:
            raise ValidationError("Passwords don't match.")
        if p1 and len(p1) < 8:
            raise ValidationError('Password must be at least 8 characters.')
        return cleaned


class ProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'company', 'job_title',
                  'github_username', 'bio', 'avatar', 'email_notifications']
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-input'}),
            'last_name': forms.TextInput(attrs={'class': 'form-input'}),
            'email': forms.EmailInput(attrs={'class': 'form-input'}),
            'company': forms.TextInput(attrs={'class': 'form-input'}),
            'job_title': forms.TextInput(attrs={'class': 'form-input'}),
            'github_username': forms.TextInput(attrs={'class': 'form-input', 'placeholder': 'octocat'}),
            'bio': forms.Textarea(attrs={'class': 'form-input', 'rows': 4}),
        }
