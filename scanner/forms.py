from django import forms

from .models import Scan


class PasteCodeForm(forms.Form):
    project_name = forms.CharField(
        max_length=255, required=False,
        widget=forms.TextInput(attrs={'class': 'form-input', 'placeholder': 'e.g. Login View'})
    )
    filename_hint = forms.CharField(
        max_length=255, required=False,
        widget=forms.TextInput(attrs={'class': 'form-input', 'placeholder': 'e.g. views.py (optional)'})
    )
    code = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-input code-textarea',
            'placeholder': 'Paste your code here...',
            'rows': 16,
        })
    )


class FileUploadForm(forms.Form):
    project_name = forms.CharField(
        max_length=255, required=False,
        widget=forms.TextInput(attrs={'class': 'form-input', 'placeholder': 'e.g. Auth Module'})
    )
    file = forms.FileField()

    ALLOWED_EXTENSIONS = ('.py', '.js', '.jsx', '.ts', '.tsx', '.html', '.htm', '.css')

    def clean_file(self):
        f = self.cleaned_data['file']
        name = f.name.lower()
        if not name.endswith(self.ALLOWED_EXTENSIONS):
            raise forms.ValidationError(
                f'Unsupported file type. Allowed: {", ".join(self.ALLOWED_EXTENSIONS)}'
            )
        if f.size > 5 * 1024 * 1024:
            raise forms.ValidationError('File too large (max 5MB).')
        return f


class ZipUploadForm(forms.Form):
    project_name = forms.CharField(
        max_length=255, required=False,
        widget=forms.TextInput(attrs={'class': 'form-input', 'placeholder': 'e.g. My Django Project'})
    )
    zip_file = forms.FileField()

    def clean_zip_file(self):
        f = self.cleaned_data['zip_file']
        if not f.name.lower().endswith('.zip'):
            raise forms.ValidationError('Please upload a .zip file.')
        if f.size > 15 * 1024 * 1024:
            raise forms.ValidationError('ZIP file too large (max 15MB).')
        return f
