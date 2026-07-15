from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.views.decorators.http import require_http_methods

from .forms import RegisterForm, LoginForm, ForgotPasswordForm, SetNewPasswordForm, ProfileForm

User = get_user_model()


def register_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard:home')

    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.email = form.cleaned_data['email']
            user.scans_remaining = settings.FREE_PLAN_SCAN_LIMIT
            user.save()

            # Bootstrap a free subscription record so downstream apps
            # (dashboard, subscriptions) have a consistent source of truth.
            from subscriptions.models import Plan, Subscription
            free_plan, _ = Plan.objects.get_or_create(
                slug='free',
                defaults={'name': 'Free', 'price_monthly': 0, 'scan_limit': settings.FREE_PLAN_SCAN_LIMIT}
            )
            Subscription.objects.create(user=user, plan=free_plan, status='active')

            login(request, user)
            messages.success(request, f'Welcome to Fora AI, {user.username}! You have {user.scans_remaining} free scans.')
            return redirect('dashboard:home')
    else:
        form = RegisterForm()

    return render(request, 'accounts/register.html', {'form': form})


def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard:home')

    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            identifier = form.cleaned_data['username']
            password = form.cleaned_data['password']

            # Allow login with username OR email
            user_obj = User.objects.filter(email__iexact=identifier).first()
            username = user_obj.username if user_obj else identifier

            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                if not form.cleaned_data.get('remember_me'):
                    request.session.set_expiry(0)
                messages.success(request, f'Welcome back, {user.username}!')
                next_url = request.GET.get('next') or 'dashboard:home'
                return redirect(next_url)
            else:
                messages.error(request, 'Invalid username/email or password.')
    else:
        form = LoginForm()

    return render(request, 'accounts/login.html', {'form': form})


@login_required
def logout_view(request):
    logout(request)
    messages.info(request, "You've been logged out. See you soon!")
    return redirect('accounts:login')


def forgot_password_view(request):
    if request.method == 'POST':
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            user = User.objects.filter(email__iexact=email).first()
            if user:
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                token = default_token_generator.make_token(user)
                reset_url = request.build_absolute_uri(
                    reverse('accounts:reset_password', kwargs={'uidb64': uid, 'token': token})
                )
                send_mail(
                    subject='Reset your Fora AI password',
                    message=(
                        f'Hi {user.username},\n\n'
                        f'Click the link below to reset your password:\n{reset_url}\n\n'
                        f'This link expires in 1 hour. If you did not request this, ignore this email.'
                    ),
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user.email],
                    fail_silently=True,
                )
               # If an account exists with that email, a reset link has been sent
            # Always show the same message (avoid leaking whether an email exists)
            messages.success(request, 'Oops! This feature is temporarily unavailable. Please check back soon.')
                            
            return redirect('accounts:login')
    else:
        form = ForgotPasswordForm()

    return render(request, 'accounts/forgot_password.html', {'form': form})


@require_http_methods(['GET', 'POST'])
def reset_password_view(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (User.DoesNotExist, ValueError, TypeError, OverflowError):
        user = None

    valid_link = user is not None and default_token_generator.check_token(user, token)

    if not valid_link:
        messages.error(request, 'This password reset link is invalid or has expired.')
        return redirect('accounts:forgot_password')

    if request.method == 'POST':
        form = SetNewPasswordForm(request.POST)
        if form.is_valid():
            user.set_password(form.cleaned_data['password1'])
            user.save()
            messages.success(request, 'Your password has been reset. You can now log in.')
            return redirect('accounts:login')
    else:
        form = SetNewPasswordForm()

    return render(request, 'accounts/reset_password.html', {'form': form})


@login_required
def profile_view(request):
    if request.method == 'POST':
        form = ProfileForm(request.POST, request.FILES, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile updated successfully.')
            return redirect('accounts:profile')
    else:
        form = ProfileForm(instance=request.user)

    return render(request, 'accounts/profile.html', {'form': form})
