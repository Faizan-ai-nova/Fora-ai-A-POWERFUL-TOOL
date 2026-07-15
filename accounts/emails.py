import logging

from django.conf import settings
from django.core.mail import send_mail

logger = logging.getLogger(__name__)


def send_welcome_email(user):
    """
    Fired once, right after a new account is created. Plain-text is enough
    here - deliverability matters more than fancy HTML for a first email,
    and it keeps this simple to read/maintain.
    """
    if not user.email:
        return

    subject = f"Welcome to Fora AI, {user.username}! Here's how to get started"

    message = (
        f"Hi {user.username},\n\n"
        f"Thanks for signing up - you've got {user.scans_remaining} free scans ready to use.\n\n"
        f"Here's how Fora AI works, in 3 steps:\n\n"
        f"1. Paste your code, upload a file, or drop a whole ZIP of your project\n"
        f"2. We scan it for SQL injection, XSS, hardcoded secrets, and OWASP Top 10 issues\n"
        f"3. You get a 0-100 security score with a fix for every issue found\n\n"
        f"Start your first scan here: {getattr(settings, 'SITE_URL', '')}/scanner/\n\n"
        f"Need unlimited scans later? Pro plans start at just Rs 199/month, payable via UPI or PayPal.\n\n"
        f"Questions? Just reply to this email - a real person (me) reads these.\n\n"
        f"Happy scanning,\n"
        f"Faizan, Fora AI"
    )

    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', None),
            recipient_list=[user.email],
            fail_silently=True,
        )
    except Exception as exc:  # pragma: no cover
        logger.warning('Welcome email failed for user=%s: %s', user.username, exc)
