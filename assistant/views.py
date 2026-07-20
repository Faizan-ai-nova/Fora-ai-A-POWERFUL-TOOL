import json
import logging

import requests
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are the Fora AI assistant, embedded on the Fora AI website - an AI-powered "
    "code security scanner that finds SQL injection, XSS, hardcoded secrets, and "
    "OWASP Top 10 issues in Python, Django, JavaScript, HTML and CSS.\n\n"
    "Answer simply and briefly (2-4 short sentences unless the user clearly wants more "
    "detail). Help with two things: (1) plain-language explanations of security concepts, "
    "and (2) how to use Fora AI itself - free plan gives 10 scans, Pro is unlimited via "
    "UPI or PayPal on the pricing page, and repos can be connected via GitHub integration. "
    "If you don't know something about a user's specific account or scan result, say so "
    "honestly instead of guessing. Keep a friendly, helpful, concise tone."
)

MAX_HISTORY_MESSAGES = 10
MAX_MESSAGES_PER_SESSION = 5
MAX_MESSAGE_LENGTH = 1000

MISTRAL_URL = 'https://api.mistral.ai/v1/chat/completions'
MISTRAL_MODEL = 'mistral-small-latest'


@require_POST
@csrf_protect
def chat_api(request):
    try:
        data = json.loads(request.body or '{}')
    except (json.JSONDecodeError, TypeError):
        return JsonResponse({'error': 'Invalid request.'}, status=400)

    user_message = (data.get('message') or '').strip()
    if not user_message:
        return JsonResponse({'error': 'Message is empty.'}, status=400)
    if len(user_message) > MAX_MESSAGE_LENGTH:
        return JsonResponse({'error': f'Message is too long (max {MAX_MESSAGE_LENGTH} characters).'}, status=400)

    if not getattr(settings, 'MISTRAL_API_KEY', ''):
        return JsonResponse({
            'reply': "The AI assistant isn't configured yet - add MISTRAL_API_KEY in your environment variables."
        })

    sent_count = request.session.get('assistant_msg_count', 0)
    if sent_count >= MAX_MESSAGES_PER_SESSION:
        return JsonResponse({
            'reply': "Whoa there, chatterbox. I've hit my 5-message limit — go touch some code instead.",
            'limit_reached': True,
        })

    history = request.session.get('assistant_history', [])

    messages = [{'role': 'system', 'content': SYSTEM_PROMPT}]
    messages.extend(history[-(MAX_HISTORY_MESSAGES * 2):])
    messages.append({'role': 'user', 'content': user_message})

    # Count this attempt now, before calling the API - so a failed/errored
    # request still counts against the session limit instead of letting
    # someone retry indefinitely during an outage.
    request.session['assistant_msg_count'] = sent_count + 1
    request.session.modified = True

    try:
        resp = requests.post(
            MISTRAL_URL,
            headers={
                'Authorization': f'Bearer {settings.MISTRAL_API_KEY}',
                'Content-Type': 'application/json',
            },
            json={
                'model': MISTRAL_MODEL,
                'messages': messages,
                'temperature': 0.5,
                'max_tokens': 300,
            },
            timeout=20,
        )
        resp.raise_for_status()
        reply = resp.json()['choices'][0]['message']['content'].strip()
    except Exception as exc:
        logger.warning('Assistant (Mistral) request failed: %s', exc)
        return JsonResponse({
            'reply': "Sorry, I couldn't reach the assistant right now. Please try again in a moment."
        })

    history.append({'role': 'user', 'content': user_message})
    history.append({'role': 'assistant', 'content': reply})
    request.session['assistant_history'] = history[-(MAX_HISTORY_MESSAGES * 2):]

    return JsonResponse({'reply': reply})