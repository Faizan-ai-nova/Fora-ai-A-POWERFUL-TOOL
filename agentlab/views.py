from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.shortcuts import render, redirect, get_object_or_404
from django.utils import timezone

from .client import run_agent_test, AgentTestError
from .forms import AgentTestForm, MODEL_PROVIDER_MAP
from .models import AgentTest


def _guard_test_quota(request):
    """Returns a redirect response if the user is out of agent tests, else None."""
    if not request.user.can_run_agent_test():
        messages.warning(request, "You've used all your free agent tests. Upgrade to continue testing.")
        return redirect('subscriptions:upgrade')
    return None


@login_required
def new_test_view(request):
    guard = _guard_test_quota(request)
    if guard:
        return guard

    if request.method == 'POST':
        form = AgentTestForm(request.POST)
        if not form.is_valid():
            for err in form.errors.values():
                messages.error(request, err.as_text())
            return redirect('agentlab:new_test')

        cleaned = form.cleaned_data
        selected = cleaned['model_name']
        user_api_key = cleaned.get('api_key', '')
        custom_provider_type = ''
        custom_api_base = ''

        if selected == 'custom':
            provider = 'custom'
            model_name = cleaned['custom_model_name'].strip()
            custom_provider_type = cleaned.get('custom_provider_type', '') or 'openai_compatible'
            custom_api_base = cleaned.get('custom_api_base', '').strip()
        else:
            provider = MODEL_PROVIDER_MAP.get(selected, 'groq')
            model_name = selected

        test = AgentTest.objects.create(
            user=request.user,
            name=cleaned.get('name') or 'Untitled Test',
            provider=provider,
            model_name=model_name,
            system_prompt=cleaned.get('system_prompt', ''),
            input_prompt=cleaned['input_prompt'],
            expected_output=cleaned.get('expected_output', ''),
            status=AgentTest.Status.RUNNING,
        )

        try:
            result = run_agent_test(
                provider=provider,
                model_name=model_name,
                system_prompt=test.system_prompt,
                input_prompt=test.input_prompt,
                user_api_key=user_api_key,
                custom_provider_type=custom_provider_type,
                custom_api_base=custom_api_base,
            )
        except AgentTestError as exc:
            test.status = AgentTest.Status.FAILED
            test.error_message = str(exc)
            test.completed_at = timezone.now()
            test.save()
            request.user.consume_agent_test()
            messages.error(request, f'Test failed: {exc}')
            return redirect('agentlab:detail', test_id=test.id)

        test.actual_output = result['text']
        test.model_name = result['model']
        test.prompt_tokens = result['prompt_tokens']
        test.completion_tokens = result['completion_tokens']
        test.total_tokens = result['total_tokens']
        test.latency_ms = result['latency_ms']
        test.estimated_cost_usd = result['estimated_cost_usd']
        test.status = AgentTest.Status.COMPLETED
        test.completed_at = timezone.now()

        if test.expected_output.strip():
            test.passed = test.expected_output.strip().lower() in test.actual_output.lower()
        else:
            test.passed = None

        test.save()
        request.user.consume_agent_test()
        messages.success(request, 'Test complete!')
        return redirect('agentlab:detail', test_id=test.id)

    form = AgentTestForm()
    return render(request, 'agentlab/new_test.html', {
        'form': form,
        'tests_remaining': request.user.agent_tests_remaining,
    })


@login_required
def history_view(request):
    tests = AgentTest.objects.filter(user=request.user)
    paginator = Paginator(tests, 10)
    page_obj = paginator.get_page(request.GET.get('page'))
    return render(request, 'agentlab/history.html', {'page_obj': page_obj})


@login_required
def detail_view(request, test_id):
    test = get_object_or_404(AgentTest, id=test_id, user=request.user)
    return render(request, 'agentlab/detail.html', {'test': test})
