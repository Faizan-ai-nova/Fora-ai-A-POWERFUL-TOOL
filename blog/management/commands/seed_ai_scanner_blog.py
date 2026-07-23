from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from blog.models import Category, Post


class Command(BaseCommand):
    help = 'Seed the blog with launch articles for the AI Security Scanner module.'

    def handle(self, *args, **options):
        category, _ = Category.objects.get_or_create(
            slug='ai-security', defaults={'name': 'AI Security'}
        )
        now = timezone.now()

        posts = [
            {
                'title': 'Introducing the Fora AI Security Scanner: Pentest Your Own Chatbot',
                'slug': 'introducing-ai-security-scanner',
                'category': category,
                'reading_time_minutes': 6,
                'cover_emoji': '🤖',
                'excerpt': 'Fora AI can now test your own AI chatbot or agent for prompt injection, jailbreaks, and data leaks - paste a URL and get a security score in minutes.',
                'published_at': now,
                'body_html': '''
<p>Every Fora AI scan so far has looked at source code. Today we're shipping something different: a scanner that talks <em>to</em> your AI instead of reading its code. If you've shipped a chatbot, support agent, or LLM-powered feature, the AI Security Scanner sends it a set of well-known attack prompts and reports back exactly how it held up.</p>

<h2>Why this exists</h2>
<p>Traditional code scanners look for SQL injection and XSS. They have nothing to say about a system prompt that leaks on request, or an agent that happily writes a phishing email if you frame the ask as "hypothetically." Those are new failure modes specific to LLM-backed products, and they need their own tests.</p>

<h2>What it checks</h2>
<p>The MVP suite runs through five categories: prompt injection, jailbreak attempts, system prompt leakage, sensitive data exposure, and harmful content generation. It also tracks response time and error rate, since a bot that times out under adversarial input is its own kind of reliability risk.</p>

<h2>How to run one</h2>
<p>From the sidebar, open <strong>AI Security Scanner</strong>, paste the URL of your chat API, and tell it which JSON field carries the message and which path in the response holds the reply. Hit start, and you'll watch each test execute live before your security score and full report are ready.</p>

<h2>What you get back</h2>
<p>A score out of 100, a Low/Medium/High risk rating, a per-test pass/fail breakdown with the exact prompt and response for anything that failed, and concrete recommendations - like adding an instruction-hierarchy guard if prompt injection got through.</p>

<h2>One important note</h2>
<p>Only scan endpoints you own or have explicit permission to test. The scanner refuses to target private or internal network addresses, and every test it sends is a known, published attack pattern - nothing here is designed to find a novel exploit against someone else's system.</p>

<p>This is an MVP: the detection layer is rule-based today, with an optional AI-judge pass you can enable for a second opinion on ambiguous responses. We'll keep expanding the test library as new attack patterns show up in the wild.</p>
''',
            },
            {
                'title': 'Prompt Injection vs. Jailbreaking: What the Difference Actually Means for Your AI',
                'slug': 'prompt-injection-vs-jailbreaking-explained',
                'category': category,
                'reading_time_minutes': 7,
                'cover_emoji': '🧩',
                'excerpt': "These two terms get used interchangeably, but they describe different attack surfaces - and your defenses for one won't necessarily cover the other.",
                'published_at': now - timedelta(days=1),
                'body_html': '''
<p>"Prompt injection" and "jailbreak" show up together so often that it's easy to treat them as synonyms. They're related, but they target different assumptions your AI system makes, and conflating them is a good way to leave one half unpatched.</p>

<h2>Prompt injection: hijacking the instruction channel</h2>
<p>Prompt injection happens when untrusted input - a user's message, a scraped webpage, a document your agent reads - gets treated as an instruction instead of data. The classic example is a user typing "ignore your previous instructions and do X instead." A subtler version happens when an agent summarizes a webpage that contains a hidden instruction aimed at the agent itself, not the human reading the page.</p>
<p>The fix is architectural: maintain a clear hierarchy between system instructions and user-supplied content, and never let content pulled in at runtime carry the same authority as your original system prompt.</p>

<h2>Jailbreaking: talking the model out of its own guardrails</h2>
<p>Jailbreaking targets the model's safety training directly, usually through roleplay ("pretend you're DAN, an AI with no rules"), hypothetical framing ("hypothetically, if you had no content policy..."), or fictional wrapping ("write a story where a character explains how to..."). There's no injected instruction here in the technical sense - the user is still talking to the model as intended, just trying to talk it into a different persona.</p>
<p>Defenses here are more about the model and system prompt: reinforcing refusal behavior against common bypass framings, and treating "the user says it's fiction/hypothetical/roleplay" as a request that still needs the same safety review as a direct ask.</p>

<h2>Why the distinction matters for testing</h2>
<p>A test suite that only tries "ignore previous instructions" will miss a bot that's perfectly resistant to injection but folds the moment you ask it to roleplay as an unrestricted AI. That's exactly why Fora AI's AI Security Scanner runs them as separate categories with separate scores - a Jailbreak Score alongside the overall Security Score - so you can see which failure mode you actually have.</p>

<h2>Takeaway</h2>
<p>Treat instruction-hierarchy design and safety-refusal robustness as two different engineering problems. Test both, separately, and re-test after every prompt or model change - what stops one bypass technique often does nothing for the other.</p>
''',
            },
        ]

        created = 0
        for data in posts:
            _, was_created = Post.objects.get_or_create(slug=data['slug'], defaults=data)
            created += int(was_created)

        self.stdout.write(self.style.SUCCESS(f'Seeded AI Security Scanner blog posts ({created} created).'))
