# Fora AI

AI-powered security vulnerability scanner for developers — paste code, upload a file,
or drop a whole ZIP project and get a security score, a severity-ranked issue list, and
a fix for every finding.

Built with Django, SQLite (dev) / PostgreSQL (prod-ready), and a pluggable AI engine that
works out of the box with **zero API keys** (via a built-in static-analysis rule engine)
and can be upgraded to use OpenAI, Gemini, Claude, or Groq for deeper analysis.

## Features

- **Auth**: register, login, logout, forgot/reset password, profile
- **Scanner**: paste code / upload a file / upload a ZIP project — detects SQL injection,
  XSS, CSRF, hardcoded secrets, command injection, path traversal, insecure
  deserialization, weak auth logic, missing security headers, and more, mapped to OWASP
  Top 10 references
- **Reports**: security score (0–100), severity breakdown, per-issue description, why
  it's dangerous, recommended fix, and a secure code example
- **Dashboard**: scans remaining, total scans, recent reports, subscription status
- **Subscriptions**: Free (6 scans) and Basic (unlimited), admin-editable pricing
- **Payments**: modular Stripe & PayPal integration (drop in real keys, no code changes)
- **Admin panel**: manage users, plans, scans, issues, payments, and AI settings
- **Marketing content**: editorial-styled About, Privacy Policy, and Terms pages, plus a
  built-in Blog (with 5 seeded, production-quality articles) — SEO metadata, Open Graph
  tags, JSON-LD article schema, `robots.txt`, and a hand-rolled `sitemap.xml` all included
- **Dark-mode-by-default glassmorphism UI** for the product/app, and a calmer,
  typography-led "editorial" theme (serif display face, no ambient glow) for the
  content/marketing pages, mobile responsive, toast notifications

## Tech stack

- Backend: Python / Django 5
- Database: SQLite by default, one env var away from PostgreSQL
- Frontend: server-rendered Django templates + vanilla JS (no build step)
- Deployment: Railway-ready (`railway.json`, `Procfile`, Whitenoise for static files)

## Project structure

```
freebug_ai/
├── freebug_ai/        # Django project settings/urls/wsgi
├── accounts/          # Custom user model, auth flows, profile
├── dashboard/          # Dashboard home view
├── scanner/            # Scan models + pluggable AI engine
│   └── engine/
│       ├── base.py          # AIProvider abstract interface
│       ├── providers.py     # OpenAI / Gemini / Claude / Groq implementations
│       ├── rules.py         # Deterministic regex-based vulnerability rules
│       ├── analyzer.py       # Orchestrator: language detection + rules + AI + scoring
│       └── zip_handler.py    # Safe ZIP extraction (zip-slip / zip-bomb guarded)
├── subscriptions/      # Plan & Subscription models, pricing/upgrade pages
├── payments/           # Stripe & PayPal modular provider classes
├── reports/            # Scan history & report detail views
├── pages/              # About, Privacy, Terms + robots.txt/sitemap.xml views
├── blog/               # Post/Category models, blog list & detail views
├── templates/          # All HTML templates (dark glassmorphism + editorial design systems)
└── static/             # CSS design system + JS (toasts, tabs, drag-drop, accordions)
```

## Local setup

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt

cp .env.example .env            # then edit values as needed

python manage.py makemigrations accounts scanner subscriptions payments reports pages blog
python manage.py migrate
python manage.py seed_plans     # creates the Free & Basic plans
python manage.py seed_blog      # creates 5 starter blog posts
python manage.py createsuperuser

python manage.py runserver
```

Visit `http://127.0.0.1:8000`.

> **Note:** This project ships without pre-generated migration files so the schema
> always matches whatever Django version you install. Run `makemigrations` once after
> installing dependencies, as shown above.

## Enabling a real AI provider

By default `AI_PROVIDER=mock` in `.env`, meaning Fora AI relies entirely on its
built-in rule engine (`scanner/engine/rules.py`) — this already detects real
vulnerabilities with zero configuration.

To add a real LLM for deeper, contextual analysis:

1. Install the provider's SDK (uncomment it in `requirements.txt`), e.g. `pip install openai`
2. Set `AI_PROVIDER=openai` (or `gemini` / `claude` / `groq`) in `.env`
3. Set the matching API key env var (`OPENAI_API_KEY`, `GEMINI_API_KEY`,
   `ANTHROPIC_API_KEY`, or `GROQ_API_KEY`)

Admins can also flip providers at runtime from **Admin Panel → AI Settings** without a
redeploy (`use_database_override` + `active_provider`).

## Enabling real payments

Both Stripe and PayPal are implemented behind a shared `PaymentProvider` interface
(`payments/providers/`). Until you add real keys, the checkout buttons show a friendly
"not yet configured" message instead of erroring.

- **Stripe**: set `STRIPE_SECRET_KEY`, `STRIPE_PUBLIC_KEY`, `STRIPE_WEBHOOK_SECRET`, and
  `STRIPE_BASIC_PRICE_ID` (or set `stripe_price_id` on the Plan in admin)
- **PayPal**: set `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`, and set `paypal_plan_id` on
  the Plan in admin

Webhooks: `/payments/webhook/stripe/` and `/payments/webhook/paypal/` are wired up and
verify signatures once keys are present — extend the `TODO` sections in
`payments/views.py` to update `Subscription`/`Payment` records on each event type you
care about.

## Deploying to Railway

1. Push this repo to GitHub and create a new Railway project from it
2. Add a PostgreSQL plugin — Railway will inject `DATABASE_URL` automatically
3. Set the environment variables from `.env.example` in the Railway dashboard
   (`DJANGO_SECRET_KEY`, `DJANGO_DEBUG=False`, `DJANGO_ALLOWED_HOSTS`, etc.)
4. Railway will run `railway.json`'s `deploy.startCommand`, which migrates, seeds plans,
   collects static files, and starts Gunicorn

## Roadmap (architecture is ready for)

- GitHub integration, VS Code extension, Chrome extension, MCP server
- AI chat assistant over scan results
- Team workspaces (multi-user orgs)
- Public REST API
- PDF & email reports (placeholder endpoints already exist)
- Light/dark theme toggle (CSS tokens already support both — `User.dark_mode` field)
- Notification system

## Security notes

- Custom `User` model with UUID primary keys
- ZIP uploads are protected against zip-slip and zip-bomb attacks
- CSRF protection is on by default across every form
- Production settings (`DEBUG=False`) automatically enable HSTS, secure cookies, and
  clickjacking protection — see `freebug_ai/settings.py`
- All secrets are read from environment variables, never hardcoded
