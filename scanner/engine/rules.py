"""
Deterministic static-analysis rule engine.

This is what makes Fora AI actually work out of the box with zero API
keys: a curated set of regex-based detectors for the most common and
highest-impact vulnerability classes across Python/Django, JavaScript,
HTML and CSS. When a real AI provider is configured (see providers.py),
its findings are merged alongside these for deeper, contextual analysis.

Each rule returns a dict matching the Issue model fields.
"""

import re


def _line_of(code: str, match_start: int) -> int:
    return code.count('\n', 0, match_start) + 1


def _snippet(code: str, line_number: int, context: int = 0) -> str:
    lines = code.splitlines()
    idx = line_number - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()[:200]
    return ''


# ---------------------------------------------------------------------------
# PYTHON / DJANGO RULES
# ---------------------------------------------------------------------------

PYTHON_RULES = [
    {
        'pattern': re.compile(r'\.raw\(\s*["\'].*?%s|\.raw\(\s*f["\']|\.raw\(\s*.*\+\s*|cursor\.execute\(\s*["\'].*%s|cursor\.execute\(\s*f["\']|cursor\.execute\(.*\+\s*\w'),
        'title': 'SQL Injection via Raw Query',
        'category': 'SQL Injection',
        'severity': 'critical',
        'owasp_reference': 'A03:2021 - Injection',
        'description': 'User-controlled data appears to be concatenated or interpolated directly into a raw SQL query or cursor.execute() call instead of using parameterized queries.',
        'why_dangerous': 'An attacker can manipulate the SQL query structure to read, modify, or delete arbitrary data, bypass authentication, or in some database configurations execute OS commands.',
        'recommended_fix': 'Always use parameterized queries. Never use string formatting (%, f-strings, +) to build SQL. Pass parameters as a separate list/tuple to .raw() or cursor.execute().',
        'secure_code_example': (
            "# Safe - parameters are escaped by the DB driver\n"
            "cursor.execute(\"SELECT * FROM users WHERE username = %s\", [username])\n\n"
            "# Or with the Django ORM (preferred)\n"
            "User.objects.filter(username=username)"
        ),
    },
    {
        'pattern': re.compile(r'\beval\(|\bexec\('),
        'title': 'Use of Dangerous eval()/exec() Function',
        'category': 'Dangerous Functions',
        'severity': 'critical',
        'owasp_reference': 'A03:2021 - Injection',
        'description': 'The code uses eval() or exec(), which execute arbitrary Python code constructed at runtime.',
        'why_dangerous': 'If any part of the evaluated string is influenced by user input, an attacker can execute arbitrary code on the server (Remote Code Execution).',
        'recommended_fix': 'Avoid eval()/exec() entirely. Use ast.literal_eval() for parsing literals, json.loads() for JSON, or explicit dispatch dictionaries instead of dynamic code execution.',
        'secure_code_example': (
            "import ast\n"
            "# Safe - only parses Python literals, never executes code\n"
            "value = ast.literal_eval(user_input)"
        ),
    },
    {
        'pattern': re.compile(r'os\.system\(|subprocess\.(call|run|Popen|check_output)\([^)]*shell\s*=\s*True'),
        'title': 'OS Command Injection',
        'category': 'Command Injection',
        'severity': 'critical',
        'owasp_reference': 'A03:2021 - Injection',
        'description': 'The code executes an OS command via os.system() or subprocess with shell=True, which passes the command through a shell.',
        'why_dangerous': 'If user input reaches this command, an attacker can chain additional shell commands (e.g. using ; or &&) to execute arbitrary code on the host.',
        'recommended_fix': 'Avoid shell=True. Pass the command as a list of arguments to subprocess.run() without shell interpretation, and validate/allowlist any user-supplied arguments.',
        'secure_code_example': (
            "import subprocess\n"
            "# Safe - no shell interpretation, arguments passed as a list\n"
            "subprocess.run(['ls', '-la', user_supplied_path], shell=False, check=True)"
        ),
    },
    {
        'pattern': re.compile(r'open\([^)]*request\.(GET|POST)\[|open\(.*\+\s*request'),
        'title': 'Path Traversal via Unvalidated File Access',
        'category': 'Path Traversal',
        'severity': 'high',
        'owasp_reference': 'A01:2021 - Broken Access Control',
        'description': 'A file path derived directly from request input is passed to open() without sanitization.',
        'why_dangerous': 'An attacker can supply sequences like "../../etc/passwd" to read or write files outside the intended directory.',
        'recommended_fix': 'Validate and normalize the path, restrict it to an allowlisted base directory, and use os.path.realpath() combined with a startswith() check against that base directory.',
        'secure_code_example': (
            "import os\n"
            "base_dir = '/var/app/uploads'\n"
            "requested = os.path.realpath(os.path.join(base_dir, filename))\n"
            "if not requested.startswith(base_dir):\n"
            "    raise PermissionError('Invalid path')"
        ),
    },
    {
        'pattern': re.compile(r'(SECRET_KEY|API_KEY|PASSWORD|AWS_SECRET|PRIVATE_KEY|TOKEN)\s*=\s*["\'][A-Za-z0-9_\-+/=]{8,}["\']'),
        'title': 'Hardcoded Secret / Credential',
        'category': 'Hardcoded Secrets',
        'severity': 'critical',
        'owasp_reference': 'A02:2021 - Cryptographic Failures',
        'description': 'A secret key, password, API key, or token appears to be hardcoded directly in the source code.',
        'why_dangerous': 'Hardcoded secrets are exposed to anyone with source access (including via version control history) and cannot be rotated without a code deploy, making compromise likely and recovery slow.',
        'recommended_fix': 'Move all secrets to environment variables or a secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault). Never commit real secrets to source control; add a .env.example instead.',
        'secure_code_example': (
            "import os\n"
            "SECRET_KEY = os.environ['DJANGO_SECRET_KEY']  # loaded from environment, not hardcoded"
        ),
    },
    {
        'pattern': re.compile(r'DEBUG\s*=\s*True'),
        'title': 'Django DEBUG Mode Enabled',
        'category': 'Security Misconfiguration',
        'severity': 'high',
        'owasp_reference': 'A05:2021 - Security Misconfiguration',
        'description': 'Django DEBUG is set to True.',
        'why_dangerous': 'In production, DEBUG=True leaks detailed stack traces, settings values, installed apps, and SQL queries to any visitor who triggers an error page.',
        'recommended_fix': 'Set DEBUG = False in production and drive it from an environment variable so it defaults safely.',
        'secure_code_example': (
            "import os\n"
            "DEBUG = os.getenv('DJANGO_DEBUG', 'False') == 'True'"
        ),
    },
    {
        'pattern': re.compile(r'ALLOWED_HOSTS\s*=\s*\[\s*[\'"]\*[\'"]\s*\]'),
        'title': 'Wildcard ALLOWED_HOSTS',
        'category': 'Security Misconfiguration',
        'severity': 'medium',
        'owasp_reference': 'A05:2021 - Security Misconfiguration',
        'description': "ALLOWED_HOSTS is set to ['*'], accepting requests with any Host header.",
        'why_dangerous': 'This enables HTTP Host header attacks such as cache poisoning and password-reset link poisoning.',
        'recommended_fix': 'Explicitly list the domains your application serves.',
        'secure_code_example': "ALLOWED_HOSTS = ['yourdomain.com', 'www.yourdomain.com']",
    },
    {
        'pattern': re.compile(r'@csrf_exempt'),
        'title': 'CSRF Protection Disabled on View',
        'category': 'CSRF',
        'severity': 'high',
        'owasp_reference': 'A01:2021 - Broken Access Control',
        'description': 'The @csrf_exempt decorator disables Django\'s built-in CSRF protection for this view.',
        'why_dangerous': 'Without CSRF protection, a malicious site can trick an authenticated user\'s browser into submitting unwanted requests (e.g. changing their password or making a purchase) without their consent.',
        'recommended_fix': 'Remove @csrf_exempt unless absolutely required (e.g. verified webhook with signature validation). If exemption is unavoidable, validate the request through another strong mechanism such as HMAC signature verification.',
        'secure_code_example': (
            "# Let Django's CsrfViewMiddleware protect the view (default)\n"
            "def my_view(request):\n"
            "    ...\n\n"
            "# Templates must include: {% csrf_token %} inside <form>"
        ),
    },
    {
        'pattern': re.compile(r'mark_safe\(|\|\s*safe\b'),
        'title': 'Unsafe HTML Rendering (mark_safe / |safe filter)',
        'category': 'Cross-Site Scripting (XSS)',
        'severity': 'high',
        'owasp_reference': 'A03:2021 - Injection',
        'description': 'mark_safe() or the |safe template filter disables Django\'s automatic HTML escaping for this content.',
        'why_dangerous': 'If any part of the marked-safe content originates from user input, an attacker can inject <script> tags or event handlers to run arbitrary JavaScript in victims\' browsers (stored/reflected XSS).',
        'recommended_fix': 'Avoid mark_safe()/|safe on user-controlled data. Use Django\'s automatic escaping, or explicitly sanitize with a library like bleach if raw HTML must be allowed.',
        'secure_code_example': (
            "import bleach\n"
            "clean_html = bleach.clean(user_html, tags=['b', 'i', 'p'], strip=True)"
        ),
    },
    {
        'pattern': re.compile(r'pickle\.loads?\('),
        'title': 'Insecure Deserialization with pickle',
        'category': 'Insecure Deserialization',
        'severity': 'critical',
        'owasp_reference': 'A08:2021 - Software and Data Integrity Failures',
        'description': 'pickle.load()/loads() deserializes data, which in Python can execute arbitrary code as a side effect.',
        'why_dangerous': 'Deserializing untrusted or user-supplied pickle data allows an attacker to achieve Remote Code Execution by crafting a malicious pickle payload.',
        'recommended_fix': 'Never unpickle data from an untrusted source. Use JSON for data interchange, or a safe serialization format with schema validation.',
        'secure_code_example': (
            "import json\n"
            "data = json.loads(untrusted_input)  # safe - no code execution on load"
        ),
    },
    {
        'pattern': re.compile(r'yaml\.load\((?!.*Loader=yaml\.SafeLoader)'),
        'title': 'Unsafe YAML Deserialization',
        'category': 'Insecure Deserialization',
        'severity': 'high',
        'owasp_reference': 'A08:2021 - Software and Data Integrity Failures',
        'description': 'yaml.load() is called without a safe Loader.',
        'why_dangerous': 'The default/full YAML loader can construct arbitrary Python objects, enabling code execution from a crafted YAML file.',
        'recommended_fix': 'Use yaml.safe_load() or explicitly pass Loader=yaml.SafeLoader.',
        'secure_code_example': "import yaml\ndata = yaml.safe_load(untrusted_input)",
    },
    {
        'pattern': re.compile(r'def\s+\w*password\w*\([^)]*\):[^\n]*\n(?:[^\n]*\n){0,4}?[^\n]*len\([^)]*\)\s*[<>]=?\s*[1-5]\b'),
        'title': 'Weak Password Length Requirement',
        'category': 'Authentication Problems',
        'severity': 'medium',
        'owasp_reference': 'A07:2021 - Identification and Authentication Failures',
        'description': 'A password validation function appears to allow very short passwords (fewer than 6 characters).',
        'why_dangerous': 'Short passwords are dramatically easier to brute-force or guess, increasing the risk of account takeover.',
        'recommended_fix': 'Require a minimum of 8-12 characters and use Django\'s built-in AUTH_PASSWORD_VALIDATORS (MinimumLengthValidator, CommonPasswordValidator, etc.) instead of custom logic.',
        'secure_code_example': (
            "AUTH_PASSWORD_VALIDATORS = [\n"
            "    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',\n"
            "     'OPTIONS': {'min_length': 10}},\n"
            "    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},\n"
            "]"
        ),
    },
    {
        'pattern': re.compile(r'request\.(GET|POST)\.get\([^)]*\)\s*==\s*.*password|password\s*==\s*request\.(GET|POST)'),
        'title': 'Plaintext Password Comparison',
        'category': 'Authentication Problems',
        'severity': 'critical',
        'owasp_reference': 'A07:2021 - Identification and Authentication Failures',
        'description': 'A password from the request appears to be compared directly with == rather than through a secure hashing check.',
        'why_dangerous': 'This implies passwords are stored or compared in plaintext, and == comparisons are also vulnerable to timing attacks. A database breach would expose every user\'s real password.',
        'recommended_fix': 'Never store or compare plaintext passwords. Use Django\'s check_password()/user.set_password(), which use salted hashing and constant-time comparison.',
        'secure_code_example': (
            "from django.contrib.auth import authenticate\n"
            "user = authenticate(request, username=username, password=password)  # hashed & constant-time"
        ),
    },
    {
        'pattern': re.compile(r'verify\s*=\s*False|CERT_NONE'),
        'title': 'TLS Certificate Verification Disabled',
        'category': 'Insecure API Calls',
        'severity': 'high',
        'owasp_reference': 'A02:2021 - Cryptographic Failures',
        'description': 'An outgoing HTTPS request disables TLS certificate verification (verify=False or ssl.CERT_NONE).',
        'why_dangerous': 'This makes the connection vulnerable to man-in-the-middle attacks, allowing an attacker to intercept or tamper with data in transit, including credentials and API tokens.',
        'recommended_fix': 'Always verify TLS certificates. If a private/self-signed CA is in use, point verify= at the CA bundle instead of disabling verification entirely.',
        'secure_code_example': "requests.get(url, verify=True)  # or verify='/path/to/ca-bundle.pem'",
    },
    {
        'pattern': re.compile(r'random\.(random|randint|choice)\([^)]*\).*(?:token|password|secret|otp)', re.IGNORECASE),
        'title': 'Insecure Randomness for Security Token',
        'category': 'Cryptographic Failures',
        'severity': 'high',
        'owasp_reference': 'A02:2021 - Cryptographic Failures',
        'description': 'The standard random module appears to be used to generate a security-sensitive value (token, password, OTP, or secret).',
        'why_dangerous': "Python's random module is not cryptographically secure - its output can be predicted, allowing an attacker to guess tokens or reset codes.",
        'recommended_fix': 'Use the secrets module for anything security-sensitive.',
        'secure_code_example': "import secrets\ntoken = secrets.token_urlsafe(32)",
    },
    {
        'pattern': re.compile(r'MIDDLEWARE\s*=\s*\[(?!(?:.|\n)*XFrameOptionsMiddleware)'),
        'title': 'Missing Clickjacking Protection Middleware',
        'category': 'Missing Security Headers',
        'severity': 'low',
        'owasp_reference': 'A05:2021 - Security Misconfiguration',
        'description': "Django's XFrameOptionsMiddleware does not appear in the MIDDLEWARE list.",
        'why_dangerous': 'Without X-Frame-Options, the site can be embedded in an <iframe> on a malicious page, enabling clickjacking attacks against users.',
        'recommended_fix': "Add 'django.middleware.clickjacking.XFrameOptionsMiddleware' to MIDDLEWARE and set X_FRAME_OPTIONS = 'DENY'.",
        'secure_code_example': "MIDDLEWARE = [\n    ...,\n    'django.middleware.clickjacking.XFrameOptionsMiddleware',\n]\nX_FRAME_OPTIONS = 'DENY'",
    },
]

# ---------------------------------------------------------------------------
# JAVASCRIPT RULES
# ---------------------------------------------------------------------------

JS_RULES = [
    {
        'pattern': re.compile(r'\.innerHTML\s*='),
        'title': 'DOM-based XSS via innerHTML',
        'category': 'Cross-Site Scripting (XSS)',
        'severity': 'high',
        'owasp_reference': 'A03:2021 - Injection',
        'description': 'Content is assigned directly to .innerHTML.',
        'why_dangerous': 'If the assigned value includes any user-controlled data, an attacker can inject <script> tags or event handler attributes that execute in the victim\'s browser.',
        'recommended_fix': 'Use .textContent for plain text, or sanitize HTML with a library like DOMPurify before assigning it to innerHTML.',
        'secure_code_example': (
            "import DOMPurify from 'dompurify';\n"
            "element.innerHTML = DOMPurify.sanitize(userSuppliedHtml);"
        ),
    },
    {
        'pattern': re.compile(r'\beval\(|new\s+Function\('),
        'title': 'Use of eval() / Function() Constructor',
        'category': 'Dangerous Functions',
        'severity': 'critical',
        'owasp_reference': 'A03:2021 - Injection',
        'description': 'The code dynamically executes a string as JavaScript using eval() or the Function() constructor.',
        'why_dangerous': 'If any part of the executed string comes from user input or an untrusted source, an attacker can run arbitrary JavaScript in the page context.',
        'recommended_fix': 'Avoid eval()/Function(). Use JSON.parse() for data, and explicit logic (switch/dispatch objects) instead of dynamically generated code.',
        'secure_code_example': "const data = JSON.parse(jsonString); // safe - parses data only, never executes code",
    },
    {
        'pattern': re.compile(r'document\.write\('),
        'title': 'Unsafe document.write() Usage',
        'category': 'Cross-Site Scripting (XSS)',
        'severity': 'medium',
        'owasp_reference': 'A03:2021 - Injection',
        'description': 'document.write() is used to inject content into the page.',
        'why_dangerous': 'Content written this way is not escaped, so if it includes untrusted data an attacker can inject executable script tags.',
        'recommended_fix': 'Use safe DOM APIs (createElement/textContent) or a templating library that auto-escapes output instead of document.write().',
        'secure_code_example': (
            "const el = document.createElement('p');\n"
            "el.textContent = userSuppliedText;\n"
            "document.body.appendChild(el);"
        ),
    },
    {
        'pattern': re.compile(r'localStorage\.setItem\([^)]*(token|password|secret|jwt)', re.IGNORECASE),
        'title': 'Sensitive Data Stored in localStorage',
        'category': 'Insecure Storage',
        'severity': 'medium',
        'owasp_reference': 'A02:2021 - Cryptographic Failures',
        'description': 'A token, password, or secret appears to be stored in localStorage.',
        'why_dangerous': 'localStorage is accessible to any JavaScript running on the page, so a single XSS vulnerability anywhere on the site can exfiltrate these credentials.',
        'recommended_fix': 'Store session tokens in an HttpOnly, Secure cookie instead, which JavaScript cannot read, or use short-lived in-memory tokens.',
        'secure_code_example': (
            "// Server sets the cookie:\n"
            "// Set-Cookie: session=<token>; HttpOnly; Secure; SameSite=Strict"
        ),
    },
    {
        'pattern': re.compile(r'(api[_-]?key|secret|token)\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}["\']', re.IGNORECASE),
        'title': 'Hardcoded API Key in Client-Side Code',
        'category': 'Hardcoded Secrets',
        'severity': 'critical',
        'owasp_reference': 'A02:2021 - Cryptographic Failures',
        'description': 'An API key, secret, or token appears to be hardcoded in client-side JavaScript.',
        'why_dangerous': 'Anything shipped to the browser is visible to every visitor via view-source or devtools, so hardcoded secrets here are effectively public.',
        'recommended_fix': 'Never embed secret keys in frontend code. Proxy sensitive API calls through your own backend, which holds the real key server-side.',
        'secure_code_example': (
            "// Frontend calls your own backend, not the third-party API directly\n"
            "fetch('/api/proxy/weather?city=' + city)"
        ),
    },
    {
        'pattern': re.compile(r'fetch\(["\']http://'),
        'title': 'Insecure HTTP Request',
        'category': 'Insecure API Calls',
        'severity': 'medium',
        'owasp_reference': 'A02:2021 - Cryptographic Failures',
        'description': 'A network request is made over plain HTTP instead of HTTPS.',
        'why_dangerous': 'Unencrypted traffic can be intercepted or modified in transit by a man-in-the-middle attacker.',
        'recommended_fix': 'Always use https:// endpoints, and configure HSTS on the server.',
        'secure_code_example': "fetch('https://api.example.com/data')",
    },
    {
        'pattern': re.compile(r'postMessage\([^)]*,\s*["\']\*["\']\)'),
        'title': 'Overly Permissive postMessage Target',
        'category': 'Cross-Origin Issues',
        'severity': 'medium',
        'owasp_reference': 'A05:2021 - Security Misconfiguration',
        'description': "window.postMessage is called with a wildcard '*' target origin.",
        'why_dangerous': 'The message can be received by any origin embedded in or embedding the page, potentially leaking sensitive data to an attacker-controlled frame.',
        'recommended_fix': 'Specify the exact expected origin instead of "*", and validate event.origin on the receiving end.',
        'secure_code_example': "targetWindow.postMessage(data, 'https://trusted-app.example.com');",
    },
]

# ---------------------------------------------------------------------------
# HTML RULES
# ---------------------------------------------------------------------------

HTML_RULES = [
    {
        'pattern': re.compile(r'<form[^>]*method=["\']?post["\']?(?![^>]*csrf)(?![^>]*{%\s*csrf_token)', re.IGNORECASE),
        'title': 'Form Missing CSRF Token',
        'category': 'CSRF',
        'severity': 'high',
        'owasp_reference': 'A01:2021 - Broken Access Control',
        'description': 'A POST form does not appear to include a CSRF token.',
        'why_dangerous': 'Without a CSRF token, a malicious external page can submit this form on behalf of a logged-in victim without their consent.',
        'recommended_fix': 'Add {% csrf_token %} inside every POST form when using Django templates.',
        'secure_code_example': (
            '<form method="post">\n'
            '  {% csrf_token %}\n'
            '  <input type="text" name="username">\n'
            '</form>'
        ),
    },
    {
        'pattern': re.compile(r'\{\{.*\|\s*safe\s*\}\}'),
        'title': 'Unescaped Template Output',
        'category': 'Cross-Site Scripting (XSS)',
        'severity': 'high',
        'owasp_reference': 'A03:2021 - Injection',
        'description': 'A template variable is rendered with the |safe filter, disabling Django\'s automatic HTML escaping.',
        'why_dangerous': 'If the variable contains user-supplied content, an attacker can inject script tags that execute in every visitor\'s browser (stored XSS).',
        'recommended_fix': 'Remove |safe unless the content is fully sanitized server-side. Let Django escape output automatically by default.',
        'secure_code_example': '{{ user_comment }}  {# auto-escaped by default, no |safe needed #}',
    },
    {
        'pattern': re.compile(r'<script[^>]*src=["\']http://'),
        'title': 'Script Loaded Over Insecure HTTP',
        'category': 'Insecure API Calls',
        'severity': 'medium',
        'owasp_reference': 'A02:2021 - Cryptographic Failures',
        'description': 'A <script> tag loads a resource over plain HTTP.',
        'why_dangerous': 'A network attacker can intercept the request and inject arbitrary JavaScript into the page.',
        'recommended_fix': 'Always load scripts over HTTPS and consider Subresource Integrity (integrity attribute) for third-party scripts.',
        'secure_code_example': '<script src="https://cdn.example.com/lib.js" integrity="sha384-..." crossorigin="anonymous"></script>',
    },
    {
        'pattern': re.compile(r'autocomplete=["\']?off["\']?[^>]*type=["\']?password', re.IGNORECASE),
        'title': 'Password Autocomplete Disabled (Minor)',
        'category': 'Security Misconfiguration',
        'severity': 'info',
        'owasp_reference': 'A05:2021 - Security Misconfiguration',
        'description': 'A password field disables autocomplete.',
        'why_dangerous': 'This is a minor usability/security tradeoff - it can push users toward weaker, easier-to-remember passwords or reusing passwords across sites since password managers may not offer to save them.',
        'recommended_fix': 'Allow password managers to work by not disabling autocomplete on password fields; rely on strong password policy and MFA instead.',
        'secure_code_example': '<input type="password" name="password" autocomplete="current-password">',
    },
]

# ---------------------------------------------------------------------------
# CSS RULES (mostly informational / hardening)
# ---------------------------------------------------------------------------

CSS_RULES = [
    {
        'pattern': re.compile(r'expression\s*\('),
        'title': 'Legacy CSS expression() Usage',
        'category': 'Dangerous Functions',
        'severity': 'medium',
        'owasp_reference': 'A03:2021 - Injection',
        'description': 'The obsolete CSS expression() function is used, which historically allowed JavaScript execution in old IE versions.',
        'why_dangerous': "In legacy Internet Explorer, expression() could execute arbitrary JavaScript, functioning as an XSS vector if the CSS value is attacker-influenced.",
        'recommended_fix': 'Remove expression() entirely; use standard CSS or JavaScript for dynamic styling instead.',
        'secure_code_example': '/* Use a CSS class toggled via JS instead of expression() */\n.dynamic-width { width: var(--computed-width); }',
    },
    {
        'pattern': re.compile(r'@import\s+url\(["\']?http://'),
        'title': 'CSS Import Over Insecure HTTP',
        'category': 'Insecure API Calls',
        'severity': 'low',
        'owasp_reference': 'A02:2021 - Cryptographic Failures',
        'description': 'A stylesheet is imported over plain HTTP.',
        'why_dangerous': 'An attacker on the network path can inject malicious CSS (e.g. exfiltrating form data via attribute selectors) or replace the stylesheet entirely.',
        'recommended_fix': 'Always import external stylesheets over HTTPS.',
        'secure_code_example': "@import url('https://fonts.googleapis.com/css2?family=Inter');",
    },
]


LANGUAGE_RULE_MAP = {
    'python': PYTHON_RULES,
    'django': PYTHON_RULES,
    'javascript': JS_RULES,
    'html': HTML_RULES,
    'css': CSS_RULES,
}


def run_rules_for_language(code: str, language: str) -> list[dict]:
    """Run every applicable rule set for the given language against the code."""
    rules = LANGUAGE_RULE_MAP.get(language, [])
    findings = []
    for rule in rules:
        for match in rule['pattern'].finditer(code):
            line_number = _line_of(code, match.start())
            findings.append({
                'title': rule['title'],
                'category': rule['category'],
                'severity': rule['severity'],
                'owasp_reference': rule['owasp_reference'],
                'description': rule['description'],
                'why_dangerous': rule['why_dangerous'],
                'recommended_fix': rule['recommended_fix'],
                'secure_code_example': rule['secure_code_example'],
                'line_number': line_number,
                'code_snippet': _snippet(code, line_number),
            })
            # One finding per rule per file keeps reports readable;
            # remove this break to report every occurrence.
            break
    return findings


def detect_missing_security_headers(code: str, filename: str) -> list[dict]:
    """Special-case check: Django settings.py missing common security headers."""
    findings = []
    if not filename.endswith('settings.py'):
        return findings

    checks = [
        ('SECURE_HSTS_SECONDS', 'Missing HTTP Strict Transport Security (HSTS)',
         'HSTS is not configured in settings.py.',
         'Without HSTS, browsers may still connect over plain HTTP first, leaving an opening for SSL-stripping attacks.',
         'Set SECURE_HSTS_SECONDS (e.g. 31536000) along with SECURE_HSTS_INCLUDE_SUBDOMAINS.',
         "SECURE_HSTS_SECONDS = 31536000\nSECURE_HSTS_INCLUDE_SUBDOMAINS = True"),
        ('SECURE_CONTENT_TYPE_NOSNIFF', 'Missing X-Content-Type-Options Header',
         'SECURE_CONTENT_TYPE_NOSNIFF is not set.',
         'Without this header, browsers may MIME-sniff responses, which can turn a file upload into an XSS vector.',
         'Set SECURE_CONTENT_TYPE_NOSNIFF = True.',
         'SECURE_CONTENT_TYPE_NOSNIFF = True'),
        ('SESSION_COOKIE_SECURE', 'Session Cookie Not Marked Secure',
         'SESSION_COOKIE_SECURE is not enabled.',
         'Session cookies can be transmitted over unencrypted HTTP connections, exposing them to network eavesdroppers.',
         'Set SESSION_COOKIE_SECURE = True in production.',
         'SESSION_COOKIE_SECURE = True'),
    ]
    for setting_name, title, description, why, fix, example in checks:
        if setting_name not in code:
            findings.append({
                'title': title,
                'category': 'Missing Security Headers',
                'severity': 'medium',
                'owasp_reference': 'A05:2021 - Security Misconfiguration',
                'description': description,
                'why_dangerous': why,
                'recommended_fix': fix,
                'secure_code_example': example,
                'line_number': None,
                'code_snippet': '',
            })
    return findings
