"""
Maps Fora AI's internal vulnerability categories to their corresponding
CWE (Common Weakness Enumeration) identifiers.

This runs as a post-processing step in analyzer.py so both the rule engine
and any configured AI provider get a consistent CWE reference attached to
every finding, without needing to hardcode a CWE string into each of the
29+ individual rule definitions in rules.py.

Reference: https://cwe.mitre.org/data/definitions/699.html
"""

CATEGORY_TO_CWE = {
    'SQL Injection': 'CWE-89 — SQL Injection',
    'Cross-Site Scripting (XSS)': 'CWE-79 — Cross-Site Scripting',
    'CSRF': 'CWE-352 — Cross-Site Request Forgery',
    'Command Injection': 'CWE-78 — OS Command Injection',
    'Path Traversal': 'CWE-22 — Path Traversal',
    'Hardcoded Secrets': 'CWE-798 — Use of Hard-coded Credentials',
    'Dangerous Functions': 'CWE-95 — Eval Injection',
    'Security Misconfiguration': 'CWE-16 — Configuration',
    'Authentication Problems': 'CWE-287 — Improper Authentication',
    'Cryptographic Failures': 'CWE-327 — Broken or Risky Crypto Algorithm',
    'Insecure Deserialization': 'CWE-502 — Deserialization of Untrusted Data',
    'Insecure Storage': 'CWE-312 — Cleartext Storage of Sensitive Information',
    'Missing Security Headers': 'CWE-693 — Protection Mechanism Failure',
    'Cross-Origin Issues': 'CWE-346 — Origin Validation Error',
    'Insecure API Calls': 'CWE-829 — Inclusion of Untrusted Functionality',
}

DEFAULT_CWE = 'CWE-1035 — OWASP Top 10'


def get_cwe_reference(category: str) -> str:
    """Look up the CWE reference for a category. Falls back to a generic
    OWASP-aligned CWE category if the category isn't in the table (covers
    novel categories an AI provider might invent)."""
    return CATEGORY_TO_CWE.get(category, DEFAULT_CWE)
