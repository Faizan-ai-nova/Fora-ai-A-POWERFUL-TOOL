"""
Scan orchestrator: detects language, runs the deterministic rule engine,
optionally augments with a configured AI provider, deduplicates findings,
and computes the overall security score.
"""

import logging
import os

from . import rules as rule_engine
from .providers import get_provider
from .cwe_map import get_cwe_reference

logger = logging.getLogger(__name__)


EXTENSION_LANGUAGE_MAP = {
    '.py': 'python',
    '.js': 'javascript',
    '.jsx': 'javascript',
    '.ts': 'javascript',
    '.tsx': 'javascript',
    '.html': 'html',
    '.htm': 'html',
    '.css': 'css',
}


def detect_language(filename: str, code: str) -> str:
    ext = os.path.splitext(filename)[1].lower()
    if ext in EXTENSION_LANGUAGE_MAP:
        lang = EXTENSION_LANGUAGE_MAP[ext]
        if lang == 'python' and ('django' in code.lower() or 'from django' in code):
            return 'django'
        return lang

    # No filename/extension hint (pasted code) - guess from content
    stripped = code.strip()
    if stripped.startswith('<') or '<html' in code.lower() or '<!doctype' in code.lower():
        return 'html'
    if 'def ' in code and ':' in code and 'import' in code:
        return 'django' if 'django' in code.lower() else 'python'
    if '{' in code and (';' in code) and ('function' in code or '=>' in code or 'const ' in code or 'let ' in code or 'var ' in code):
        return 'javascript'
    if '{' in code and ':' in code and ';' in code and '@' not in code and 'function' not in code:
        return 'css'
    return 'python'


def analyze_single_file(filename: str, code: str, use_ai: bool = True) -> tuple[str, list[dict]]:
    """Run the full pipeline (rules + optional AI) for one file's code. Returns (language, findings).

    use_ai=False skips the AI provider pass entirely even if one is configured -
    this is how free-plan scans stay rules-only while Pro scans get the AI pass merged in.
    """
    language = detect_language(filename, code)

    findings = rule_engine.run_rules_for_language(code, language)
    findings.extend(rule_engine.detect_missing_security_headers(code, filename))

    if use_ai:
        try:
            provider = get_provider()
            if provider.is_configured:
                ai_findings = provider.analyze(code, filename, language)
                findings.extend(_normalize_ai_findings(ai_findings))
        except Exception as exc:
            # Safety net: an AI provider outage/rate-limit/timeout must never
            # take down the whole zip scan. Worst case, this file just falls
            # back to rule-engine-only findings.
            logger.warning('AI analysis failed for %s, continuing without it: %s', filename, exc)

    return language, _attach_cwe(_deduplicate(findings))


def _attach_cwe(findings: list[dict]) -> list[dict]:
    """Attach a cwe_reference to every finding based on its category, unless
    one was already supplied (e.g. by an AI provider that returns its own)."""
    for f in findings:
        if not f.get('cwe_reference'):
            f['cwe_reference'] = get_cwe_reference(f.get('category', ''))
    return findings


def _normalize_ai_findings(ai_findings: list[dict]) -> list[dict]:
    """Ensure AI-provider output has every field the Issue model expects."""
    normalized = []
    valid_severities = {'critical', 'high', 'medium', 'low', 'info'}
    for item in ai_findings:
        if not isinstance(item, dict) or not item.get('title'):
            continue
        severity = str(item.get('severity', 'medium')).lower()
        if severity not in valid_severities:
            severity = 'medium'
        normalized.append({
            'title': item.get('title', 'AI-detected issue')[:255],
            'category': item.get('category', 'AI Analysis')[:100],
            'severity': severity,
            'owasp_reference': item.get('owasp_reference', '')[:100],
            'cwe_reference': item.get('cwe_reference', '')[:100],
            'description': item.get('description', ''),
            'why_dangerous': item.get('why_dangerous', ''),
            'recommended_fix': item.get('recommended_fix', ''),
            'secure_code_example': item.get('secure_code_example', ''),
            'line_number': item.get('line_number'),
            'code_snippet': item.get('code_snippet', ''),
        })
    return normalized


def _deduplicate(findings: list[dict]) -> list[dict]:
    seen = set()
    unique = []
    for f in findings:
        key = (f['title'], f.get('line_number'))
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    return unique


def compute_security_score(all_findings: list[dict]) -> int:
    """
    Start at 100 and deduct weighted points per issue, floor at 0.
    Weighting mirrors Issue.SEVERITY_WEIGHT so the dashboard score always
    matches what's shown per-issue.
    """
    weights = {'critical': 40, 'high': 20, 'medium': 10, 'low': 4, 'info': 1}
    penalty = sum(weights.get(f['severity'], 0) for f in all_findings)
    score = max(0, 100 - penalty)
    return score


def count_by_severity(all_findings: list[dict]) -> dict:
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for f in all_findings:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1
    return counts
