"""
Generates a shields.io-style SVG badge for a scan's security score.

Kept as plain string templating (no image libraries needed) so this stays
fast and dependency-free - the same approach shields.io itself uses under
the hood for flat-style badges.
"""

LABEL_TEXT = 'Fora AI security'

FONT_FAMILY = 'Verdana,Geneva,DejaVu Sans,sans-serif'


def _color_for_score(score: int) -> str:
    if score >= 90:
        return '#10b981'   # green
    if score >= 75:
        return '#4c8dff'   # blue
    if score >= 50:
        return '#e0b83e'   # amber
    return '#e5484d'       # red


def _text_width(text: str) -> int:
    """Rough monospace-ish width estimate - good enough for badge sizing
    without pulling in a font-metrics library."""
    return max(6, int(len(text) * 6.5))


def render_score_badge_svg(score: int, grade: str) -> str:
    """Returns a complete <svg> string: 'Fora AI security | 92/100 (A)'."""
    right_text = f'{score}/100 ({grade})'
    color = _color_for_score(score)

    left_w = _text_width(LABEL_TEXT) + 20
    right_w = _text_width(right_text) + 20
    total_w = left_w + right_w

    left_center = left_w / 2
    right_center = left_w + right_w / 2

    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="20" role="img" aria-label="{LABEL_TEXT}: {right_text}">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total_w}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{left_w}" height="20" fill="#3a3a3a"/>
    <rect x="{left_w}" width="{right_w}" height="20" fill="{color}"/>
    <rect width="{total_w}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="{FONT_FAMILY}" font-size="11">
    <text x="{left_center}" y="14" fill="#010101" fill-opacity=".3">{LABEL_TEXT}</text>
    <text x="{left_center}" y="13">{LABEL_TEXT}</text>
    <text x="{right_center}" y="14" fill="#010101" fill-opacity=".3">{right_text}</text>
    <text x="{right_center}" y="13">{right_text}</text>
  </g>
</svg>'''


def render_unavailable_badge_svg() -> str:
    """Shown when a scan_id doesn't exist or badge sharing is off."""
    text = 'badge unavailable'
    w = _text_width(LABEL_TEXT) + 20
    w2 = _text_width(text) + 20
    total_w = w + w2
    center1 = w / 2
    center2 = w + w2 / 2
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="20" role="img" aria-label="{LABEL_TEXT}: {text}">
  <g clip-path="inset(0% round 3px)">
    <rect width="{w}" height="20" fill="#3a3a3a"/>
    <rect x="{w}" width="{w2}" height="20" fill="#8b8d98"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="{FONT_FAMILY}" font-size="11">
    <text x="{center1}" y="14" fill="#010101" fill-opacity=".3">{LABEL_TEXT}</text>
    <text x="{center1}" y="13">{LABEL_TEXT}</text>
    <text x="{center2}" y="14" fill="#010101" fill-opacity=".3">{text}</text>
    <text x="{center2}" y="13">{text}</text>
  </g>
</svg>'''
