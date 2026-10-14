"""Which AI product is calling us, and which of them may see which data source.

A provider label is a DATA-GOVERNANCE control (results sent to OpenAI/Google leave the
organisation's Anthropic-only setup), not an authentication boundary: it stops accidental
exposure, but a user who deliberately mislabels their own client can still do so."""
from urllib.parse import urlsplit

PROVIDERS = ("claude", "openai", "gemini", "other")
LABELS = {"claude": "Claude (Anthropic)", "openai": "ChatGPT / OpenAI", "gemini": "Gemini (Google)",
          "other": "Other"}
DEFAULT_ALLOWED = ["claude"]          # a new data source is visible to Claude only
LEGACY_PROVIDER = "claude"            # tokens issued before providers existed were Claude's

# Known web clients are identified by where they send the user back (not user-selectable).
_HOSTS = {"claude.ai": "claude", "www.claude.ai": "claude",
          "chatgpt.com": "openai", "chat.openai.com": "openai"}
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}


def normalize(value: str | None) -> str:
    v = (value or "").strip().lower()
    return v if v in PROVIDERS else LEGACY_PROVIDER


def provider_for_redirect_uris(uris: list[str]) -> str:
    """'claude' / 'openai' when EVERY redirect URI is a known web host of that provider;
    '' (ask the user) for loopback/native or mixed/unknown clients."""
    found = set()
    for u in uris:
        try:
            host = (urlsplit(u).hostname or "").lower()
        except ValueError:
            return ""
        if host in _LOOPBACK or host not in _HOSTS:
            return ""
        found.add(_HOSTS[host])
    return found.pop() if len(found) == 1 else ""


def is_allowed(allowed, provider: str) -> bool:
    """May `provider` use a data source whose allow-list is `allowed`? (None/[] = nobody)"""
    return normalize(provider) in set(allowed or [])


def clean_allowed(values) -> list[str]:
    """Validated, de-duplicated, ordered list (never empty-by-accident: [] means 'nobody')."""
    got = {normalize(v) for v in (values or []) if str(v).strip().lower() in PROVIDERS}
    return [p for p in PROVIDERS if p in got]
