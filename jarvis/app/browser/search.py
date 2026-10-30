from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qs, quote_plus, unquote, urlsplit

from app.browser.models import PageSnapshot, SearchResult
from app.browser.security import BrowserSecurityError, normalize_url


SEARCH_ENGINES: dict[str, str] = {
    "google": "https://www.google.com/search?hl=es&q={query}",
    "bing": "https://www.bing.com/search?setlang=es&q={query}",
    "duckduckgo": "https://html.duckduckgo.com/html/?kl=es-es&q={query}",
    "youtube": "https://www.youtube.com/results?search_query={query}",
}


@dataclass(frozen=True, slots=True)
class SearchReport:
    query: str
    engine: str
    url: str
    results: tuple[SearchResult, ...]
    requires_manual_verification: bool = False


def supported_search_engines() -> tuple[str, ...]:
    return tuple(SEARCH_ENGINES)


def build_search_url(query: str, engine: str = "google") -> str:
    if not query.strip():
        raise ValueError("Indica qué quieres buscar.")
    template = SEARCH_ENGINES.get(engine.casefold().strip())
    if template is None:
        raise ValueError("Ese buscador no está configurado.")
    return template.format(query=quote_plus(query.strip()))


def build_search_report(query: str, engine: str, snapshot: PageSnapshot, *, limit: int = 5) -> SearchReport:
    selected = engine.casefold().strip()
    if selected not in SEARCH_ENGINES:
        raise ValueError("Ese buscador no está configurado.")
    return SearchReport(
        query=query.strip(),
        engine=selected,
        url=snapshot.url,
        results=tuple(extract_search_results(snapshot, query, selected, limit=limit)),
        requires_manual_verification=requires_manual_verification(snapshot, selected),
    )


def requires_manual_verification(snapshot: PageSnapshot, engine: str) -> bool:
    if engine != "google":
        return False
    url, text = snapshot.url.casefold(), snapshot.text.casefold()
    return "google." in url and (
        "/sorry/" in url
        or "tráfico inusual" in text
        or "trafico inusual" in text
        or "unusual traffic" in text
        or "verify you are human" in text
    )


def extract_search_results(snapshot: PageSnapshot, query: str, engine: str, *, limit: int = 5) -> list[SearchResult]:
    candidates: list[SearchResult] = []
    seen: set[str] = set()
    for link in snapshot.links:
        if not link.href or not link.text:
            continue
        target = _result_target(link.href, engine)
        if target is None or target in seen or _is_search_navigation(target, engine):
            continue
        seen.add(target)
        parsed = urlsplit(target)
        title = re.sub(r"\s+", " ", link.text).strip()
        candidates.append(SearchResult(0, title[:220], target, parsed.hostname or "sitio desconocido"))
    ranked = sorted(candidates, key=lambda item: _score(item, query), reverse=True)[:limit]
    return [SearchResult(index, item.title, item.url, item.domain) for index, item in enumerate(ranked, 1)]


def _result_target(value: str, engine: str) -> str | None:
    try:
        candidate = normalize_url(value)
    except BrowserSecurityError:
        return None
    parsed = urlsplit(candidate)
    host = (parsed.hostname or "").casefold()
    if engine == "google" and host.endswith("google.com") and parsed.path == "/url":
        redirect = (parse_qs(parsed.query).get("q") or parse_qs(parsed.query).get("url") or [""])[0]
        if redirect:
            try:
                return normalize_url(unquote(redirect))
            except BrowserSecurityError:
                return None
    if engine == "duckduckgo" and host.endswith("duckduckgo.com") and parsed.path.startswith("/l/"):
        redirect = (parse_qs(parsed.query).get("uddg") or [""])[0]
        if redirect:
            try:
                return normalize_url(unquote(redirect))
            except BrowserSecurityError:
                return None
    return candidate


def _is_search_navigation(url: str, engine: str) -> bool:
    parsed = urlsplit(url)
    host = (parsed.hostname or "").casefold()
    if engine == "google":
        return host.endswith("google.com")
    if engine == "bing":
        return host.endswith("bing.com")
    if engine == "duckduckgo":
        return host.endswith("duckduckgo.com")
    if engine == "youtube":
        return host.endswith("youtube.com") and not parsed.path.startswith("/watch")
    return False


def _score(result: SearchResult, query: str) -> tuple[int, int, int]:
    terms = [term for term in re.findall(r"[\wáéíóúñ]+", query.casefold()) if len(term) > 1]
    haystack = f"{result.title} {result.domain}".casefold()
    matched = sum(term in haystack for term in terms)
    official = int(any(marker in result.domain for marker in (".gov", ".edu", "docs.", "developer.")))
    return matched, official, -len(result.url)
