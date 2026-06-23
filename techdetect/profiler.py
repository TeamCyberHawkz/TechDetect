from __future__ import annotations

import re
import json
import ssl
import time
import socket
import logging
import asyncio
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

from .__version__ import __version__

logger = logging.getLogger("techdetect")


@dataclass
class TechnologyMatch:
    name: str
    confidence: int
    version: Optional[str] = None
    categories: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    implies: list[str] = field(default_factory=list)
    website: str = ""
    oss: bool = False
    saas: bool = False

    def to_dict(self) -> dict:
        d: dict[str, Any] = {
            "name": self.name, "confidence": self.confidence,
            "categories": self.categories,
        }
        if self.version:
            d["version"] = self.version
        if self.evidence:
            d["evidence"] = self.evidence
        if self.implies:
            d["implies"] = self.implies
        if self.website:
            d["website"] = self.website
        if self.oss:
            d["oss"] = self.oss
        if self.saas:
            d["saas"] = self.saas
        return d


@dataclass
class ProfileResult:
    url: str
    status_code: int
    technologies: list[TechnologyMatch] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[dict[str, Any]] = field(default_factory=list)
    meta_tags: dict[str, str] = field(default_factory=dict)
    robots_txt: str = ""
    ssl_issuer: str = ""
    scan_time_ms: float = 0
    error: Optional[str] = None
    final_url: str = ""
    redirect_chain: list[str] = field(default_factory=list)
    content_length: int = 0
    server: str = ""
    content_type: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url, "final_url": self.final_url,
            "status_code": self.status_code, "scan_time_ms": round(self.scan_time_ms, 2),
            "server": self.server, "content_type": self.content_type,
            "content_length": self.content_length, "redirect_chain": self.redirect_chain,
            "technologies": [t.to_dict() for t in self.technologies],
            "headers": self.headers, "cookies": self.cookies,
            "meta_tags": self.meta_tags,
            "robots_txt": self.robots_txt[:500] if self.robots_txt else "",
            "ssl_issuer": self.ssl_issuer, "error": self.error,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @property
    def categories(self) -> list[str]:
        cats: set[str] = set()
        for t in self.technologies:
            cats.update(t.categories)
        return sorted(cats)

    @property
    def technologies_by_category(self) -> dict[str, list[dict]]:
        result: dict[str, list[dict]] = {}
        for t in self.technologies:
            for cat in t.categories:
                result.setdefault(cat, []).append(t.to_dict())
        return result


def _extract_version(template: str | None, match: re.Match) -> str | None:
    if not template:
        return None
    ternary = re.match(r"\\(\d+)\?(.*?):(.*)", template)
    if ternary:
        gi = int(ternary.group(1))
        if gi < len(match.groups()) and match.group(gi):
            return ternary.group(2) or None
        return ternary.group(3) or None
    cond = re.match(r"\\(\d+)\?:(.*)", template)
    if cond:
        gi = int(cond.group(1))
        if gi < len(match.groups()) and match.group(gi):
            return None
        return cond.group(2)
    gr = re.match(r"\\(\d+)(.*)", template)
    if gr:
        gi = int(gr.group(1))
        if gi < len(match.groups()) and match.group(gi):
            return match.group(gi) + (gr.group(2) or "")
        return None
    return template


class TechDetect:

    def __init__(
        self,
        fingerprints_path: str | Path | None = None,
        timeout: float = 15.0,
        max_redirects: int = 10,
        user_agent: str | None = None,
        verify_ssl: bool = True,
        fetch_robots: bool = True,
        max_concurrent: int = 5,
    ):
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.user_agent = user_agent or f"TechDetect/{__version__}"
        self.verify_ssl = verify_ssl
        self.fetch_robots = fetch_robots
        self.max_concurrent = max_concurrent

        if fingerprints_path is None:
            fingerprints_path = Path(__file__).parent / "fingerprints.json"
        else:
            fingerprints_path = Path(fingerprints_path)
        if not fingerprints_path.exists():
            raise FileNotFoundError(f"Fingerprint DB not found: {fingerprints_path}")

        with open(fingerprints_path, "r", encoding="utf-8") as f:
            db = json.load(f)
        self._technologies: dict = db.get("technologies", {})
        self._categories: dict = db.get("categories", {})

        self._compiled: dict[str, dict] = {}
        self._compile_all()

        self._client: httpx.AsyncClient | None = None

    @staticmethod
    def _safe_compile(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern | None:
        try:
            return re.compile(pattern, flags)
        except re.error:
            return None

    def _compile_list(self, items: list[dict], key: str = "regex") -> list[dict]:
        out = []
        for item in items:
            rx = self._safe_compile(item[key]) if item.get(key) else None
            if rx or key != "regex":
                out.append({**item, "regex": rx})
        return out

    def _compile_all(self):
        for name, tech in self._technologies.items():
            c: dict = {}
            pats = tech.get("patterns", {})
            for vec in ("headers", "cookies", "meta"):
                if vec in pats:
                    c[vec] = self._compile_list(pats[vec])
            if "js" in pats:
                c["js"] = self._compile_list(pats["js"], key="regex")
            for vec in ("text", "html", "css", "url", "xhr", "robots", "script_src", "scripts"):
                if vec in pats:
                    c[vec] = self._compile_list(pats[vec])
            if "cert_issuer" in pats:
                c["cert_issuer"] = self._safe_compile(pats["cert_issuer"])
            if "dom" in pats:
                c["dom"] = pats["dom"]
            self._compiled[name] = c

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                follow_redirects=True,
                max_redirects=self.max_redirects,
                verify=self.verify_ssl,
                headers={"User-Agent": self.user_agent},
                http2=True,
            )
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    def _check_headers(self, headers: dict[str, str], compiled: dict) -> list[tuple[int, str | None, list[str]]]:
        out = []
        for pat in compiled.get("headers", []):
            hval = next((v for k, v in headers.items() if k.lower() == pat["name"].lower()), None)
            if hval is None:
                continue
            m = pat["regex"].search(hval) if pat["regex"] else None
            if m:
                ver = _extract_version(pat.get("version"), m)
                out.append((pat["confidence"], ver, [f"Header {pat['name']}: {hval[:100]}"]))
        return out

    def _check_cookies(self, cookies: list[dict], compiled: dict) -> list[tuple[int, str | None, list[str]]]:
        out = []
        for pat in compiled.get("cookies", []):
            for cookie in cookies:
                cname = cookie.get("name", "")
                if pat["name"].lower() in cname.lower():
                    ver = None
                    if pat["regex"]:
                        m = pat["regex"].search(cookie.get("value", ""))
                        if m:
                            ver = _extract_version(pat.get("version"), m)
                    out.append((pat["confidence"], ver, [f"Cookie: {cname}"]))
                    break
        return out

    def _check_meta(self, meta_tags: dict[str, str], compiled: dict) -> list[tuple[int, str | None, list[str]]]:
        out = []
        for pat in compiled.get("meta", []):
            mval = meta_tags.get(pat["name"])
            if mval is None:
                mval = next((v for k, v in meta_tags.items() if k.lower() == pat["name"].lower()), None)
            if mval is None:
                continue
            m = pat["regex"].search(mval) if pat["regex"] else None
            if m:
                ver = _extract_version(pat.get("version"), m)
                out.append((pat["confidence"], ver, [f"Meta {pat['name']}: {mval[:100]}"]))
        return out

    def _check_body(self, body: str, compiled: dict) -> list[tuple[int, str | None, list[str]]]:
        out = []
        for vec in ("text", "html", "css", "scripts"):
            for pat in compiled.get(vec, []):
                if pat["regex"]:
                    m = pat["regex"].search(body)
                    if m:
                        ver = _extract_version(pat.get("version"), m)
                        out.append((pat["confidence"], ver, [f"{vec} match: {m.group()[:80]}"]))
        for pat in compiled.get("script_src", []):
            if pat["regex"]:
                for m in pat["regex"].finditer(body):
                    ver = _extract_version(pat.get("version"), m)
                    out.append((pat["confidence"], ver, [f"Script src: {m.group()[:100]}"]))
        return out

    def _check_js_globals(self, body: str, compiled: dict) -> list[tuple[int, str | None, list[str]]]:
        out = []
        for pat in compiled.get("js", []):
            prop = pat.get("property", "")
            if prop and prop in body:
                ver = None
                if pat["regex"]:
                    idx = body.find(prop)
                    ctx = body[max(0, idx - 50):idx + len(prop) + 200]
                    m = pat["regex"].search(ctx)
                    if m:
                        ver = _extract_version(pat.get("version"), m)
                out.append((pat["confidence"], ver, [f"JS global: {prop}"]))
        return out

    def _check_url(self, url: str, compiled: dict) -> list[tuple[int, str | None, list[str]]]:
        out = []
        for pat in compiled.get("url", []):
            if pat["regex"]:
                m = pat["regex"].search(url)
                if m:
                    ver = _extract_version(pat.get("version"), m)
                    out.append((pat["confidence"], ver, [f"URL match: {url[:100]}"]))
        return out

    def _check_robots(self, robots: str, compiled: dict) -> list[tuple[int, str | None, list[str]]]:
        out = []
        for pat in compiled.get("robots", []):
            if pat["regex"] and robots:
                m = pat["regex"].search(robots)
                if m:
                    ver = _extract_version(pat.get("version"), m)
                    out.append((pat["confidence"], ver, [f"robots.txt: {m.group()[:80]}"]))
        return out

    def _check_ssl(self, issuer: str, compiled: dict) -> list[tuple[int, str | None, list[str]]]:
        cert_pat = compiled.get("cert_issuer")
        if cert_pat and issuer and cert_pat.search(issuer):
            return [(100, None, [f"SSL issuer: {issuer}"])]
        return []

    def _check_xhr(self, body: str, compiled: dict) -> list[tuple[int, str | None, list[str]]]:
        out = []
        for pat in compiled.get("xhr", []):
            if pat["regex"]:
                m = pat["regex"].search(body)
                if m:
                    ver = _extract_version(pat.get("version"), m)
                    out.append((pat["confidence"], ver, [f"XHR pattern: {m.group()[:80]}"]))
        return out

    def _check_constraints(self, detected: dict[str, TechnologyMatch], name: str, tech: dict) -> list[str] | None:
        for excl in tech.get("excludes", []):
            if excl in detected:
                return None
        for req in tech.get("requires", []):
            if req not in detected:
                return None
        for req_cat_id in tech.get("requires_category", []):
            cat = self._categories.get(str(req_cat_id), "")
            if cat and not any(cat in m.categories for m in detected.values()):
                return None
        return tech.get("implies", [])

    async def scan(self, url: str) -> ProfileResult:
        start = time.monotonic()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        result = ProfileResult(url=url, status_code=0)
        parsed = urlparse(url)

        try:
            client = await self._get_client()
            tasks: dict[str, Any] = {"main": client.get(url)}
            if self.fetch_robots:
                tasks["robots"] = client.get(f"{parsed.scheme}://{parsed.netloc}/robots.txt")

            responses: dict[str, Any] = {}
            for key, task in tasks.items():
                try:
                    responses[key] = await task
                except Exception as e:
                    logger.debug("Failed to fetch %s: %s", key, e)
                    responses[key] = None

            main_resp = responses.get("main")
            if main_resp is None or isinstance(main_resp, Exception):
                result.error = str(main_resp) if main_resp else "Failed to connect"
                result.scan_time_ms = (time.monotonic() - start) * 1000
                return result

            result.status_code = main_resp.status_code
            result.final_url = str(main_resp.url)
            result.headers = dict(main_resp.headers)
            result.server = main_resp.headers.get("server", "")
            result.content_type = main_resp.headers.get("content-type", "")
            result.content_length = len(main_resp.content)
            if main_resp.history:
                result.redirect_chain = [str(r.url) for r in main_resp.history]

            body = ""
            try:
                body = main_resp.text
            except Exception:
                body = main_resp.content.decode("utf-8", errors="replace")

            result.cookies = [
                {"name": c.name, "value": c.value, "domain": c.domain, "path": c.path}
                for c in main_resp.cookies.jar
            ]
            result.meta_tags = self._parse_meta(body)

            robots_resp = responses.get("robots")
            if robots_resp and hasattr(robots_resp, "text"):
                try:
                    result.robots_txt = robots_resp.text
                except Exception:
                    pass

            try:
                result.ssl_issuer = await self._get_ssl_issuer(parsed.hostname)
            except Exception:
                pass

            detected: dict[str, TechnologyMatch] = {}

            for tech_name, tech_data in self._technologies.items():
                compiled = self._compiled.get(tech_name, {})
                if not compiled:
                    continue

                implies = self._check_constraints(detected, tech_name, tech_data)
                if implies is None:
                    continue

                evidence: list[tuple[int, str | None, list[str]]] = []
                evidence.extend(self._check_headers(result.headers, compiled))
                evidence.extend(self._check_cookies(result.cookies, compiled))
                evidence.extend(self._check_meta(result.meta_tags, compiled))
                evidence.extend(self._check_body(body, compiled))
                evidence.extend(self._check_js_globals(body, compiled))
                evidence.extend(self._check_url(url, compiled))
                evidence.extend(self._check_robots(result.robots_txt, compiled))
                evidence.extend(self._check_ssl(result.ssl_issuer, compiled))
                evidence.extend(self._check_xhr(body, compiled))

                if evidence:
                    combined = 1.0
                    best_ver = None
                    ev_list: list[str] = []
                    for conf, ver, ev in evidence:
                        combined *= (1 - conf / 100)
                        ev_list.extend(ev)
                        if ver and not best_ver:
                            best_ver = ver
                    final_conf = min(round((1 - combined) * 100), 100)

                    if final_conf >= 10:
                        detected[tech_name] = TechnologyMatch(
                            name=tech_name,
                            confidence=final_conf,
                            version=best_ver,
                            categories=tech_data.get("categories", []),
                            evidence=ev_list[:5],
                            implies=implies if isinstance(implies, list) else [],
                            website=tech_data.get("website", ""),
                            oss=tech_data.get("oss", False),
                            saas=tech_data.get("saas", False),
                        )

            for tech_name, match in list(detected.items()):
                for imp in match.implies:
                    if imp not in detected:
                        td = self._technologies.get(imp, {})
                        if td:
                            detected[imp] = TechnologyMatch(
                                name=imp,
                                confidence=max(10, match.confidence - 20),
                                categories=td.get("categories", []),
                                evidence=[f"Implied by {tech_name}"],
                            )

            result.technologies = sorted(detected.values(), key=lambda t: -t.confidence)

        except httpx.ConnectError as e:
            result.error = f"Connection failed: {e}"
        except httpx.TimeoutException:
            result.error = "Request timed out"
        except Exception as e:
            result.error = f"Scan error: {e}"
            logger.exception("Scan error for %s", url)

        result.scan_time_ms = (time.monotonic() - start) * 1000
        return result

    async def scan_many(self, urls: list[str], max_concurrent: int | None = None) -> dict[str, ProfileResult]:
        sem = asyncio.Semaphore(max_concurrent or self.max_concurrent)

        async def _one(url: str) -> tuple[str, ProfileResult]:
            async with sem:
                return url, await self.scan(url)

        results = {}
        for coro in asyncio.as_completed([_one(u) for u in urls]):
            url, result = await coro
            results[url] = result
        return results

    @staticmethod
    def _parse_meta(html: str) -> dict[str, str]:
        meta: dict[str, str] = {}
        for m in re.finditer(
            r'<meta\s+[^>]*?name=["\']?([^"\'\s]+)["\']?[^>]*?content=["\']([^"\']*)["\']',
            html, re.IGNORECASE,
        ):
            meta[m.group(1)] = m.group(2)
        for m in re.finditer(
            r'<meta\s+[^>]*?content=["\']([^"\']*)["\'][^>]*?name=["\']?([^"\'\s]+)["\']?',
            html, re.IGNORECASE,
        ):
            meta.setdefault(m.group(2), m.group(1))
        for m in re.finditer(
            r'<meta\s+[^>]*?property=["\']?([^"\'\s]+)["\']?[^>]*?content=["\']([^"\']*)["\']',
            html, re.IGNORECASE,
        ):
            meta[m.group(1)] = m.group(2)
        return meta

    @staticmethod
    async def _get_ssl_issuer(hostname: str) -> str:
        def _fetch() -> str:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if cert and "issuer" in cert:
                        parts = []
                        for rdn in cert["issuer"]:
                            for attr in rdn:
                                if attr[0] in ("organizationName", "commonName"):
                                    parts.append(attr[1])
                        return ", ".join(parts)
                    return ""
        try:
            return await asyncio.get_event_loop().run_in_executor(None, _fetch)
        except Exception:
            return ""
