import re
from typing import Any

import requests

from .common import make_check
from .models import Check

USER_AGENT = "Mozilla/5.0 (compatible; SecConfigAuditor/1.0; audit passif)"


def _rest_value(cookie: Any, key: str) -> str | None:
    for name, value in getattr(cookie, "_rest", {}).items():
        if name.lower() == key.lower():
            return value
    return None


def _has_rest_attribute(cookie: Any, key: str) -> bool:
    return any(name.lower() == key.lower() for name in getattr(cookie, "_rest", {}))


def _cookie_rows(session: requests.Session) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for cookie in session.cookies:
        samesite = _rest_value(cookie, "SameSite")
        rows.append(
            {
                "name": cookie.name,
                "secure": bool(cookie.secure),
                "httponly": _has_rest_attribute(cookie, "HttpOnly")
                or bool(getattr(cookie, "httponly", False)),
                "samesite": samesite.lower() if samesite else None,
                "domain": cookie.domain,
            }
        )
    return rows


def _header_checks(checks: list[Check], headers: dict[str, str]) -> None:
    hsts = headers.get("strict-transport-security", "")
    csp = headers.get("content-security-policy", "")

    if not hsts:
        make_check(checks, "HSTS", "En-têtes", False, 0, 12, "Strict-Transport-Security absent")
    else:
        match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
        age = int(match.group(1)) if match else 0
        if age >= 31536000 and "includesubdomains" in hsts.lower():
            make_check(checks, "HSTS", "En-têtes", True, 12, 12, "max-age >= 1 an et includeSubDomains")
        elif age >= 31536000:
            make_check(checks, "HSTS", "En-têtes", False, 10, 12, "max-age valide mais includeSubDomains absent")
        else:
            make_check(checks, "HSTS", "En-têtes", False, 4, 12, "max-age absent ou inferieur a 31536000")

    if not csp:
        make_check(checks, "CSP", "En-têtes", False, 0, 12, "Content-Security-Policy absente")
    elif "default-src" in csp.lower() and "unsafe-inline" not in csp.lower():
        make_check(checks, "CSP", "En-têtes", True, 12, 12, "CSP avec default-src et sans unsafe-inline")
    elif "default-src" in csp.lower():
        make_check(checks, "CSP", "En-têtes", False, 8, 12, "CSP presente mais unsafe-inline autorise")
    else:
        make_check(checks, "CSP", "En-têtes", False, 6, 12, "CSP presente mais sans default-src")

    nosniff = headers.get("x-content-type-options", "").strip().lower() == "nosniff"
    make_check(
        checks,
        "X-Content-Type-Options",
        "En-têtes",
        nosniff,
        8 if nosniff else 0,
        8,
        "nosniff present" if nosniff else "X-Content-Type-Options: nosniff absent",
    )

    frame = headers.get("x-frame-options", "").strip().lower()
    frame_ancestors = "frame-ancestors" in csp.lower()
    frame_ok = frame in ("deny", "sameorigin") or frame_ancestors
    make_check(
        checks,
        "Protection framing",
        "En-têtes",
        frame_ok,
        8 if frame_ok else 0,
        8,
        "X-Frame-Options ou frame-ancestors present" if frame_ok else "Aucune protection contre le framing",
    )

    referrer = headers.get("referrer-policy", "").strip().lower()
    accepted = {
        "no-referrer",
        "same-origin",
        "origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }
    referrer_ok = referrer in accepted
    make_check(
        checks,
        "Referrer-Policy",
        "En-têtes",
        referrer_ok,
        5 if referrer_ok else 0,
        5,
        f"Referrer-Policy: {referrer}" if referrer_ok else "Referrer-Policy absent ou trop permissif",
    )

    permissions = headers.get("permissions-policy") or headers.get("feature-policy")
    make_check(
        checks,
        "Permissions-Policy",
        "En-têtes",
        bool(permissions),
        5 if permissions else 0,
        5,
        "Permissions-Policy present" if permissions else "Permissions-Policy absent",
    )


def _cookie_checks(checks: list[Check], cookies: list[dict[str, Any]]) -> None:
    if not cookies:
        make_check(checks, "Cookies", "Cookies", None, 0, 0, "Aucun cookie recu - controle non applicable")
        return

    def evaluate(label: str, predicate: Any, maximum: float, success: str, failure: str) -> None:
        valid = [cookie for cookie in cookies if predicate(cookie)]
        invalid = ", ".join(cookie["name"] for cookie in cookies if not predicate(cookie))
        if len(valid) == len(cookies):
            points, detail = maximum, success
        elif valid:
            points, detail = round(maximum / 2, 1), f"{failure} : {invalid}"
        else:
            points, detail = 0.0, f"{failure} : {invalid}"
        make_check(checks, label, "Cookies", points == maximum, points, maximum, detail)

    evaluate(
        "Cookie Secure",
        lambda cookie: cookie["secure"],
        8,
        "Tous les cookies possedent Secure",
        "Attribut Secure absent",
    )
    evaluate(
        "Cookie HttpOnly",
        lambda cookie: cookie["httponly"],
        7,
        "Tous les cookies possedent HttpOnly",
        "Attribut HttpOnly absent",
    )
    evaluate(
        "Cookie SameSite",
        lambda cookie: cookie["samesite"] in ("lax", "strict"),
        5,
        "SameSite=Lax ou Strict sur tous les cookies",
        "SameSite absent ou permissif",
    )


def audit_http(url: str, timeout: float) -> tuple[list[Check], dict[str, Any]]:
    checks: list[Check] = []
    meta: dict[str, Any] = {
        "final_url": url,
        "status_code": None,
        "redirects": [],
        "cookies": [],
        "error": None,
    }
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "fr,en;q=0.9",
        }
    )
    try:
        response = session.get(url, timeout=timeout, allow_redirects=True, verify=True)
    except requests.RequestException as exc:
        meta["error"] = f"{type(exc).__name__}: {exc}"
        return checks, meta

    meta["final_url"] = response.url
    meta["status_code"] = response.status_code
    meta["redirects"] = [item.url for item in response.history]
    meta["cookies"] = _cookie_rows(session)

    headers = {key.lower(): value for key, value in response.headers.items()}
    _header_checks(checks, headers)
    _cookie_checks(checks, meta["cookies"])
    return checks, meta
