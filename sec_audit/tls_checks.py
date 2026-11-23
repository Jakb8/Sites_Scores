import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlparse

from .common import make_check
from .models import Check


def _host_matches(cert: dict, host: str) -> bool:
    names: list[str] = []
    for kind, value in cert.get("subjectAltName", ()):
        if kind == "DNS":
            names.append(value.lower())
        elif kind == "IP Address":
            names.append(value)
    try:
        return str(ipaddress.ip_address(host)) in names
    except ValueError:
        pass
    host = host.lower()
    for name in names:
        if name == host:
            return True
        if name.startswith("*."):
            suffix = name[1:]
            if host.endswith(suffix):
                prefix = host[: -len(suffix)]
                if prefix and "." not in prefix:
                    return True
    return False


def _parse_date(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def audit_tls(url: str, timeout: float) -> tuple[list[Check], dict[str, Any]]:
    target = url if "://" in url else "https://" + url
    parsed = urlparse(target)
    if parsed.scheme != "https":
        return [], {"applicable": False, "error": "URL en HTTP : aucun controle TLS"}
    host = parsed.hostname
    port = parsed.port or 443
    if not host:
        return [], {"applicable": False, "error": "Hote absent de l'URL"}

    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                version = tls.version()
                cipher = tls.cipher()
                cert = tls.getpeercert()
    except (OSError, ssl.SSLError, ValueError) as exc:
        return [], {
            "applicable": True,
            "error": f"{type(exc).__name__}: {exc}",
            "host": host,
            "port": port,
        }

    checks: list[Check] = []
    if version == "TLSv1.3":
        make_check(checks, "Version TLS", "TLS", True, 10, 10, "TLS 1.3")
    elif version == "TLSv1.2":
        make_check(checks, "Version TLS", "TLS", False, 8, 10, "TLS 1.2 (TLS 1.3 recommande)")
    else:
        make_check(checks, "Version TLS", "TLS", False, 0, 10, f"Version {version} obsolete")

    not_before = _parse_date(cert.get("notBefore", ""))
    not_after = _parse_date(cert.get("notAfter", ""))
    now = datetime.now(timezone.utc)
    if not_before and not_after:
        days = (not_after - now).days
        if not_before <= now < not_after and days >= 30:
            make_check(checks, "Validite du certificat", "TLS", True, 8, 8, f"Valide, expire dans {days} jours")
        elif not_before <= now < not_after:
            make_check(checks, "Validite du certificat", "TLS", False, 4, 8, f"Valide mais expire dans {days} jours")
        else:
            make_check(checks, "Validite du certificat", "TLS", False, 0, 8, "Certificat expire ou pas encore valide")
    else:
        make_check(checks, "Validite du certificat", "TLS", False, 0, 8, "Dates du certificat illegibles")

    matches = _host_matches(cert, host)
    make_check(
        checks,
        "SAN / nom d'hote",
        "TLS",
        matches,
        6 if matches else 0,
        6,
        "Le SAN couvre le nom d'hote" if matches else f"Le SAN ne couvre pas {host}",
    )

    cipher_name = cipher[0] if cipher else "inconnu"
    bits = cipher[2] if cipher else 0
    if bits >= 128:
        points, detail = 6, f"{cipher_name} ({bits} bits)"
    elif bits >= 112:
        points, detail = 4, f"{cipher_name} ({bits} bits, force limite)"
    else:
        points, detail = 0, f"{cipher_name} ({bits} bits, trop faible)"
    make_check(checks, "Suite cryptographique", "TLS", points == 6, points, 6, detail)

    issuer = cert.get("issuer", ())
    issuer_text = ", ".join(f"{key}={value}" for item in issuer for key, value in item) or "inconnu"
    meta = {
        "applicable": True,
        "error": None,
        "host": host,
        "port": port,
        "version": version,
        "cipher": cipher_name,
        "bits": bits,
        "issuer": issuer_text,
        "not_after": cert.get("notAfter"),
        "subject_alt_names": [value for _, value in cert.get("subjectAltName", ())],
    }
    return checks, meta
