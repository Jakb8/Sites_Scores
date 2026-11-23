import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import report, scoring
from .http_checks import audit_http
from .models import SiteResult
from .tls_checks import audit_tls


def normalize(raw: str) -> str:
    value = raw.strip()
    if "://" not in value:
        value = "https://" + value
    return value


def load_sites(sites: list[str], path: str | None) -> list[str]:
    targets = [normalize(item) for item in sites]
    if path:
        with open(path, encoding="utf-8") as stream:
            for line in stream:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(normalize(line))
    return [target for target in targets if target]


def audit_site(url: str, timeout: float) -> SiteResult:
    result = SiteResult(url=url)
    http_checks, metadata = audit_http(url, timeout)
    result.checks.extend(http_checks)
    result.final_url = metadata["final_url"]
    result.status_code = metadata["status_code"]
    result.redirects = metadata["redirects"]
    result.error = metadata["error"]
    result.reachable = result.status_code is not None and result.error is None

    tls_checks, tls_metadata = audit_tls(result.final_url or url, timeout)
    result.checks.extend(tls_checks)
    result.tls_info = tls_metadata
    result.score, result.grade = scoring.compute_score(result.checks)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sec_audit",
        description="Audit passif de la configuration de securite de sites web (requetes normales, aucun payload)",
    )
    parser.add_argument("sites", nargs="*", help="URL ou nom d'hote a auditer")
    parser.add_argument("-f", "--file", help="fichier d'une cible par ligne")
    parser.add_argument("-w", "--workers", type=int, default=4, help="nombre d'audits en parallele (defaut 4)")
    parser.add_argument("-t", "--timeout", type=float, default=10.0, help="delai par requete en secondes (defaut 10)")
    parser.add_argument("--json", dest="json_path", help="ecrire le rapport detaille en JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="afficher le detail des controles")
    parser.add_argument("--bareme", action="store_true", help="afficher le bareme de notation")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.bareme:
        scoring.print_bareme()
        return 0

    targets = load_sites(args.sites, args.file)
    if not targets:
        parser.error("indiquez au moins une cible ou un fichier avec --file")
    if args.workers < 1:
        parser.error("--workers doit etre >= 1")
    if args.timeout <= 0:
        parser.error("--timeout doit etre > 0")

    ordered: dict[str, SiteResult] = {}
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(audit_site, target, args.timeout): target for target in targets}
        for future in as_completed(futures):
            try:
                ordered[futures[future]] = future.result()
            except Exception as exc:
                ordered[futures[future]] = SiteResult(url=futures[future], error=f"Erreur inattendue: {exc}")
    results = [ordered[target] for target in targets]

    report.print_table(results)
    if args.verbose:
        report.print_detail(results)
    report.print_summary(results)
    if args.json_path:
        report.write_json(results, args.json_path)
    return 0
