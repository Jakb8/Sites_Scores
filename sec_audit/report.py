import json
from collections import Counter
from dataclasses import asdict

from .models import SiteResult


def _short(text: str, length: int) -> str:
    return text if len(text) <= length else text[: length - 1] + "…"


def print_table(results: list[SiteResult]) -> None:
    print()
    print(f"{'Site':<44} {'Statut':>6} {'Note':>5} {'Score':>7}  Points faibles")
    print("-" * 104)
    for result in results:
        status = str(result.status_code) if result.status_code else ("OK" if result.reachable else "ERR")
        site = _short(result.final_url or result.url, 44)
        score = "-" if result.score is None else f"{result.score:.1f}"
        failures = ", ".join(check.name for check in result.failed_checks()[:3]) or "-"
        print(f"{site:<44} {status:>6} {result.grade:>5} {score:>7}  {_short(failures, 34)}")


def print_detail(results: list[SiteResult]) -> None:
    for result in results:
        print()
        print(f"=== {result.url} ===")
        if result.final_url and result.final_url != result.url:
            print(f"  Redirection finale : {result.final_url}")
        if result.redirects:
            print(f"  Chainage : {' -> '.join(result.redirects)}")
        if result.status_code is not None:
            print(f"  Code HTTP : {result.status_code}")
        if result.error:
            print(f"  Erreur : {result.error}")
        if result.tls_info.get("error") and result.tls_info.get("applicable") is not False:
            print(f"  Erreur TLS : {result.tls_info['error']}")
        for check in result.checks:
            mark = "OK" if check.passed else ("NA" if check.passed is None else "NO")
            print(
                f"  [{mark}] {check.name:<27} {check.points:>4}/{check.max_points:<4} "
                f"{check.detail}"
            )
        if result.tls_info.get("version"):
            print(
                f"  TLS {result.tls_info['version']} - {result.tls_info.get('cipher')} - "
                f"émetteur : {_short(result.tls_info.get('issuer', ''), 70)}"
            )


def print_summary(results: list[SiteResult]) -> None:
    scores = [result.score for result in results if result.score is not None]
    print()
    print("=== Rapport comparatif ===")
    if scores:
        print(f"Sites évalués    : {len(scores)} / {len(results)}")
        print(f"Score moyen      : {sum(scores) / len(scores):.1f} / 100")
        print(f"Meilleur / pire  : {max(scores):.1f} / {min(scores):.1f}")
    else:
        print("Aucun site n'a pu être évalué.")
    grades = Counter(result.grade for result in results)
    if grades:
        print("Notes            : " + ", ".join(f"{key}={value}" for key, value in sorted(grades.items())))
    issues = Counter(check.name for result in results for check in result.failed_checks())
    if issues:
        print("Points faibles les plus fréquents :")
        for name, count in issues.most_common(5):
            print(f"  {count:>3} x {name}")
    print()


def write_json(results: list[SiteResult], path: str) -> None:
    with open(path, "w", encoding="utf-8") as stream:
        json.dump([asdict(result) for result in results], stream, ensure_ascii=False, indent=2)
    print(f"Rapport JSON écrit : {path}")
