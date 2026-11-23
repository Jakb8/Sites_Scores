from .models import Check

GRADES = ((90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "E"))

BAREME = [
    ("En-têtes", "HSTS", 12),
    ("En-têtes", "CSP", 12),
    ("En-têtes", "X-Content-Type-Options", 8),
    ("En-têtes", "Protection framing", 8),
    ("En-têtes", "Referrer-Policy", 5),
    ("En-têtes", "Permissions-Policy", 5),
    ("Cookies", "Cookie Secure", 8),
    ("Cookies", "Cookie HttpOnly", 7),
    ("Cookies", "Cookie SameSite", 5),
    ("TLS", "Version TLS", 10),
    ("TLS", "Validite du certificat", 8),
    ("TLS", "SAN / nom d'hote", 6),
    ("TLS", "Suite cryptographique", 6),
]


def compute_score(checks: list[Check]) -> tuple[float | None, str]:
    applicable = [check for check in checks if check.passed is not None and check.max_points > 0]
    if not applicable:
        return None, "N/A"
    maximum = sum(check.max_points for check in applicable)
    earned = sum(check.points for check in applicable)
    value = round(100 * earned / maximum, 1)
    grade = next(letter for threshold, letter in GRADES if value >= threshold)
    return value, grade


def print_bareme() -> None:
    print("Barème de notation (100 points au maximum)")
    print("-" * 62)
    for category, name, points in BAREME:
        print(f"  {category:<10} {name:<28} {points:>3} pts")
    print("-" * 62)
    print("  Total : 100 pts")
    print("  Note = points obtenus / points applicables x 100")
    print("  Les contrôles non applicables (aucun cookie, URL HTTP) sont exclus")
    print("  du dénominateur pour garder les sites comparables.")
    print("  A >= 90   B >= 75   C >= 60   D >= 40   E < 40   N/A = site injoignable")
    print("  Un contrôle partiellement conforme reçoit une fraction des points ;")
    print("  le détail et la raison figurent dans le rapport verbeux (--verbose).")
