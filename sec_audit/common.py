from .models import Check


def make_check(
    checks: list[Check],
    name: str,
    category: str,
    passed: bool | None,
    points: float,
    maximum: float,
    detail: str,
) -> None:
    checks.append(
        Check(
            name=name,
            category=category,
            passed=passed,
            points=float(points),
            max_points=float(maximum),
            detail=detail,
        )
    )
