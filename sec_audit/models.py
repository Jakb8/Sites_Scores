from dataclasses import dataclass, field


@dataclass
class Check:
    name: str
    category: str
    passed: bool | None
    points: float
    max_points: float
    detail: str


@dataclass
class SiteResult:
    url: str
    final_url: str | None = None
    status_code: int | None = None
    reachable: bool = False
    error: str | None = None
    redirects: list[str] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)
    tls_info: dict = field(default_factory=dict)
    score: float | None = None
    grade: str = "N/A"

    def failed_checks(self) -> list[Check]:
        return [check for check in self.checks if check.passed is False]
