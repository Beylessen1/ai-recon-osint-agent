
ALLOWED_TARGETS: set[str] = {
    "acme-corp.com", "scanme.nmap.org"  # example
}


def enforce_scope(hostname: str) -> None:
    normalized = hostname.strip().lower().rstrip(".")
    # Strip a scheme if one was passed in (e.g. "https://dev.acme-corp.com")
    normalized = normalized.split("://", 1)[-1].split("/", 1)[0]

    allowed = {t.lower() for t in ALLOWED_TARGETS}
    in_scope = any(
        normalized == target or normalized.endswith("." + target)
        for target in allowed
    )

    if not in_scope:
        raise ValueError(
            f"'{hostname}' is not in scope of ALLOWED_TARGETS ({sorted(allowed)}). "
        )