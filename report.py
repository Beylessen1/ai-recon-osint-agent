

from datetime import datetime, timezone


def build_report(target: str, subdomains: list[dict]) -> dict:
    
    alive = [s for s in subdomains if s.get("status") is not None]
    dead = [s for s in subdomains if s.get("status") is None]

    return {
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_subdomains": len(subdomains),
            "alive": len(alive),
            "dead_or_unreachable": len(dead),
        },
        "subdomains": subdomains,
    }