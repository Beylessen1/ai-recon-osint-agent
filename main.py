

import sys
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

# Load .env BEFORE importing anything that reads os.environ at import time
# (e.g. agent.py building an LLM client that expects an API key present).
load_dotenv()

from config import enforce_scope, ALLOWED_TARGETS
from tools.recon import subfinder, httpx_probe
from agent import build_agent
from report import build_report


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("osint-agent")


def parse_httpx_output(raw_output: str) -> list[dict]:
    
    results = []
    for line in raw_output.strip().splitlines():
        if not line.strip():
            continue
        try:
            url_part, rest = line.split(" [", 1)
            status_part, title_part = rest.split("] [", 1)
            status = status_part.strip()
            title = title_part.rstrip("]").strip()
            results.append({
                "url": url_part.strip(),
                "status": status,
                "title": title,
            })
        except ValueError:
            # Line didn't match the expected format — keep the raw text
            # rather than silently dropping it, so nothing gets lost.
            logger.warning("Could not parse httpx line: %r", line)
            results.append({"url": line.strip(), "status": None, "title": None})
    return results


def collect_subdomains(target: str) -> list[dict]:
    
    logger.info("Enumerating subdomains for %s", target)
    raw_subdomains = subfinder(target)
    hostnames = [line.strip() for line in raw_subdomains.strip().splitlines() if line.strip()]

    if not hostnames:
        logger.warning("subfinder returned no subdomains for %s", target)
        return []

    logger.info("Found %d candidate subdomains, probing with httpx", len(hostnames))
    subdomain_records = []
    for host in hostnames:
        raw_probe = httpx_probe(host)
        parsed = parse_httpx_output(raw_probe)
        if parsed:
            subdomain_records.extend(parsed)
        else:
            # Host didn't respond / httpx returned nothing — record as dead
            subdomain_records.append({"url": host, "status": None, "title": None})

    return subdomain_records


def run_agent_reasoning(target: str) -> str:
    
    agent = build_agent()
    prompt = f"Enumerate and check alive subdomains for {target}"
    logger.info("Starting agent run: %s", prompt)

    config = {"configurable": {"thread_id": target}, "recursion_limit": 8}
    result = agent.invoke(
        {"messages": [{"role": "user", "content": prompt}]},
        config=config,
    )
    final_message = result["messages"][-1]
    return final_message.content


def save_report(target: str, subdomain_records: list[dict]) -> Path:
    report = build_report(target=target, subdomains=subdomain_records)

    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = reports_dir / f"{target}_{timestamp}.json"

    with out_path.open("w") as f:
        json.dump(report, f, indent=2)

    return out_path


def main():
    if len(sys.argv) != 2:
        print("Usage: python main.py <target-domain>")
        sys.exit(1)

    target = sys.argv[1]

    # Step 0's guardrail — fail fast, before any tool or agent call runs.
    try:
        enforce_scope(target)
    except ValueError as e:
        logger.error(str(e))
        logger.error("Authorized targets: %s", ", ".join(sorted(ALLOWED_TARGETS)))
        sys.exit(1)

    # Structured, authoritative data collection.
    subdomain_records = collect_subdomains(target)

    # LLM reasoning trace, logged for visibility — not used as the data source.
    try:
        agent_summary = run_agent_reasoning(target)
        logger.info("Agent summary: %s", agent_summary)
    except Exception as e:
        # Agent failure shouldn't take down the whole run — the direct
        # collection pass above already has the real data.
        logger.warning("Agent reasoning step failed, continuing with direct results: %s", e)

    out_path = save_report(target, subdomain_records)
    logger.info("Report saved to %s", out_path)
    print(f"\nDone. {len(subdomain_records)} subdomain records written to {out_path}")


if __name__ == "__main__":
    main()