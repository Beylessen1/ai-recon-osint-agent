
import os
import logging
import requests

from config import enforce_scope

logger = logging.getLogger("osint-agent.enrichment")

VT_BASE_URL = "https://www.virustotal.com/api/v3"


def check_virustotal_ip(ip: str) -> dict | None:
    
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        logger.warning("VIRUSTOTAL_API_KEY not set — skipping enrichment for %s", ip)
        return None

    try:
        response = requests.get(
            f"{VT_BASE_URL}/ip_addresses/{ip}",
            headers={"x-apikey": api_key},
            timeout=15,
        )
    except requests.RequestException as e:
        logger.warning("VirusTotal request failed for %s: %s", ip, e)
        return None

    if response.status_code == 429:
        logger.warning("VirusTotal rate limit hit — skipping enrichment for %s", ip)
        return None
    if response.status_code != 200:
        logger.warning("VirusTotal returned %d for %s", response.status_code, ip)
        return None

    return response.json()


def check_virustotal_domain(domain: str) -> dict | None:
    enforce_scope(domain)
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        logger.warning("VIRUSTOTAL_API_KEY not set — skipping enrichment for %s", domain)
        return None

    try:
        response = requests.get(
            f"{VT_BASE_URL}/domains/{domain}",
            headers={"x-apikey": api_key},
            timeout=15,
        )
    except requests.RequestException as e:
        logger.warning("VirusTotal request failed for %s: %s", domain, e)
        return None

    if response.status_code != 200:
        logger.warning("VirusTotal returned %d for %s", response.status_code, domain)
        return None

    return response.json()