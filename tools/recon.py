

import subprocess
import logging

from config import enforce_scope

logger = logging.getLogger("osint-agent.recon")


def subfinder(domain: str) -> str:
    
    enforce_scope(domain)

    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except FileNotFoundError:
        logger.error("subfinder binary not found on PATH. Is it installed? ")
        return ""
    except subprocess.TimeoutExpired:
        logger.warning("subfinder timed out for %s", domain)
        return ""

    if result.returncode != 0:
        logger.warning("subfinder exited %d for %s: %s", result.returncode, domain, result.stderr.strip())

    return result.stdout


def httpx_probe(url: str) -> str:
    
    enforce_scope(url)

    try:
        result = subprocess.run(
            ["httpx", "-silent", "-status-code", "-title", "-u", url],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError:
        logger.error("httpx binary not found on PATH. Is it installed? (Step 1)")
        return ""
    except subprocess.TimeoutExpired:
        logger.warning("httpx timed out for %s", url)
        return ""

    return result.stdout


def dnsx_resolve(hostname: str) -> str:
    
    enforce_scope(hostname)

    try:
        result = subprocess.run(
            ["dnsx", "-silent", "-a", "-resp"],
            input=hostname,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError:
        logger.error("dnsx binary not found on PATH. Is it installed? ")
        return ""
    except subprocess.TimeoutExpired:
        logger.warning("dnsx timed out for %s", hostname)
        return ""

    return result.stdout