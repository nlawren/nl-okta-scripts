"""Export all Okta users, including deactivated ones, to JSON and CSV.

READ ONLY: this script only makes GET requests. Nothing in Okta changes.

Each user is exported with their login, the basic Okta fields (status and key
dates), days_since_status_changed (for deactivated users, usually days since
deactivation) and days_since_last_login (blank if they have never logged in).

Output (both written every run):
    okta_users.json
    okta_users.csv

Environment:
    OKTA_ORG_URL    e.g. https://example.okta.com
    OKTA_API_TOKEN  Okta API token (sent as "SSWS <token>")

Locally these come from .env (copy .env.example):
    uv run --env-file .env export_users.py

The output files contain personal information. Keep them out of git.
"""

import argparse
import csv
import json
import logging
import os
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

import requests

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

OKTA_ORG_URL: Final = os.getenv("OKTA_ORG_URL", "").strip().rstrip("/")

PAGE_SIZE: Final = "200"  # Okta's maximum page size for listing users

# Okta's API calls a deactivated user "DEPROVISIONED" (the admin console shows "Deactivated").
# The default user list leaves these out, so they need a separate search.
DEACTIVATED_SEARCH: Final = 'status eq "DEPROVISIONED"'

# The fields exported for each user, in this order
COLUMNS: Final = [
    "login",
    "id",
    "status",
    "created",
    "activated",
    "statusChanged",
    "days_since_status_changed",
    "lastLogin",
    "days_since_last_login",
    "lastUpdated",
    "passwordChanged",
    "type_id",
]

MAX_ATTEMPTS: Final = 5  # Tries per API call before giving up
REQUEST_TIMEOUT_SECONDS: Final = 30
RATE_LIMIT_HEADROOM: Final = 2  # Pause when this few requests remain in Okta's rate-limit window
MAX_RATE_LIMIT_WAIT_SECONDS: Final = 65

HTTP_TOO_MANY_REQUESTS: Final = 429
HTTP_SERVER_ERROR: Final = 500

log = logging.getLogger("okta-export-users")


# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------


def get_okta_token() -> str:
    """Return the Okta API token.

    This is the only place the credential is read. To move to Key Vault or an
    Okta OAuth service app later, change this function and nothing else.
    """
    return os.getenv("OKTA_API_TOKEN", "").strip()


def in_pipeline() -> bool:
    """Return True when running in Azure Pipelines (the agent sets TF_BUILD=True)."""
    return os.getenv("TF_BUILD", "").casefold() == "true"


# ---------------------------------------------------------------------------
# Talking to Okta
# ---------------------------------------------------------------------------


def make_session(token: str) -> requests.Session:
    """Create an HTTP session that sends the Okta token with every request.

    A session also reuses connections, which makes many calls faster.
    """
    session = requests.Session()
    session.headers.update(
        {
            "Authorization": f"SSWS {token}",
            "Accept": "application/json",
            "User-Agent": "ado-okta-export-users/1.0",
        },
    )
    return session


def api_url(path: str) -> str:
    """Build a full Okta API URL from a path such as /users."""
    return f"{OKTA_ORG_URL}/api/v1{path}"


def error_summary(resp: requests.Response) -> str:
    """Turn an Okta error response into a short readable message."""
    try:
        body = resp.json()
    except ValueError:
        return f"HTTP {resp.status_code}: {resp.text[:200]}"
    summary = body.get("errorSummary") or body.get("errorCode") or "unknown error"
    causes = "; ".join(cause.get("errorSummary", "") for cause in body.get("errorCauses", []))
    if causes:
        return f"HTTP {resp.status_code}: {summary} ({causes})"
    return f"HTTP {resp.status_code}: {summary}"


def seconds_until_reset(resp: requests.Response) -> float:
    """Work out how long to wait until Okta's rate-limit window resets."""
    reset = resp.headers.get("X-Rate-Limit-Reset", "")  # A Unix timestamp
    wait = float(reset) - time.time() + 1 if reset.isdigit() else 10.0
    return min(max(wait, 1.0), MAX_RATE_LIMIT_WAIT_SECONDS)


def pause_if_near_rate_limit(resp: requests.Response) -> None:
    """Wait for the rate-limit window to reset if we're about to run out of requests."""
    remaining = resp.headers.get("X-Rate-Limit-Remaining", "")
    if remaining.isdigit() and int(remaining) <= RATE_LIMIT_HEADROOM:
        wait = seconds_until_reset(resp)
        log.info("Approaching Okta rate limit; pausing %.0fs", wait)
        time.sleep(wait)


def okta_get(
    session: requests.Session,
    url: str,
    params: dict[str, str] | None = None,
) -> requests.Response | None:
    """GET an Okta API URL, retrying on rate limits (429), server errors (5xx) and network errors.

    Returns the response (which may still be an error such as 403), or None if
    Okta couldn't be reached at all.
    """
    for attempt in range(1, MAX_ATTEMPTS + 1):
        is_last_attempt = attempt == MAX_ATTEMPTS

        try:
            resp = session.get(url, params=params, timeout=REQUEST_TIMEOUT_SECONDS)
        except requests.RequestException as exc:
            if is_last_attempt:
                log.warning("GET %s failed after %d attempts: %s", url, attempt, exc)
                return None
            log.warning("GET %s failed (%s); retrying in %ss", url, exc, 2**attempt)
            time.sleep(2**attempt)
            continue

        if resp.status_code == HTTP_TOO_MANY_REQUESTS and not is_last_attempt:
            wait = seconds_until_reset(resp)
            log.warning("Rate limited on %s; waiting %.0fs", url, wait)
            time.sleep(wait)
            continue

        if resp.status_code >= HTTP_SERVER_ERROR and not is_last_attempt:
            log.warning("GET %s returned %s; retrying in %ss", url, resp.status_code, 2**attempt)
            time.sleep(2**attempt)
            continue

        pause_if_near_rate_limit(resp)
        return resp

    return None  # Only reached if MAX_ATTEMPTS is 0


def get_all_pages(
    session: requests.Session,
    path: str,
    params: dict[str, str],
) -> tuple[list[dict[str, Any]], str]:
    """Get every item from a paged Okta list endpoint.

    Okta returns one page at a time and puts the URL of the next page in the
    Link header (rel="next"). requests parses that header into resp.links.

    Returns (items, problem): problem is "" if every page was read.
    """
    items: list[dict[str, Any]] = []
    url: str | None = api_url(path)
    page_params: dict[str, str] | None = params  # The next-page URL already contains the parameters

    while url:
        resp = okta_get(session, url, page_params)
        if resp is None:
            return items, f"could not reach Okta after {len(items)} items"
        if not resp.ok:
            return items, f"{error_summary(resp)} after {len(items)} items"

        page = resp.json()
        items.extend(page)
        log.info("Fetched %d (total %d)", len(page), len(items))

        url = resp.links.get("next", {}).get("url")
        page_params = None

        # Only ever send the token back to our own Okta org
        if url and not url.startswith(f"{OKTA_ORG_URL}/"):
            return items, f"next-page link points outside {OKTA_ORG_URL}: {url}"

    return items, ""


def who_am_i(session: requests.Session) -> str | None:
    """Return the login of the token's owner, or None if the token or org URL doesn't work."""
    resp = okta_get(session, api_url("/users/me"))
    if resp is None:
        log.error("Cannot reach %s", OKTA_ORG_URL)
        return None
    if not resp.ok:
        log.error("Preflight check against %s failed (%s)", OKTA_ORG_URL, error_summary(resp))
        return None
    return resp.json().get("profile", {}).get("login", "unknown")


def list_users(session: requests.Session) -> tuple[list[dict[str, Any]], str]:
    """Return every user: the default list (everyone not deactivated) plus deactivated users.

    Returns (users, problem): problem is "" if every user was read.
    """
    log.info("Listing users")
    users, problem = get_all_pages(session, "/users", {"limit": PAGE_SIZE})
    if problem:
        return users, problem

    log.info("Listing deactivated users")
    deactivated, problem = get_all_pages(session, "/users", {"limit": PAGE_SIZE, "search": DEACTIVATED_SEARCH})
    return users + deactivated, problem


# ---------------------------------------------------------------------------
# Building the output
# ---------------------------------------------------------------------------


def days_since(timestamp: str | None, now: datetime) -> int | None:
    """Return whole days between an Okta timestamp and now, or None if there's no timestamp."""
    if not timestamp:
        return None
    try:
        then = datetime.fromisoformat(timestamp)  # Okta format: 2026-10-01T03:12:45.000Z
    except ValueError:
        log.warning("Unrecognised timestamp %r", timestamp)
        return None
    return (now - then).days


def to_record(user: dict[str, Any], now: datetime) -> dict[str, Any]:
    """Pick the basic fields out of one Okta user."""
    return {
        "login": user.get("profile", {}).get("login"),
        "id": user.get("id"),
        "status": user.get("status"),
        "created": user.get("created"),
        "activated": user.get("activated"),
        "statusChanged": user.get("statusChanged"),
        "days_since_status_changed": days_since(user.get("statusChanged"), now),
        "lastLogin": user.get("lastLogin"),
        "days_since_last_login": days_since(user.get("lastLogin"), now),
        "lastUpdated": user.get("lastUpdated"),
        "passwordChanged": user.get("passwordChanged"),
        "type_id": user.get("type", {}).get("id"),
    }


def write_json(path: Path, records: list[dict[str, Any]], now: datetime) -> None:
    """Write the users as one JSON file, with a short summary at the top."""
    export = {
        "exported_at": now.isoformat(timespec="seconds"),
        "org_url": OKTA_ORG_URL,
        "user_count": len(records),
        "status_counts": dict(Counter(record["status"] for record in records)),
        "users": records,
    }
    with path.open("w", encoding="utf-8") as fh:
        json.dump(export, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


def write_csv(path: Path, records: list[dict[str, Any]]) -> None:
    """Write the users as a CSV file. Missing values (e.g. never logged in) are left blank."""
    # utf-8-sig adds the marker (BOM) Excel needs to show non-English characters correctly
    with path.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(records)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    """Read command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--json",
        type=Path,
        default=Path("okta_users.json"),
        help="JSON output file (default: okta_users.json)",
    )
    parser.add_argument(
        "--csv",
        type=Path,
        default=Path("okta_users.csv"),
        help="CSV output file (default: okta_users.csv)",
    )
    return parser.parse_args()


def check_config(token: str) -> str | None:
    """Return a setup problem, or None if everything needed is present."""
    where = "map it with env: on the pipeline step" if in_pipeline() else "set it in .env, run with --env-file .env"
    if not OKTA_ORG_URL.startswith("https://"):
        return f"OKTA_ORG_URL must be your Okta org URL, e.g. https://example.okta.com ({where})"
    if not token:
        return f"OKTA_API_TOKEN is not set ({where})"
    return None


def main() -> int:
    """Run the export and return an exit code (0 = done, 1 = Okta problem, 2 = setup problem)."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s")
    args = parse_args()
    token = get_okta_token()

    problem = check_config(token)
    if problem:
        log.error(problem)
        return 2

    session = make_session(token)
    me = who_am_i(session)
    if me is None:
        return 1
    log.info("Authenticated as %s against %s", me, OKTA_ORG_URL)

    users, problem = list_users(session)
    if problem:
        # Don't write a partial export that could be mistaken for a complete one
        log.error("Export stopped: %s. No files written.", problem)
        return 1

    now = datetime.now(UTC)
    records = sorted((to_record(user, now) for user in users), key=lambda r: (r["login"] or "").casefold())

    write_json(args.json, records, now)
    write_csv(args.csv, records)

    statuses = ", ".join(f"{status} {count}" for status, count in Counter(r["status"] for r in records).most_common())
    log.info("Exported %d users (%s)", len(records), statuses or "none")
    log.info("Wrote %s and %s", args.json, args.csv)
    return 0


if __name__ == "__main__":
    sys.exit(main())
