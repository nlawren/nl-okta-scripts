"""Export all Okta users, with every field Okta holds on them, to JSON and CSV.

READ ONLY: this script only makes GET requests. Nothing in Okta changes.

Output:
    okta_users.json  Everything Okta returned for each user, plus the org's user
                     profile schema (which attributes exist, their types and titles)
    okta_users.csv   One row per user. Nested fields are flattened into dotted
                     columns, e.g. profile.email, credentials.provider.type.
                     Every attribute in the profile schema gets a column, even if
                     no user has a value for it, so empty attributes are visible.

Okta's user list leaves out deactivated users unless you pass --include-deactivated.

Environment:
    OKTA_ORG_URL    e.g. https://example.okta.com
    OKTA_API_TOKEN  Okta API token (sent as "SSWS <token>")

Locally these come from .env (copy .env.example):
    uv run --env-file .env export_users.py
    uv run --env-file .env export_users.py --include-deactivated

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

# CSV columns that come first, in this order. Everything else follows.
LEADING_COLUMNS: Final = [
    "id",
    "status",
    "created",
    "activated",
    "statusChanged",
    "lastLogin",
    "lastUpdated",
    "passwordChanged",
    "type.id",
]

# Fields left out of the CSV (they're still in the JSON). _links are API URLs, not user data.
CSV_SKIP_PREFIXES: Final = ("_links", "_embedded")

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

    A session also reuses connections, which makes hundreds of calls faster.
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


def get_profile_schema(session: requests.Session) -> dict[str, Any] | None:
    """Return the org's default user profile schema, or None if it can't be read.

    The schema lists every profile attribute (Okta's built-in "base" ones and
    your org's "custom" ones), whether or not any user has a value for it.
    Not being able to read it isn't fatal: the export still works without it.
    """
    resp = okta_get(session, api_url("/meta/schemas/user/default"))
    if resp is None or not resp.ok:
        reason = "could not reach Okta" if resp is None else error_summary(resp)
        log.warning("Could not read the user profile schema (%s); continuing without it", reason)
        return None
    return resp.json()


def schema_attribute_names(schema: dict[str, Any] | None) -> list[str]:
    """List profile attribute names from the schema: base attributes first, then custom ones."""
    if not schema:
        return []
    definitions = schema.get("definitions", {})
    names: list[str] = []
    for section in ("base", "custom"):
        names.extend(definitions.get(section, {}).get("properties", {}))
    return names


def list_users(session: requests.Session, *, include_deactivated: bool) -> tuple[list[dict[str, Any]], str]:
    """Return all users, plus deactivated ones if asked for.

    Returns (users, problem): problem is "" if every user was read.
    """
    log.info("Listing users")
    users, problem = get_all_pages(session, "/users", {"limit": PAGE_SIZE})
    if problem or not include_deactivated:
        return users, problem

    log.info("Listing deactivated users")
    deactivated, problem = get_all_pages(session, "/users", {"limit": PAGE_SIZE, "search": DEACTIVATED_SEARCH})
    return users + deactivated, problem


# ---------------------------------------------------------------------------
# Writing the output
# ---------------------------------------------------------------------------


def cell_text(value: Any) -> str:  # noqa: ANN401 - Okta values can be any JSON type
    """Turn one Okta value into text for a CSV cell."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        if all(isinstance(item, str | int | float) for item in value):
            return "; ".join(str(item) for item in value)
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def flatten(value: Any, prefix: str = "") -> dict[str, str]:  # noqa: ANN401 - Okta values can be any JSON type
    """Flatten nested dictionaries into dotted keys.

    {"profile": {"email": "a@b.com"}} becomes {"profile.email": "a@b.com"}.
    """
    if not isinstance(value, dict):
        return {prefix: cell_text(value)}
    flat: dict[str, str] = {}
    for key, item in value.items():
        flat.update(flatten(item, f"{prefix}.{key}" if prefix else key))
    return flat


def csv_columns(rows: list[dict[str, str]], profile_attributes: list[str]) -> list[str]:
    """Choose the CSV columns: the leading ones, then every schema attribute, then anything else found."""
    columns = list(LEADING_COLUMNS)
    columns.extend(f"profile.{name}" for name in profile_attributes)

    # Profile attributes the schema didn't list come next, then everything else (credentials etc.)
    found = {key for row in rows for key in row}
    columns.extend(sorted(found - set(columns), key=lambda key: (not key.startswith("profile."), key)))

    return [column for column in columns if not column.startswith(CSV_SKIP_PREFIXES)]


def write_json(
    path: Path, users: list[dict[str, Any]], schema: dict[str, Any] | None, *, include_deactivated: bool
) -> None:
    """Write the full export, untouched, as one JSON file."""
    export = {
        "exported_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "org_url": OKTA_ORG_URL,
        "include_deactivated": include_deactivated,
        "user_count": len(users),
        "status_counts": dict(Counter(user.get("status", "UNKNOWN") for user in users)),
        "profile_schema": schema,
        "users": users,
    }
    with path.open("w", encoding="utf-8") as fh:
        json.dump(export, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


def write_csv(path: Path, users: list[dict[str, Any]], profile_attributes: list[str]) -> int:
    """Write one row per user with nested fields flattened. Returns the number of columns."""
    rows = [flatten(user) for user in users]
    columns = csv_columns(rows, profile_attributes)

    # utf-8-sig adds the marker (BOM) Excel needs to show non-English characters correctly
    with path.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return len(columns)


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
    parser.add_argument(
        "--include-deactivated",
        action="store_true",
        help="also export deactivated (DEPROVISIONED) users",
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

    schema = get_profile_schema(session)
    profile_attributes = schema_attribute_names(schema)
    if profile_attributes:
        log.info("Profile schema has %d attributes", len(profile_attributes))

    users, problem = list_users(session, include_deactivated=args.include_deactivated)
    if problem:
        # Don't write a partial export that could be mistaken for a complete one
        log.error("Export stopped: %s. No files written.", problem)
        return 1

    users.sort(key=lambda user: user.get("profile", {}).get("login", "").casefold())

    write_json(args.json, users, schema, include_deactivated=args.include_deactivated)
    column_count = write_csv(args.csv, users, profile_attributes)

    statuses = ", ".join(f"{status} {count}" for status, count in Counter(u.get("status") for u in users).most_common())
    log.info("Exported %d users (%s)", len(users), statuses or "none")
    log.info("Wrote %s and %s (%d columns)", args.json, args.csv, column_count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
