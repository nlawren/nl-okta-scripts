"""Deactivate Okta users listed in a CSV file and write a status report.

DRY RUN BY DEFAULT: users are only looked up and reported on. Nothing in Okta
changes unless --apply is passed.

Input  (users.csv):  name, email
Output (output.csv): name, email, okta_login, okta_status, last_login, action, status, detail

Users are found by their Okta primary email (profile.email) by default, or by
their Okta login with --match-by login (the second column is then a login, and
named "login" in the outputs). okta_login is the login of the user found. okta_login, okta_status and
last_login are as Okta had them before this run. action is
"deactivated", "would deactivate" (dry run) or "none". status is "success" or
"error"; detail explains why.

With --apply, each user is backed up just before they're deactivated: their
Okta record, groups and app assignments, as one JSON line per user in
backup-<UTC time>.jsonl (or --backup). If the backup fails, the user isn't
deactivated. The backup contains personal data; treat it like the user list.

--validate is a separate, read-only mode: it looks every user up and writes a
copy of the input with their Okta status and last login added
(users.csv -> users-validated.csv): name, email, okta_login, okta_status, last_login

Environment:
    OKTA_ORG_URL    e.g. https://example.okta.com
    OKTA_API_TOKEN  Okta API token (sent as "SSWS <token>")

Locally these come from .env (copy .env.example):
    uv run --env-file .env deactivate_users.py            # dry run
    uv run --env-file .env deactivate_users.py --apply    # make changes
    uv run --env-file .env deactivate_users.py --validate # report statuses only
"""

import argparse
import contextlib
import csv
import json
import logging
import os
import re
import sys
import time
from datetime import UTC, datetime
from http import HTTPStatus
from pathlib import Path
from typing import Any, Final, NamedTuple, TextIO
from urllib.parse import quote

import requests

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

OKTA_ORG_URL: Final = os.getenv("OKTA_ORG_URL", "").strip().rstrip("/")

# What --match-by can match the CSV's second column on: the Okta profile field, and how messages name it
MATCH_FIELDS: Final = {"email": "primary email", "login": "login"}

# Emails and Okta logins (which are email-formatted by default). Quotes and backslashes
# aren't allowed, so a value can go straight into an Okta search expression.
MATCH_PATTERN: Final = re.compile(r'^[^@\s"\\]+@[^@\s"\\]+\.[^@\s"\\]+$')

# If the first row's second column is one of these, treat the row as a header and skip it.
# Compared lower-case with everything but letters removed, so "Email Address" and "E-mail" match.
HEADER_NAMES: Final = {
    "email",
    "emailaddress",
    "primaryemail",
    "login",
    "loginid",
    "oktalogin",
    "username",
    "userprincipalname",
    "upn",
}

# Okta's API calls a deactivated user "DEPROVISIONED" (the admin console shows "Deactivated").
DEACTIVATED_STATUS: Final = "DEPROVISIONED"

SUCCESS: Final = "success"
ERROR: Final = "error"
# Report columns after "name" and the matched field ("email" or "login")
REPORT_COLUMNS: Final = ["okta_login", "okta_status", "last_login", "action", "status", "detail"]

# Values of the report's action column
DEACTIVATED: Final = "deactivated"
WOULD_DEACTIVATE: Final = "would deactivate"
NO_ACTION: Final = "none"

# --validate: plain-English names for Okta's user statuses, and the columns of its report.
# Okta can't tell a deleted user from one that never existed; both come back as not found.
NOT_IN_OKTA: Final = "not in Okta"
OKTA_STATUS_NAMES: Final = {
    "STAGED": "pending",  # Created, but activation not started
    "PROVISIONED": "pending",  # Activation started, user hasn't finished it
    "ACTIVE": "active",
    "RECOVERY": "active (password reset in progress)",
    "PASSWORD_EXPIRED": "active (password expired)",
    "LOCKED_OUT": "locked out",
    "SUSPENDED": "suspended",
    DEACTIVATED_STATUS: "deactivated",
}
VALIDATE_COLUMNS: Final = ["okta_login", "okta_status", "last_login"]

MAX_ATTEMPTS: Final = 5  # Tries per API call before giving up
REQUEST_TIMEOUT_SECONDS: Final = 30
# For calls that change something, which aren't retried. Deactivating a user with many
# app assignments can take a while.
CHANGE_TIMEOUT_SECONDS: Final = 120
RATE_LIMIT_HEADROOM: Final = 2  # Pause when this few requests remain in Okta's rate-limit window
MAX_RATE_LIMIT_WAIT_SECONDS: Final = 65

log = logging.getLogger("okta-deprovision")


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


def ado_command(command: str) -> None:
    """Print an Azure DevOps logging command, but only when running in a pipeline."""
    if in_pipeline():
        print(f"##vso[{command}", flush=True)  # noqa: T201 - the agent reads these from stdout


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
            "Content-Type": "application/json",
            "User-Agent": "ado-okta-deprovision/1.0",
        },
    )
    return session


def json_body(resp: requests.Response) -> dict[str, Any] | None:
    """Return a response's JSON object, or None if it isn't one (e.g. an HTML page from a proxy)."""
    try:
        body = resp.json()
    except ValueError:
        return None
    return body if isinstance(body, dict) else None


def error_summary(resp: requests.Response) -> str:
    """Turn an Okta error response into a short readable message."""
    body = json_body(resp)
    if body is None:
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


def okta_request(
    session: requests.Session,
    method: str,
    path: str,
    params: dict[str, str] | None = None,
    *,
    safe_to_repeat: bool = True,
) -> requests.Response | None:
    """Call the Okta API, retrying on rate limits (429), server errors (5xx) and network errors.

    Pass safe_to_repeat=False for calls that change something: after a 5xx or a
    network error Okta may already have acted, so those aren't retried (429s still
    are, because Okta rejects those without acting) and get a longer timeout.

    Returns the response (which may still be an error such as 404), or None if
    Okta couldn't be reached at all.
    """
    url = f"{OKTA_ORG_URL}/api/v1{path}"
    timeout = REQUEST_TIMEOUT_SECONDS if safe_to_repeat else CHANGE_TIMEOUT_SECONDS

    for attempt in range(1, MAX_ATTEMPTS + 1):
        is_last_attempt = attempt == MAX_ATTEMPTS

        try:
            resp = session.request(method, url, params=params, timeout=timeout)
        except requests.RequestException as exc:
            if is_last_attempt or not safe_to_repeat:
                log.warning("%s %s failed after %d attempts: %s", method, path, attempt, exc)
                return None
            log.warning("%s %s failed (%s); retrying in %ss", method, path, exc, 2**attempt)
            time.sleep(2**attempt)
            continue

        if resp.status_code == HTTPStatus.TOO_MANY_REQUESTS and not is_last_attempt:
            wait = seconds_until_reset(resp)
            log.warning("Rate limited on %s %s; waiting %.0fs", method, path, wait)
            time.sleep(wait)
            continue

        if resp.status_code >= HTTPStatus.INTERNAL_SERVER_ERROR and safe_to_repeat and not is_last_attempt:
            log.warning("%s %s returned %s; retrying in %ss", method, path, resp.status_code, 2**attempt)
            time.sleep(2**attempt)
            continue

        pause_if_near_rate_limit(resp)
        return resp

    return None  # Only reached if MAX_ATTEMPTS is 0


def who_am_i(session: requests.Session) -> str | None:
    """Return the login of the token's owner, or None if the token or org URL doesn't work."""
    resp = okta_request(session, "GET", "/users/me")
    if resp is None:
        log.error("Cannot reach %s", OKTA_ORG_URL)
        return None
    if not resp.ok:
        log.error("Preflight check against %s failed (%s)", OKTA_ORG_URL, error_summary(resp))
        return None
    body = json_body(resp)
    if body is None:
        log.error(
            "%s didn't answer like an Okta org (HTTP %s, not JSON); check OKTA_ORG_URL", OKTA_ORG_URL, resp.status_code
        )
        return None
    return body.get("profile", {}).get("login", "unknown")


def look_up_user(session: requests.Session, value: str, match_by: str) -> tuple[dict[str, Any] | None, str, bool]:
    """Find a user in Okta whose profile.<match_by> (email or login) is value.

    Okta doesn't require primary emails to be unique, so more than one match is a
    problem rather than a guess. Search results include deactivated users.

    Returns (user, problem, stop):
        user     the user's details from Okta, or None if exactly one couldn't be found
        problem  why not, or "" if found or if there's simply no such user
        stop     True if the token was rejected, so the whole run should stop
    """
    users, problem, stop = get_all(session, "/users", {"search": f'profile.{match_by} eq "{value}"'})
    if users is None:
        return None, problem if stop else f"Lookup failed: {problem}", stop

    # Okta's search is case-insensitive; check the match is exact apart from case
    matches = [user for user in users if user.get("profile", {}).get(match_by, "").casefold() == value.casefold()]
    if len(matches) > 1:
        logins = ", ".join(sorted(user.get("profile", {}).get("login", "?") for user in matches))
        return None, f"{len(matches)} Okta users have this {MATCH_FIELDS[match_by]} ({logins}); skipped", False
    return (matches[0] if matches else None), "", False


def send_deactivation(session: requests.Session, user_id: str) -> tuple[str, bool]:
    """Ask Okta to deactivate a user, without emailing the admin.

    The request isn't retried. If it times out or Okta returns a server error,
    Okta may still have deactivated the user, so check before reporting a failure.

    Returns (problem, stop): problem is "" on success; stop is True if the token was rejected.
    """
    resp = okta_request(
        session,
        "POST",
        f"/users/{quote(user_id, safe='')}/lifecycle/deactivate",
        params={"sendEmail": "false"},
        safe_to_repeat=False,
    )

    if resp is not None and resp.status_code == HTTPStatus.UNAUTHORIZED:
        return f"Okta rejected the API token ({error_summary(resp)})", True
    if resp is not None and resp.ok:
        return "", False

    problem = "could not reach Okta" if resp is None else error_summary(resp)
    if resp is None or resp.status_code >= HTTPStatus.INTERNAL_SERVER_ERROR:
        if is_deactivated(session, user_id):
            log.warning("Deactivate request for %s failed (%s), but Okta shows the user deactivated", user_id, problem)
            return "", False
        problem += "; Okta doesn't show the user as deactivated"
    return problem, False


def is_deactivated(session: requests.Session, user_id: str) -> bool:
    """Return True if Okta shows the user deactivated, or finishing deactivation."""
    resp = okta_request(session, "GET", f"/users/{quote(user_id, safe='')}")
    user = json_body(resp) if resp is not None and resp.ok else None
    return user is not None and DEACTIVATED_STATUS in {user.get("status"), user.get("transitioningToStatus")}


def get_all(
    session: requests.Session,
    path: str,
    params: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]] | None, str, bool]:
    """GET every page of an Okta list.

    Returns (items, problem, stop): items is None if any page failed, problem says
    why; stop is True if the token was rejected.
    """
    items: list[dict[str, Any]] = []
    api_prefix = f"{OKTA_ORG_URL}/api/v1/"
    next_path: str | None = path
    while next_path:
        resp = okta_request(session, "GET", next_path, params)
        if resp is None:
            return None, "could not reach Okta", False
        if resp.status_code == HTTPStatus.UNAUTHORIZED:
            return None, f"Okta rejected the API token ({error_summary(resp)})", True
        if not resp.ok:
            return None, error_summary(resp), False
        try:
            page = resp.json()
        except ValueError:
            page = None
        if not isinstance(page, list):
            return None, f"Okta's response wasn't a JSON list (HTTP {resp.status_code})", False
        items.extend(page)

        # Okta links to the next page with a full URL; only follow it within this org's API,
        # since the token goes with every request
        next_url = resp.links.get("next", {}).get("url", "")
        if next_url and not next_url.startswith(api_prefix):
            return None, f"Okta's next-page link points outside {OKTA_ORG_URL}: {next_url}", False
        next_path = next_url.removeprefix(api_prefix[:-1]) or None
        params = None  # The next-page link already carries them
    return items, "", False


def open_backup(path: Path) -> TextIO:
    """Open the backup file for adding to, readable by its owner only. Never overwrites an earlier backup."""
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600), "a", encoding="utf-8")


def write_backup(session: requests.Session, user: dict[str, Any], backup: TextIO) -> tuple[str, bool]:
    """Save a user's Okta record, groups and app assignments as one JSON line in the backup.

    Called just before the user is deactivated. Returns (problem, stop): problem is
    "" once the line is safely on disk; stop is True if the token was rejected.
    """
    user_id = user["id"]
    groups, problem, stop = get_all(session, f"/users/{quote(user_id, safe='')}/groups")
    if groups is None:
        return f"could not list groups: {problem}", stop

    # expand=user/<id> embeds each app's assignment for this user, including its
    # scope: USER (assigned directly) or GROUP (assigned through a group)
    app_params = {"filter": f'user.id eq "{user_id}"', "expand": f"user/{user_id}", "limit": "200"}
    apps, problem, stop = get_all(session, "/apps", app_params)
    if apps is None:
        return f"could not list apps: {problem}", stop

    record = {
        "backed_up_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "org": OKTA_ORG_URL,
        "login": user.get("profile", {}).get("login", ""),
        "email": user.get("profile", {}).get("email", ""),
        "user": without_links(user),
        "groups": [
            {"id": group.get("id"), "name": group.get("profile", {}).get("name"), "type": group.get("type")}
            for group in groups
        ],
        "apps": [
            {
                "id": app.get("id"),
                "name": app.get("name"),
                "label": app.get("label"),
                "status": app.get("status"),
                "assignment": without_links(app.get("_embedded", {}).get("user", {})),
            }
            for app in apps
        ],
    }
    try:
        backup.write(json.dumps(record) + "\n")
        backup.flush()
        os.fsync(backup.fileno())  # On disk before the user is deactivated
    except OSError as exc:
        return f"could not write the backup file: {exc}", True
    return "", False


def without_links(obj: dict[str, Any]) -> dict[str, Any]:
    """Drop Okta's _links (API URLs, not data) from an object."""
    return {key: value for key, value in obj.items() if key != "_links"}


# ---------------------------------------------------------------------------
# Reading and checking the CSV
# ---------------------------------------------------------------------------


def safe_cells(cells: list[str]) -> list[str]:
    """Stop spreadsheet apps running report cells as formulas, by prefixing risky ones with '."""
    return [f"'{cell}" if cell.startswith(("=", "+", "-", "@", "\t", "\r")) else cell for cell in cells]


def read_rows(path: Path) -> list[dict[str, str]]:
    """Read the input CSV into a list of {"line", "name", "match"} dictionaries.

    match is the second column: the email or login to find the user by (see --match-by).

    Skips a header row if there is one. Blank rows are kept so they show up in the report.
    """
    rows = []
    # utf-8-sig removes the invisible marker (BOM) Excel adds to the start of CSV files
    with path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.reader(fh)
        for index, raw in enumerate(reader):
            cells = [cell.strip() for cell in raw]
            name = cells[0] if len(cells) > 0 else ""
            match = cells[1] if len(cells) > 1 else ""

            if index == 0 and re.sub(r"[^a-z]", "", match.lower()) in HEADER_NAMES:
                log.info("Skipping header row")
                continue

            rows.append({"line": str(reader.line_num), "name": name, "match": match})
    return rows


def validate_row(row: dict[str, str], seen: set[str], match_by: str) -> str | None:
    """Return why a row can't be processed, or None if it looks valid.

    seen is updated with each valid email or login, to catch duplicates.
    """
    line = row["line"]
    if not row["name"] and not row["match"]:
        return f"Blank row (line {line})"
    if not row["match"]:
        return f"Missing {match_by} (line {line})"
    if not MATCH_PATTERN.fullmatch(row["match"]):
        return f"Invalid {match_by} format (line {line})"

    key = row["match"].casefold()  # Okta matches emails and logins case-insensitively
    if key in seen:
        return f"Duplicate {match_by} in input (line {line})"
    seen.add(key)
    return None


# ---------------------------------------------------------------------------
# Processing
# ---------------------------------------------------------------------------


class Outcome(NamedTuple):
    """What happened to one row, as written to the report."""

    status: str
    detail: str
    okta_login: str = ""
    okta_status: str = ""
    last_login: str = ""
    action: str = NO_ACTION
    stop: bool = False  # True if the whole run should stop


def describe_user(user: dict[str, Any]) -> tuple[str, str, str]:
    """Return a user's (okta_login, okta_status, last_login) as the reports show them."""
    okta_login = user.get("profile", {}).get("login", "")
    status = user.get("status", "UNKNOWN")
    last_login = user.get("lastLogin") or "never"  # ISO 8601, UTC
    return okta_login, OKTA_STATUS_NAMES.get(status, status.lower()), last_login


def process_row(  # noqa: PLR0911 - one return per outcome
    session: requests.Session,
    row: dict[str, str],
    *,
    me: str,
    backup: TextIO | None,
    match_by: str,
) -> Outcome:
    """Look up one user and, unless this is a dry run, back them up and deactivate them.

    me is the login of the token's owner, which is never deactivated: that would
    revoke the token and stop the run partway through. backup is where each user
    is saved before being deactivated; None means a dry run.
    """
    user, problem, stop = look_up_user(session, row["match"], match_by)
    if user is None and not problem:
        return Outcome(ERROR, f"No Okta user has this {MATCH_FIELDS[match_by]}", okta_status=NOT_IN_OKTA)
    if user is None:
        return Outcome(ERROR, problem, stop=stop)

    described = describe_user(user)  # okta_login, okta_status, last_login
    okta_login = described[0]
    current_status = user.get("status", "UNKNOWN")
    if current_status == DEACTIVATED_STATUS:
        return Outcome(SUCCESS, "Already deactivated; nothing to do", *described)
    if okta_login.casefold() == me.casefold():
        detail = "Skipped: this is the API token's own account (deactivate it by hand after the run)"
        return Outcome(ERROR, detail, *described)

    if backup is None:
        detail = f"Dry run: would deactivate (current status {current_status})"
        return Outcome(SUCCESS, detail, *described, WOULD_DEACTIVATE)

    problem, stop = write_backup(session, user, backup)
    if problem:
        return Outcome(ERROR, f"Not deactivated: backup failed ({problem})", *described, stop=stop)

    problem, stop = send_deactivation(session, user["id"])
    if problem:
        return Outcome(ERROR, f"Deactivation failed: {problem}", *described, stop=stop)
    return Outcome(SUCCESS, f"Deactivated (was {current_status})", *described, DEACTIVATED)


def process_all(
    session: requests.Session,
    rows: list[dict[str, str]],
    args: argparse.Namespace,
    *,
    me: str,
) -> tuple[dict[str, int], bool]:
    """Process every row and write the report (and, unless dry run, the backup) as we go.

    Uses args.output, args.match_by and args.backup; args.backup is None for a dry
    run, when nothing is backed up or deactivated.

    Returns (counts, stopped): counts of success/error, and whether the run stopped early.
    """
    counts = {SUCCESS: 0, ERROR: 0}
    seen: set[str] = set()
    stopped = False

    with (
        args.output.open("w", newline="", encoding="utf-8") as fh,
        open_backup(args.backup) if args.backup else contextlib.nullcontext() as backup,
    ):
        writer = csv.writer(fh)
        writer.writerow(["name", args.match_by, *REPORT_COLUMNS])

        for row in rows:
            if stopped:
                outcome = Outcome(ERROR, "Not processed (run stopped early)")
            else:
                problem = validate_row(row, seen, args.match_by)
                if problem:
                    outcome = Outcome(ERROR, problem)
                else:
                    outcome = process_row(session, row, me=me, backup=backup, match_by=args.match_by)
                    stopped = outcome.stop
                    if stopped:
                        log.error("Stopping run: %s", outcome.detail)

            writer.writerow(
                safe_cells(
                    [
                        row["name"],
                        row["match"],
                        outcome.okta_login,
                        outcome.okta_status,
                        outcome.last_login,
                        outcome.action,
                        outcome.status,
                        outcome.detail,
                    ],
                ),
            )
            fh.flush()  # Keep the report up to date in case the job is cancelled
            counts[outcome.status] += 1
            log.info("%-7s %s: %s", outcome.status, row["match"] or "<blank>", outcome.detail)

    return counts, stopped


def validate_user(session: requests.Session, value: str, match_by: str) -> tuple[str, str, str, bool]:
    """Look up one user for --validate, changing nothing.

    Returns (okta_login, okta_status, last_login, stop): stop is True if the whole run should stop.
    """
    user, problem, stop = look_up_user(session, value, match_by)
    if user is None and not problem:
        return "", NOT_IN_OKTA, "", False
    if user is None:
        return "", f"error: {problem}", "", stop
    return (*describe_user(user), False)


def validate_all(
    session: requests.Session,
    rows: list[dict[str, str]],
    args: argparse.Namespace,
) -> tuple[dict[str, int], bool]:
    """Look up every row and write the validated copy of the CSV (args.output) as we go.

    Returns (counts, stopped): how many rows got each okta_status, and whether the run stopped early.
    """
    counts: dict[str, int] = {}
    seen: set[str] = set()
    stopped = False

    with args.output.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["name", args.match_by, *VALIDATE_COLUMNS])

        for row in rows:
            okta_login = last_login = ""
            if stopped:
                okta_status = "error: not checked (run stopped early)"
            else:
                problem = validate_row(row, seen, args.match_by)
                if problem:
                    okta_status = f"error: {problem}"
                else:
                    okta_login, okta_status, last_login, stopped = validate_user(session, row["match"], args.match_by)
                    if stopped:
                        log.error("Stopping run: %s", okta_status)

            writer.writerow(safe_cells([row["name"], row["match"], okta_login, okta_status, last_login]))
            fh.flush()  # Keep the report up to date in case the job is cancelled
            key = ERROR if okta_status.startswith("error:") else okta_status
            counts[key] = counts.get(key, 0) + 1
            log.info("%-12s %s %s %s", okta_status, row["match"] or "<blank>", okta_login, last_login)

    return counts, stopped


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    """Read command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", type=Path, default=Path("users.csv"), help="input CSV (default: users.csv)")
    parser.add_argument(
        "--output",
        type=Path,
        help="report CSV (default: output.csv, or <input>-validated.csv with --validate)",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--apply",
        action="store_true",
        help="actually deactivate users (without this, the run is a dry run and changes nothing)",
    )
    parser.add_argument(
        "--match-by",
        choices=MATCH_FIELDS,
        default="email",
        help="what the CSV's second column is: the Okta primary email (default) or the Okta login",
    )
    parser.add_argument(
        "--backup",
        type=Path,
        help="with --apply: where to back users up before deactivating them (default: backup-<UTC time>.jsonl)",
    )
    mode.add_argument(
        "--validate",
        action="store_true",
        help="only report each user's Okta status and last login; changes nothing",
    )
    args = parser.parse_args()
    if args.backup and not args.apply:
        parser.error("--backup only applies with --apply")
    if args.apply and args.backup is None:
        args.backup = Path(f"backup-{datetime.now(UTC):%Y%m%dT%H%M%SZ}.jsonl")
    if args.output is None:
        args.output = (
            args.input.with_name(f"{args.input.stem}-validated{args.input.suffix}")
            if args.validate
            else Path("output.csv")
        )
    return args


def check_config(input_path: Path, token: str) -> str | None:
    """Return a setup problem, or None if everything needed is present."""
    where = "map it with env: on the pipeline step" if in_pipeline() else "set it in .env, run with --env-file .env"
    if not OKTA_ORG_URL.startswith("https://"):
        return f"OKTA_ORG_URL must be your Okta org URL, e.g. https://example.okta.com ({where})"
    if not token:
        return f"OKTA_API_TOKEN is not set ({where})"
    if not input_path.is_file():
        return f"Input file not found: {input_path}"
    return None


def write_unprocessed_report(rows: list[dict[str, str]], args: argparse.Namespace, reason: str) -> None:
    """Write a report (args.output) marking every row as not processed, so a failed run still has one to publish."""
    with args.output.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["name", args.match_by, *(VALIDATE_COLUMNS if args.validate else REPORT_COLUMNS)])
        for row in rows:
            if args.validate:
                cells = [row["name"], row["match"], "", f"error: not checked ({reason})", ""]
            else:
                cells = [row["name"], row["match"], "", "", "", NO_ACTION, ERROR, f"Not processed ({reason})"]
            writer.writerow(safe_cells(cells))


def run_validate(session: requests.Session, rows: list[dict[str, str]], args: argparse.Namespace) -> int:
    """Run --validate and return main's exit code."""
    log.warning("VALIDATE: looking users up only; no changes will be made in Okta.")
    output = args.output
    counts, stopped = validate_all(session, rows, args)
    summary = ", ".join(f"{count} {status}" for status, count in sorted(counts.items()))
    log.info("Done (validate): %s. Report written to %s", summary, output)
    if stopped:
        return 1
    if counts.get(ERROR):
        ado_command(f"task.logissue type=warning]{counts[ERROR]} row(s) could not be checked; see {output}")
        ado_command("task.complete result=SucceededWithIssues;]")
    return 0


def main() -> int:
    """Run the script and return an exit code (0 = finished, 1 = stopped early, 2 = setup problem)."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s")
    args = parse_args()
    token = get_okta_token()

    problem = check_config(args.input, token)
    if problem:
        log.error(problem)
        return 2

    rows = read_rows(args.input)
    if not rows:
        log.error("No rows found in %s", args.input)
        return 2

    if args.apply:
        # Create it up front, so even a run that fails at preflight has one to publish
        open_backup(args.backup).close()

    session = make_session(token)
    me = who_am_i(session)
    if me is None:
        write_unprocessed_report(rows, args, "preflight check failed; see the log")
        return 2

    log.info("Authenticated as %s; %d rows to process, matching on Okta %s", me, len(rows), MATCH_FIELDS[args.match_by])
    if args.validate:
        return run_validate(session, rows, args)

    if args.apply:
        log.warning("APPLY: users will be deactivated in %s, after backing each up to %s", OKTA_ORG_URL, args.backup)
    else:
        log.warning("DRY RUN: no changes will be made in Okta. Pass --apply to deactivate users.")

    counts, stopped = process_all(session, rows, args, me=me)

    log.info(
        "Done (%s): %d success, %d error. Report written to %s",
        "applied" if args.apply else "dry run",
        counts[SUCCESS],
        counts[ERROR],
        args.output,
    )

    if stopped:
        return 1
    if counts[ERROR]:
        ado_command(f"task.logissue type=warning]{counts[ERROR]} row(s) had errors; see {args.output}")
        ado_command("task.complete result=SucceededWithIssues;]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
