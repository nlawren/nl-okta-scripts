"""Deactivate Okta users listed in a CSV file and write a status report.

DRY RUN BY DEFAULT: users are only looked up and reported on. Nothing in Okta
changes unless --apply is passed.

Input  (users.csv):  name, login
Output (output.csv): name, login, status, detail

status is "success" or "error"; detail explains why.

Environment:
    OKTA_ORG_URL    e.g. https://example.okta.com
    OKTA_API_TOKEN  Okta API token (sent as "SSWS <token>")

Locally these come from .env (copy .env.example):
    uv run --env-file .env deactivate_users.py            # dry run
    uv run --env-file .env deactivate_users.py --apply    # make changes
"""

import argparse
import csv
import logging
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Final
from urllib.parse import quote

import requests

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

OKTA_ORG_URL: Final = os.getenv("OKTA_ORG_URL", "").strip().rstrip("/")

# Okta logins are email-formatted by default. Relax this if your org allows other formats.
LOGIN_PATTERN: Final = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# If the first row's second column is one of these, treat the row as a header and skip it.
HEADER_LOGIN_NAMES: Final = {"login", "login id", "loginid", "login_id", "username", "email"}

# Okta's API calls a deactivated user "DEPROVISIONED" (the admin console shows "Deactivated").
DEACTIVATED_STATUS: Final = "DEPROVISIONED"

SUCCESS: Final = "success"
ERROR: Final = "error"
REPORT_COLUMNS: Final = ["name", "login", "status", "detail"]

MAX_ATTEMPTS: Final = 5  # Tries per API call before giving up
REQUEST_TIMEOUT_SECONDS: Final = 30
RATE_LIMIT_HEADROOM: Final = 2  # Pause when this few requests remain in Okta's rate-limit window
MAX_RATE_LIMIT_WAIT_SECONDS: Final = 65

HTTP_UNAUTHORIZED: Final = 401
HTTP_NOT_FOUND: Final = 404
HTTP_TOO_MANY_REQUESTS: Final = 429
HTTP_SERVER_ERROR: Final = 500

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


def okta_request(
    session: requests.Session,
    method: str,
    path: str,
    params: dict[str, str] | None = None,
) -> requests.Response | None:
    """Call the Okta API, retrying on rate limits (429), server errors (5xx) and network errors.

    Returns the response (which may still be an error such as 404), or None if
    Okta couldn't be reached at all.
    """
    url = f"{OKTA_ORG_URL}/api/v1{path}"

    for attempt in range(1, MAX_ATTEMPTS + 1):
        is_last_attempt = attempt == MAX_ATTEMPTS

        try:
            resp = session.request(method, url, params=params, timeout=REQUEST_TIMEOUT_SECONDS)
        except requests.RequestException as exc:
            if is_last_attempt:
                log.warning("%s %s failed after %d attempts: %s", method, path, attempt, exc)
                return None
            log.warning("%s %s failed (%s); retrying in %ss", method, path, exc, 2**attempt)
            time.sleep(2**attempt)
            continue

        if resp.status_code == HTTP_TOO_MANY_REQUESTS and not is_last_attempt:
            wait = seconds_until_reset(resp)
            log.warning("Rate limited on %s %s; waiting %.0fs", method, path, wait)
            time.sleep(wait)
            continue

        if resp.status_code >= HTTP_SERVER_ERROR and not is_last_attempt:
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
    return resp.json().get("profile", {}).get("login", "unknown")


def look_up_user(session: requests.Session, login: str) -> tuple[dict[str, Any] | None, str, bool]:
    """Find a user in Okta by login.

    Returns (user, problem, stop):
        user     the user's details from Okta, or None if they couldn't be found
        problem  why the user couldn't be found ("" if they were)
        stop     True if the token was rejected, so the whole run should stop
    """
    resp = okta_request(session, "GET", f"/users/{quote(login, safe='')}")

    if resp is None:
        return None, "Lookup failed: could not reach Okta", False
    if resp.status_code == HTTP_UNAUTHORIZED:
        return None, f"Okta rejected the API token ({error_summary(resp)})", True
    if resp.status_code == HTTP_NOT_FOUND:
        return None, "User not found in Okta", False
    if not resp.ok:
        return None, f"Lookup failed: {error_summary(resp)}", False

    user = resp.json()

    # Okta also matches the start of a login (e.g. "jane" finds "jane@example.com"),
    # so make sure we got exactly the user we asked for.
    actual_login = user.get("profile", {}).get("login", "")
    if actual_login.casefold() != login.casefold():
        return None, f"Lookup returned a different user ({actual_login}); skipped", False

    return user, "", False


def send_deactivation(session: requests.Session, user_id: str) -> tuple[str, bool]:
    """Ask Okta to deactivate a user, without emailing the admin.

    Returns (problem, stop): problem is "" on success; stop is True if the token was rejected.
    """
    resp = okta_request(
        session,
        "POST",
        f"/users/{quote(user_id, safe='')}/lifecycle/deactivate",
        params={"sendEmail": "false"},
    )

    if resp is None:
        return "could not reach Okta", False
    if resp.status_code == HTTP_UNAUTHORIZED:
        return f"Okta rejected the API token ({error_summary(resp)})", True
    if not resp.ok:
        return error_summary(resp), False
    return "", False


# ---------------------------------------------------------------------------
# Reading and checking the CSV
# ---------------------------------------------------------------------------


def read_rows(path: Path) -> list[dict[str, str]]:
    """Read the input CSV into a list of {"line", "name", "login"} dictionaries.

    Skips a header row if there is one. Blank rows are kept so they show up in the report.
    """
    rows = []
    # utf-8-sig removes the invisible marker (BOM) Excel adds to the start of CSV files
    with path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.reader(fh)
        for index, raw in enumerate(reader):
            cells = [cell.strip() for cell in raw]
            name = cells[0] if len(cells) > 0 else ""
            login = cells[1] if len(cells) > 1 else ""

            if index == 0 and login.lower() in HEADER_LOGIN_NAMES:
                log.info("Skipping header row")
                continue

            rows.append({"line": str(reader.line_num), "name": name, "login": login})
    return rows


def validate_row(row: dict[str, str], seen_logins: set[str]) -> str | None:
    """Return why a row can't be processed, or None if it looks valid.

    seen_logins is updated with each valid login, to catch duplicates.
    """
    line = row["line"]
    if not row["name"] and not row["login"]:
        return f"Blank row (line {line})"
    if not row["login"]:
        return f"Missing login ID (line {line})"
    if not LOGIN_PATTERN.fullmatch(row["login"]):
        return f"Invalid login ID format (line {line})"

    key = row["login"].casefold()  # Okta logins aren't case-sensitive
    if key in seen_logins:
        return f"Duplicate login ID in input (line {line})"
    seen_logins.add(key)
    return None


# ---------------------------------------------------------------------------
# Processing
# ---------------------------------------------------------------------------


def process_row(session: requests.Session, row: dict[str, str], *, apply: bool) -> tuple[str, str, bool]:
    """Look up one user and, if apply is True, deactivate them.

    Returns (status, detail, stop): stop is True if the whole run should stop.
    """
    user, problem, stop = look_up_user(session, row["login"])
    if user is None:
        return ERROR, problem, stop

    current_status = user.get("status", "UNKNOWN")
    if current_status == DEACTIVATED_STATUS:
        return ERROR, "Already deactivated", False

    if not apply:
        return SUCCESS, f"Dry run: would deactivate (current status {current_status})", False

    problem, stop = send_deactivation(session, user["id"])
    if problem:
        return ERROR, f"Deactivation failed: {problem}", stop
    return SUCCESS, f"Deactivated (was {current_status})", False


def process_all(
    session: requests.Session,
    rows: list[dict[str, str]],
    output: Path,
    *,
    apply: bool,
) -> tuple[dict[str, int], bool]:
    """Process every row and write the report as we go.

    Returns (counts, stopped): counts of success/error, and whether the run stopped early.
    """
    counts = {SUCCESS: 0, ERROR: 0}
    seen_logins: set[str] = set()
    stopped = False

    with output.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(REPORT_COLUMNS)

        for row in rows:
            if stopped:
                status, detail = ERROR, "Not processed (run stopped early)"
            else:
                problem = validate_row(row, seen_logins)
                if problem:
                    status, detail = ERROR, problem
                else:
                    status, detail, stopped = process_row(session, row, apply=apply)
                    if stopped:
                        log.error("Stopping run: %s", detail)

            writer.writerow([row["name"], row["login"], status, detail])
            fh.flush()  # Keep the report up to date in case the job is cancelled
            counts[status] += 1
            log.info("%-7s %s: %s", status, row["login"] or "<blank>", detail)

    return counts, stopped


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    """Read command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", type=Path, default=Path("users.csv"), help="input CSV (default: users.csv)")
    parser.add_argument("--output", type=Path, default=Path("output.csv"), help="report CSV (default: output.csv)")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="actually deactivate users (without this, the run is a dry run and changes nothing)",
    )
    return parser.parse_args()


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

    session = make_session(token)
    me = who_am_i(session)
    if me is None:
        return 1

    log.info("Authenticated as %s; %d rows to process", me, len(rows))
    if args.apply:
        log.warning("APPLY: users will be deactivated in %s", OKTA_ORG_URL)
    else:
        log.warning("DRY RUN: no changes will be made in Okta. Pass --apply to deactivate users.")

    counts, stopped = process_all(session, rows, args.output, apply=args.apply)

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
