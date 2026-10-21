# okta-deprovision

Deactivates the Okta users listed in `users.csv` (name, email) and writes
`output.csv` (name, email, okta_login, okta_status, last_login, action, status,
detail). Self-contained: nothing here is imported from elsewhere in the repo,
and nothing elsewhere depends on it.

Users are matched on their Okta **primary email** (`profile.email`) by
default, since the Okta login can be on a different domain. `okta_login` is the
login of the user found. If more than one Okta user has the same primary email,
the row is an error listing their logins, and none of them is deactivated.

If your CSV has Okta logins instead, pass `--match-by login` (in the pipeline,
set **Match users by** to `login`). The second column is then named `login` in
every output instead of `email`.

`okta_login`, `okta_status` and `last_login` are as Okta had them before the
run; `action` is `deactivated`, `would deactivate` (dry run) or `none`.

**Dry run by default.** Without `--apply` the script only looks users up and
reports what it would do.

## Run locally

Needs only [uv](https://docs.astral.sh/uv/).

```sh
cp .env.example .env        # then fill in OKTA_ORG_URL and OKTA_API_TOKEN
uv run --env-file .env deactivate_users.py            # dry run
uv run --env-file .env deactivate_users.py --apply    # deactivates users
uv run --env-file .env deactivate_users.py --validate # status report only
```

`--validate` is read-only. It writes a copy of the input with three columns
added (`users.csv` -> `users-validated.csv`):

- `okta_login`: the Okta login of the user with that primary email, or blank
  if there isn't exactly one.
- `okta_status`: `not in Okta`, `deactivated`, `pending`, `active`,
  `suspended`, `locked out`, or `error: <reason>` if the row couldn't be
  checked. Okta can't tell a deleted user from one that never existed, so
  both show as `not in Okta`.
- `last_login`: UTC timestamp, `never`, or blank if the user wasn't found.

## Run in Azure DevOps

Pipeline: `pipelines/okta-deprovision.yml`. It only ever runs when someone
starts it manually.

Pick a **Mode** when you start it:

- `validate`: report each user's Okta status and last login. Changes
  nothing, runs from any branch, no approval. Artifact:
  `okta-deprovision-validate-report-<attempt>` (`users-validated.csv`).
- `dry-run` (the default): report what apply would do. Changes nothing.
  Artifact: `okta-deprovision-dry-run-report-<attempt>` (`output.csv`).
- `apply`: deactivate users. Only from `main`. The run first does a dry run
  of the same commit, then waits for approval on the `okta-production`
  environment before deactivating anyone. Artifacts: the dry-run report, then
  `okta-deprovision-applied-report-<attempt>` and
  `okta-deprovision-backup-<attempt>` (see [Backup](#backup)).

**Approvers:** before approving an `apply` run, download the dry-run report
from that same run and check it. It shows exactly which users the apply stage
will deactivate.

`<attempt>` is the job attempt number; after a retry, use the highest.

Re-running `apply` after a partial or cancelled run is safe: users who are
already deactivated count as success. The API token's own account is never
deactivated (it would revoke the token mid-run); it shows as an error to
handle by hand.

## Backup

`--apply` backs each user up just before deactivating them, as one JSON line
per user in `backup-<UTC time>.jsonl` (override with `--backup`; the pipeline
uses `backup.jsonl`). Each line has:

- `user`: the user's full Okta record, including their profile
- `groups`: id, name and type of each group they were in
- `apps`: each assigned app, with `assignment.scope` `USER` (assigned
  directly) or `GROUP` (through a group), plus the app username and profile

If the backup for a user fails (for example, the token can't read groups or
apps), that user isn't deactivated and shows as an error. Re-running adds to
the backup file; it never overwrites one.

There is no restore command. To restore someone, reactivate them in Okta and
re-add the groups and direct (`USER`) app assignments from their line.
Passwords and MFA enrolments aren't backed up and can't be restored.

The backup contains personal data. Locally it's created readable by you only
and is git-ignored; in Azure DevOps anyone who can view the pipeline's runs can
download it, for as long as the retention policy keeps it.
