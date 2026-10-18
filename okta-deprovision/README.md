# okta-deprovision

Deactivates the Okta users listed in `users.csv` and writes `output.csv`
(name, login, status, detail). Self-contained: nothing here is imported from
elsewhere in the repo, and nothing elsewhere depends on it.

**Dry run by default.** Without `--apply` the script only looks users up and
reports what it would do.

## Run locally

Needs only [uv](https://docs.astral.sh/uv/).

```sh
cp .env.example .env        # then fill in OKTA_ORG_URL and OKTA_API_TOKEN
uv run --env-file .env deactivate_users.py            # dry run
uv run --env-file .env deactivate_users.py --apply    # deactivates users
```

## Run in Azure DevOps

Pipeline: `pipelines/okta-deprovision.yml`. It only ever runs when someone
starts it manually.

1. Run with **Apply changes** unticked (the default) and download the
   `okta-deprovision-report` artifact.
2. Check the report, then run again from `main` with **Apply changes**
   ticked. That run waits for approval on the `okta-production` environment.
