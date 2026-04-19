Github Argo Proxy
=================

A simple Cloudflare Worker that accepts Github Webhooks and forwards them to ArgoCD which is protected by Access.

Configuration
-------------

The worker supports either a single default webhook secret via `WEBHOOK_SECRET`, or per-repository secrets via `WEBHOOK_SECRETS`.

`WEBHOOK_SECRETS` should be a JSON object keyed by GitHub repository full name:

```json
{
  "octo-org/argo-app": "repo-secret-1",
  "octo-org/another-app": "repo-secret-2"
}
```

When `WEBHOOK_SECRETS` is present, the worker uses `repository.full_name` from the webhook payload to select that repository's secret. If a repository is not listed, it falls back to `WEBHOOK_SECRET` when one is configured.
