# Security Watchtower — Production Observability

Security Watchtower is a **production-only, observational security service**.
It does not sit in the request path, modify application traffic, authenticate
users, block requests, or apply remediation automatically.

It performs three bounded tasks:

1. Sends TLS-verified `GET` probes to explicitly configured production health endpoints.
2. Scans a read-only source mount for selected static security patterns.
3. Correlates API and code findings in Redis and sends redacted notifications.

The runtime accepts only `WATCHTOWER_ENV=production`. Any other environment is
rejected before Redis or watcher startup.

## Security boundaries

- Source is mounted read-only.
- Watcher container runs as UID/GID 1001 with all Linux capabilities dropped.
- Root filesystem is read-only; only `/tmp` is writable through tmpfs.
- Redis is private to the Compose network and is not published to the host.
- Redis authentication is mandatory and dangerous administrative commands are disabled.
- Health targets require explicit HTTPS paths and reject credentials, queries,
  fragments, loopback, link-local, multicast, unspecified and reserved IPs.
- DNS results for API probes are checked before connection to reduce SSRF/DNS-rebinding risk.
- HTTP redirects are disabled for probes and notifications.
- Notification content is bounded and credential-shaped values are redacted.
- Static scanner snapshots are bounded, regular files only, and final symlinks are not followed.
- Finding/alert payloads are schema validated and unknown fields are rejected.
- Alert cooldown claims use atomic Redis ownership tokens.

Watchtower is **not** a WAF, DDoS service, authentication system, authorization
system, SIEM replacement, or Kubernetes admission controller. Enforcement stays
with the authoritative edge/application/platform controls.

## Existing environment

A real `.env` is intentionally not part of this component archive. Keep the
existing untracked production `.env` when replacing the component.

Required values include:

```dotenv
WATCHTOWER_ENV=production
REDIS_PASSWORD=<high-entropy secret, at least 20 characters>
API_WATCHER_TARGETS=https://service.example.com/health
```

See `.env.example` for all supported settings.

## Verify

Using the component's existing virtual environment:

```bash
cd components/security-watchtower
make test PYTHON="$PWD/.venv/bin/python"
make lint PYTHON="$PWD/.venv/bin/python"
REDIS_PASSWORD='validation-only-secret-123456789' docker compose config --quiet
```

The tests are independent of the caller's working directory, so this also works
from the monorepo root:

```bash
components/security-watchtower/.venv/bin/pytest -q \
  components/security-watchtower/tests
```

## Deploy

Validate first:

```bash
cd components/security-watchtower
make check PYTHON="$PWD/.venv/bin/python"
docker compose up -d --build
docker compose ps
docker compose logs --tail=200 watchers
```

Rollback by restoring the previous component directory and running
`docker compose up -d --build` again. Redis evidence is stored in the named
`redis_data` volume and is not removed by ordinary `docker compose down`.

## Finding contract

`watchers/schema.py` is the versioned event contract. Unknown fields, malformed
identifiers, invalid enums, non-JSON context and invalid confidence values are
rejected. Code evidence stores a line hash and `[REDACTED]`, never the matched
secret text.

## Known operational limits

- Health probes confirm transport/status/latency, not business correctness.
- Static patterns are heuristics and require human review.
- A one-second window of acknowledged Redis writes can be lost with
  `appendfsync everysec` during catastrophic host failure.
- External notification delivery depends on provider availability.
- Inline/volumetric enforcement belongs outside this component.
