# Security Watchtower Production Architecture

Security Watchtower is a production-only observational component. It consumes
read-only source and side-effect-free HTTPS health signals, persists bounded
findings to an isolated Redis instance, correlates known API/code issue pairs,
and emits redacted notifications.

It has no application write path and no authority to block, mutate, deploy,
restart, authenticate, authorize, or remediate production workloads.

## Trust boundaries

1. **Production health endpoints** — explicitly configured HTTPS GET targets.
2. **Read-only source mount** — static analysis only; no writes or symlink following.
3. **Private Redis** — finding queue, evidence records, alert publication, cooldown claims.
4. **Outbound notifier** — TLS verified, redirects disabled, bounded/redacted payloads.

Enforcement remains owned by the public gateway, service authorization logic,
Kubernetes/platform controls and infrastructure firewalling.
