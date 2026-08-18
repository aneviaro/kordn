# Project Guidance

## Architecture and Security Boundaries

- Keep Kordn as one local Go binary and one `kordn run` process; do not introduce a daemon or network control plane.
- Treat non-AWS HTTPS CONNECT traffic as byte-opaque end-to-end TLS. The per-run Kordn CA is for positively classified AWS interception only and must never enter the system trust store.
