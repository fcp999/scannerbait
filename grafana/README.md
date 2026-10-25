# Grafana dashboard (backup)

`scannerbait-dashboard.json` is a Grafana dashboard export, kept here as a backup.

- **uid:** `scannerbait`
- **Title:** Scannerbait — Honeypot Probes
- **Datasource:** Loki, uid `cfw7omdnm7pq8c` (log stack fed by `SCANNERBAIT_SYSLOG` → promtail → loki)
- **Panels:** probes over time, outcome split, top source addresses, most probed paths, live probe log

## Import

Grafana → Dashboards → New → Import → upload the JSON. If your Loki datasource
has a different uid, rebind it after import (the JSON hardcodes
`cfw7omdnm7pq8c`); queries themselves are portable.
