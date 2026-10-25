# GCP Audit Log Detections for Splunk

Five high-impact detections for Google Cloud, built on **Admin Activity audit logs only** (always on, free), mapped to MITRE ATT&CK, and packaged as a drop-in Splunk app.

| # | Detection | ATT&CK | Severity |
|---|-----------|--------|----------|
| 1 | Service account key created | [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | Medium |
| 2 | Owner or Editor role granted | [T1098.003](https://attack.mitre.org/techniques/T1098/003/) | High |
| 3 | Log sink deleted or modified | [T1562.008](https://attack.mitre.org/techniques/T1562/008/) | High |
| 4 | Firewall opens SSH/RDP to the internet | [T1562.007](https://attack.mitre.org/techniques/T1562/007/) | High |
| 5 | GCS bucket made public | [T1530](https://attack.mitre.org/techniques/T1530/) | Critical |

Each detection's purpose, false positives and triage steps are in [docs/detections.md](docs/detections.md).

## Prerequisites

1. A Cloud Logging sink exporting audit logs (org or project level) to a Pub/Sub topic.
2. The Splunk Add-on for Google Cloud Platform ingesting that topic (default: `index=gcp`, `sourcetype=google:gcp:pubsub:message`). Dataflow-to-HEC also works; the base macro handles both formats.

## Install

1. Copy this repo into `$SPLUNK_HOME/etc/apps/gcp_splunk_detections/` (or package it as a `.tgz` and install via *Apps → Install app from file*).
2. Edit `default/macros.conf`:
   - `gcp_audit`: set your index and sourcetype.
   - `gcp_org_domains`: replace `yourcompany\.com` with your domain(s).
3. Edit the allowlists in `lookups/` (the sample rows are placeholders).
4. Restart Splunk, or reload via `/debug/refresh`.
5. Searches ship **disabled** (`enableSched = 0`). Enable each under *Settings → Searches, reports, and alerts* once you have tested it, and add your alert actions.

## Repo layout

```
default/      app.conf, macros.conf, savedsearches.conf, transforms.conf
lookups/      allowlist CSVs
metadata/     default.meta
docs/         detection guide
```

## Test in a lab project

Use a personal sandbox project only. Each command should produce an alert within a few minutes of ingestion.

| # | Trigger |
|---|---------|
| 1 | `gcloud iam service-accounts create lab-sa` then `gcloud iam service-accounts keys create key.json --iam-account=lab-sa@PROJECT.iam.gserviceaccount.com` |
| 2 | `gcloud projects add-iam-policy-binding PROJECT --member=user:you@example.com --role=roles/editor` |
| 3 | `gcloud logging sinks create lab-sink storage.googleapis.com/BUCKET` then `gcloud logging sinks delete lab-sink` |
| 4 | `gcloud compute firewall-rules create lab-ssh --allow=tcp:22 --source-ranges=0.0.0.0/0` |
| 5 | `gcloud storage buckets add-iam-policy-binding gs://BUCKET --member=allUsers --role=roles/storage.objectViewer` |

Clean up everything afterwards. Field names and `methodName` values can differ slightly across API versions and ingestion paths; check your own events and open an issue if something doesn't match.

## Want more?

The full GCP Detection Pack adds 31 more detections (credential theft, impersonation, persistence, discovery, exfiltration, cryptomining), an overview dashboard and tuning macros: **[link coming soon]**

## License

Apache License 2.0. See [LICENSE](LICENSE). Contributions welcome via pull request.
