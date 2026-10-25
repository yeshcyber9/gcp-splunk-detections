# Detection Guide

SPL for each detection lives in [`default/savedsearches.conf`](../default/savedsearches.conf). All searches alert only on successful actions (`status_code=0`).

---

## 1. Service account key created
**ATT&CK:** T1098.001 Additional Cloud Credentials · **Severity:** Medium (High if the SA holds Owner/Editor)

**Why it matters:** a downloaded key is a long-lived credential usable from anywhere and is the most common way attackers persist in GCP.

**Tuning:** add CI/CD identities that rotate keys to `lookups/gcp_sa_key_allowlist.csv`. The org policy `iam.disableServiceAccountKeyCreation` prevents keys entirely.

**False positives:** Terraform/deployment pipelines, legacy apps outside GCP, local testing.

**Triage:**
1. Human or service account creator? An SA creating keys for another SA suggests lateral movement.
2. Unfamiliar `caller_ip`/ASN or raw API `user_agent` raises severity.
3. Check the target SA's roles; privileged SAs are urgent.
4. Review the principal's prior hour for IAM changes or enumeration.
5. If unexplained, disable the key (`gcloud iam service-accounts keys disable`) and investigate its use.

---

## 2. Owner or Editor role granted
**ATT&CK:** T1098.003 Additional Cloud Roles · **Severity:** High (Critical for external members)

**Why it matters:** basic roles give near-total control and are the usual goal of privilege escalation.

**Tuning:** set your domains in the `gcp_org_domains` macro; the `external` column flags Gmail or partner accounts.

**False positives:** project bootstrapping, break-glass access, creator grants on new projects.

**Triage:**
1. Is the member known? External/personal accounts are Critical.
2. Is there a change ticket?
3. Did the granter recently gain permissions themselves?
4. Review what the new member did afterwards.
5. If unauthorized, remove the binding and review the granter's session.

---

## 3. Log sink deleted or modified
**ATT&CK:** T1562.008 Disable or Modify Cloud Logs · **Severity:** High (Critical for sinks in `gcp_critical_sinks.csv`)

**Why it matters:** attackers cut the export pipeline so later actions never reach the SIEM. This may be the last event you receive from that scope.

**Tuning:** list your SIEM-feeding sinks in `lookups/gcp_critical_sinks.csv`. Pair with a "no events in 30 minutes" health alert on the GCP index.

**False positives:** Terraform re-applies, planned logging migrations.

**Triage:**
1. Did the sink feed a security tool? Recreate it immediately.
2. For updates, compare destination and filter; an unknown destination project is exfiltration.
3. Review the principal's previous 30 minutes.
4. Recover the gap from Cloud Logging's `_Required` and `_Default` buckets.

---

## 4. Firewall opens SSH or RDP to the internet
**ATT&CK:** T1562.007 Disable or Modify Cloud Firewall · **Severity:** High

**Why it matters:** internet-exposed SSH/RDP is scanned within minutes and is a top initial-access vector.

**Notes:** compute operations log first/last events; the search keeps the first, which carries the request. Port ranges (e.g. `20-30`) are not matched in this sample.

**False positives:** temporary debugging rules, bastion hosts, IAP setups using `0.0.0.0/0` instead of `35.235.240.0/20`.

**Triage:**
1. Which instances does the rule cover (`targetTags` or whole network)?
2. Check those instances' auth logs after the rule time.
3. Is this normal for the creator?
4. Restrict to IAP or an admin range, or delete the rule.

---

## 5. GCS bucket made public
**ATT&CK:** T1530 Data from Cloud Storage · **Severity:** Critical

**Why it matters:** public buckets are among the most common causes of cloud data leaks.

**Tuning:** allowlist intentionally public buckets in `lookups/gcp_public_bucket_allowlist.csv`. The org policy `storage.publicAccessPrevention` blocks these grants entirely.

**False positives:** static websites, public datasets, download buckets.

**Triage:**
1. Treat as an active exposure; check the bucket's contents first.
2. Remove the public binding immediately.
3. Check reads during the exposure window (needs Data Access logs; if off, reads cannot be ruled out).
4. If personal or regulated data was exposed, start your breach process.
