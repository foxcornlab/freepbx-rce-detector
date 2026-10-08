# `freepbx-rce-detector`

Triage scanner for `CVE-2025-57819`, the `unauthenticated` SQL injection in `FreePBX` `Endpoint Manager` that chains to `RCE`. Built from the research in my `AdverXarial` write-up on the `FreePBX` `un-AUTH` `RCE` via `SQLi` initial access chain.

> `Detection` only. This tool never sends `injection` payloads, it fingerprints and compares versions. Safe to run against your own estate.

## The `bug`

`FreePBX` `Endpoint Manager` exposes `/admin/ajax.php` without `authentication`. The `brand` parameter gets concatenated straight into a `SQL` query, giving a pre-auth `error`-based injection (`EXTRACTVALUE` -> `XPATH` syntax error leaks). Attackers escalate it by writing rows into the `cron_jobs` table, which `FreePBX` executes, landing `RCE` as the `asterisk` user. In the wild since `Aug 2025`, now in `CISA KEV`. `CVSS 9.8`.

| `FreePBX` | `Fixed Endpoint Manager` |
|---|---|
| `15.x` | `15.0.66` |
| `16.x` | `16.0.89` |
| `17.x` | `17.0.3` |

## Usage

No dependencies, `standard library` only:

```shell
python3 freepbx_detector.py scan pbx.example.com
python3 freepbx_detector.py scan http://10.0.0.5 https://pbx.corp.lan -k
python3 freepbx_detector.py scan pbx.example.com --json
```

Verdicts: `VULNERABLE`, `PATCHED`, `NEEDS-MANUAL-CHECK`, `NOT-FREEPBX`, `UNREACHABLE`.

> `Note`: the `Endpoint Manager` module version is rarely exposed pre-auth, so most live hosts land on `NEEDS-MANUAL-CHECK`. That is honest triage, not a miss. Confirm the module version in `Module Admin` and patch to the fixed releases above.

Hunt your `access logs` for exploitation attempts:

```shell
python3 freepbx_detector.py logcheck /var/log/apache2/access.log
```

Flags requests to `ajax.php` carrying `brand=` plus `SQLi` markers (`EXTRACTVALUE`, `UNION SELECT`, `INSERT INTO`, stacked queries). Exits `1` when it finds hits, so it drops straight into monitoring.

## Remediation

1. Update `Endpoint Manager` to `15.0.66` / `16.0.89` / `17.0.3`.
2. Check `cron_jobs` table and system `crontab` for rows you didn't add.
3. Grep logs for `ajax.php` with sketchy `brand` parameters.
4. Take the admin panel off the internet, `VPN` + `IP` allowlist it.
5. If you find indicators, assume `compromise`: rotate creds, hunt for backdoors, rebuild the box.

## References

- `Sangoma` security advisory `GHSA-m42g-xg4c-5f3h`
- `CISA KEV` entry for `CVE-2025-57819`
- My write-up: `AdverXarial` on Substack

## Disclaimer

For `educational` and `authorized` testing only. Only scan systems you own or have `permission` to test.

## `Foxcorn Lab`

> Research by `Vineeth Kumar`, `Foxcorn Lab`. Found a bug or want a feature, open an `issue`.
