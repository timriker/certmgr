certmgr: ACME -> RFC2136 -> F5 deployer
=====================================

This project is a minimal ACME client + RFC2136 DNS updater used to obtain
Let's Encrypt certificates and deploy them to F5 BIG-IP systems.

Key points
- Uses DNS-01 challenges and will follow CNAMEs: if _acme-challenge.example.com
  is a CNAME to some other zone, the TXT will be published where the CNAME
  points.
- RFC2136 credentials (TSIG) and F5 credentials live in `credentials.yaml`.
- certificates, domains and F5 targets live in `config.yaml`.
- The CLI will renew certificates that are missing or expire within the
  configured threshold (default 30 days).

DNS Configuration Best Practice
--------------------------------

For optimal certificate validation, it's recommended to use CNAME entries pointing
to a dedicated `_tls.example.com` zone for ACME challenge records. This approach
provides several benefits:

- **Lower TTL**: The dedicated zone can use a short TTL (e.g., 60 seconds) for
  rapid DNS propagation during certificate validation without affecting your
  main domain's DNS cache times.
- **Faster replication**: Changes to challenge records replicate quickly across
  DNS servers without waiting for long TTLs on production zones.
- **Isolation**: ACME validation records are separated from production DNS,
  reducing the risk of impacting live services.

Example configuration:
```
; In your main zone (example.com)
_acme-challenge.example.com.     IN CNAME  example.com._tls.example.com.

; In another main zone (example.net)
_acme-challenge.example.net.     IN CNAME  example.net._tls.example.com.

; These records would be used in _tls.example.com zone (with short TTL)
$TTL 60
example.com._tls.example.com.    IN TXT   "challenge-token-here"
example.net._tls.example.com.    IN TXT   "challenge-token-here"
```

This allows certmgr to update the `_tls.example.com` zone (which has a 60-second
TTL and fast replication) while your main zone maintains longer TTLs for stability.

Quick start
-----------

1. Create `credentials.yaml` (copy from `example.credentials.yaml`) and fill in
   real credentials.
2. Edit `config.yaml` (copy from `example.config.yaml`) to list your certificates,
   domains and F5 targets.
3. Install dependencies: pip install -r requirements.txt
4. Run:

  ./certmgr.py --staging

   For testing, use the Let's Encrypt staging environment to avoid hitting
   production rate limits. Once this is working remove the --staging

  ./certmgr.py

   The `--staging` flag points the ACME client at the staging directory. Use
   the staging option when you're testing automation; only switch to
   production once you're confident the flow works.

Command-line Options
-------------------

The following options are available when running `certmgr.py`:

- `--config PATH`                Path to config file (default: config.yaml)
- `--credentials PATH`           Path to credentials file (default: credentials.yaml)
- `--account-key PATH`           Path to ACME account key (default: account.key)
- `--days N`                     Renew if cert expires within N days (default: 30)
- `--force`                      Force renewal regardless of expiration
- `--staging`                    Use Let's Encrypt staging directory (safe for testing)
- `--dry-run`                    Do not perform network calls; print planned actions
- `--verbose`                    Enable verbose (debug) logging output
- `--prepopulate`                Create/overwrite TXT records for all _acme-challenge.<domain> names listed in config without requesting a certificate
- `--deploy`                     Deploy existing local certificates to F5 targets without requesting new certificates
- `--list`                       List existing local certificates with their domains and expiration dates
- `--certs NAMES`                Comma-delimited list of certificate names to process (e.g. dicm.org,example.com)
- `--dns-wait-seconds N`         Seconds to wait for DNS propagation (default: 5)

Example usage:

    ./certmgr.py --force --verbose --certs=dicm.org,example.com --dns-wait-seconds=2

Notes and caveats
- The ACME interactions use the `acme` library; depending on installed
  versions you may need to adapt minor API differences.
- F5 deployment uses the Big-IP iControl REST API.
- The F5 certificate manager role cannot install certificates as it cannot
  upload the crt and key files to use. The F5 credentials need to be a
  full Administrator role.

- Use `--staging` for testing to avoid Let's Encrypt production rate limits.
