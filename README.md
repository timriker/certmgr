certmgr: ACME -> RFC2136 -> F5 deployer
=====================================

[Changelog](CHANGELOG.md)

This project is a minimal ACME client + RFC2136 DNS updater used to obtain
Let's Encrypt certificates and deploy them to F5 BIG-IP systems.

Python compatibility
- certmgr supports Python 3.9.25 and newer.
- If you run it as `./certmgr.py`, ensure the `python3` selected by the
  shebang is Python 3.9.25+.

Key points
- Uses DNS-01 challenges and will follow CNAMEs: if _acme-challenge.example.com
  is a CNAME to some other zone, the TXT will be published where the CNAME
  points.
- RFC2136 credentials (TSIG) and F5 credentials live in `credentials.yaml`.
- certificates, domains and F5 deployment targets live in `config.yaml`.
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

Key Type and Size
-----------------

By default, certmgr requests certificates using RSA keys with a size of 2048 bits. This applies to both the ACME account key and the certificate signing requests (CSRs) for all certificates issued.

**If you require ECDSA certificates or a different key size, you will need to modify the code in `acme_client.py` to generate the desired key type and size.**

All current cryptographic operations and type checks assume RSA 2048-bit keys.

Quick start
-----------

1. Create `credentials.yaml` (copy from `example.credentials.yaml`) and fill in
   real credentials.
2. Edit `config.yaml` (copy from `example.config.yaml`) to list your certificates,
   domains and F5 deployment targets.
3. Install dependencies with Python 3.9.25 or newer:

   `python3 -m pip install -r requirements.txt`
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

F5 Configuration
----------------

Each certificate can define separate F5 deployment targets:

- `f5_ltm`
  Traffic-certificate targets. These are the shared-IP or active-node names
  used for the existing LTM/client SSL deployment flow.

- `f5_httpd`
  Management-plane HTTPD targets. These should be cluster/shared-IP hostnames
  such as `lb-psb.churchofjesuschrist.org`. certmgr resolves them into the
  trusted member devices in the BIG-IP device trust store and deploys to each
  node's management interface.

Example:

```yaml
certificates:
  - name: churchofjesuschrist.org
    domains:
      - '*.churchofjesuschrist.org'
      - '*.lds.org'
      - '*.ldschurch.org'
    f5_ltm:
      - lb-psb.churchofjesuschrist.org
      - lb-rsb.churchofjesuschrist.org
    f5_httpd:
      - lb-psb.churchofjesuschrist.org
      - lb-rsb.churchofjesuschrist.org
```

Certificate Files
-----------------

certmgr writes these local artifacts for each certificate:

- `certs/<name>.key`
  The private key.

- `certs/<name>.pem`
  The normal ACME chain: leaf certificate plus intermediate certificate(s).
  This is the file used for `f5_ltm` deployment.

- `certs/<name>.with-root.pem`
  The management-plane chain: leaf certificate plus intermediate certificate(s)
  plus the root certificate. This is the file used for `f5_httpd` deployment.

Both PEM bundle files are written with a blank line between certificate blocks
to accommodate BIG-IP consumers that are sensitive to PEM formatting.

HTTPD Deployment Behavior
-------------------------

When a certificate entry has `f5_httpd` targets, `./certmgr.py --deploy` will:

- Resolve the cluster names into trusted member devices using BIG-IP device trust
- Prefer node hostnames for REST and HTTPS verification when they resolve
- Push the management certificate bundle from `certs/<name>.with-root.pem`
- Push the private key from `certs/<name>.key`
- Copy the deployed HTTPD certificate bundle to:
  - `/config/gtm/server.crt`
- Restart `httpd`
- Verify the certificate presented on the management HTTPS endpoint
- Restart `gtmd` after HTTPD recovers when the node has GTM configuration.

Notes and caveats
- The ACME interactions use the `acme` library; depending on installed
  versions you may need to adapt minor API differences.
- F5 deployment uses the Big-IP iControl REST API.
- The F5 certificate manager role cannot install certificates as it cannot
  upload the crt and key files to use. The F5 credentials need to be a
  full Administrator role.

- Use `--staging` for testing to avoid Let's Encrypt production rate limits.

https://community.f5.com/discussions/technicalforum/acme-dns-rfc-2136-lets-encrypt-certs/344541
