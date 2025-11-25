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

Quick start
-----------

1. Create `credentials.yaml` (copy from `example.credentials.yaml`) and fill in
   real credentials.
2. Edit `config.yaml` (copy from `example.config.yaml`) to list your certificates
   , domains and F5 targets.
3. Install dependencies: pip install -r requirements.txt
4. Run:

  ./certmgr.py

   For testing, use the Let's Encrypt staging environment to avoid hitting
   production rate limits:

  ./certmgr.py --staging

   The `--staging` flag points the ACME client at the staging directory. Use
   the staging option when you're testing automation; only switch to
   production once you're confident the flow works.

Notes and caveats
- The ACME interactions use the `acme` library; depending on installed
  versions you may need to adapt minor API differences.
- F5 deployment uses the Big-IP iControl REST API.

- Use `--staging` for testing to avoid Let's Encrypt production rate limits.
