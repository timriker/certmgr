#!/usr/bin/env python3
"""Command-line orchestration for obtaining and deploying certificates.

Usage:
    ./certmgr.py [options]

Default behavior (no options):
    - Shows list of all certificates with expiration status
    - Automatically renews certificates that expire within 30 days (or --days threshold)
    - Renews certificates that have domain changes in config
    - Deploys renewed certificates to configured F5 targets
    - Shows summary of actions taken

Options:
    --list: Only show certificate list, do not renew
    --deploy: Only deploy existing certificates, do not renew
    --prepopulate: Only create DNS TXT records for testing
    --staging: Use Let's Encrypt staging environment
    --force: Force renewal regardless of expiration
    --days N: Renew if expires within N days (default: 30)
"""
import argparse
import logging
import os
import yaml
from datetime import datetime, timezone
from cryptography import x509
import sys

# Make the script runnable from any current working directory by ensuring the
# script directory is on sys.path and by using config/credentials paths
# relative to the script directory by default.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

try:
    from .acme_client import AcmeClient
    from .dns_rfc2136 import resolve_cname_target, update_txt_record, discover_zone_for_name
    from .f5_deploy import F5Deployer
except Exception:
    # Allow running this file directly (not via -m) for quick testing by
    # falling back to module-level imports.
    from acme_client import AcmeClient
    from dns_rfc2136 import resolve_cname_target, update_txt_record, discover_zone_for_name
    from f5_deploy import F5Deployer

log = logging.getLogger(__name__)


def load_yaml(path):
    with open(path, 'r') as f:
        return yaml.safe_load(f)


def find_zone_for_fqdn(fqdn: str, zones: list):
    # choose longest matching zone name that is a suffix of fqdn
    fqdn = fqdn.rstrip('.')
    cand = None
    for z in zones:
        name = z.get('name')
        if fqdn == name or fqdn.endswith('.' + name):
            if cand is None or len(name) > len(cand.get('name')):
                cand = z
    return cand


def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)


def days_until_expiry(pem_data: bytes) -> int:
    cert = x509.load_pem_x509_certificate(pem_data)
    not_after = cert.not_valid_after
    # Ensure not_after is timezone-aware
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    delta = not_after - datetime.now(timezone.utc)
    return delta.days


def expand_domains(domains: list) -> list:
    """Expand domain list to include bare domains for wildcards.

    If a wildcard like *.example.com is present, automatically include
    example.com as well (unless already present).
    """
    expanded = list(domains)  # Copy the original list
    for domain in domains:
        if domain.startswith('*.'):
            bare_domain = domain[2:]  # Remove the '*.'
            if bare_domain not in expanded:
                expanded.append(bare_domain)
    return expanded


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default=os.path.join(SCRIPT_DIR, 'config.yaml'))
    parser.add_argument('--credentials', default=os.path.join(SCRIPT_DIR, 'credentials.yaml'))
    parser.add_argument('--account-key', default='account.key')
    parser.add_argument('--days', type=int, default=30, help='Renew if cert expires within DAYS')
    parser.add_argument('--force', action='store_true')
    parser.add_argument('--staging', action='store_true', help='Use Let\'s Encrypt staging directory (safe for testing)')
    parser.add_argument('--dry-run', action='store_true', help='Do not perform network calls; print planned actions')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--prepopulate', action='store_true',
                        help='Create (or overwrite) TXT records for all _acme-challenge.<domain> names listed in config without requesting a certificate')
    parser.add_argument('--deploy', action='store_true',
                        help='Deploy existing local certificates to F5 targets without requesting new certificates')
    parser.add_argument('--list', action='store_true',
                        help='List existing local certificates with their domains and expiration dates')
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)

    config = load_yaml(args.config)
    creds = load_yaml(args.credentials)

    certificates = config.get('certificates', [])

    certs_dir = os.path.join(SCRIPT_DIR, 'certs')
    if not args.dry_run:
        ensure_dir(certs_dir)

    # Choose ACME directory: production by default, staging if requested
    directory_url = "https://acme-v02.api.letsencrypt.org/directory"
    if args.staging:
        directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
        log.info("Using Let's Encrypt STAGING directory: %s", directory_url)
    acme = AcmeClient(directory_url=directory_url)

    # We'll create per-certificate publish/remove closures inside the loop so
    # that each certificate can carry its own rfc2136/zone overrides. If a
    # certificate doesn't provide rfc2136 settings, we fall back to
    # credentials.yaml rfc2136 block.

    # Handle --list option (or default with no action options)
    show_list = args.list or not (args.prepopulate or args.deploy)

    if show_list:
        print(f"{'Certificate':<30} {'Expires In':<15} {'Status':<15} {'Domains'}")
        print("-" * 120)
        for cert in certificates:
            name = cert['name']
            domains = expand_domains(cert['domains'])
            cert_path = os.path.join('certs', f"{name}.pem")

            if os.path.exists(cert_path):
                try:
                    with open(cert_path, 'rb') as f:
                        pem = f.read()
                    days = days_until_expiry(pem)
                    domains_str = ', '.join(domains)
                    if days < 0:
                        status = "EXPIRED"
                    elif days <= 30:
                        status = "RENEW SOON"
                    else:
                        status = "Valid"
                    print(f"{name:<30} {days:>3} days        {status:<15} {domains_str}")
                except Exception as e:
                    domains_str = ', '.join(domains)
                    print(f"{name:<30} {'ERROR':<15} {str(e)[:20]:<15} {domains_str}")
            else:
                domains_str = ', '.join(domains)
                print(f"{name:<30} {'NOT FOUND':<15} {'Missing':<15} {domains_str}")
        print()

    # If --list only, exit after showing list
    if args.list:
        return

    # Track summary of operations when running default mode
    summary = {
        'renewed': [],
        'reordered': [],
        'deployed': [],
        'errors': []
    }

    # Iterate certificates
    for cert in certificates:
        name = cert['name']
        domains = expand_domains(cert['domains'])
        cert_path = os.path.join('certs', f"{name}.pem")
        key_path = os.path.join('certs', f"{name}.key")

        if args.deploy:
            # Deploy existing certificates without requesting new ones
            if not os.path.exists(cert_path):
                log.warning("Certificate %s not found at %s, skipping", name, cert_path)
                continue
            if not os.path.exists(key_path):
                log.warning("Private key %s not found at %s, skipping", name, key_path)
                continue

            log.info("Deploying existing certificate %s to F5 targets", name)
            with open(cert_path, 'rb') as f:
                cert_pem = f.read()
            with open(key_path, 'rb') as f:
                key_pem = f.read()

            f5_targets = cert.get('f5_targets') or config.get('f5_targets') or []
            f5_creds = creds.get('f5', {})
            deployer = F5Deployer(f5_creds.get('username'), f5_creds.get('password'), verify_ssl=f5_creds.get('verify_ssl', False))

            for host in f5_targets:
                try:
                    deployer.deploy(host, cert_pem, key_pem, name)
                    log.info("Deployed %s to %s", name, host)
                    summary['deployed'].append(name)
                except Exception as e:
                    log.exception("Failed to deploy to %s: %s", host, e)
                    summary['errors'].append(f"Deploy {name} to {host}: {str(e)}")
            continue

        if args.prepopulate:
            # For each domain create its ACME challenge name and publish a placeholder TXT.
            # Wildcard domains (*.example.com) map to base domain for dns-01.
            log.info("Prepopulating TXT records for certificate %s", name)
            placeholder = f"prepopulate-{int(datetime.now(timezone.utc).timestamp())}"
            for d in domains:
                base = d.lstrip('*.')
                challenge_name = f"_acme-challenge.{base}"
                try:
                    r = creds.get('rfc2136')
                    if not r:
                        raise RuntimeError("No rfc2136 block in credentials.yaml for prepopulate")
                    server = r.get('server')
                    port = r.get('port', 53)
                    key_name = r.get('key_name')
                    key = r.get('key')
                    algorithm = r.get('algorithm')
                    target = resolve_cname_target(challenge_name, server, key_name, key, algorithm)
                    zname = discover_zone_for_name(target, server, key_name, key, algorithm)
                    log.info("Publishing placeholder TXT for %s (target %s zone %s): %s", challenge_name, target, zname, placeholder)
                    update_txt_record(server, port, key_name, key, algorithm, zname, target, placeholder)
                except Exception as e:
                    log.error("Failed to prepopulate %s: %s", challenge_name, e)
            # Skip renewal logic when prepopulate is requested
            continue

        need = args.force
        reorder = False  # Track if domains have changed
        if not need and os.path.exists(cert_path):
            with open(cert_path, 'rb') as f:
                pem = f.read()
                days = days_until_expiry(pem)
                if days <= args.days:
                    log.info("Certificate %s expires in %d days (<= %d), will renew", name, days, args.days)
                    need = True
                else:
                    log.info("Certificate %s is valid for %d more days, skipping", name, days)

                # Check if domains have changed
                try:
                    cert_obj = x509.load_pem_x509_certificate(pem)
                    # Extract Subject Alternative Names
                    san_ext = cert_obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    cert_domains = set()
                    for san in san_ext.value:
                        if isinstance(san, x509.DNSName):
                            cert_domains.add(san.value)
                    config_domains = set(domains)
                    if cert_domains != config_domains:
                        log.info("Certificate %s has domain changes (cert: %s, config: %s), will reorder", name, cert_domains, config_domains)
                        need = True
                        reorder = True
                except Exception as e:
                    log.warning("Failed to check domains for %s: %s", name, e)
        else:
            need = True

        if need:
            log.info("Requesting certificate for %s (%s)", name, domains)

            if args.dry_run:
                # Dry-run: print the planned actions and skip network interactions.
                log.info("DRY RUN: would request ACME certificate for %s with domains %s", name, domains)
                f5_targets = cert.get('f5_targets') or config.get('f5_targets') or []
                for host in f5_targets:
                    log.info("DRY RUN: would deploy %s.crt and %s.key to %s", name, name, host)
                # continue to next certificate without making network calls
                continue

            # Publish/remove helpers use only the RFC2136 settings from
            # credentials.yaml. We follow CNAMEs for the challenge and if the
            # zone name is not explicit we derive the last two labels as a
            # best-effort zone name.
            def publish(fqdn, txt):
                r = creds.get('rfc2136')
                if not r:
                    raise RuntimeError(f"No RFC2136 configuration in credentials.yaml required for publishing challenge for {fqdn}")
                server = r.get('server')
                port = r.get('port', 53)
                key_name = r.get('key_name')
                key = r.get('key')
                algorithm = r.get('algorithm')
                target = resolve_cname_target(fqdn, server, key_name, key, algorithm)
                # Discover authoritative zone by walking DNS (SOA/NS checks)
                zname = discover_zone_for_name(target, server, key_name, key, algorithm)
                # Log the final target (after following any CNAME) and the TXT value
                log.info("Publishing TXT record for %s (zone %s): %s", target, zname, txt)
                update_txt_record(server, port, key_name, key, algorithm, zname, target, txt)

            def remove(fqdn):
                r = creds.get('rfc2136')
                if not r:
                    log.warning("No rfc2136 in credentials.yaml for %s, skipping removal", fqdn)
                    return
                server = r.get('server')
                port = r.get('port', 53)
                key_name = r.get('key_name')
                key = r.get('key')
                algorithm = r.get('algorithm')
                target = resolve_cname_target(fqdn, server, key_name, key, algorithm)
                zname = discover_zone_for_name(target, server, key_name, key, algorithm)
                log.info("Removing TXT record for %s (zone %s)", target, zname)
                try:
                    update_txt_record(server, port, key_name, key, algorithm, zname, target, "")
                except Exception as e:
                    log.warning("Failed to remove TXT record for %s: %s", target, e)

            cert_pem, _, key_pem = acme.obtain_certificate(domains, publish, remove, account_key_path=args.account_key)
            # cert_pem is fullchain; save key and cert
            # CSR creation returned a private key saved inside acme flow; for now
            # the client wrote key to account; in create_csr we generated a key
            # --- assume acme.obtain_certificate returned cert_pem and we saved key earlier
            with open(cert_path, 'wb') as f:
                f.write(cert_pem)
            # save private key if returned
            if key_pem:
                with open(key_path, 'wb') as kf:
                    kf.write(key_pem)
                log.info("Saved private key to %s", key_path)
            log.info("Saved certificate to %s", cert_path)

            # Track what was done
            if reorder:
                summary['reordered'].append(name)
            else:
                summary['renewed'].append(name)

            # Deploy to F5 targets
            # Determine f5 targets: per-cert override, per-zone or global
            f5_targets = cert.get('f5_targets') or config.get('f5_targets') or []
            f5_creds = creds.get('f5', {})
            deployer = F5Deployer(f5_creds.get('username'), f5_creds.get('password'), verify_ssl=f5_creds.get('verify_ssl', False))
            # We currently do not have the private key saved separately; if the
            # ACME client returns it we should save and deploy it. This example
            # expects the CSR-generation key to be made available; for now we
            # store cert only and attempt to deploy cert (some F5s accept cert-only)
            for host in f5_targets:
                try:
                    # pass empty key for now if not present
                    key_pem = b""
                    if os.path.exists(key_path):
                        with open(key_path, 'rb') as kf:
                            key_pem = kf.read()
                    # use certificate base name; on the F5 the objects will be
                    # named <name>.crt and <name>.key
                    deployer.deploy(host, cert_pem, key_pem, name)
                    log.info("Deployed %s to %s", name, host)
                except Exception as e:
                    log.exception("Failed to deploy to %s: %s", host, e)
                    summary['errors'].append(f"Deploy {name} to {host}: {str(e)}")

    # Print summary if running in default mode (not --prepopulate, not --deploy, not --list)
    if not (args.prepopulate or args.deploy or args.list):
        print()
        print("=" * 80)
        print("SUMMARY")
        print("=" * 80)

        if summary['renewed']:
            print(f"Renewed certificates: {', '.join(summary['renewed'])}")
        if summary['reordered']:
            print(f"Reordered certificates (domain changes): {', '.join(summary['reordered'])}")
        if summary['deployed']:
            deployed_unique = list(set(summary['deployed']))
            print(f"Deployed certificates: {', '.join(deployed_unique)}")
        if summary['errors']:
            print(f"Errors encountered: {len(summary['errors'])}")
            for err in summary['errors']:
                print(f"  - {err}")

        if not (summary['renewed'] or summary['reordered'] or summary['deployed']):
            if summary['errors']:
                print("No certificates were renewed or deployed due to errors.")
            else:
                print("No certificates needed renewal. All certificates are up to date.")

if __name__ == '__main__':
    main()
