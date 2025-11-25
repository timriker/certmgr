#!/usr/bin/env python3
"""Utility to walk CNAME chain and discover authoritative zone via SOA for a name.

Usage:
  ./zone_discover.py <fqdn> [--credentials credentials.yaml]

It will:
 1. Follow any CNAME chain to a terminal target using TSIG if configured.
 2. Walk up labels performing SOA (then NS) lookups to determine zone apex.
 3. Print the original name, CNAME-resolved target (if different), and zone.

Requires dnspython (listed in requirements.txt).
"""
import sys
import os
import yaml
import argparse
from dns_rfc2136 import resolve_cname_target, discover_zone_for_name


def load_yaml(path):
    with open(path, 'r') as f:
        return yaml.safe_load(f)


def main():
    parser = argparse.ArgumentParser(
        description='Discover DNS zone for a given FQDN',
        epilog='Example: %(prog)s _acme-challenge.example.com'
    )
    parser.add_argument('fqdn', help='Fully qualified domain name to look up')
    parser.add_argument('--credentials', default=os.path.join(os.path.dirname(__file__), 'credentials.yaml'),
                        help='Path to credentials file with TSIG configuration (default: %(default)s)')
    args = parser.parse_args()

    fqdn = args.fqdn.rstrip('.')

    # Try to load TSIG credentials
    server = None
    key_name = None
    key = None
    algorithm = None
    try:
        if os.path.exists(args.credentials):
            creds = load_yaml(args.credentials)
            rfc2136 = creds.get('rfc2136', {})
            server = rfc2136.get('server')
            key_name = rfc2136.get('key_name')
            key = rfc2136.get('key')
            algorithm = rfc2136.get('algorithm')
            if server and key_name and key:
                print(f"Using TSIG authentication with key: {key_name}")
    except Exception as e:
        print(f"Warning: Could not load TSIG credentials: {e}")

    target = resolve_cname_target(fqdn, server, key_name, key, algorithm)
    zone = discover_zone_for_name(target, server, key_name, key, algorithm)
    print(f"Original: {fqdn}")
    print(f"Target:   {target}")
    print(f"Zone:     {zone}")

if __name__ == "__main__":
    main()
