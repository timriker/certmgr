#!/usr/bin/env python3
"""RFC2136 DNS updater helpers with CNAME-following for ACME DNS-01.

This module uses dnspython to resolve CNAMEs and perform TSIG-signed DNS updates
to add and remove _acme-challenge TXT records where required.

The public API is:
- resolve_cname_target(fqdn) -> returns the ultimate target FQDN if a CNAME chain
  exists for the supplied name, otherwise returns the original fqdn.
- update_txt_record(server, port, key_name, key, algorithm, zone, name, txt_value)
  -> performs an add/replace of the TXT record for `name` in `zone` on the given
  server using TSIG credentials.

The code intentionally keeps operations explicit and synchronous so the CLI
workflow can call it when ready to publish and remove challenge TXT records.
"""
from typing import Optional
import socket
import dns.resolver
import dns.update
import dns.query
import dns.tsigkeyring
import dns.exception
import logging

log = logging.getLogger(__name__)


def resolve_cname_target(fqdn: str, nameserver: Optional[str] = None,
                         key_name: Optional[str] = None, key: Optional[str] = None,
                         algorithm: Optional[str] = None) -> str:
    """Follow CNAME chain for fqdn and return the final target.

    If no CNAME exists, returns the original fqdn.
    If TSIG credentials provided, uses them for queries.
    """
    try:
        if nameserver and key_name and key:
            # Use TSIG-authenticated query
            keyring = None
            algo_const = None
            if algorithm:
                algo_map = {
                    'hmac-md5': dns.tsig.HMAC_MD5,
                    'hmac-sha1': dns.tsig.HMAC_SHA1,
                    'hmac-sha224': dns.tsig.HMAC_SHA224,
                    'hmac-sha256': dns.tsig.HMAC_SHA256,
                    'hmac-sha384': dns.tsig.HMAC_SHA384,
                    'hmac-sha512': dns.tsig.HMAC_SHA512,
                }
                algo_const = algo_map.get(algorithm.lower())
            try:
                keyring = dns.tsigkeyring.from_text({key_name: key})
            except Exception:
                # Try without trailing dot
                key_name_stripped = key_name.rstrip('.')
                keyring = dns.tsigkeyring.from_text({key_name_stripped: key})
                key_name = key_name_stripped

            q = dns.message.make_query(fqdn, 'CNAME', use_edns=True)
            q.use_tsig(keyring=keyring, keyname=key_name, algorithm=algo_const)
            try:
                response = dns.query.tcp(q, nameserver, timeout=10)
                for rrset in response.answer:
                    if rrset.rdtype == dns.rdatatype.CNAME:
                        for rdata in rrset:
                            target = rdata.target.to_text(omit_final_dot=True)
                            return resolve_cname_target(target, nameserver, key_name, key, algorithm)
                return fqdn
            except Exception as e:
                log.debug("TSIG CNAME query for %s failed: %s", fqdn, e)
                return fqdn
        else:
            # Use default resolver
            answers = dns.resolver.resolve(fqdn, "CNAME")
            for r in answers:
                target = r.target.to_text(omit_final_dot=True)
                return resolve_cname_target(target, nameserver, key_name, key, algorithm)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return fqdn
    except Exception as e:
        log.debug("CNAME resolution for %s failed: %s", fqdn, e)
        return fqdn


def discover_zone_for_name(fqdn: str, nameserver: Optional[str] = None,
                           key_name: Optional[str] = None, key: Optional[str] = None,
                           algorithm: Optional[str] = None) -> str:
    """Discover the authoritative zone for a given FQDN by walking up
    the domain labels and looking for an SOA record (preferred) or NS record.

    Returns the zone name (without trailing dot). If discovery fails, returns
    the last two labels as a best-effort fallback.
    If TSIG credentials provided, uses them for queries.
    """
    name = fqdn.rstrip('.')
    labels = name.split('.')

    # Setup TSIG if provided
    keyring = None
    algo_const = None
    if nameserver and key_name and key:
        if algorithm:
            algo_map = {
                'hmac-md5': dns.tsig.HMAC_MD5,
                'hmac-sha1': dns.tsig.HMAC_SHA1,
                'hmac-sha224': dns.tsig.HMAC_SHA224,
                'hmac-sha256': dns.tsig.HMAC_SHA256,
                'hmac-sha384': dns.tsig.HMAC_SHA384,
                'hmac-sha512': dns.tsig.HMAC_SHA512,
            }
            algo_const = algo_map.get(algorithm.lower())
        try:
            keyring = dns.tsigkeyring.from_text({key_name: key})
        except Exception:
            key_name = key_name.rstrip('.')
            keyring = dns.tsigkeyring.from_text({key_name: key})
    # Walk from the full name up to the root, looking for SOA/NS records
    for i in range(len(labels)):
        candidate = '.'.join(labels[i:])
        try:
            if keyring:
                # Use TSIG query
                q = dns.message.make_query(candidate, 'SOA', use_edns=True)
                q.use_tsig(keyring=keyring, keyname=key_name, algorithm=algo_const)
                try:
                    response = dns.query.tcp(q, nameserver, timeout=10)
                    if response.answer:
                        log.debug("Discovered SOA for %s; using zone %s", fqdn, candidate)
                        return candidate
                except Exception:
                    pass
            else:
                # Use default resolver
                dns.resolver.resolve(candidate, 'SOA')
                log.debug("Discovered SOA for %s; using zone %s", fqdn, candidate)
                return candidate
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            # try NS as a fallback
            try:
                if keyring:
                    q = dns.message.make_query(candidate, 'NS', use_edns=True)
                    q.use_tsig(keyring=keyring, keyname=key_name, algorithm=algo_const)
                    response = dns.query.tcp(q, nameserver, timeout=10)
                    if response.answer:
                        log.debug("Found NS for %s; using zone %s", fqdn, candidate)
                        return candidate
                else:
                    answers = dns.resolver.resolve(candidate, 'NS')
                    if answers.rrset:
                        log.debug("Found NS for %s; using zone %s", fqdn, candidate)
                        return candidate
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                continue
        except Exception as e:
            log.debug("Error while discovering zone for %s at %s: %s", fqdn, candidate, e)
            continue

    # Fallback: use last two labels
    parts = name.split('.')
    if len(parts) >= 2:
        fallback = '.'.join(parts[-2:])
    else:
        fallback = name
    log.debug("Zone discovery failed for %s; falling back to %s", fqdn, fallback)
    return fallback


def update_txt_record(server: str,
                      port: int,
                      key_name: Optional[str],
                      key: Optional[str],
                      algorithm: Optional[str],
                      zone: str,
                      name: str,
                      txt_value: str,
                      ttl: int = 60) -> None:
    """Add/replace a TXT record `name` in `zone` on the DNS server.

    - server: target authoritative DNS server ip/host
    - key_name/key: TSIG key name and base64 key string (optional)
    - algorithm: e.g. 'hmac-sha256' (optional)
    - zone: DNS zone to update (e.g. example.com)
    - name: full name to set (e.g. _acme-challenge.example.com.) or relative name
    - txt_value: the TXT value (without surrounding quotes)
    """
    # Prepare candidate key names (try with and without trailing dot).
    candidates = [None]
    if key_name and key:
        if key_name.endswith('.'):
            candidates = [key_name, key_name.rstrip('.')]
        else:
            candidates = [key_name, key_name + '.']

    try:
        # Resolve server hostname to IP addresses (supports both hostnames and IPs).
        addrs = []
        try:
            for res in socket.getaddrinfo(server, None):
                family, _socktype, _proto, _canonname, sockaddr = res
                ip = sockaddr[0]
                addrs.append((family, ip))
        except Exception:
            # fallback: use server string as-is (may be IP already)
            addrs = [(socket.AF_UNSPEC, server)]

        last_exc = None
        # Try each candidate key name (if any) and each resolved IP address.
        for candidate in candidates:
            # build keyring/update object per candidate
            keyring = None
            if candidate and key:
                try:
                    keyring = dns.tsigkeyring.from_text({candidate: key})
                except Exception as e:
                    log.debug("Failed to build keyring for %s: %s", candidate, e)
                    last_exc = e
                    continue
            # Map algorithm string to dnspython constant if provided.
            algo_const = None
            if algorithm:
                algo_lower = algorithm.lower()
                algo_map = {
                    'hmac-md5': dns.tsig.HMAC_MD5,
                    'hmac-sha1': dns.tsig.HMAC_SHA1,
                    'hmac-sha224': dns.tsig.HMAC_SHA224,
                    'hmac-sha256': dns.tsig.HMAC_SHA256,
                    'hmac-sha384': dns.tsig.HMAC_SHA384,
                    'hmac-sha512': dns.tsig.HMAC_SHA512,
                }
                algo_const = algo_map.get(algo_lower)
                if not algo_const:
                    log.debug("Unrecognized TSIG algorithm '%s'; falling back to default", algorithm)

            if keyring and candidate:
                u = dns.update.Update(zone, keyring=keyring, keyname=candidate, keyalgorithm=algo_const)
            else:
                u = dns.update.Update(zone)

            for family, ip in addrs:
                try:
                    # name within zone: make it relative if it's a subdomain
                    relative_name = name
                    if name.endswith('.' + zone):
                        relative_name = name[:-(len(zone) + 1)]
                    # Delete existing records
                    u.delete(relative_name, 'TXT')
                    # Only add new value if txt_value is non-empty (for removal, just delete)
                    if txt_value:
                        u.add(relative_name, ttl, 'TXT', txt_value)
                        log.debug("Sending DNS update to %s:%s for zone %s: %s -> %s (key=%s)",
                                  ip, port, zone, relative_name, txt_value, candidate)
                    else:
                        log.debug("Sending DNS delete to %s:%s for zone %s: %s (key=%s)",
                                  ip, port, zone, relative_name, candidate)

                    response = dns.query.tcp(u, ip, port=port, timeout=10)
                    log.debug("DNS update response from %s: %s", ip, response)
                    return
                except Exception as e:
                    log.debug("DNS update to %s using key %s failed: %s", ip, candidate, e)
                    last_exc = e

        # If we get here, all attempts failed
        if last_exc:
            raise last_exc
    except dns.exception.DNSException as e:
        log.error("DNS update failed for %s on %s: %s", name, server, e)
        raise
