#!/usr/bin/env python3
# Copyright (c) 2025 Tim Riker
# SPDX-License-Identifier: MIT
"""Lightweight ACME client wrapper to request certificates from Let's Encrypt.

This module provides a high-level AcmeClient that can:
- create/load an ACME account key
- request an order for a set of domain names
- request DNS-01 challenges and rely on a provided DNS updater callable to
  publish and remove TXT records

Notes:
- This implementation uses the `acme` library (from certbot project). Make
  sure it's installed (listed in requirements.txt). The ACME protocol parts are
  implemented with best-effort calls to the `acme` API; depending on library
  versions minor adjustments may be required.
"""
from typing import Callable, Iterable, Tuple
import logging
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509 import NameOID

log = logging.getLogger(__name__)

class AcmeClient:
    def __init__(self, directory_url: str = "https://acme-v02.api.letsencrypt.org/directory", dns_wait_seconds: int = 5):
        self.directory_url = directory_url
        # account key and client will be created lazily
        self.account_key = None
        self.client = None
        self.dns_wait_seconds = dns_wait_seconds

    def generate_account_key(self, bits: int = 2048):
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        self.account_key = key
        return key

    def load_or_create_account_key(self, path: str) -> rsa.RSAPrivateKey:
        if os.path.exists(path):
            with open(path, "rb") as f:
                data = f.read()
                key = serialization.load_pem_private_key(data, password=None)
                self.account_key = key
                return key
        key = self.generate_account_key()
        with open(path, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
        return key

    def create_csr(self, domains: Iterable[str], key=None) -> Tuple[bytes, rsa.RSAPrivateKey]:
        # create key for CSR if not provided
        if key is None:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, list(domains)[0])])
        alt_names = [x509.DNSName(d) for d in domains]
        csr = x509.CertificateSigningRequestBuilder().subject_name(name).add_extension(
            x509.SubjectAlternativeName(alt_names), critical=False)
        csr = csr.sign(key, hashes.SHA256())
        return csr.public_bytes(serialization.Encoding.PEM), key

    def obtain_certificate(self,
                           domains: Iterable[str],
                           publish_challenge: Callable[[str, str], None],
                           remove_challenge: Callable[[str], None],
                           account_key_path: str = "account.key") -> Tuple[bytes, bytes, bytes]:
        """High-level flow:

        - ensure account key exists
        - create CSR for domains
        - create an order with ACME server and for each authorization ask the
          caller to publish the challenge (DNS TXT value) via publish_challenge
          callable which receives (fqdn, txt_value)
        - after validation finalize the order and return (cert_pem, chain_pem)

        publish_challenge should publish the TXT record and wait until it's
        visible to the authoritative servers (or perform its own checks).

        remove_challenge should remove the TXT record when called with fqdn.
        """
        # Load or create account key
        self.load_or_create_account_key(account_key_path)

        # Create CSR and key
        csr_pem, privkey = self.create_csr(domains)

        # The ACME protocol interactions are performed using the `acme` library.
        # Implementations vary across versions; the following is a high-level
        # sequence. Consumers may need to adapt details if API surface differs.
        try:
            from acme import client as acme_client, messages, errors as acme_errors
            from josepy import JWKRSA
        except Exception as e:
            log.error("ACME library not available: %s", e)
            raise

        # Create a JWK RSA object and network client. Important: after
        # registering the account we must attach the returned registration
        # resource to the network client (net.account) so subsequent requests
        # use the account Key ID (kid) in JWS headers instead of embedding the
        # JWK. Failing to set this is a common cause of "No Key ID in JWS
        # header" errors from ACME servers.
        jwk = JWKRSA(key=self.account_key)

        # Create a temporary network client to fetch the directory and (if
        # needed) register the account. After registration we'll create a
        # new ClientNetwork that includes the returned RegistrationResource
        # so the ClientNetwork will use the account KID for subsequent JWS
        # requests.
        net = acme_client.ClientNetwork(jwk)
        directory = messages.Directory.from_json(net.get(self.directory_url).json())
        acme = acme_client.ClientV2(directory, net)

        # Register or get account using the temporary client. If registration
        # succeeds, re-create the network client with the account so future
        # requests include a Key ID (kid) in JWS headers rather than an inline
        # JWK. This avoids "No Key ID in JWS header" errors from the server.
        try:
            acc = acme.new_account(messages.NewRegistration.from_data(email=None, terms_of_service_agreed=True))
            log.info("Created/located ACME account: %s", acc)
            # The acme.client.ClientNetwork._wrap_in_jws expects `self.account`
            # to be subscriptable and to provide a 'uri' key. Some library
            # versions return a RegistrationResource object; convert to a
            # minimal mapping so the network client will include the KID.
            acct_map = {"uri": getattr(acc, 'uri', str(acc))}
            net = acme_client.ClientNetwork(jwk, account=acct_map)
            acme = acme_client.ClientV2(directory, net)
        except acme_errors.ConflictError as ce:
            # Account already exists; the ConflictError contains the
            # registration Location in its args. Use that URI as the KID.
            acct_location = ce.args[0] if ce.args else None
            log.info("Account already exists at %s, attempting to query registration", acct_location)
            try:
                regr = messages.RegistrationResource(uri=acct_location, body=messages.Registration())
                regr = acme.query_registration(regr)
                acct_map = {"uri": getattr(regr, 'uri', acct_location)}
                net = acme_client.ClientNetwork(jwk, account=acct_map)
                acme = acme_client.ClientV2(directory, net)
            except Exception:
                log.warning("Could not query registration body; using location URI as KID")
                acct_map = {"uri": acct_location}
                net = acme_client.ClientNetwork(jwk, account=acct_map)
                acme = acme_client.ClientV2(directory, net)
        except Exception as e:
            log.error("account registration failed: %s", e)
            print(f"ACME error: {e}")
            return None, None, None

        # Debug: show what the network client thinks the account is (helps
        # diagnose missing kid header situations)
        try:
            log.info("Client network account: %r", getattr(net, 'account', None))
        except Exception:
            log.info("Client network account: <unrepresentable>")

        # Create order
        try:
            order = acme.new_order(csr_pem=csr_pem)
        except Exception as e:
            # Only show acme.messages.Error cleanly, suppress traceback
            try:
                from acme import messages
                if isinstance(e, messages.Error):
                    print(f"ACME error: {e}")
                    return None, None, None
            except Exception:
                pass
            print(f"ACME error: {e}")
            return None, None, None

        # Handle authorizations and dns-01 challenges
        for authz in order.authorizations:
            chall = None
            for c in authz.body.challenges:
                if c.chall.typ == "dns-01":
                    chall = c
                    break
            if not chall:
                raise RuntimeError("No dns-01 challenge available for %s" % authz)

            # Compute validation (TXT) value for dns-01
            validation = chall.chall.validation(jwk)

            # Determine the fqdn to set: _acme-challenge.<domain>
            domain = authz.body.identifier.value
            fqdn = f"_acme-challenge.{domain}"

            # Ask caller to publish the TXT record (may need CNAME handling there)
            publish_challenge(fqdn, validation)

        # Wait for DNS propagation before validation
        import time
        log.info(f"Waiting {self.dns_wait_seconds} seconds for DNS propagation...")
        time.sleep(self.dns_wait_seconds)

        # Now tell ACME server we are ready for each challenge
        for authz in order.authorizations:
            chall = None
            for c in authz.body.challenges:
                if c.chall.typ == "dns-01":
                    chall = c
                    break
            if chall:
                response = chall.response(jwk)
                acme.answer_challenge(chall, response)

        # After responding to all challenges, poll order until valid
        try:
            finalized = acme.poll_and_finalize(order)
        except acme_errors.ValidationError as e:
            print(f"ACME validation error: {e}")
            return None, None, None
        except Exception as e:
            log.error("Certificate validation failed: %s", e)
            print(f"ACME error: {e}")
            return None, None, None

        cert_pem = finalized.fullchain_pem.encode() if hasattr(finalized, 'fullchain_pem') else finalized.fullchain.encode()
        chain_pem = b""  # chain included in fullchain

        # Export private key used for CSR so callers can deploy it
        key_pem = privkey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Clean up challenges by calling remove_challenge for each domain
        for d in domains:
            remove_challenge(f"_acme-challenge.{d}")

        return cert_pem, chain_pem, key_pem
