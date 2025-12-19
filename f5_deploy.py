#!/usr/bin/env python3
# Copyright (c) 2025 Tim Riker
# SPDX-License-Identifier: MIT
"""Simple F5 BIG-IP deployer using the iControl REST API.

This module tries to keep interactions minimal and uses the REST endpoints to
create/update SSL certificate and key objects. It uses basic auth and HTTPS
requests (verify can be disabled).
"""
from typing import Optional
import requests
import logging
import urllib3
from urllib3.exceptions import InsecureRequestWarning
from cryptography import x509
from cryptography.hazmat.primitives import serialization

log = logging.getLogger(__name__)
urllib3.disable_warnings(InsecureRequestWarning)


class F5Deployer:
    def __init__(self, username: str, password: str, verify_ssl: bool = False):
        self.username = username
        self.password = password
        self.verify = verify_ssl

    def create_token(self, host: str) -> str:
        """Create an authentication token on the F5 and return the token string.

        Uses the /mgmt/shared/authn/login endpoint. Raises requests.HTTPError
        on failure.
        """
        url = f"https://{host}/mgmt/shared/authn/login"
        payload = {
            "username": self.username,
            "password": self.password,
            "loginProviderName": "tmos"
        }
        r = requests.post(url, json=payload, verify=self.verify)
        r.raise_for_status()
        data = r.json()
        # token is at data['token']['token'] in typical BIG-IP responses
        token = data.get('token', {}).get('token')
        if not token:
            raise RuntimeError(f"Failed to obtain auth token from {host}")
        return token

    def delete_token(self, host: str, token: str) -> None:
        """Delete/revoke an authentication token on the F5.

        Uses the /mgmt/shared/authz/tokens/{token} DELETE endpoint. Any
        non-2xx response will be raised as an HTTPError.
        """
        url = f"https://{host}/mgmt/shared/authz/tokens/{token}"
        headers = {"X-F5-Auth-Token": token}
        r = requests.delete(url, headers=headers, verify=self.verify)
        # Some versions may return 204 or 200; raise for other errors
        if r.status_code >= 400:
            r.raise_for_status()

    def upload_file(self, host: str, content: bytes, filename: str, headers: Optional[dict] = None) -> None:
        """Upload file content to F5 file transfer endpoint."""
        url = f"https://{host}/mgmt/shared/file-transfer/uploads/{filename}"
        log.debug("Uploading file to %s as %s (%d bytes)", host, filename, len(content))
        content_headers = {"Content-Type": "application/octet-stream", "Content-Range": f"0-{len(content)-1}/{len(content)}"}
        # Try with token auth if available, otherwise fall back to basic auth
        if headers and "X-F5-Auth-Token" in headers:
            content_headers.update(headers)
            r = requests.post(url, headers=content_headers, data=content, verify=self.verify)
        else:
            r = requests.post(url, auth=(self.username, self.password), headers=content_headers, data=content, verify=self.verify)
        if r.status_code >= 400:
            log.error("File upload failed: %s - %s", r.status_code, r.text)
        r.raise_for_status()

    def install_key_from_file(self, host: str, name: str, filename: str, headers: Optional[dict] = None) -> dict:
        """Install a key from an uploaded file."""
        url = f"https://{host}/mgmt/tm/sys/crypto/key"
        data = {
            "command": "install",
            "name": name,
            "from-local-file": f"/var/config/rest/downloads/{filename}"
        }
        log.debug("Installing key on %s as %s from file %s", host, name, filename)
        if headers:
            r = requests.post(url, headers=headers, json=data, verify=self.verify)
        else:
            r = requests.post(url, auth=(self.username, self.password), json=data, verify=self.verify)
        r.raise_for_status()
        return r.json()

    def install_cert_from_file(self, host: str, name: str, filename: str, headers: Optional[dict] = None) -> dict:
        """Install a certificate from an uploaded file."""
        url = f"https://{host}/mgmt/tm/sys/crypto/cert"
        data = {
            "command": "install",
            "name": name,
            "from-local-file": f"/var/config/rest/downloads/{filename}"
        }
        log.debug("Installing cert on %s as %s from file %s", host, name, filename)
        if headers:
            r = requests.post(url, headers=headers, json=data, verify=self.verify)
        else:
            r = requests.post(url, auth=(self.username, self.password), json=data, verify=self.verify)
        r.raise_for_status()
        return r.json()

    def upload_key(self, host: str, key_pem: bytes, name: str, headers: Optional[dict] = None) -> dict:
        # Upload as file first, then install
        # name already includes .key extension from deploy()
        filename = name if name.endswith('.key') else f"{name}.key"
        self.upload_file(host, key_pem, filename, headers)
        return self.install_key_from_file(host, name, filename, headers)

    def upload_cert(self, host: str, cert_pem: bytes, name: str, headers: Optional[dict] = None) -> dict:
        # Upload as file first, then install
        # name already includes .crt extension from deploy()
        filename = name if name.endswith('.crt') else f"{name}.crt"
        self.upload_file(host, cert_pem, filename, headers)
        return self.install_cert_from_file(host, name, filename, headers)

    def create_or_update_clientssl_profile(self, host: str, profile_name: str, cert_name: str, key_name: str,
                                          parent_profile: str = "clientssl", headers: Optional[dict] = None) -> None:
        """Create or update an SSL client profile based on a parent profile.

        Args:
            host: F5 host
            profile_name: Name of the profile to create/update
            cert_name: Name of the certificate (e.g., le_dicm.org.crt)
            key_name: Name of the key (e.g., le_dicm.org.key)
            parent_profile: Parent profile to base this on (default: clientssl)
            headers: Optional auth headers
        """
        url = f"https://{host}/mgmt/tm/ltm/profile/client-ssl/{profile_name}"

        # Check if profile exists
        if headers:
            r = requests.get(url, headers=headers, verify=self.verify)
        else:
            r = requests.get(url, auth=(self.username, self.password), verify=self.verify)

        profile_data = {
            "name": profile_name,
            "cert": cert_name,
            "key": key_name,
            "defaultsFrom": parent_profile
        }

        if r.status_code == 404:
            # Profile doesn't exist, create it
            log.info("Creating SSL client profile %s on %s", profile_name, host)
            create_url = f"https://{host}/mgmt/tm/ltm/profile/client-ssl"
            if headers:
                r = requests.post(create_url, headers=headers, json=profile_data, verify=self.verify)
            else:
                r = requests.post(create_url, auth=(self.username, self.password), json=profile_data, verify=self.verify)
            r.raise_for_status()
            log.info("Created SSL client profile %s on %s", profile_name, host)
        elif r.status_code == 200:
            # Profile exists, update it
            log.info("Updating SSL client profile %s on %s", profile_name, host)
            if headers:
                r = requests.patch(url, headers=headers, json={"cert": cert_name, "key": key_name}, verify=self.verify)
            else:
                r = requests.patch(url, auth=(self.username, self.password), json={"cert": cert_name, "key": key_name}, verify=self.verify)
            r.raise_for_status()
            log.debug("Updated SSL client profile %s on %s", profile_name, host)
        else:
            r.raise_for_status()

    def deploy(self, host: str, cert_pem: bytes, key_pem: bytes, base_name: str) -> None:
        """Upload key and certificate using names derived from `base_name`.

        The deployed object names on the F5 will be:
          - certificate: le_<base_name>.crt
          - key:         le_<base_name>.key

        This function uploads key and cert files, then updates both objects in a single transaction.
        """
        key_name = f"le_{base_name}.key"
        cert_name = f"le_{base_name}.crt"
        key_filename = key_name
        cert_filename = cert_name

        token = None
        headers = None
        try:
            # Acquire a token and use it for subsequent operations
            token = self.create_token(host)
            headers = {"X-F5-Auth-Token": token, "Content-Type": "application/json"}

            # Upload key and cert files
            self.upload_file(host, key_pem, key_filename, headers)
            self.upload_file(host, cert_pem, cert_filename, headers)

            # Start transaction (POST with empty payload)
            tx_url = f"https://{host}/mgmt/tm/transaction"
            tx_resp = requests.post(tx_url, headers=headers, json={}, verify=self.verify)
            tx_resp.raise_for_status()
            tx_id = tx_resp.json().get('transId')
            if not tx_id:
                raise RuntimeError(f"Failed to start transaction on {host}")
            tx_headers = headers.copy()
            tx_headers['X-F5-REST-Coordination-Id'] = str(tx_id)

            # Update key and cert sourcePath in transaction (use PUT)
            key_obj_url = f"https://{host}/mgmt/tm/sys/file/ssl-key/{key_name}"
            cert_obj_url = f"https://{host}/mgmt/tm/sys/file/ssl-cert/{cert_name}"
            key_data = {"sourcePath": f"file:/var/config/rest/downloads/{key_filename}"}
            cert_data = {"sourcePath": f"file:/var/config/rest/downloads/{cert_filename}"}
            key_put = requests.put(key_obj_url, headers=tx_headers, json=key_data, verify=self.verify)
            key_put.raise_for_status()
            cert_put = requests.put(cert_obj_url, headers=tx_headers, json=cert_data, verify=self.verify)
            cert_put.raise_for_status()

            # Remove coordination header before commit
            commit_headers = headers.copy()
            # Commit transaction
            tx_commit_url = f"https://{host}/mgmt/tm/transaction/{tx_id}"
            tx_commit = requests.patch(tx_commit_url, headers=commit_headers, json={"state": "VALIDATING"}, verify=self.verify)
            tx_commit.raise_for_status()

            # Create or update SSL client profile
            profile_name = f"le_{base_name}"
            self.create_or_update_clientssl_profile(host, profile_name, cert_name, key_name, headers=headers)
        finally:
            # Always attempt to delete the token if created
            if token:
                try:
                    self.delete_token(host, token)
                except Exception:
                    log.debug("Failed to delete token on %s", host, exc_info=True)
