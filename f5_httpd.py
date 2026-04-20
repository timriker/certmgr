#!/usr/bin/env python3
# Copyright (c) 2025-2026 Tim Riker
# SPDX-License-Identifier: MIT
"""Helpers for BIG-IP management HTTPD certificate deployment.

Each configured target is expected to be a cluster/shared-IP hostname such as
`lb-psb.churchofjesuschrist.org`. The helper resolves that cluster into the
member devices and their management IP addresses using iControl REST, uploads
HTTPD certificate/key files, propagates the trusted chain to GTM/big3d, and
restarts HTTPD.
"""

import logging
import socket
import ssl
import time
import requests
import urllib3
from typing import Dict, List, Optional, Tuple
from cryptography import x509
from urllib3.exceptions import InsecureRequestWarning

log = logging.getLogger(__name__)
urllib3.disable_warnings(InsecureRequestWarning)


class F5HTTPD:
    def __init__(self, username: str, password: str, verify_ssl: bool = False):
        self.username = username
        self.password = password
        self.verify = verify_ssl

    def _get(self, host: str, path: str) -> dict:
        url = f"https://{host}{path}"
        response = requests.get(
            url,
            auth=(self.username, self.password),
            verify=self.verify,
            timeout=20,
        )
        response.raise_for_status()
        return response.json()

    def _post(self, host: str, path: str, payload: dict, timeout: int = 20) -> dict:
        url = f"https://{host}{path}"
        response = requests.post(
            url,
            auth=(self.username, self.password),
            json=payload,
            verify=self.verify,
            timeout=timeout,
        )
        response.raise_for_status()
        return response.json()

    def run_bash(self, host: str, command: str) -> dict:
        return self._post(
            host,
            "/mgmt/tm/util/bash",
            {"command": "run", "utilCmdArgs": f'-c "{command}"'},
            timeout=60,
        )

    def upload_file(self, host: str, content: bytes, filename: str) -> None:
        url = f"https://{host}/mgmt/shared/file-transfer/uploads/{filename}"
        headers = {
            "Content-Type": "application/octet-stream",
            "Content-Range": f"0-{len(content) - 1}/{len(content)}",
        }
        response = requests.post(
            url,
            auth=(self.username, self.password),
            headers=headers,
            data=content,
            verify=self.verify,
            timeout=60,
        )
        response.raise_for_status()

    @staticmethod
    def cluster_name_from_host(cluster_host: str) -> str:
        return cluster_host.split(".", 1)[0]

    def get_device_management_ips(self, host: str) -> Dict[str, dict]:
        """Return a map of device hostname and short name to management details."""
        data = self._get(host, "/mgmt/tm/cm/device?$select=name,hostname,managementIp")
        devices = {}
        for item in data.get("items", []):
            for key in (item.get("name"), item.get("hostname")):
                if not key:
                    continue
                devices[key] = {
                    "name": item.get("name"),
                    "hostname": item.get("hostname"),
                    "management_ip": item.get("managementIp"),
                }
                short_name = key.split(".", 1)[0]
                devices.setdefault(short_name, devices[key])
        return devices

    def get_trust_domain_devices(self, host: str) -> List[str]:
        """Return device names from the trust-domain CA device list."""
        data = self._get(host, "/mgmt/tm/cm/trust-domain?$select=name,caDevices")
        device_names = []
        for item in data.get("items", []):
            for ca_device in item.get("caDevices", []):
                device_names.append(ca_device.rsplit("/", 1)[-1])
        return device_names

    def discover_cluster_members(self, cluster_host: str) -> List[dict]:
        """Resolve a shared-IP cluster host into trusted member devices and management IPs."""
        cluster_name = self.cluster_name_from_host(cluster_host)
        cluster_prefix = f"{cluster_name}-"
        trusted_devices = self.get_trust_domain_devices(cluster_host)
        management_devices = self.get_device_management_ips(cluster_host)
        members = []

        for device_name in trusted_devices:
            short_name = device_name.split(".", 1)[0]
            if short_name != cluster_name and not short_name.startswith(cluster_prefix):
                continue
            management = management_devices.get(short_name, {})
            member = {
                "cluster_host": cluster_host,
                "device_name": management.get("name") or short_name,
                "hostname": management.get("hostname"),
                "management_ip": management.get("management_ip"),
            }
            members.append(member)

        return sorted(members, key=lambda member: member["device_name"] or "")

    def validate_rest_connectivity(self, target: str) -> Tuple[bool, Optional[str]]:
        """Confirm a REST target responds."""
        try:
            self._get(target, "/mgmt/tm/sys/version")
        except Exception as exc:  # pragma: no cover - live environment behavior
            return False, str(exc)
        return True, None

    def get_preferred_rest_target(self, member: dict) -> str:
        """Prefer the node hostname for REST when it resolves and responds."""
        hostname = member.get("hostname")
        if hostname:
            try:
                socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
                ok, _ = self.validate_rest_connectivity(hostname)
                if ok:
                    return hostname
            except OSError:
                pass

        management_ip = member.get("management_ip")
        if not management_ip:
            raise RuntimeError(f"No usable REST target for {member.get('device_name')}")
        ok, err = self.validate_rest_connectivity(management_ip)
        if not ok:
            raise RuntimeError(f"{member.get('device_name')} management connectivity failed: {err}")
        return management_ip

    @staticmethod
    def get_preferred_https_target(member: dict) -> str:
        """Prefer the node hostname for HTTPS verification when it resolves."""
        hostname = member.get("hostname")
        if hostname:
            try:
                socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
                return hostname
            except OSError:
                pass

        management_ip = member.get("management_ip")
        if not management_ip:
            raise RuntimeError(f"No usable HTTPS target for {member.get('device_name')}")
        return management_ip

    def get_httpd_paths(self, host: str) -> dict:
        return self._get(
            host,
            "/mgmt/tm/sys/httpd?$select=sslCertfile,sslCertkeyfile,sslCertchainfile,sslCaCertFile",
        )

    @staticmethod
    def _escape_single_quotes(value: str) -> str:
        return value.replace("'", "'\"'\"'")

    def copy_download_to_path(self, host: str, source_filename: str, destination_path: str, mode: str = "0644") -> None:
        escaped_destination = self._escape_single_quotes(destination_path)
        command = (
            f"cp /var/config/rest/downloads/{source_filename} '{escaped_destination}'"
            f" && chmod {mode} '{escaped_destination}'"
        )
        self.run_bash(host, command)

    def copy_file_to_path(self, host: str, source_path: str, destination_path: str) -> None:
        escaped_source = self._escape_single_quotes(source_path)
        escaped_destination = self._escape_single_quotes(destination_path)
        command = f"cp '{escaped_source}' '{escaped_destination}' && chmod 0644 '{escaped_destination}'"
        self.run_bash(host, command)

    def deploy_member(self, member: dict, base_name: str, with_root_pem: bytes, key_pem: bytes) -> dict:
        rest_target = self.get_preferred_rest_target(member)
        httpd_paths = self.get_httpd_paths(rest_target)

        cert_filename = f"{base_name}.httpd.with-root.crt"
        key_filename = f"{base_name}.httpd.key"

        self.upload_file(rest_target, with_root_pem, cert_filename)
        self.upload_file(rest_target, key_pem, key_filename)

        self.copy_download_to_path(rest_target, cert_filename, httpd_paths["sslCertfile"])
        self.copy_download_to_path(rest_target, cert_filename, httpd_paths["sslCertchainfile"])
        self.copy_download_to_path(rest_target, key_filename, httpd_paths["sslCertkeyfile"], mode="0600")

        self.copy_file_to_path(rest_target, httpd_paths["sslCertchainfile"], "/config/gtm/server.crt")
        self.copy_file_to_path(rest_target, httpd_paths["sslCertchainfile"], "/config/big3d/client.crt")

        try:
            self.run_bash(rest_target, "bigstart restart httpd")
        except requests.exceptions.ConnectionError:
            # Restarting HTTPD often tears down the active REST connection
            # before BIG-IP can return a response. Treat that as expected and
            # verify the service afterwards.
            log.info("HTTPD restart on %s closed the REST connection; verifying service after reconnect", rest_target)

        verification = self.wait_for_https_certificate(member)

        return {
            "member": member,
            "rest_target": rest_target,
            "httpd_paths": httpd_paths,
            "verification": verification,
        }

    def verify_https_certificate(self, member: dict) -> dict:
        connect_target = self.get_preferred_https_target(member)
        hostname = member.get("hostname") or member.get("device_name") or connect_target
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((connect_target, 443), timeout=15) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as wrapped:
                certificate = x509.load_der_x509_certificate(wrapped.getpeercert(binary_form=True))
        return {
            "connect_target": connect_target,
            "subject": certificate.subject.rfc4514_string(),
            "issuer": certificate.issuer.rfc4514_string(),
            "not_after": certificate.not_valid_after.isoformat(),
        }

    def wait_for_https_certificate(self, member: dict, timeout_seconds: int = 120, interval_seconds: int = 5) -> dict:
        """Wait for HTTPS to come back after an HTTPD restart and return the served cert."""
        deadline = time.time() + timeout_seconds
        last_error = None

        while time.time() < deadline:
            try:
                return self.verify_https_certificate(member)
            except Exception as exc:  # pragma: no cover - depends on live node timing
                last_error = exc
                time.sleep(interval_seconds)

        raise RuntimeError(
            f"{member.get('device_name')} HTTPS did not recover within {timeout_seconds} seconds: {last_error}"
        )
