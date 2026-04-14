#!/usr/bin/env python3
# Copyright (c) 2025-2026 Tim Riker
# SPDX-License-Identifier: MIT
"""Helpers for BIG-IP management HTTPD certificate deployment.

This module currently focuses on cluster discovery for `f5_httpd` targets.
Each configured target is expected to be a cluster/shared-IP hostname such as
`lb-psb.churchofjesuschrist.org`. The helper resolves that cluster into the
member devices and their management IP addresses using iControl REST.
"""

import logging
from typing import Optional

import requests
import urllib3
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

    @staticmethod
    def cluster_name_from_host(cluster_host: str) -> str:
        return cluster_host.split(".", 1)[0]

    def get_cluster_devices(self, cluster_host: str) -> list[dict]:
        """Return GTM device entries for a shared-IP cluster host."""
        cluster_name = self.cluster_name_from_host(cluster_host)
        data = self._get(cluster_host, f"/mgmt/tm/gtm/server/~Common~{cluster_name}/devices")
        return data.get("items", [])

    def get_device_management_ips(self, host: str) -> dict[str, dict]:
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

    def discover_cluster_members(self, cluster_host: str) -> list[dict]:
        """Resolve a shared-IP cluster host into member devices and management IPs."""
        cluster_devices = self.get_cluster_devices(cluster_host)
        management_devices = self.get_device_management_ips(cluster_host)
        members = []

        for cluster_device in cluster_devices:
            short_name = cluster_device.get("name")
            management = management_devices.get(short_name, {})
            member = {
                "cluster_host": cluster_host,
                "device_name": management.get("name") or short_name,
                "hostname": management.get("hostname"),
                "management_ip": management.get("management_ip"),
                "cluster_addresses": [a.get("name") for a in cluster_device.get("addresses", []) if a.get("name")],
            }
            members.append(member)

        return members

    def validate_management_connectivity(self, member: dict) -> tuple[bool, Optional[str]]:
        """Confirm the member management IP responds to REST."""
        management_ip = member.get("management_ip")
        if not management_ip:
            return False, "missing management IP"

        try:
            self._get(management_ip, "/mgmt/tm/sys/version")
        except Exception as exc:  # pragma: no cover - live environment behavior
            return False, str(exc)
        return True, None
