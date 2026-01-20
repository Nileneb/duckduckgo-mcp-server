from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import socket
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .policy_store import PolicyStore


DNS_CACHE_TTL = 300


class DNSCache:
    def __init__(self, ttl: int = DNS_CACHE_TTL):
        self.ttl = ttl
        self._cache: Dict[str, Tuple[List[str], float]] = {}

    async def resolve(self, host: str) -> List[str]:
        now = time.time()
        if host in self._cache:
            ips, ts = self._cache[host]
            if now - ts < self.ttl:
                return ips
        try:
            loop = asyncio.get_running_loop()
            infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            ips = list(set(sockaddr[0] for _, _, _, _, sockaddr in infos))
            self._cache[host] = (ips, now)
            return ips
        except Exception:
            return []


class AccessPolicy:
    DEFAULT_POLICY = {
        "allow_domains": [],
        "deny_domains": [],
        "allow_url_patterns": [],
        "deny_url_patterns": [],
        "block_private_ips": True,
        "max_redirects": 5,
    }

    def __init__(self, db_path: Path):
        self._dns_cache = DNSCache()
        self._store = PolicyStore(db_path)
        self._policy: Dict[str, Any] = self.DEFAULT_POLICY.copy()

    async def init(self) -> None:
        await self._store.init()
        # ensure default settings exist (but keep DB as source-of-truth)
        settings = await self._store.get_all_settings()
        if "block_private_ips" not in settings:
            await self._store.set_setting("block_private_ips", "true")
        if "max_redirects" not in settings:
            await self._store.set_setting("max_redirects", "5")

        await self.reload()

    async def reload(self) -> None:
        policy = self.DEFAULT_POLICY.copy()

        # load rules from DB
        policy["allow_domains"] = [d.strip().lower().rstrip(".") for d in await self._store.list_rules("allow_domain")]
        policy["deny_domains"] = [d.strip().lower().rstrip(".") for d in await self._store.list_rules("deny_domain")]
        policy["allow_url_patterns"] = await self._store.list_rules("allow_pattern")
        policy["deny_url_patterns"] = await self._store.list_rules("deny_pattern")

        # load settings from DB
        settings = await self._store.get_all_settings()
        block_private = (settings.get("block_private_ips", "true").strip().lower() in ("1", "true", "yes"))
        policy["block_private_ips"] = block_private
        try:
            policy["max_redirects"] = int(settings.get("max_redirects", "5"))
        except ValueError:
            policy["max_redirects"] = 5

        # ENV overrides (optional, replace DB lists/settings)
        if env_allow := os.getenv("DDG_ALLOW_DOMAINS"):
            policy["allow_domains"] = [d.strip().lower().rstrip(".") for d in env_allow.split(",") if d.strip()]
        if env_deny := os.getenv("DDG_DENY_DOMAINS"):
            policy["deny_domains"] = [d.strip().lower().rstrip(".") for d in env_deny.split(",") if d.strip()]
        if env_block := os.getenv("DDG_BLOCK_PRIVATE_IPS"):
            policy["block_private_ips"] = env_block.strip().lower() in ("1", "true", "yes")
        if env_redirects := os.getenv("DDG_MAX_REDIRECTS"):
            try:
                policy["max_redirects"] = int(env_redirects)
            except ValueError:
                pass

        self._policy = policy

    def get_policy(self) -> Dict[str, Any]:
        return dict(self._policy)

    async def set_block_private_ips(self, enabled: bool) -> None:
        await self._store.set_setting("block_private_ips", "true" if enabled else "false")
        await self.reload()

    async def set_max_redirects(self, value: int) -> None:
        await self._store.set_setting("max_redirects", str(int(value)))
        await self.reload()

    async def add_allow_domain(self, domain: str) -> bool:
        domain = domain.strip().lower().rstrip(".")
        ok = await self._store.add_rule("allow_domain", domain)
        await self.reload()
        return ok

    async def add_deny_domain(self, domain: str) -> bool:
        domain = domain.strip().lower().rstrip(".")
        ok = await self._store.add_rule("deny_domain", domain)
        await self.reload()
        return ok

    async def add_allow_pattern(self, pattern: str) -> bool:
        pattern = pattern.strip()
        try:
            re.compile(pattern)
        except re.error:
            return False
        ok = await self._store.add_rule("allow_pattern", pattern)
        await self.reload()
        return ok

    async def add_deny_pattern(self, pattern: str) -> bool:
        pattern = pattern.strip()
        try:
            re.compile(pattern)
        except re.error:
            return False
        ok = await self._store.add_rule("deny_pattern", pattern)
        await self.reload()
        return ok

    async def remove_rule(self, rule_type: str, value: str) -> bool:
        key_map = {
            "allow_domain": "allow_domain",
            "deny_domain": "deny_domain",
            "allow_pattern": "allow_pattern",
            "deny_pattern": "deny_pattern",
        }
        kind = key_map.get(rule_type)
        if not kind:
            return False

        val = value.strip().lower().rstrip(".") if "domain" in rule_type else value.strip()
        ok = await self._store.remove_rule(kind, val)
        await self.reload()
        return ok

    def _host_matches(self, rule_domain: str, host: str) -> bool:
        rule = rule_domain.lower().rstrip(".")
        host = host.lower().rstrip(".")
        return host == rule or host.endswith("." + rule)

    def _is_private_ip(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            return (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
                or ip.is_unspecified
            )
        except ValueError:
            return False

    async def is_url_allowed(self, url: str) -> Tuple[bool, str]:
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception:
            return False, "URL parse failed"

        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            return False, f"scheme not allowed: {scheme}"

        if parsed.username or parsed.password:
            return False, "credentials in URL not allowed"

        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            return False, "missing host"

        # deny patterns
        for pattern in self._policy["deny_url_patterns"]:
            try:
                if re.search(pattern, url, re.IGNORECASE):
                    return False, f"denied by URL pattern: {pattern}"
            except re.error:
                continue

        # deny domains
        for domain in self._policy["deny_domains"]:
            if self._host_matches(domain, host):
                return False, f"denied by domain: {domain}"

        # SSRF: block private IPs
        if self._policy["block_private_ips"]:
            if self._is_private_ip(host):
                return False, "private IP literal blocked"

            resolved_ips = await self._dns_cache.resolve(host)
            for ip in resolved_ips:
                if self._is_private_ip(ip):
                    return False, f"host resolves to private IP: {ip}"

        # allowlist mode?
        has_allow_rules = bool(self._policy["allow_domains"] or self._policy["allow_url_patterns"])
        if has_allow_rules:
            for domain in self._policy["allow_domains"]:
                if self._host_matches(domain, host):
                    return True, f"allowed by domain: {domain}"

            for pattern in self._policy["allow_url_patterns"]:
                try:
                    if re.search(pattern, url, re.IGNORECASE):
                        return True, f"allowed by pattern: {pattern}"
                except re.error:
                    continue

            return False, "not in allowlist"

        return True, "allowed (no allowlist configured)"
