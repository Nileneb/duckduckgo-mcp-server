from mcp.server.fastmcp import FastMCP, Context
import httpx
from bs4 import BeautifulSoup
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass, field
import urllib.parse
import sys
import traceback
import asyncio
from datetime import datetime, timedelta
import time
import re
import os
import json
from pathlib import Path
import ipaddress
import socket


# Config directory for persistent policy file
CONFIG_DIR = Path.home() / ".duckduckgo-mcp"
POLICY_FILE = CONFIG_DIR / "policy.json"

# DNS cache TTL in seconds
DNS_CACHE_TTL = 300  # 5 minutes


@dataclass
class SearchResult:
    title: str
    link: str
    snippet: str
    position: int


class DNSCache:
    """Simple DNS cache to avoid repeated lookups."""
    
    def __init__(self, ttl: int = DNS_CACHE_TTL):
        self.ttl = ttl
        self._cache: Dict[str, Tuple[List[str], float]] = {}
    
    async def resolve(self, host: str) -> List[str]:
        """Resolve hostname to IP addresses with caching."""
        now = time.time()
        
        if host in self._cache:
            ips, timestamp = self._cache[host]
            if now - timestamp < self.ttl:
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
    """
    Black/Whitelist policy with JSON persistence and ENV override.
    
    Priority: ENV variables override JSON file settings.
    Logic: Deny rules always win over allow rules.
    
    ENV variables (optional overrides):
        DDG_ALLOW_DOMAINS: Comma-separated allowed domains
        DDG_DENY_DOMAINS: Comma-separated denied domains  
        DDG_BLOCK_PRIVATE_IPS: "true" or "false" (default: true)
        DDG_MAX_REDIRECTS: Max redirect hops (default: 5)
    """
    
    DEFAULT_POLICY = {
        "allow_domains": [],
        "deny_domains": [],
        "allow_url_patterns": [],
        "deny_url_patterns": [],
        "block_private_ips": True,
        "max_redirects": 5
    }
    
    def __init__(self):
        self._dns_cache = DNSCache()
        self._policy = self._load_policy()
    
    def _load_policy(self) -> Dict[str, Any]:
        """Load policy from JSON file, create default if not exists."""
        policy = self.DEFAULT_POLICY.copy()
        
        # Load from JSON file if exists
        if POLICY_FILE.exists():
            try:
                with open(POLICY_FILE, "r", encoding="utf-8") as f:
                    file_policy = json.load(f)
                    for key in policy:
                        if key in file_policy:
                            policy[key] = file_policy[key]
            except (json.JSONDecodeError, IOError):
                pass  # Use defaults on error
        
        # ENV overrides (comma-separated for lists)
        if env_allow := os.getenv("DDG_ALLOW_DOMAINS"):
            policy["allow_domains"] = [d.strip().lower() for d in env_allow.split(",") if d.strip()]
        if env_deny := os.getenv("DDG_DENY_DOMAINS"):
            policy["deny_domains"] = [d.strip().lower() for d in env_deny.split(",") if d.strip()]
        if env_block := os.getenv("DDG_BLOCK_PRIVATE_IPS"):
            policy["block_private_ips"] = env_block.strip().lower() in ("1", "true", "yes")
        if env_redirects := os.getenv("DDG_MAX_REDIRECTS"):
            try:
                policy["max_redirects"] = int(env_redirects)
            except ValueError:
                pass
        
        return policy
    
    def _save_policy(self) -> bool:
        """Save current policy to JSON file."""
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            with open(POLICY_FILE, "w", encoding="utf-8") as f:
                json.dump(self._policy, f, indent=2, ensure_ascii=False)
            return True
        except IOError:
            return False
    
    def reload(self) -> None:
        """Reload policy from file."""
        self._policy = self._load_policy()
    
    def get_policy(self) -> Dict[str, Any]:
        """Get current policy as dict."""
        return self._policy.copy()
    
    def add_allow_domain(self, domain: str) -> bool:
        """Add domain to allowlist."""
        domain = domain.strip().lower().rstrip(".")
        if domain and domain not in self._policy["allow_domains"]:
            self._policy["allow_domains"].append(domain)
            return self._save_policy()
        return False
    
    def add_deny_domain(self, domain: str) -> bool:
        """Add domain to denylist."""
        domain = domain.strip().lower().rstrip(".")
        if domain and domain not in self._policy["deny_domains"]:
            self._policy["deny_domains"].append(domain)
            return self._save_policy()
        return False
    
    def add_allow_pattern(self, pattern: str) -> bool:
        """Add URL regex pattern to allowlist."""
        if pattern and pattern not in self._policy["allow_url_patterns"]:
            # Validate regex
            try:
                re.compile(pattern)
            except re.error:
                return False
            self._policy["allow_url_patterns"].append(pattern)
            return self._save_policy()
        return False
    
    def add_deny_pattern(self, pattern: str) -> bool:
        """Add URL regex pattern to denylist."""
        if pattern and pattern not in self._policy["deny_url_patterns"]:
            try:
                re.compile(pattern)
            except re.error:
                return False
            self._policy["deny_url_patterns"].append(pattern)
            return self._save_policy()
        return False
    
    def remove_rule(self, rule_type: str, value: str) -> bool:
        """Remove a rule. rule_type: allow_domain, deny_domain, allow_pattern, deny_pattern"""
        key_map = {
            "allow_domain": "allow_domains",
            "deny_domain": "deny_domains", 
            "allow_pattern": "allow_url_patterns",
            "deny_pattern": "deny_url_patterns"
        }
        key = key_map.get(rule_type)
        if not key or key not in self._policy:
            return False
        
        value = value.strip().lower() if "domain" in rule_type else value.strip()
        if value in self._policy[key]:
            self._policy[key].remove(value)
            return self._save_policy()
        return False
    
    def _host_matches(self, rule_domain: str, host: str) -> bool:
        """Check if host matches rule domain (including subdomains)."""
        rule = rule_domain.lower().rstrip(".")
        host = host.lower().rstrip(".")
        return host == rule or host.endswith("." + rule)
    
    def _is_private_ip(self, ip_str: str) -> bool:
        """Check if IP is private/local/reserved."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return (ip.is_private or ip.is_loopback or ip.is_link_local or 
                    ip.is_reserved or ip.is_multicast or ip.is_unspecified)
        except ValueError:
            return False
    
    async def is_url_allowed(self, url: str) -> Tuple[bool, str]:
        """
        Check if URL is allowed by policy.
        Returns (allowed: bool, reason: str)
        """
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
        
        # Deny patterns (regex)
        for pattern in self._policy["deny_url_patterns"]:
            try:
                if re.search(pattern, url, re.IGNORECASE):
                    return False, f"denied by URL pattern: {pattern}"
            except re.error:
                continue
        
        # Deny domains
        for domain in self._policy["deny_domains"]:
            if self._host_matches(domain, host):
                return False, f"denied by domain: {domain}"
        
        # SSRF protection: block private IPs
        if self._policy["block_private_ips"]:
            # Direct IP literal check
            if self._is_private_ip(host):
                return False, "private IP literal blocked"
            
            # DNS resolution check (cached)
            resolved_ips = await self._dns_cache.resolve(host)
            for ip in resolved_ips:
                if self._is_private_ip(ip):
                    return False, f"host resolves to private IP: {ip}"
        
        # Allow rules (if any configured, default-deny)
        has_allow_rules = bool(self._policy["allow_domains"] or self._policy["allow_url_patterns"])
        
        if has_allow_rules:
            # Check allow domains
            for domain in self._policy["allow_domains"]:
                if self._host_matches(domain, host):
                    return True, f"allowed by domain: {domain}"
            
            # Check allow patterns
            for pattern in self._policy["allow_url_patterns"]:
                try:
                    if re.search(pattern, url, re.IGNORECASE):
                        return True, f"allowed by pattern: {pattern}"
                except re.error:
                    continue
            
            return False, "not in allowlist"
        
        return True, "allowed (no allowlist configured)"


class RateLimiter:
    def __init__(self, requests_per_minute: int = 30):
        self.requests_per_minute = requests_per_minute
        self.requests = []

    async def acquire(self):
        now = datetime.now()
        # Remove requests older than 1 minute
        self.requests = [
            req for req in self.requests if now - req < timedelta(minutes=1)
        ]

        if len(self.requests) >= self.requests_per_minute:
            # Wait until we can make another request
            wait_time = 60 - (now - self.requests[0]).total_seconds()
            if wait_time > 0:
                await asyncio.sleep(wait_time)

        self.requests.append(now)


class DuckDuckGoSearcher:
    BASE_URL = "https://html.duckduckgo.com/html"
    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    def __init__(self, policy: AccessPolicy):
        self.rate_limiter = RateLimiter()
        self.policy = policy

    def format_results_for_llm(self, results: List[SearchResult]) -> str:
        """Format results in a natural language style that's easier for LLMs to process"""
        if not results:
            return "No results were found for your search query. This could be due to DuckDuckGo's bot detection or the query returned no matches. Please try rephrasing your search or try again in a few minutes."

        output = []
        output.append(f"Found {len(results)} search results:\n")

        for result in results:
            output.append(f"{result.position}. {result.title}")
            output.append(f"   URL: {result.link}")
            output.append(f"   Summary: {result.snippet}")
            output.append("")  # Empty line between results

        return "\n".join(output)

    async def search(
        self, query: str, ctx: Context, max_results: int = 10
    ) -> List[SearchResult]:
        try:
            # Apply rate limiting
            await self.rate_limiter.acquire()

            # Create form data for POST request
            data = {
                "q": query,
                "b": "",
                "kl": "",
            }

            await ctx.info(f"Searching DuckDuckGo for: {query}")

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.BASE_URL, data=data, headers=self.HEADERS, timeout=30.0
                )
                response.raise_for_status()

            # Parse HTML response
            soup = BeautifulSoup(response.text, "html.parser")
            if not soup:
                await ctx.error("Failed to parse HTML response")
                return []

            results = []
            for result in soup.select(".result"):
                title_elem = result.select_one(".result__title")
                if not title_elem:
                    continue

                link_elem = title_elem.find("a")
                if not link_elem:
                    continue

                title = link_elem.get_text(strip=True)
                link = link_elem.get("href", "")

                # Skip ad results
                if "y.js" in link:
                    continue

                # Clean up DuckDuckGo redirect URLs
                if link.startswith("//duckduckgo.com/l/?uddg="):
                    link = urllib.parse.unquote(link.split("uddg=")[1].split("&")[0])
                
                # Ensure absolute URL
                if link.startswith("//"):
                    link = "https:" + link
                
                # Apply access policy filter
                allowed, reason = await self.policy.is_url_allowed(link)
                if not allowed:
                    await ctx.info(f"Filtered by policy: {link} ({reason})")
                    continue

                snippet_elem = result.select_one(".result__snippet")
                snippet = snippet_elem.get_text(strip=True) if snippet_elem else ""

                results.append(
                    SearchResult(
                        title=title,
                        link=link,
                        snippet=snippet,
                        position=len(results) + 1,
                    )
                )

                if len(results) >= max_results:
                    break

            await ctx.info(f"Successfully found {len(results)} results")
            return results

        except httpx.TimeoutException:
            await ctx.error("Search request timed out")
            return []
        except httpx.HTTPError as e:
            await ctx.error(f"HTTP error occurred: {str(e)}")
            return []
        except (ValueError, AttributeError) as e:
            await ctx.error(f"Error parsing search results: {str(e)}")
            traceback.print_exc(file=sys.stderr)
            return []


class WebContentFetcher:
    def __init__(self, policy: AccessPolicy):
        self.rate_limiter = RateLimiter(requests_per_minute=20)
        self.policy = policy

    async def _get_with_policy_redirects(self, url: str, ctx: Context) -> httpx.Response:
        """
        Follow redirects manually so every hop is validated by policy.
        This prevents SSRF via redirect chains to internal networks.
        """
        current_url = url
        max_redirects = self.policy._policy.get("max_redirects", 5)
        
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
            for hop in range(max_redirects + 1):
                # Validate current URL against policy
                allowed, reason = await self.policy.is_url_allowed(current_url)
                if not allowed:
                    raise httpx.RequestError(f"Blocked by policy: {current_url} ({reason})")
                
                response = await client.get(
                    current_url,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
                )
                
                # Handle redirects manually
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get("Location")
                    if not location:
                        return response
                    
                    next_url = urllib.parse.urljoin(str(response.url), location)
                    await ctx.info(f"Redirect {hop + 1}: {current_url} -> {next_url}")
                    current_url = next_url
                    continue
                
                return response
        
        raise httpx.TooManyRedirects(f"Exceeded max_redirects={max_redirects}")

    async def fetch_and_parse(self, url: str, ctx: Context) -> str:
        """Fetch and parse content from a webpage"""
        try:
            await self.rate_limiter.acquire()

            await ctx.info(f"Fetching content from: {url}")
            
            # Initial policy check
            allowed, reason = await self.policy.is_url_allowed(url)
            if not allowed:
                await ctx.error(f"Blocked by policy: {url} ({reason})")
                return f"Error: URL blocked by policy ({reason})"

            response = await self._get_with_policy_redirects(url, ctx)
            response.raise_for_status()

            # Parse the HTML
            soup = BeautifulSoup(response.text, "html.parser")

            # Remove script and style elements
            for element in soup(["script", "style", "nav", "div", "head", "body", "header", "class", ".js", "font", "Icon","link", "href", "footer", "meta", "svg", "png", "container", "Hero Header", "hero-"]):
                element.decompose()

            # Get the text content
            text = soup.get_text()

            # Clean up the text
            lines = (line.strip() for line in text.splitlines())
            chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
            text = " ".join(chunk for chunk in chunks if chunk)

            # Remove extra whitespace
            text = re.sub(r"\s+", " ", text).strip()

            # Truncate if too long
            if len(text) > 8000:
                text = text[:8000] + "... [content truncated]"

            await ctx.info(
                f"Successfully fetched and parsed content ({len(text)} characters)"
            )
            return text

        except httpx.TimeoutException:
            await ctx.error(f"Request timed out for URL: {url}")
            return "Error: The request timed out while trying to fetch the webpage."
        except httpx.TooManyRedirects:
            await ctx.error(f"Too many redirects for URL: {url}")
            return "Error: Too many redirects while trying to fetch the webpage."
        except httpx.HTTPError as e:
            await ctx.error(
                f"HTTP error occurred while fetching {url}: {str(e)}"
            )
            return f"Error: Could not access the webpage ({str(e)})"
        except (ValueError, AttributeError) as e:
            await ctx.error(f"Error fetching content from {url}: {str(e)}")
            error_msg = (
                "Error: An unexpected error occurred while fetching the "
                f"webpage ({str(e)})"
            )
            return error_msg


# Initialize FastMCP server
mcp = FastMCP("ddg-search")
policy = AccessPolicy()
searcher = DuckDuckGoSearcher(policy=policy)
fetcher = WebContentFetcher(policy=policy)


@mcp.tool()
async def search(query: str, ctx: Context, max_results: int = 10) -> str:
    """
    Search DuckDuckGo and return formatted results.

    Args:
        query: The search query string
        max_results: Maximum number of results to return (default: 10)
        ctx: MCP context for logging
    """
    try:
        results = await searcher.search(query, ctx, max_results)
        return searcher.format_results_for_llm(results)
    except (httpx.TimeoutException, httpx.HTTPError, ValueError, AttributeError) as e:
        traceback.print_exc(file=sys.stderr)
        return f"An error occurred while searching: {str(e)}"


@mcp.tool()
async def fetch_content(url: str, ctx: Context) -> str:
    """
    Fetch and parse content from a webpage URL.

    Args:
        url: The webpage URL to fetch content from
        ctx: MCP context for logging
    """
    return await fetcher.fetch_and_parse(url, ctx)


@mcp.tool()
async def get_policy(ctx: Context) -> str:
    """
    Get the current access policy configuration.
    
    Returns the current allow/deny lists for domains and URL patterns,
    as well as SSRF protection settings.
    """
    current = policy.get_policy()
    policy_file = str(POLICY_FILE)
    
    output = [
        "=== Current Access Policy ===",
        f"Config file: {policy_file}",
        "",
        "ALLOW DOMAINS:",
    ]
    
    if current["allow_domains"]:
        for d in current["allow_domains"]:
            output.append(f"  - {d}")
    else:
        output.append("  (none - all domains allowed unless denied)")
    
    output.append("")
    output.append("DENY DOMAINS:")
    if current["deny_domains"]:
        for d in current["deny_domains"]:
            output.append(f"  - {d}")
    else:
        output.append("  (none)")
    
    output.append("")
    output.append("ALLOW URL PATTERNS (regex):")
    if current["allow_url_patterns"]:
        for p in current["allow_url_patterns"]:
            output.append(f"  - {p}")
    else:
        output.append("  (none)")
    
    output.append("")
    output.append("DENY URL PATTERNS (regex):")
    if current["deny_url_patterns"]:
        for p in current["deny_url_patterns"]:
            output.append(f"  - {p}")
    else:
        output.append("  (none)")
    
    output.append("")
    output.append("SETTINGS:")
    output.append(f"  Block private IPs (SSRF protection): {current['block_private_ips']}")
    output.append(f"  Max redirects: {current['max_redirects']}")
    
    await ctx.info("Retrieved current access policy")
    return "\n".join(output)


@mcp.tool()
async def add_allow_rule(
    ctx: Context,
    domain: Optional[str] = None,
    url_pattern: Optional[str] = None
) -> str:
    """
    Add a domain or URL pattern to the allowlist.
    
    When an allowlist has entries, only matching URLs are permitted (default-deny).
    
    Args:
        domain: Domain to allow (e.g., "wikipedia.org" allows all subdomains)
        url_pattern: Regex pattern to allow (e.g., "^https://docs\\.python\\.org/")
    """
    if not domain and not url_pattern:
        return "Error: Provide either 'domain' or 'url_pattern'"
    
    results = []
    
    if domain:
        if policy.add_allow_domain(domain):
            results.append(f"Added domain to allowlist: {domain}")
            await ctx.info(f"Added allow domain: {domain}")
        else:
            results.append(f"Domain already in allowlist or invalid: {domain}")
    
    if url_pattern:
        if policy.add_allow_pattern(url_pattern):
            results.append(f"Added URL pattern to allowlist: {url_pattern}")
            await ctx.info(f"Added allow pattern: {url_pattern}")
        else:
            results.append(f"Pattern already in allowlist or invalid regex: {url_pattern}")
    
    return "\n".join(results)


@mcp.tool()
async def add_deny_rule(
    ctx: Context,
    domain: Optional[str] = None,
    url_pattern: Optional[str] = None
) -> str:
    """
    Add a domain or URL pattern to the denylist.
    
    Deny rules always take precedence over allow rules.
    
    Args:
        domain: Domain to deny (e.g., "t.co" blocks all URL shorteners from t.co)
        url_pattern: Regex pattern to deny (e.g., "\\btracking\\b" blocks URLs with "tracking")
    """
    if not domain and not url_pattern:
        return "Error: Provide either 'domain' or 'url_pattern'"
    
    results = []
    
    if domain:
        if policy.add_deny_domain(domain):
            results.append(f"Added domain to denylist: {domain}")
            await ctx.info(f"Added deny domain: {domain}")
        else:
            results.append(f"Domain already in denylist or invalid: {domain}")
    
    if url_pattern:
        if policy.add_deny_pattern(url_pattern):
            results.append(f"Added URL pattern to denylist: {url_pattern}")
            await ctx.info(f"Added deny pattern: {url_pattern}")
        else:
            results.append(f"Pattern already in denylist or invalid regex: {url_pattern}")
    
    return "\n".join(results)


@mcp.tool()
async def remove_rule(
    ctx: Context,
    rule_type: str,
    value: str
) -> str:
    """
    Remove a rule from the access policy.
    
    Args:
        rule_type: Type of rule - one of: "allow_domain", "deny_domain", "allow_pattern", "deny_pattern"
        value: The domain or pattern to remove
    """
    valid_types = ["allow_domain", "deny_domain", "allow_pattern", "deny_pattern"]
    if rule_type not in valid_types:
        return f"Error: rule_type must be one of: {', '.join(valid_types)}"
    
    if policy.remove_rule(rule_type, value):
        await ctx.info(f"Removed {rule_type}: {value}")
        return f"Successfully removed {rule_type}: {value}"
    else:
        return f"Rule not found or could not be removed: {rule_type} = {value}"


@mcp.tool()
async def reload_policy(ctx: Context) -> str:
    """
    Reload the access policy from the configuration file.
    
    Use this after manually editing the policy.json file.
    """
    policy.reload()
    await ctx.info("Reloaded access policy from file")
    return f"Policy reloaded from {POLICY_FILE}"


def main():
    mcp.run()


if __name__ == "__main__":
    main()
