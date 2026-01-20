from mcp.server.fastmcp import FastMCP, Context
from mcp.server.transport_security import TransportSecuritySettings
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
import httpx
from bs4 import BeautifulSoup, Tag
from typing import List
from dataclasses import dataclass
import urllib.parse
import sys
import traceback
import asyncio
from datetime import datetime, timedelta
import re
import json
from pathlib import Path
import contextlib
from starlette.applications import Starlette
from starlette.routing import Mount
from .policy import AccessPolicy

CONFIG_DIR = Path.home() / ".duckduckgo-mcp-server"
DB_FILE = CONFIG_DIR / "policy.sqlite3"

policy = AccessPolicy(DB_FILE)


@dataclass
class SearchResult:
    title: str
    link: str
    snippet: str
    position: int



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
        self, query: str, max_results: int = 10, *, ctx: Context
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
                if not link_elem or not isinstance(link_elem, Tag):
                    continue

                title = link_elem.get_text(strip=True)
                link_attr = link_elem.get("href")
                if not link_attr:
                    continue
                
                # Convert to string to satisfy type checker
                link = str(link_attr)

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
searcher = DuckDuckGoSearcher(policy=policy)
fetcher = WebContentFetcher(policy=policy)


@mcp.tool()
async def search(query: str, max_results: int = 10, *, ctx: Context) -> str:
    """
    Search DuckDuckGo and return formatted results.

    Args:
        query: The search query string
        max_results: Maximum number of results to return (default: 10)
        ctx: MCP context for logging
    """
    try:
        results = await searcher.search(query, max_results, ctx=ctx)
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

# Black/whitelist Tools:
@mcp.tool()
async def add_allow_domain(domain: str, ctx: Context) -> str:
    """Add a domain to the allowlist (e.g., wikipedia.org)."""
    if not domain.strip():
        return "Error: domain is required"

    if await policy.add_allow_domain(domain):
        await ctx.info(f"Added allow domain: {domain}")
        return f"Added domain to allowlist: {domain}"
    return f"Domain already in allowlist or invalid: {domain}"


@mcp.tool()
async def add_allow_pattern(url_pattern: str, ctx: Context) -> str:
    """Add a regex URL pattern to the allowlist (e.g., ^https://docs\\.python\\.org/)."""
    if not url_pattern.strip():
        return "Error: url_pattern is required"

    if await policy.add_allow_pattern(url_pattern):
        await ctx.info(f"Added allow pattern: {url_pattern}")
        return f"Added URL pattern to allowlist: {url_pattern}"
    return f"Pattern already in allowlist or invalid regex: {url_pattern}"


@mcp.tool()
async def add_deny_domain(domain: str, ctx: Context) -> str:
    """Add a domain to the denylist (e.g., t.co)."""
    if not domain.strip():
        return "Error: domain is required"

    if await policy.add_deny_domain(domain):
        await ctx.info(f"Added deny domain: {domain}")
        return f"Added domain to denylist: {domain}"
    return f"Domain already in denylist or invalid: {domain}"


@mcp.tool()
async def add_deny_pattern(url_pattern: str, ctx: Context) -> str:
    """Add a regex URL pattern to the denylist."""
    if not url_pattern.strip():
        return "Error: url_pattern is required"

    if await policy.add_deny_pattern(url_pattern):
        await ctx.info(f"Added deny pattern: {url_pattern}")
        return f"Added URL pattern to denylist: {url_pattern}"
    return f"Pattern already in denylist or invalid regex: {url_pattern}"

#Remove Rule
@mcp.tool()
async def remove_rule(rule_type: str, value: str, ctx: Context) -> str:
    """Remove a rule. rule_type: allow_domain|deny_domain|allow_pattern|deny_pattern"""
    valid_types = ["allow_domain", "deny_domain", "allow_pattern", "deny_pattern"]
    if rule_type not in valid_types:
        return f"Error: rule_type must be one of: {', '.join(valid_types)}"

    if await policy.remove_rule(rule_type, value):
        await ctx.info(f"Removed {rule_type}: {value}")
        return f"Successfully removed {rule_type}: {value}"
    return f"Rule not found or could not be removed: {rule_type} = {value}"

#Get/reload Policy async:
@mcp.tool()
async def get_policy(ctx: Context) -> str:
    await ctx.info("Retrieved current access policy")
    return json.dumps(policy.get_policy(), indent=2, ensure_ascii=False)


@mcp.tool()
async def reload_policy(ctx: Context) -> str:
    await policy.reload()
    await ctx.info("Reloaded access policy from DB/ENV")
    return "Policy reloaded"




# Access underlying MCP server instance
_lowlevel = getattr(mcp, "server", None) or getattr(mcp, "_server", None) or getattr(mcp, "_mcp_server", None)
if _lowlevel is None:
    raise RuntimeError("Could not access underlying MCP server instance from FastMCP")

security = TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    allowed_hosts=[
        "192.168.178.12:*",
        "127.0.0.1:*",
        "localhost:*",
        "n8n.linn.games:*",
    ],
    allowed_origins=[],
)

session_manager = StreamableHTTPSessionManager(
    app=_lowlevel,
    json_response=True,
    stateless=False,
    security_settings=security,
)

@contextlib.asynccontextmanager
async def lifespan(app: Starlette):
    await policy.init()
    async with session_manager.run():
        yield

async def mcp_asgi(scope, receive, send):
    # Handle OPTIONS ourselves (n8n schickt das)
    if scope["type"] == "http" and scope["method"] == "OPTIONS":
        headers = dict(scope.get("headers") or [])
        req_hdrs = headers.get(b"access-control-request-headers", b"").decode() or "Content-Type, Authorization, Accept"
        resp_headers = [
            (b"access-control-allow-origin", b"*"),
            (b"access-control-allow-methods", b"GET,POST,DELETE,OPTIONS"),
            (b"access-control-allow-headers", req_hdrs.encode()),
            (b"access-control-max-age", b"86400"),
        ]
        await send({"type": "http.response.start", "status": 204, "headers": resp_headers})
        await send({"type": "http.response.body", "body": b""})
        return

    # All real MCP traffic
    await session_manager.handle_request(scope, receive, send)

http_app = Starlette(
    routes=[Mount("/", app=mcp_asgi)],
    lifespan=lifespan,
)


def main():
    mcp.run()


if __name__ == "__main__":
    main()
