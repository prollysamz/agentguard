import ipaddress
import socket
from urllib.parse import urlsplit

import httpx

from agentguard.core.decision import GuardError
from agentguard.policy.matcher import domain_matches


class NetworkExecutor:
    """Bounded GET only; domain allowlist, public DNS preflight, no proxies/redirects."""

    capabilities = frozenset({"network.request"})

    def __init__(self, domains: list[str], *, timeout: float = 10, max_bytes: int = 65536):
        self.domains = tuple(domains)
        self.timeout, self.max_bytes = timeout, max_bytes

    def execute(self, action):
        url = action.arguments["url"]
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        if (
            parsed.scheme != "https"
            or parsed.port not in (None, 443)
            or parsed.username
            or parsed.password
        ):
            raise GuardError("Only credential-free HTTPS on port 443 is supported")
        if not any(domain_matches(host, d) for d in self.domains):
            raise GuardError("Network domain outside executor allowlist")
        addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        if not addresses or any(
            not ipaddress.ip_address(item[4][0]).is_global for item in addresses
        ):
            raise GuardError("Non-public network address rejected")
        with httpx.Client(timeout=self.timeout, follow_redirects=False, trust_env=False) as client:
            with client.stream("GET", url) as response:
                if 300 <= response.status_code < 400:
                    raise GuardError("Redirects are disabled")
                response.raise_for_status()
                data = bytearray()
                for chunk in response.iter_bytes(chunk_size=4096):
                    data.extend(chunk)
                    if len(data) > self.max_bytes:
                        raise GuardError("Network response exceeds limit")
                return data.decode("utf-8", errors="replace")
