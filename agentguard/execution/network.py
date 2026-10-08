from urllib.parse import urlsplit

from agentguard.core.decision import GuardError
from agentguard.execution.pinning import pinned_client, resolve_public
from agentguard.policy.matcher import domain_matches


class NetworkExecutor:
    """Bounded GET only; domain allowlist, pinned public DNS, no proxies or redirects."""

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
        # Resolve once and connect to that checked address: no DNS rebinding window.
        addresses = resolve_public(host, 443)
        with pinned_client(host, addresses, timeout=self.timeout) as client:
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
