"""Resolve once, check, and connect to exactly that address (no DNS rebinding window).

``resolve_public`` resolves a host and refuses any non-public address. ``pinned_client``
returns an httpx client whose connections for that host go to the checked address, while
TLS still verifies the certificate for the hostname (SNI and verification use the URL).
"""

import ipaddress
import socket

import httpcore
import httpx

from agentguard.core.decision import GuardError


def resolve_public(host, port, *, allow_private=False):
    """Resolved addresses for ``host`` (deduplicated, in order); every one must be public."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise GuardError("DNS resolution failed") from exc
    addresses = [info[4][0] for info in infos]
    if not addresses:
        raise GuardError("DNS resolution returned no addresses")
    for address in addresses:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
        if not allow_private and not ip.is_global:
            raise GuardError("Non-public network address rejected")
    return list(dict.fromkeys(addresses))


class PinnedBackend(httpcore.SyncBackend):
    """Connects ``host`` only to the checked ``addresses``, in order; refuses other hosts."""

    def __init__(self, host, addresses):
        self.host, self.addresses = host.lower().rstrip("."), list(addresses)

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        if host.lower().rstrip(".") != self.host:
            raise httpcore.ConnectError(f"Connection to unpinned host {host!r} refused")
        error = None
        for address in self.addresses:
            try:
                return super().connect_tcp(address, port, timeout, local_address, socket_options)
            except httpcore.ConnectError as exc:
                error = exc
        raise error or httpcore.ConnectError("No address to connect to")


def pinned_client(host, addresses, *, timeout):
    transport = httpx.HTTPTransport(trust_env=False)
    transport._pool = httpcore.ConnectionPool(
        ssl_context=httpx.create_ssl_context(trust_env=False),
        network_backend=PinnedBackend(host, addresses),
    )
    return httpx.Client(
        transport=transport, timeout=timeout, follow_redirects=False, trust_env=False
    )
