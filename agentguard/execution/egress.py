"""An allowlisting HTTPS egress proxy with pinned, public-only DNS.

Point tools or containers at it with ``HTTPS_PROXY=http://host:port``. It accepts only
``CONNECT host:port`` for allowlisted domains and ports, resolves each host once, refuses
non-public addresses, and tunnels to exactly the checked address. Everything else is
refused. Run it with ``agentguard egress-proxy --allow docs.python.org``.

It cannot see inside TLS: a client may present a different SNI or Host to a server it is
allowed to reach (e.g. domain fronting on a shared CDN). Combine it with network isolation
so that the proxy is the only route out.
"""

import asyncio
import logging
import threading
import time

from agentguard.core.decision import GuardError
from agentguard.execution.pinning import resolve_public
from agentguard.policy.matcher import domain_matches

log = logging.getLogger(__name__)
MAX_HEADER = 16384


class EgressProxy:
    def __init__(
        self,
        domains,
        *,
        host="127.0.0.1",
        port=0,
        ports=(443,),
        allow_private=False,
        connect_timeout=10.0,
        idle_timeout=300.0,
        max_connections=64,
        on_decision=None,
    ):
        """``on_decision(event)`` receives one dict per CONNECT, e.g. ``AuditLogger.append``."""
        if not domains:
            raise ValueError("At least one allowed domain is required")
        self.domains, self.host, self.port = tuple(domains), host, port
        self.ports = frozenset(ports)
        self.allow_private = allow_private
        self.connect_timeout, self.idle_timeout = connect_timeout, idle_timeout
        self.on_decision = on_decision
        self._slots = None
        self._max_connections = max_connections
        self._loop = self._server = self._thread = None
        self._ready = threading.Event()

    # ------------------------------------------------------------------ lifecycle

    def start(self):
        """Serve in a background thread. Returns (host, port)."""
        self._thread = threading.Thread(target=self._serve, name="agentguard-egress", daemon=True)
        self._thread.start()
        if not self._ready.wait(10):
            raise RuntimeError("Egress proxy did not start")
        return self.host, self.port

    def stop(self):
        if self._loop and self._server:

            async def shutdown():
                self._server.close()
                await asyncio.wait_for(self._server.wait_closed(), 3)

            try:
                asyncio.run_coroutine_threadsafe(shutdown(), self._loop).result(5)
            except Exception:  # Open tunnels may outlive the wait; the loop still stops.
                log.debug("Egress proxy closed with open tunnels", exc_info=True)
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread:
            self._thread.join(5)

    def serve_forever(self):
        asyncio.run(self._main(forever=True))

    def _serve(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._main(forever=False))
        self._loop.run_forever()

    async def _main(self, forever):
        self._slots = asyncio.Semaphore(self._max_connections)
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        self.port = self._server.sockets[0].getsockname()[1]
        self._ready.set()
        if forever:
            async with self._server:
                await self._server.serve_forever()

    # ------------------------------------------------------------------ connections

    def _record(self, **event):
        if self.on_decision:
            try:
                self.on_decision({"stage": "egress", "capability": "network.request", **event})
            except Exception:
                log.warning("Egress decision callback failed", exc_info=True)

    async def _refuse(self, writer, status, reason, **event):
        self._record(final_decision="deny", reasons=[reason], **event)
        body = reason.encode()
        writer.write(
            f"HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n".encode()
            + body
        )
        await writer.drain()
        writer.close()

    async def _handle(self, reader, writer):
        async with self._slots:
            try:
                head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), self.connect_timeout)
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError):
                writer.close()
                return
            if len(head) > MAX_HEADER:
                return await self._refuse(
                    writer, "431 Request Header Fields Too Large", "Too large"
                )
            method, _, rest = head.split(b"\r\n", 1)[0].decode("latin-1").partition(" ")
            target = rest.split(" ", 1)[0]
            if method != "CONNECT":
                return await self._refuse(writer, "405 Method Not Allowed", "Only CONNECT")
            host, _, port_text = target.rpartition(":")
            host = host.strip("[]").lower().rstrip(".")
            if not host or not port_text.isdigit() or int(port_text) not in self.ports:
                return await self._refuse(
                    writer, "403 Forbidden", "Port not allowed", url=f"https://{target}"
                )
            port = int(port_text)
            event = {"url": f"https://{host}:{port}", "tool": "egress-proxy"}
            if not any(domain_matches(host, d) for d in self.domains):
                return await self._refuse(writer, "403 Forbidden", "Domain not allowed", **event)
            try:
                addresses = await asyncio.to_thread(
                    resolve_public, host, port, allow_private=self.allow_private
                )
            except GuardError as exc:
                return await self._refuse(writer, "403 Forbidden", str(exc), **event)
            upstream_reader = upstream_writer = None
            for address in addresses:  # Only checked addresses, in resolver order.
                try:
                    upstream_reader, upstream_writer = await asyncio.wait_for(
                        asyncio.open_connection(address, port), self.connect_timeout
                    )
                    break
                except (OSError, TimeoutError):
                    continue
            if upstream_writer is None:
                return await self._refuse(
                    writer, "502 Bad Gateway", "Upstream unreachable", **event
                )
            self._record(final_decision="allow", reasons=[f"Pinned to {address}"], **event)
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            await self._pipe(reader, writer, upstream_reader, upstream_writer)

    async def _pipe(self, reader, writer, upstream_reader, upstream_writer):
        last = [time.monotonic()]

        async def copy(source, sink):
            try:
                while data := await source.read(65536):
                    last[0] = time.monotonic()
                    sink.write(data)
                    await sink.drain()
            except (ConnectionError, OSError):
                pass
            finally:
                sink.close()

        async def watchdog():
            while time.monotonic() - last[0] < self.idle_timeout:
                await asyncio.sleep(min(5.0, self.idle_timeout))
            writer.close()
            upstream_writer.close()

        tasks = [
            asyncio.ensure_future(copy(reader, upstream_writer)),
            asyncio.ensure_future(copy(upstream_reader, writer)),
        ]
        guard = asyncio.ensure_future(watchdog())
        await asyncio.gather(*tasks, return_exceptions=True)
        guard.cancel()
