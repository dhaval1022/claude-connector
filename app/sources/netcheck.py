"""SSRF protection for user-supplied database hosts."""
import ipaddress
import socket

from app.config import get_settings


class HostBlocked(ValueError):
    pass


def check_host(host: str) -> None:
    """Resolve the host and refuse link-local/metadata (and, by default, loopback) targets.
    Private LAN ranges are allowed: internal Medkart databases live there."""
    if not host:
        raise HostBlocked("Host is required.")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise HostBlocked(f"Cannot resolve host '{host}'.")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            raise HostBlocked("That address range is not allowed.")
        if ip.is_loopback and not get_settings().allow_loopback:
            raise HostBlocked("Loopback addresses are not allowed.")
