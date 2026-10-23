"""
Network Safety and SSRF Defense Module for SecureScan.
Validates destination IP addresses, enforces strict SSRF boundaries,
resolves hostnames, and detects non-routable, private, loopback, or metadata addresses.
"""

import ipaddress
import socket
from urllib.parse import urljoin, urlsplit
from scanner.url_validation import validate_target_url


# Explicit blocked CIDR ranges for IPv4
BLOCKED_IPV4_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network
    ipaddress.ip_network("10.0.0.0/8"),         # Private-Use (RFC 1918)
    ipaddress.ip_network("100.64.0.0/10"),      # Shared Address Space / CGNAT (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback (RFC 1122)
    ipaddress.ip_network("169.254.0.0/16"),     # Link-Local / Cloud Metadata (RFC 3927)
    ipaddress.ip_network("172.16.0.0/12"),      # Private-Use (RFC 1918)
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments (RFC 6890)
    ipaddress.ip_network("192.0.2.0/24"),       # Documentation TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("192.88.99.0/24"),     # 6to4 Relay Anycast (RFC 3068)
    ipaddress.ip_network("192.168.0.0/16"),     # Private-Use (RFC 1918)
    ipaddress.ip_network("198.18.0.0/15"),      # Network Interconnect Benchmarking (RFC 2544)
    ipaddress.ip_network("198.51.100.0/24"),    # Documentation TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),     # Documentation TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast (RFC 5771)
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved for Future Use (RFC 1112)
    ipaddress.ip_network("255.255.255.255/32"), # Limited Broadcast (RFC 919)
]

# Explicit blocked CIDR ranges for IPv6
BLOCKED_IPV6_NETWORKS = [
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("64:ff9b:1::/48"),     # Local-Use IPv4/IPv6 Translation
    ipaddress.ip_network("100::/64"),           # Discard-Only Prefix (RFC 6666)
    ipaddress.ip_network("2001:db8::/32"),      # Documentation (RFC 3849)
    ipaddress.ip_network("fc00::/7"),           # Unique Local Address ULA (RFC 4193)
    ipaddress.ip_network("fe80::/10"),          # Link-Local Unicast (RFC 4291)
    ipaddress.ip_network("ff00::/8"),           # Multicast (RFC 4291)
]


def is_safe_public_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[bool, str]:
    """
    Determines if an IP address belongs to the routable public Internet.
    Blocks private networks, cloud metadata endpoints, loopback, multicast, and reserved ranges.

    Args:
        ip_obj: An ipaddress.IPv4Address or ipaddress.IPv6Address object.

    Returns:
        tuple (is_safe: bool, reason: str)
    """
    # Unpack IPv4-mapped IPv6 address (e.g. ::ffff:192.168.1.1) to its underlying IPv4
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        ip_obj = ip_obj.ipv4_mapped

    # Check built-in Python ipaddress attributes
    if ip_obj.is_loopback:
        return False, f"IP address {ip_obj} is a loopback address (disallowed for remote scans)."

    if ip_obj.is_link_local:
        return False, f"IP address {ip_obj} is a link-local address (potential cloud metadata risk)."

    if ip_obj.is_private:
        return False, f"IP address {ip_obj} is in a private network range (RFC 1918 / RFC 4193)."

    if ip_obj.is_multicast:
        return False, f"IP address {ip_obj} is a multicast address."

    if ip_obj.is_reserved:
        return False, f"IP address {ip_obj} is in an IETF reserved address range."

    if ip_obj.is_unspecified:
        return False, f"IP address {ip_obj} is an unspecified network address."

    # Explicit check against defined IPv4 networks
    if isinstance(ip_obj, ipaddress.IPv4Address):
        for network in BLOCKED_IPV4_NETWORKS:
            if ip_obj in network:
                return False, f"IP address {ip_obj} falls within blocked network {network}."

    # Explicit check against defined IPv6 networks
    if isinstance(ip_obj, ipaddress.IPv6Address):
        for network in BLOCKED_IPV6_NETWORKS:
            if ip_obj in network:
                return False, f"IP address {ip_obj} falls within blocked IPv6 network {network}."

    return True, "IP address is an authorized public routable destination."


def resolve_and_validate_hostname(hostname: str) -> tuple[bool, str, list[str]]:
    """
    Performs safe DNS resolution and validates every returned IP address.
    If ANY resolved IP is private, internal, or reserved, the hostname is rejected.

    Args:
        hostname: The hostname string to resolve.

    Returns:
        tuple (is_valid: bool, error_message: str, resolved_ips: list[str])
    """
    # Direct IP literal check first
    try:
        direct_ip = ipaddress.ip_address(hostname)
        is_safe, reason = is_safe_public_ip(direct_ip)
        if not is_safe:
            return False, reason, [str(direct_ip)]
        return True, "", [str(direct_ip)]
    except ValueError:
        # Not a raw IP literal; proceed to DNS resolution
        pass

    resolved_ips: list[str] = []
    try:
        # Resolve both IPv4 and IPv6 socket addresses
        addr_info = socket.getaddrinfo(
            hostname,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        return False, f"DNS resolution failed for hostname '{hostname}': {exc}", []
    except Exception as exc:
        return False, f"Unexpected error during DNS resolution for '{hostname}': {exc}", []

    for entry in addr_info:
        sockaddr = entry[4]
        ip_str = sockaddr[0]
        if ip_str not in resolved_ips:
            resolved_ips.append(ip_str)

    if not resolved_ips:
        return False, f"DNS query for '{hostname}' returned no IP addresses.", []

    # Validate EVERY resolved IP address. Rebinding defense: even if one is public,
    # if another is private, we must abort to prevent multi-A record SSRF attacks.
    for ip_str in resolved_ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, f"Invalid IP address format received from DNS: '{ip_str}'", []

        is_safe, reason = is_safe_public_ip(ip_obj)
        if not is_safe:
            return (
                False,
                f"Destination '{hostname}' resolved to prohibited address ({ip_str}): {reason}",
                resolved_ips,
            )

    return True, "", resolved_ips


def validate_redirect_target(base_url: str, target_location: str) -> tuple[bool, str, str]:
    """
    Validates a redirection target header (HTTP 3xx Location) before following it.
    Resolves relative URLs against base_url, validates the protocol, and enforces SSRF boundaries.

    Args:
        base_url: The URL that issued the redirect.
        target_location: The raw Location header value.

    Returns:
        tuple (is_safe: bool, error_message: str, absolute_target_url: str)
    """
    if not target_location or not target_location.strip():
        return False, "Empty Location header in redirect response.", ""

    # Convert relative redirect to absolute URL
    try:
        absolute_target = urljoin(base_url, target_location.strip())
    except Exception as exc:
        return False, f"Failed to construct redirect destination: {exc}", ""

    # Validate scheme and syntax
    is_valid, err_msg, meta = validate_target_url(absolute_target)
    if not is_valid:
        return False, f"Redirect to invalid destination: {err_msg}", absolute_target

    # Validate network safety and DNS of the redirection target
    is_safe, net_err, _ = resolve_and_validate_hostname(meta["hostname"])
    if not is_safe:
        return False, f"Redirect target blocked by SSRF policy: {net_err}", absolute_target

    return True, "", meta["normalized_url"]
