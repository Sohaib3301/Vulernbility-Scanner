
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


# Common ports associated with network and IoT services.
DEFAULT_PORTS = [22, 23, 80, 443, 1883, 8883, 554, 8080]

# Limit this first version to a small, controlled port set.
MAX_WORKERS = 8
TIMEOUT = 0.5


def validate_target(target):
    """Accept only private or loopback IPv4 addresses."""
    try:
        address = ipaddress.ip_address(target)
    except ValueError as exc:
        raise ValueError("Enter a valid IP address.") from exc

    if not isinstance(address, ipaddress.IPv4Address):
        raise ValueError("This version supports IPv4 only.")

    if not (address.is_private or address.is_loopback):
        raise ValueError(
            "For safety, only private or loopback IPs are allowed."
        )

    return str(address)


def check_port(host, port):
    """Check whether a TCP connection succeeds."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(TIMEOUT)

        try:
            result = sock.connect_ex((host, port))
        except OSError:
            return {
                "host": host,
                "port": port,
                "status": "error",
            }

    return {
        "host": host,
        "port": port,
        "status": "open" if result == 0 else "closed_or_filtered",
    }


def scan_ports(target, ports=None):
    """Check selected ports on one authorized target."""
    host = validate_target(target)
    ports = DEFAULT_PORTS if ports is None else list(ports)

    if not ports or len(ports) > 32:
        raise ValueError("Provide between 1 and 32 ports.")

    if any(
        not isinstance(port, int)
        or isinstance(port, bool)
        or not 1 <= port <= 65535
        for port in ports
    ):
        raise ValueError("Ports must be integers from 1 to 65535.")

    if len(set(ports)) != len(ports):
        raise ValueError("Duplicate ports are not allowed.")

    results = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [
            executor.submit(check_port, host, port)
            for port in ports
        ]

        for future in as_completed(futures):
            results.append(future.result())

    return sorted(results, key=lambda item: item["port"])
