import argparse
import socket
import ipaddress
import sys
from typing import Tuple, List


def parse_cidr_from_ip_and_mask(ip: str, mask: str) -> str:
    """Return CIDR suffix computed from subnet mask string like '255.255.255.0'."""
    try:
        net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        return str(net.prefixlen)
    except Exception:
        raise ValueError("Invalid IP or subnet mask")


def network_info(ip: str, cidr_or_mask: str) -> dict:
    """Return network information for a given IP and CIDR (or mask).

    Returns a dict with keys: network_address, broadcast_address, total_hosts
    """
    try:
        # Allow user to pass either a prefixlen (e.g. '24') or a mask '255.255.255.0'
        if cidr_or_mask.isdigit():
            network = ipaddress.IPv4Network(f"{ip}/{cidr_or_mask}", strict=False)
        else:
            network = ipaddress.IPv4Network(f"{ip}/{cidr_or_mask}", strict=False)
        return {
            "network_address": str(network.network_address),
            "broadcast_address": str(network.broadcast_address),
            "total_hosts": max(network.num_addresses - 2, 0),
        }
    except Exception:
        raise ValueError("Invalid IP or CIDR/mask")


def example_use_cases(ip: str) -> List[str]:
    return [
        f"Web (HTTP): http://{ip}:80",
        f"Web (HTTPS): https://{ip}:443",
        f"File share: \\\\{ip}\\shared_files",
        f"RDP: {ip}:3389",
    ]


def current_machine_info() -> Tuple[str, str]:
    hostname = socket.gethostname()
    local_ip = "unknown"
    try:
        local_ip = socket.gethostbyname(hostname)
    except Exception:
        # Could not determine local IP; leave as 'unknown'
        pass
    return hostname, local_ip


def generate_static_ip_examples(base_ip: str, count: int = 1) -> List[str]:
    """Generate up to `count` example IP addresses within the base /24 network.

    For simplicity the base_ip will be used with the same network prefix.
    If count is larger than available hosts, stop at the broadcast-1.
    """
    try:
        net = ipaddress.IPv4Network(f"{base_ip}/24", strict=False)
    except Exception:
        raise ValueError("Base IP is invalid")

    hosts = list(net.hosts())
    examples = []
    for i in range(min(count, len(hosts))):
        examples.append(str(hosts[i]))
    return examples


def main(argv=None):
    parser = argparse.ArgumentParser(description="Static IP example and helpers")
    parser.add_argument("ip", nargs="?", default="192.168.1.100", help="Static IP address to use")
    parser.add_argument("-m", "--mask", default="255.255.255.0", help="Subnet mask or prefix length (e.g. 24 or 255.255.255.0)")
    parser.add_argument("-g", "--gateway", default="192.168.1.1", help="Default gateway")
    parser.add_argument("-n", "--generate", type=int, default=0, help="Generate N example IPs in the same /24 network")

    args = parser.parse_args(argv)

    try:
        cidr = parse_cidr_from_ip_and_mask(args.ip, args.mask) if not args.mask.isdigit() else args.mask
        info = network_info(args.ip, cidr)
    except ValueError as e:
        print(f"Error: {e}")
        return 2

    print(f"\n=== Static IP Configuration Example ===")
    print(f"Static IP Address: {args.ip}")
    print(f"Subnet Mask / Prefix: {args.mask} / {cidr}")
    print(f"Default Gateway: {args.gateway}")
    print(f"Network Address: {info['network_address']}")
    print(f"Broadcast Address: {info['broadcast_address']}")
    print(f"Total Available Hosts: {info['total_hosts']}")

    print(f"\n=== Example Use Cases for {args.ip} ===")
    for line in example_use_cases(args.ip):
        print(f"  - {line}")

    if args.generate > 0:
        try:
            examples = generate_static_ip_examples(args.ip, args.generate)
            print(f"\n=== Generated {len(examples)} Example IP(s) in the same /24 ===")
            for e in examples:
                print(f"  - {e}")
        except ValueError as e:
            print(f"Could not generate examples: {e}")

    hostname, local_ip = current_machine_info()
    print(f"\n=== Current Machine Info ===")
    print(f"Hostname: {hostname}")
    print(f"Current IP Address: {local_ip}")
    return 0


if __name__ == "__main__":
    sys.exit(main())