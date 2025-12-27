import argparse
import socket
from typing import Tuple, List

"""
When listening for connections from a target, we need to know which interface will be used. This utility provides the
interface IP address and the interface name.
"""

try:
    import psutil
except ImportError:
    psutil = None


def pick_local_addr(dest_host: str, port: int = 53) -> Tuple[str, int]:
    """
    Returns (local_ip, family) that the OS would use to reach dest_host.
    Uses a UDP 'connect' which does not actually send packets.
    """
    # Resolve like the OS would; prefer system order
    infos = socket.getaddrinfo(dest_host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    last_err = None
    for family, socktype, proto, canonname, sockaddr in infos:
        try:
            s = socket.socket(family, socket.SOCK_DGRAM)
            try:
                s.connect(sockaddr)  # no packets sent for UDP connect
                local_ip = s.getsockname()[0]
                return local_ip, family
            finally:
                s.close()
        except OSError as e:
            last_err = e
            continue
    raise OSError(f"Could not determine local address for {dest_host}: {last_err}")


def map_ip_to_interfaces(local_ip: str, family: int) -> List[str]:
    """
    Returns a list of interface names that have local_ip assigned.
    If psutil is unavailable or nothing matches, returns [].
    """
    if psutil is None:
        return []
    want = socket.AF_INET if family == socket.AF_INET else socket.AF_INET6
    matches = []
    for ifname, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            # psutil uses socket.AF_INET / AF_INET6 for IP addrs
            if a.family == want and a.address == local_ip:
                matches.append(ifname)
    return sorted(set(matches))


def main():
    ap = argparse.ArgumentParser(
        description="Show the local IP and interface used to reach a destination."
    )
    ap.add_argument("destination", help="Destination IP or hostname")
    ap.add_argument("--port", type=int, default=53, help="UDP port to use for routing decision (default: 53)")
    args = ap.parse_args()

    local_ip, fam = pick_local_addr(args.destination, args.port)
    ifnames = map_ip_to_interfaces(local_ip, fam)
    fam_str = "IPv6" if fam == socket.AF_INET6 else "IPv4"

    print(f"Destination     : {args.destination}")
    print(f"Address family  : {fam_str}")
    print(f"Local source IP : {local_ip}")
    if ifnames:
        # Usually a single match, but VLANs/bridges could yield more than one
        print(f"Interface       : {', '.join(ifnames)}")
    else:
        if psutil is None:
            print("Interface       : (unknown; install psutil to map IP→interface: pip install psutil)")
        else:
            print("Interface       : (no interface matched this IP; check routes/aliases)")


if __name__ == "__main__":
    main()
