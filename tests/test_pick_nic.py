from __future__ import annotations

import socket
import pytest

import modules.utils.pick_nic as m


def test_pick_local_addr_loopback_ipv4():
    ip, fam = m.pick_local_addr("127.0.0.1", 53)
    assert ip == "127.0.0.1"
    assert fam == socket.AF_INET


def test_pick_local_addr_invalid_destination_raises():
    # getaddrinfo should fail for an invalid IP literal
    with pytest.raises((socket.gaierror, OSError)):
        m.pick_local_addr("256.256.256.256", 53)


def test_pick_local_addr_loopback_ipv6_if_available():
    try:
        ip, fam = m.pick_local_addr("::1", 53)
    except (socket.gaierror, OSError):
        pytest.skip("IPv6 loopback not available on this system")

    assert ip == "::1"
    assert fam == socket.AF_INET6


def test_map_ip_to_interfaces_returns_empty_when_psutil_unavailable(monkeypatch):
    monkeypatch.setattr(m, "psutil", None)
    assert m.map_ip_to_interfaces("127.0.0.1", socket.AF_INET) == []


def test_map_ip_to_interfaces_returns_empty_when_no_interface_matches(monkeypatch):
    psutil = pytest.importorskip("psutil")
    monkeypatch.setattr(m, "psutil", psutil)

    # TEST-NET-3, should not be assigned locally
    assert m.map_ip_to_interfaces("203.0.113.123", socket.AF_INET) == []


def test_map_ip_to_interfaces_real_loopback_mapping(monkeypatch):
    psutil = pytest.importorskip("psutil")
    monkeypatch.setattr(m, "psutil", psutil)

    ip, fam = m.pick_local_addr("127.0.0.1", 53)
    ifnames = m.map_ip_to_interfaces(ip, fam)

    # Should map to some loopback interface name (lo, lo0, Loopback Pseudo-Interface, etc.)
    assert isinstance(ifnames, list)
    assert len(ifnames) >= 1

    # Sanity: returned names exist in psutil's interface list
    all_ifaces = set(psutil.net_if_addrs().keys())
    assert set(ifnames).issubset(all_ifaces)
