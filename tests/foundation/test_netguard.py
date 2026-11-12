import socket
import urllib.request

import pytest

from gamekernel import netguard


@pytest.fixture(scope="module", autouse=True)
def guard():
    netguard.install()
    yield


def test_self_test_reports_blocked():
    result = netguard.self_test()
    assert result["ok"], result


def test_urllib_blocked():
    with pytest.raises(netguard.NetworkBlockedError):
        urllib.request.urlopen("http://192.0.2.1/", timeout=0.2)


def test_external_dns_and_connect_blocked():
    with pytest.raises(netguard.NetworkBlockedError):
        socket.getaddrinfo("clamav.net", 443)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with pytest.raises(netguard.NetworkBlockedError):
            s.sendto(b"x", ("8.8.8.8", 53))
    finally:
        s.close()


def test_socketpair_still_works():
    a, b = socket.socketpair()
    try:
        a.sendall(b"ok")
        assert b.recv(2) == b"ok"
    finally:
        a.close()
        b.close()


def test_attempts_are_recorded():
    assert any(a.event for a in netguard.blocked_attempts())
