import socket
import pytest
from keyholderd.peercred import PeerCredentialError, get_peercred, uid_to_name

def test_uid_to_username_resolution():
    assert uid_to_name(0) == "root"

def test_peercred_returns_pid_uid_gid_for_unix_socket():
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        pid, uid, gid = get_peercred(a)
        assert pid > 0 and uid >= 0 and gid >= 0
    finally:
        a.close(); b.close()

def test_peercred_failure_explicit_on_non_unix_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(PeerCredentialError):
            get_peercred(s)
    finally:
        s.close()
