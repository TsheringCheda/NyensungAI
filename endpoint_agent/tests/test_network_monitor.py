import socket
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from collections import namedtuple

from network_monitor import collect_new_connections, connection_event, is_usable_remote_ip

Addr = namedtuple('Addr', 'ip port')
Conn = namedtuple('Conn', 'type status laddr raddr')


def test_loopback_and_invalid_addresses_are_rejected():
    assert not is_usable_remote_ip('127.0.0.1')
    assert not is_usable_remote_ip('::1')
    assert not is_usable_remote_ip('not-an-ip')
    assert is_usable_remote_ip('192.0.2.10')


def test_connection_event_normalizes_tcp_socket():
    event = connection_event('192.168.1.10', 443, '192.0.2.10', 53000, 'LAB-PC', 'NyensungAI')
    assert event['event_type'] == 'NETWORK_CONNECTION_OBSERVED'
    assert event['source_ip'] == '192.0.2.10'
    assert 'local_port=443' in event['description']
    assert 'protocol=TCP' in event['description']


def test_snapshot_emits_only_new_established_tcp_connections():
    rows = [
        Conn(socket.SOCK_STREAM, 'ESTABLISHED', Addr('192.168.1.10', 443), Addr('192.0.2.10', 53000)),
        Conn(socket.SOCK_STREAM, 'LISTEN', Addr('0.0.0.0', 443), None),
        Conn(socket.SOCK_DGRAM, 'ESTABLISHED', Addr('192.168.1.10', 53), Addr('192.0.2.10', 53001)),
    ]
    events, snapshot = collect_new_connections(set(), rows, 'LAB-PC', 'NyensungAI')
    assert len(events) == 1
    assert len(snapshot) == 1
    second_events, second_snapshot = collect_new_connections(snapshot, rows, 'LAB-PC', 'NyensungAI')
    assert second_events == []
    assert second_snapshot == snapshot
