import json

from app.ebpf_manager import EBPFManager, FlowEntry


def test_flow_key_matches_packet_filter_layout():
    flow, key = EBPFManager._flow_key(
        "10.77.0.2",
        "172.20.0.5",
        5678,
        "tcp",
    )

    assert flow == FlowEntry("10.77.0.2", "172.20.0.5", 5678, "tcp")
    assert key == bytes.fromhex("0a4d0002ac140005162e0600")


def test_map_operations_use_configured_pin_path(monkeypatch):
    manager = EBPFManager(map_path="/sys/fs/bpf/ztna/maps/allowed_flows")
    calls = []

    def fake_run(arguments):
        calls.append(arguments)
        if arguments[:3] == ["-j", "map", "dump"]:
            key = bytes.fromhex("0a4d0002ac140005162e0600")
            return json.dumps(
                [{"key": list(key), "value": [1]}]
            )
        return ""

    monkeypatch.setattr(manager, "_run", fake_run)

    added = manager.add_flow("10.77.0.2", "172.20.0.5", 5678, "tcp")
    listed = manager.list_flows()
    manager.delete_flow("10.77.0.2", "172.20.0.5", 5678, "tcp")

    assert added == listed[0]
    assert calls[0][:4] == [
        "map",
        "update",
        "pinned",
        "/sys/fs/bpf/ztna/maps/allowed_flows",
    ]
    assert calls[1][:5] == [
        "-j",
        "map",
        "dump",
        "pinned",
        "/sys/fs/bpf/ztna/maps/allowed_flows",
    ]
    assert calls[2][:4] == [
        "map",
        "delete",
        "pinned",
        "/sys/fs/bpf/ztna/maps/allowed_flows",
    ]
