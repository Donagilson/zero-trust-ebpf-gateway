from fastapi.testclient import TestClient

from app import main
from app.auth import AuthenticatedUser, get_current_user
from app.ebpf_manager import EBPFMapError, FlowEntry


class FakeMap:
    def __init__(self):
        self.flows = []

    def list_flows(self):
        return list(self.flows)

    def add_flow(self, client_ipv4, destination_ipv4, destination_port, protocol):
        flow = FlowEntry(
            client_ipv4,
            destination_ipv4,
            destination_port,
            protocol,
        )
        if flow not in self.flows:
            self.flows.append(flow)
        return flow

    def delete_flow(self, client_ipv4, destination_ipv4, destination_port, protocol):
        flow = FlowEntry(
            client_ipv4,
            destination_ipv4,
            destination_port,
            protocol,
        )
        if flow not in self.flows:
            raise EBPFMapError("flow does not exist")
        self.flows.remove(flow)


class FakeRegistry:
    def __init__(self):
        self.owners = {}

    def get_owner(self, flow_id):
        return self.owners.get(flow_id)

    def list_owners(self):
        return dict(self.owners)

    def set_owner(self, flow_id, subject_sub):
        self.owners[flow_id] = subject_sub

    def remove_owner(self, flow_id):
        self.owners.pop(flow_id, None)


def test_user_can_authorize_list_and_revoke_own_flow(monkeypatch):
    state = {
        "user": AuthenticatedUser(
            subject="user-1",
            username="alice",
            roles=frozenset({"gateway-user"}),
            claims={"wg_client_ipv4": "10.77.0.2"},
        )
    }
    fake_map = FakeMap()
    monkeypatch.setattr(main, "ebpf_manager", fake_map)
    monkeypatch.setattr(main, "flow_registry", FakeRegistry())
    monkeypatch.setattr(main, "_resolve_service_ipv4", lambda _name: "172.20.0.5")

    async def allow_access(**_kwargs):
        return True

    monkeypatch.setattr(main, "authorize_access", allow_access)
    main.app.dependency_overrides[get_current_user] = lambda: state["user"]

    try:
        with TestClient(main.app) as client:
            response = client.post(
                "/flows/authorize",
                json={
                    "resource_name": "mock-backend",
                    "port": 5678,
                    "protocol": "tcp",
                },
            )
            assert response.status_code == 201
            flow = response.json()
            assert flow["client_ipv4"] == "10.77.0.2"
            assert flow["subject_sub"] == "user-1"

            repeated = client.post(
                "/flows/authorize",
                json={
                    "resource_name": "mock-backend",
                    "port": 5678,
                    "protocol": "tcp",
                },
            )
            assert repeated.status_code == 200
            assert repeated.json()["flow_id"] == flow["flow_id"]

            listed = client.get("/flows")
            assert listed.status_code == 200
            assert [entry["flow_id"] for entry in listed.json()] == [flow["flow_id"]]

            state["user"] = AuthenticatedUser(
                subject="user-2",
                username="bob",
                roles=frozenset({"gateway-user"}),
                claims={"wg_client_ipv4": "10.77.0.3"},
            )
            assert client.get("/flows").json() == []
            assert client.delete(f"/flows/{flow['flow_id']}").status_code == 404

            state["user"] = AuthenticatedUser(
                subject="admin-1",
                username="admin",
                roles=frozenset({"gateway-admin"}),
                claims={"wg_client_ipv4": "10.77.0.4"},
            )
            assert len(client.get("/flows").json()) == 1
            assert client.delete(f"/flows/{flow['flow_id']}").status_code == 204
            assert client.get("/flows").json() == []

            async def deny_access(**_kwargs):
                return False

            monkeypatch.setattr(main, "authorize_access", deny_access)
            denied = client.post(
                "/flows/authorize",
                json={
                    "resource_name": "unlisted-service",
                    "port": 5678,
                    "protocol": "tcp",
                },
            )
            assert denied.status_code == 403
            assert fake_map.flows == []
    finally:
        main.app.dependency_overrides.pop(get_current_user, None)
