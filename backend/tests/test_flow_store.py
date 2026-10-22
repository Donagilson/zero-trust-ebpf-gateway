from app.flow_store import FlowRegistry


def test_flow_owner_persists_between_registry_instances(tmp_path):
    database = tmp_path / "gateway.sqlite3"
    first_registry = FlowRegistry(str(database))
    first_registry.set_owner("flow-123", "subject-456")

    reopened_registry = FlowRegistry(str(database))

    assert reopened_registry.get_owner("flow-123") == "subject-456"

    reopened_registry.remove_owner("flow-123")
    assert first_registry.get_owner("flow-123") is None
