"""Manage authorized flow entries in the gateway's eBPF map."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from ipaddress import IPv4Address


DEFAULT_MAP_NAME = "allowed_flows"
_PROTOCOL_NUMBERS = {"tcp": 6, "udp": 17}
_PROTOCOL_NAMES = {number: name for name, number in _PROTOCOL_NUMBERS.items()}
_FLOW_KEY_SIZE = 12


class EBPFMapError(RuntimeError):
    """The eBPF map could not be read or updated."""


class EBPFMapNotFoundError(EBPFMapError):
    """The configured eBPF map is not loaded."""


@dataclass(frozen=True)
class FlowEntry:
    """A flow key accepted by the packet filter."""

    client_ipv4: str
    destination_ipv4: str
    destination_port: int
    protocol: str


class EBPFManager:
    """Add, list, and remove entries from the loaded ``allowed_flows`` map."""

    def __init__(
        self,
        map_name: str = DEFAULT_MAP_NAME,
        bpftool_path: str = "bpftool",
        timeout: float = 5.0,
    ) -> None:
        if not isinstance(map_name, str) or not map_name:
            raise ValueError("map_name must be a non-empty string")
        if not isinstance(bpftool_path, str) or not bpftool_path:
            raise ValueError("bpftool_path must be a non-empty string")
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero")

        self.map_name = map_name
        self.bpftool_path = bpftool_path
        self.timeout = timeout

    def add_flow(
        self,
        client_ipv4: str,
        destination_ipv4: str,
        destination_port: int,
        protocol: str,
    ) -> FlowEntry:
        """Add an authorized flow to the map, replacing an existing entry."""
        flow, key = self._flow_key(
            client_ipv4, destination_ipv4, destination_port, protocol
        )
        map_id = self._map_id()
        self._run(
            [
                "map",
                "update",
                "id",
                str(map_id),
                "key",
                "hex",
                *self._hex_bytes(key),
                "value",
                "hex",
                "01",
                "any",
            ]
        )
        return flow

    def list_flows(self) -> list[FlowEntry]:
        """Return all flow keys currently stored in the map."""
        map_id = self._map_id()
        output = self._run(["-j", "map", "dump", "id", str(map_id)])
        try:
            entries = json.loads(output)
        except json.JSONDecodeError as exc:
            raise EBPFMapError(
                "bpftool returned invalid JSON while dumping the map"
            ) from exc

        if not isinstance(entries, list):
            raise EBPFMapError("bpftool returned an invalid map dump")

        flows: list[FlowEntry] = []
        for entry in entries:
            if not isinstance(entry, dict):
                raise EBPFMapError("bpftool returned an invalid map entry")
            flows.append(self._decode_flow(entry.get("key"), entry.get("value")))
        return flows

    def delete_flow(
        self,
        client_ipv4: str,
        destination_ipv4: str,
        destination_port: int,
        protocol: str,
    ) -> None:
        """Remove a flow key from the map; raise if bpftool cannot delete it."""
        _, key = self._flow_key(
            client_ipv4, destination_ipv4, destination_port, protocol
        )
        map_id = self._map_id()
        self._run(
            [
                "map",
                "delete",
                "id",
                str(map_id),
                "key",
                "hex",
                *self._hex_bytes(key),
            ]
        )

    def _map_id(self) -> int:
        output = self._run(["-j", "map", "show"])
        try:
            maps = json.loads(output)
        except json.JSONDecodeError as exc:
            raise EBPFMapError(
                "bpftool returned invalid JSON while listing maps"
            ) from exc

        if not isinstance(maps, list):
            raise EBPFMapError("bpftool returned an invalid map list")

        matches = [
            map_info
            for map_info in maps
            if isinstance(map_info, dict) and map_info.get("name") == self.map_name
        ]
        if not matches:
            raise EBPFMapNotFoundError(
                f"eBPF map {self.map_name!r} is not loaded"
            )
        if len(matches) > 1:
            raise EBPFMapError(
                f"multiple eBPF maps named {self.map_name!r} are loaded"
            )

        map_id = matches[0].get("id")
        if isinstance(map_id, bool) or not isinstance(map_id, int):
            raise EBPFMapError(
                f"bpftool returned an invalid ID for map {self.map_name!r}"
            )
        return map_id

    def _run(self, arguments: list[str]) -> str:
        try:
            result = subprocess.run(
                [self.bpftool_path, *arguments],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            raise EBPFMapError(
                f"bpftool executable {self.bpftool_path!r} was not found"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise EBPFMapError(
                f"bpftool command timed out after {self.timeout} seconds"
            ) from exc
        except OSError as exc:
            raise EBPFMapError(f"could not run bpftool: {exc}") from exc

        if result.returncode:
            detail = result.stderr.strip() or result.stdout.strip()
            if detail:
                raise EBPFMapError(f"bpftool failed: {detail}")
            raise EBPFMapError(f"bpftool failed with exit code {result.returncode}")
        return result.stdout

    @staticmethod
    def _flow_key(
        client_ipv4: str,
        destination_ipv4: str,
        destination_port: int,
        protocol: str,
    ) -> tuple[FlowEntry, bytes]:
        if not isinstance(client_ipv4, str):
            raise ValueError("client_ipv4 must be an IPv4 address")
        if not isinstance(destination_ipv4, str):
            raise ValueError("destination_ipv4 must be an IPv4 address")
        try:
            client = IPv4Address(client_ipv4)
        except ValueError as exc:
            raise ValueError("client_ipv4 must be a valid IPv4 address") from exc
        try:
            destination = IPv4Address(destination_ipv4)
        except ValueError as exc:
            raise ValueError("destination_ipv4 must be a valid IPv4 address") from exc

        if (
            isinstance(destination_port, bool)
            or not isinstance(destination_port, int)
            or not 1 <= destination_port <= 65535
        ):
            raise ValueError("destination_port must be an integer between 1 and 65535")
        if not isinstance(protocol, str) or protocol not in _PROTOCOL_NUMBERS:
            raise ValueError("protocol must be 'tcp' or 'udp'")

        flow = FlowEntry(
            client_ipv4=str(client),
            destination_ipv4=str(destination),
            destination_port=destination_port,
            protocol=protocol,
        )
        key = (
            client.packed
            + destination.packed
            + destination_port.to_bytes(2, byteorder="big")
            + bytes((_PROTOCOL_NUMBERS[protocol], 0))
        )
        if len(key) != _FLOW_KEY_SIZE:
            raise EBPFMapError(
                "generated flow key does not match the eBPF map layout"
            )
        return flow, key

    @staticmethod
    def _hex_bytes(value: bytes) -> list[str]:
        return [f"{byte:02x}" for byte in value]

    @classmethod
    def _decode_flow(cls, raw_key: object, raw_value: object) -> FlowEntry:
        key = cls._map_bytes(raw_key, "key", _FLOW_KEY_SIZE)
        cls._map_bytes(raw_value, "value", 1)

        protocol_number = key[10]
        protocol = _PROTOCOL_NAMES.get(protocol_number)
        if protocol is None:
            raise EBPFMapError(
                f"map contains unsupported IP protocol number {protocol_number}"
            )
        if key[11] != 0:
            raise EBPFMapError("map contains a flow key with non-zero padding")

        return FlowEntry(
            client_ipv4=str(IPv4Address(key[:4])),
            destination_ipv4=str(IPv4Address(key[4:8])),
            destination_port=int.from_bytes(key[8:10], byteorder="big"),
            protocol=protocol,
        )

    @staticmethod
    def _map_bytes(value: object, field: str, expected_size: int) -> bytes:
        if (
            not isinstance(value, list)
            or len(value) != expected_size
            or any(
                isinstance(byte, bool)
                or not isinstance(byte, int)
                or not 0 <= byte <= 255
                for byte in value
            )
        ):
            raise EBPFMapError(f"bpftool returned an invalid map {field}")
        return bytes(value)
