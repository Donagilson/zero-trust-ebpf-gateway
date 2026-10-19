"""FastAPI control plane for authenticated, policy-approved network flows."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from typing import Annotated, Literal
from uuid import UUID, uuid5

from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from app.auth import AuthenticatedUser, get_current_user
from app.ebpf_manager import EBPFManager, EBPFMapError, FlowEntry
from app.policy import OPAClientError, authorize_access

app = FastAPI(title="Zero-Trust eBPF Gateway")
ebpf_manager = EBPFManager()
FLOW_ID_NAMESPACE = UUID("aeb7d3d5-eef7-41f3-9bdd-12a9e706c072")


class AuthorizeFlowRequest(BaseModel):
    resource_name: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"]


class FlowResponse(BaseModel):
    flow_id: UUID
    client_ipv4: str
    destination_ipv4: str
    destination_port: int
    protocol: str
    subject_sub: str | None


@dataclass(frozen=True)
class _OwnedFlow:
    flow: FlowEntry
    subject_sub: str


_owned_flows: dict[UUID, _OwnedFlow] = {}
_flow_lock = asyncio.Lock()


def _flow_id(flow: FlowEntry) -> UUID:
    key = (
        f"{flow.client_ipv4}|{flow.destination_ipv4}|"
        f"{flow.destination_port}|{flow.protocol}"
    )
    return uuid5(FLOW_ID_NAMESPACE, key)


def _flow_tuple(flow: FlowEntry) -> tuple[str, str, int, str]:
    return (
        flow.client_ipv4,
        flow.destination_ipv4,
        flow.destination_port,
        flow.protocol,
    )


def _client_ipv4(user: AuthenticatedUser) -> str:
    value = user.claims.get("wg_client_ipv4")
    if not isinstance(value, str):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated identity has no WireGuard client address",
        )
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated identity has an invalid WireGuard client address",
        ) from exc


def _resolve_service_ipv4(resource_name: str) -> str:
    try:
        addresses = socket.getaddrinfo(
            resource_name,
            None,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authorized service could not be resolved",
        ) from exc

    for address in addresses:
        try:
            ipv4 = ipaddress.IPv4Address(address[4][0])
        except (IndexError, ipaddress.AddressValueError):
            continue
        if ipv4.is_private and not (
            ipv4.is_loopback
            or ipv4.is_link_local
            or ipv4.is_multicast
            or ipv4.is_reserved
            or ipv4.is_unspecified
        ):
            return str(ipv4)

    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Authorized service has no private IPv4 address",
    )


def _map_error() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="The eBPF flow map is unavailable",
    )


def _response(
    flow: FlowEntry, subject_sub: str | None
) -> FlowResponse:
    return FlowResponse(
        flow_id=_flow_id(flow),
        client_ipv4=flow.client_ipv4,
        destination_ipv4=flow.destination_ipv4,
        destination_port=flow.destination_port,
        protocol=flow.protocol,
        subject_sub=subject_sub,
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post(
    "/flows/authorize",
    response_model=FlowResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_flow(
    request: AuthorizeFlowRequest,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
) -> FlowResponse:
    client_ipv4 = _client_ipv4(user)
    try:
        allowed = await authorize_access(
            subject_sub=user.subject,
            roles=user.roles,
            resource_name=request.resource_name,
            port=request.port,
            protocol=request.protocol,
        )
    except OPAClientError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to evaluate access policy",
        ) from exc

    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied by policy",
        )

    destination_ipv4 = await run_in_threadpool(
        _resolve_service_ipv4, request.resource_name
    )
    flow = FlowEntry(
        client_ipv4=client_ipv4,
        destination_ipv4=destination_ipv4,
        destination_port=request.port,
        protocol=request.protocol,
    )
    flow_id = _flow_id(flow)

    async with _flow_lock:
        owner = _owned_flows.get(flow_id)
        if owner is not None:
            if owner.subject_sub != user.subject:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="This flow is already owned by another identity",
                )
            return _response(owner.flow, owner.subject_sub)

        try:
            existing_flows = await run_in_threadpool(ebpf_manager.list_flows)
            if any(_flow_tuple(existing) == _flow_tuple(flow) for existing in existing_flows):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="An existing flow cannot be attributed to this identity",
                )
            installed_flow = await run_in_threadpool(
                ebpf_manager.add_flow,
                flow.client_ipv4,
                flow.destination_ipv4,
                flow.destination_port,
                flow.protocol,
            )
        except EBPFMapError as exc:
            raise _map_error() from exc

        _owned_flows[flow_id] = _OwnedFlow(
            flow=installed_flow,
            subject_sub=user.subject,
        )

    return _response(installed_flow, user.subject)


@app.get("/flows", response_model=list[FlowResponse])
async def list_flows(
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
) -> list[FlowResponse]:
    is_admin = "gateway-admin" in user.roles
    async with _flow_lock:
        try:
            flows = await run_in_threadpool(ebpf_manager.list_flows)
        except EBPFMapError as exc:
            raise _map_error() from exc

        response: list[FlowResponse] = []
        for flow in flows:
            owned = _owned_flows.get(_flow_id(flow))
            if not is_admin and (
                owned is None or owned.subject_sub != user.subject
            ):
                continue
            response.append(
                _response(
                    flow,
                    owned.subject_sub if owned is not None else None,
                )
            )
        return response


@app.delete("/flows/{flow_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_flow(
    flow_id: UUID,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
) -> None:
    is_admin = "gateway-admin" in user.roles
    async with _flow_lock:
        owned = _owned_flows.get(flow_id)
        if owned is None and not is_admin:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Flow not found",
            )
        if owned is not None and owned.subject_sub != user.subject and not is_admin:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Flow not found",
            )

        if owned is None:
            try:
                flows = await run_in_threadpool(ebpf_manager.list_flows)
            except EBPFMapError as exc:
                raise _map_error() from exc
            owned_flow = next(
                (flow for flow in flows if _flow_id(flow) == flow_id),
                None,
            )
            if owned_flow is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Flow not found",
                )
            flow = owned_flow
        else:
            flow = owned.flow

        try:
            await run_in_threadpool(
                ebpf_manager.delete_flow,
                flow.client_ipv4,
                flow.destination_ipv4,
                flow.destination_port,
                flow.protocol,
            )
        except EBPFMapError as exc:
            raise _map_error() from exc

        _owned_flows.pop(flow_id, None)
