# Zero-Trust eBPF Gateway

Starter scaffold for a zero-trust gateway with a FastAPI control plane, OPA
policy checks, and an eBPF data plane.

## Project layout

- `backend/` — FastAPI API and authorization/eBPF integration
- `ebpf/` — eBPF packet filter source and build file
- `opa/` — OPA policy
- `dashboard/` — React + Vite dashboard
- `docker-compose.yml` — local service definitions

This is a scaffold, not a production-ready security gateway. The eBPF program,
map management, identity verification, and network attachment must be
implemented and tested for the target Linux kernel and deployment environment
before use.

## Quick start

The services are described in `docker-compose.yml`. Build and run them from
this directory with:

```sh
docker compose up --build
```

The eBPF component requires Linux, kernel headers, and the toolchain specified
in `ebpf/Makefile`; it is not loaded by Docker Compose yet.
