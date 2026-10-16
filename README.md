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

The services are described in `docker-compose.yml`. With Docker Compose and
GNU Make installed, build and run them from this directory with:

```sh
make -C ebpf up
```

Useful project commands:

```sh
make -C ebpf help       # list available targets
make -C ebpf down       # stop the Compose services
make -C ebpf logs       # follow Compose logs
make -C ebpf status     # show running services
make -C ebpf ebpf       # build the eBPF object
make -C ebpf clean      # remove the generated eBPF object
```

For local development outside Docker, install dependencies with
`make -C ebpf backend-install` and `make -C ebpf dashboard-install`, then run
`make -C ebpf backend-dev` and `make -C ebpf dashboard-dev` in separate
terminals.

The eBPF component requires Linux, kernel headers, and the toolchain specified
in `ebpf/Makefile`; it is not loaded by Docker Compose yet.
