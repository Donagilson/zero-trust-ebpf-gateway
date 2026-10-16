CLANG ?= clang
ARCH ?= x86
COMPOSE ?= docker compose -f ../docker-compose.yml
PYTHON ?= python
NPM ?= npm
BPF_CFLAGS ?= -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -Wall -Werror

.PHONY: help all build up down logs status backend-install backend-dev dashboard-install dashboard-dev ebpf clean

help:
	@echo Usage: make -C ebpf target
	@echo
	@echo Compose:
	@echo   build             Build the Docker Compose services
	@echo   up                Build and start the services
	@echo   down              Stop and remove the services
	@echo   logs              Follow service logs
	@echo   status            Show service status
	@echo
	@echo Local development:
	@echo   backend-install   Install backend Python dependencies
	@echo   backend-dev       Run the FastAPI development server
	@echo   dashboard-install Install dashboard dependencies
	@echo   dashboard-dev     Run the dashboard development server
	@echo
	@echo eBPF:
	@echo   all or ebpf        Build the TC eBPF object
	@echo   clean              Remove the generated eBPF object

all: filter.bpf.o

ebpf: all

filter.bpf.o: filter.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

build:
	$(COMPOSE) build

up:
	$(COMPOSE) up --build

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs --follow

status:
	$(COMPOSE) ps

backend-install:
	cd ../backend && $(PYTHON) -m pip install -r requirements.txt

backend-dev:
	cd ../backend && $(PYTHON) -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

dashboard-install:
	cd ../dashboard && $(NPM) install

dashboard-dev:
	cd ../dashboard && $(NPM) run dev

clean:
	rm -f filter.bpf.o
