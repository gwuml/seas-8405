.PHONY: up down reset logs setup

# Determine docker compose command
DOCKER_COMPOSE := $(shell command -v docker-compose > /dev/null && echo docker-compose || echo docker compose)

# Build and start containers
up:
	@echo "[*] Building and starting containers..."
	@$(DOCKER_COMPOSE) up -d --build

# Stop and remove containers
down:
	@echo "[*] Stopping and removing containers..."
	@$(DOCKER_COMPOSE) down -v

# Reset the environment
reset: down up

# View logs
logs:
	@$(DOCKER_COMPOSE) logs -f

# Run Keycloak setup script
setup:
	@echo "[*] Running Keycloak setup script..."
	@bash keycloak/setup.sh

# Default target: up and setup
all: up setup
