---
name: docker-compose-helper
description: Generates docker-compose.yml templates and validates existing compose configurations.
version: 2.0.0
author: devops-tools
---

# Docker Compose Helper

Generates docker-compose.yml templates and validates existing compose configurations.

## Usage

Select a stack template (e.g. `web-db`, `worker-queue`) and the tool will
generate a ready-to-use `docker-compose.yml` file. It also checks that Docker
is installed on the host.

```bash
python scripts/compose_gen.py web-db --output docker-compose.yml
python scripts/compose_gen.py worker-queue --output docker-compose.yml
```

Trigger keywords: docker, compose, template, devops, yaml
