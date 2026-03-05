# RedSentinel — Docker Cleanup Guide

How to cleanly tear down the Docker environment after use, from a quick stop all the way to a full wipe.

---

## Table of Contents

1. [Quick Reference](#1-quick-reference)
2. [Stop Containers (keep data)](#2-stop-containers-keep-data)
3. [Remove Containers](#3-remove-containers)
4. [Remove Built Images](#4-remove-built-images)
5. [Remove Volumes](#5-remove-volumes)
6. [Full Teardown (nuclear)](#6-full-teardown-nuclear)
7. [Dev Mode Cleanup](#7-dev-mode-cleanup)
8. [Prune Dangling Resources](#8-prune-dangling-resources)
9. [What Each Volume Holds](#9-what-each-volume-holds)

---

## 1. Quick Reference

| Goal | Command |
|------|---------|
| Stop everything, keep data | `docker compose down` |
| Stop + remove containers & networks | `docker compose down` |
| Stop + remove containers, images, volumes | `docker compose down --rmi all -v` |
| Remove only built images | `docker compose down --rmi local` |
| Remove a single named volume | `docker volume rm ratopaleydai_pgdata` |
| Nuke everything Docker-related on machine | `docker system prune -a --volumes` |

---

## 2. Stop Containers (keep data)

Stops all running containers. Volumes and images are **preserved** — re-running `docker compose up` picks up where you left off.

```bash
docker compose down
```

For the dev stack:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml down
```

---

## 3. Remove Containers

`docker compose down` already removes the stopped containers and the default network. Nothing extra needed. To confirm nothing lingers:

```bash
docker compose ps -a
```

All entries should be gone after `down`.

---

## 4. Remove Built Images

RedSentinel builds five images locally (`context`, `payload-gen`, `fuzzer`, `core`, `dashboard`). To delete them:

```bash
# Remove only the images built by this compose file (leaves pulled images like redis, postgres alone)
docker compose down --rmi local
```

To also remove the pulled base images (redis, postgres):

```bash
docker compose down --rmi all
```

To delete images manually by name:

```bash
docker rmi \
  ratopaleydai-context \
  ratopaleydai-payload-gen \
  ratopaleydai-fuzzer \
  ratopaleydai-core \
  ratopaleydai-dashboard
```

> **Note:** The exact image names include the Compose project prefix, which defaults to the directory name (`ratopaleydai`). If you renamed the folder, substitute accordingly.  
> Check with: `docker images | grep redsentinel`

---

## 5. Remove Volumes

> **Warning:** Deleting `pgdata` permanently destroys all scan history stored in PostgreSQL. Delete it only when you no longer need that data.

### Remove all project volumes at once

```bash
docker compose down -v
```

### Remove individual volumes

```bash
# Scan results stored in PostgreSQL — DESTRUCTIVE
docker volume rm ratopaleydai_pgdata

# Generated HTML/PDF reports
docker volume rm ratopaleydai_reports

# Fuzzer online-learning data
docker volume rm ratopaleydai_training_data
```

### List volumes first to confirm names

```bash
docker volume ls | grep ratopaleydai
```

---

## 6. Full Teardown (nuclear)

Removes containers, networks, all built images, and all volumes in one shot:

```bash
docker compose down --rmi all -v
```

If you also want to free up the Docker build cache (reclaims significant disk space after repeated builds):

```bash
docker compose down --rmi all -v
docker builder prune -f
```

To also remove any lingering dangling images and stopped containers across the entire Docker installation (not just this project):

```bash
docker system prune -a --volumes
```

> **Warning:** `docker system prune -a --volumes` affects **all** Docker projects on the machine, not just RedSentinel.

---

## 7. Dev Mode Cleanup

The dev stack (`docker-compose.dev.yml`) doesn't introduce extra volumes, but it does build images with a `builder` target. Clean it up the same way, just referencing both files:

```bash
# Stop dev stack and remove containers
docker compose -f docker-compose.yml -f docker-compose.dev.yml down

# Stop dev stack, remove images and volumes
docker compose -f docker-compose.yml -f docker-compose.dev.yml down --rmi local -v
```

---

## 8. Prune Dangling Resources

After repeated builds, dangling (untagged) images and unused build layers accumulate. Clean them without touching active containers or named volumes:

```bash
# Remove dangling images only
docker image prune -f

# Remove stopped containers, dangling images, unused networks, build cache
docker system prune -f

# Same as above but also removes unused volumes (named volumes not attached to any container)
docker system prune -f --volumes
```

---

## 9. What Each Volume Holds

| Volume | Contents | Safe to delete? |
|--------|----------|-----------------|
| `ratopaleydai_pgdata` | PostgreSQL data — all scan results, findings, API keys | Only if you don't need scan history |
| `ratopaleydai_reports` | Generated HTML/PDF scan reports | Yes — reports can be re-generated from scan data |
| `ratopaleydai_training_data` | Fuzzer online-learning snapshots | Yes — fuzzer re-initialises on next run |
