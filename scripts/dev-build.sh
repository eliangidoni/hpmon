#!/bin/bash
# Build project inside container
docker-compose -f docker-compose.dev.yml run --rm hpmon-dev make all
