#!/bin/bash
# Run tests inside container
docker-compose -f docker-compose.dev.yml run --rm hpmon-dev sudo make test
