#!/bin/bash
# Run format, lint, and test inside container
docker-compose -f docker-compose.dev.yml run --rm -T hpmon-dev sudo make check
