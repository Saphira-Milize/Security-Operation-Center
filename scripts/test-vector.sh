#!/usr/bin/env bash
# Valide la configuration Vector et exécute ses tests unitaires.
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE="timberio/vector:0.61.0-debian"
RUN=(docker run --rm
  -e VECTOR_PASSWORD=test
  -e SOC_TIMEZONE=Europe/Paris
  -e VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true
  -v "$PWD/Vector:/etc/vector:ro"
  --entrypoint vector "$IMAGE")

"${RUN[@]}" validate --no-environment /etc/vector/vector.yaml
"${RUN[@]}" test /etc/vector/vector.yaml /etc/vector/tests.yaml
