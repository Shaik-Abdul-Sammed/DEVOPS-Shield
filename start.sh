#!/usr/bin/env bash
set -euo pipefail

echo "Starting DevOps Shield Backend..."

# Activate virtual environment if Railway created one
if [ -d "venv" ]; then
  echo "Activating venv..."
  source /home/bangi-abdulla/Desktop/DevOps/.venv/bin/activate
elif [ -d ".venv" ]; then
  echo "Activating .venv..."
  source /home/bangi-abdulla/Desktop/DevOps/.venv/bin/activate
fi

# Ensure backend sources are importable as "src" and "backend"
export PYTHONPATH="$(pwd):$(pwd)/backend:${PYTHONPATH:-}"

# Set default environment variables
export ENVIRONMENT="${ENVIRONMENT:-production}"
export PORT="${PORT:-8080}"

# Create necessary directories if they don't exist
mkdir -p backend/database
mkdir -p backend/logs
mkdir -p backend/backups
mkdir -p backend/ml/models

echo "Environment: $ENVIRONMENT"
echo "Port: $PORT"
echo "PYTHONPATH: $PYTHONPATH"

# Launch FastAPI backend via Uvicorn
echo "Starting Uvicorn server..."
exec uvicorn backend.main:app \
  --host 0.0.0.0 \
  --port "$PORT" \
  --workers 1 \
  --log-level info \
  --access-log \
  --timeout-keep-alive 65 \
  --timeout-graceful-shutdown 30
