#!/bin/bash
# Production startup script for OpenSMN

# Load environment variables from .env file
if [ ! -f .env ]; then
    echo "Error: .env file not found!"
    echo "Please copy .env.example to .env and configure your settings."
    exit 1
fi

# Export environment variables
set -a
source .env
set +a

# Default values if not set in .env
PORT=${PORT:-6942}
WORKERS=${WORKERS:-1}  # This can change on the future, but for now, 1 is enough
HOST=${HOST:-0.0.0.0}

echo "Starting OpenSMN..."
echo "Host: $HOST"
echo "Port: $PORT"
echo "Workers: $WORKERS"

# Start uvicorn with production settings
exec uvicorn server:app \
    --host "$HOST" \
    --port "$PORT" \
    --workers "$WORKERS" \
    --log-level info \
    --access-log
