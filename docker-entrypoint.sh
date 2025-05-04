#!/bin/bash
set -e

# Handle SIGTERM and SIGINT signals for graceful shutdown
shutdown() {
    echo "Received shutdown signal, attempting graceful shutdown..."
    # Send SIGTERM to the uvicorn process
    kill -TERM "$PID" 2>/dev/null
    # Wait for process to terminate
    wait "$PID"
    echo "Application shutdown complete."
    exit 0
}

# Set up signal trapping
trap shutdown SIGTERM SIGINT

# Start uvicorn
echo "Starting application..."
uvicorn bot.main:app --host "$UVICORN_HOST" --port "$UVICORN_PORT" --log-level "$LOG_LEVEL" &
PID=$!

# Wait for the process to terminate
wait $PID