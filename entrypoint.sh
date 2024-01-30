#!/bin/bash

# Set environment variables
export APP_ENV=production
export APP_PORT=8000

# Start the main application
exec uvicorn app.main:app --host 0.0.0.0 --port $APP_PORT
