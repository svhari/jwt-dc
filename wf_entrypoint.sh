#!/bin/bash

# Set environment variables
export APP_ENV=production
export APP_PORT=5000

# Start the main application
exec uvicorn main:app --host 0.0.0.0 --port $APP_PORT
