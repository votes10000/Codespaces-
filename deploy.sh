#!/bin/bash

# --- Configuration ---
PROJECT_PATH="/path/to/your/project"
USER="your_user"
APP_NAME="client-api"

# --- Navigate to the project directory ---
echo "Navigating to project directory: $PROJECT_PATH"
cd "$PROJECT_PATH" || exit 1

# --- Install production dependencies ---
echo "Installing production dependencies..."
npm install --production || exit 1

# --- Stop the old application (if running with PM2) ---
echo "Stopping the old application (if running)..."
pm2 stop "$APP_NAME" 2>/dev/null || true # Ignore error if app is not running

# --- Start the new application with PM2 ---
echo "Starting the new application with PM2..."
pm2 start server.js --name "$APP_NAME"

echo "Deployment complete!"
echo "You can check the status with: pm2 list"
echo "Or view logs with: pm2 logs $APP_NAME"
