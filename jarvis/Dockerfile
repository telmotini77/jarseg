# Stage 1: Build the React Dashboard
FROM node:20-alpine AS frontend-builder
WORKDIR /app/dashboard
COPY dashboard/package*.json ./
RUN npm ci
COPY dashboard/ ./
RUN npm run build

# Stage 2: Python Backend and Playwright Runtime
FROM python:3.11-slim AS backend
WORKDIR /app

# Install basic development packages and audio headers (for pyAudio compilation if needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    build-essential \
    libasound2-dev \
    portaudio19-dev \
    python3-tk \
    xauth \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright and its dependencies for Chromium
RUN playwright install chromium && playwright install-deps chromium

# Copy built frontend assets from stage 1
COPY --from=frontend-builder /app/dashboard/dist ./dashboard/dist

# Copy the rest of the application
COPY . .

# Expose the API and Dashboard port
EXPOSE 8765

# Default environment settings for Docker execution
ENV PYTHONUNBUFFERED=1 \
    DASHBOARD_HOST=0.0.0.0 \
    DASHBOARD_AUTO_OPEN=false \
    WAKE_WORD_ENABLED=false \
    TTS_ENABLED=false \
    BROWSER_HEADLESS=true

# Run the non-interactive service: the API, schedulers and CyberSeg monitor
# stay active while the native Windows HUD remains an optional host process.
CMD ["python", "main.py", "--service"]
