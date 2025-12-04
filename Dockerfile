# Use official Python image (Debian-based Linux)
FROM python:3.12-slim

# Install build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Upgrade pip
RUN pip install --upgrade pip

# Copy project
COPY . /app

# Install project + dev dependencies
RUN pip install .[dev]

# Set environment variables for pytest
ENV PYTHONUNBUFFERED=1
ENV PYTEST_ADDOPTS="--maxfail=5 --disable-warnings -q"

# Run tests by default
CMD ["pytest"]
