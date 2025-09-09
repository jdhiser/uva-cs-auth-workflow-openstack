# Use a recent Python base image
FROM python:3.12-slim

# Avoid Python writing .pyc files and using buffered stdout
ENV PYTHONUNBUFFERED=1

# Install build/test deps (adjust as needed)
RUN apt update && apt install -y \
        git curl ca-certificates sudo \
    && rm -rf /var/lib/apt/lists/* \
    && apt clean

RUN pip install --upgrade pip setuptools wheel

# Set workdir
WORKDIR /app

copy . /app


CMD ./cicd/test.sh
