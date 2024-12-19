# Using an outdated base image deliberately
FROM python:3.8-slim

# Exposing sensitive information in build args
ARG DB_PASSWORD=admin123
ARG SECRET_KEY=super_secret_key_123

# Running as root (security vulnerability)
USER root

# Installing system dependencies without cleanup
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Setting working directory
WORKDIR /app

# Copying application files
COPY . .

# Installing Python dependencies without version pinning
RUN pip install --no-cache-dir \
    flask \
    flask-sqlalchemy \
    psycopg2-binary \
    werkzeug

# Exposing sensitive environment variables
ENV DATABASE_URL="postgresql://admin:admin123@db:5432/vulnerable_db" \
    FLASK_ENV=development \
    DEBUG=1 \
    SECRET_KEY=${SECRET_KEY}

# Exposing port
EXPOSE 5000

# Running with root privileges
CMD ["python", "app.py"]
