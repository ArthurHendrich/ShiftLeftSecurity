# Using an older Python version to improve compatibility with legacy dependencies
FROM python:3.7-slim

# Exposing sensitive information in build args (for demonstration only, not recommended)
ARG DB_PASSWORD=admin123
ARG SECRET_KEY=super_secret_key_123

# Running as root (security vulnerability, but this is for PoC)
USER root

# Install system dependencies and build tools needed to compile older Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    build-essential \
    libpq-dev \
    curl \
    python3-dev \
    libffi-dev \
    libssl-dev \
    libjpeg-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy the application files
COPY . .

# Update pip to the latest version for better handling of legacy wheels
RUN pip install --no-cache-dir --upgrade pip

# Install Python dependencies
# Removed --no-deps to let pip fetch necessary indirect dependencies.
RUN pip install --no-cache-dir Flask==0.12.1 \
    Werkzeug==0.11.15 \
    Jinja2==2.8.1 \
    SQLAlchemy==1.1.5 \
    requests==2.18.0 \
    django==1.11.0 \
    pyyaml==5.1 \
    cryptography==2.1.4 \
    urllib3==1.21.1 \
    paramiko==2.0.8 \
    pillow==4.3.0 \
    python-jwt==2.0.1 \
    psycopg2-binary==2.8.3 \
    flask-sqlalchemy==2.1 \
    kubernetes==10.0.1 \
    pyjwt

# Exposing sensitive environment variables (for demonstration only)
ENV DATABASE_URL="postgresql://admin:admin123@db:5432/vulnerable_db" \
    FLASK_ENV=development \
    DEBUG=1 \
    SECRET_KEY=${SECRET_KEY}

# Expose ports
EXPOSE 5000 9090

# Run the application with root privileges (insecure, for PoC)
CMD ["python", "app.py"]
