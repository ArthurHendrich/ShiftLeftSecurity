# Using an older Python version to improve compatibility with legacy dependencies
FROM python:3.7-slim

# Exposing sensitive information in build args (for demonstration only, not recommended)
ARG DB_PASSWORD=admin123
ARG SECRET_KEY=super_secret_key_123
ARG AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
ARG AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

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
    openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config \
    && echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config \
    && echo 'root:password123' | chpasswd

# Set working directory with wide permissions
WORKDIR /app
RUN chmod 777 /app

# Copy the application files
COPY . .

# Update pip to the latest version for better handling of legacy wheels
RUN pip install --no-cache-dir --upgrade pip

# Install Python dependencies with known vulnerabilities
RUN pip install --no-cache-dir \
    Flask==0.12.1 \
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
    pyjwt==1.5.0 \
    tensorflow==1.14.0 \
    numpy==1.16.0 \
    pandas==0.24.0 \
    scrapy==1.5.0 \
    twisted==17.9.0 \
    django-debug-toolbar==1.11.1 \
    python-ldap==3.1.0 \
    xmltodict==0.11.0

# Exposing sensitive environment variables (for demonstration only)
ENV DATABASE_URL="postgresql://admin:admin123@db:5432/vulnerable_db" \
    FLASK_ENV=development \
    DEBUG=1 \
    SECRET_KEY=${SECRET_KEY} \
    AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY} \
    AWS_SECRET_ACCESS_KEY=${AWS_SECRET_KEY} \
    ADMIN_PASSWORD="admin123" \
    SMTP_PASSWORD="smtp_password123" \
    REDIS_PASSWORD="redis123" \
    SSH_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA1234567890\n-----END RSA PRIVATE KEY-----"

# Enable all debug endpoints and disable security features
ENV FLASK_DEBUG=1 \
    PYTHONWARNINGS="ignore" \
    PYTHONHTTPSVERIFY=0 \
    REQUESTS_CA_BUNDLE="" \
    NODE_TLS_REJECT_UNAUTHORIZED=0

# Expose ports
EXPOSE 5000 9090 22 3306 6379

# Run multiple services (anti-pattern)
CMD service ssh start && python app.py
