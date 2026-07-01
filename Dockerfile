FROM python:3.11-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.11-slim

# Security: non-root user
RUN groupadd -r honeypot && useradd -r -g honeypot -d /app -s /sbin/nologin honeypot

WORKDIR /app

# Copy installed python packages
COPY --from=builder /install /usr/local

# Copy application code
COPY . .

# Create required directories with correct ownership
RUN mkdir -p logs datasets config reports logs/sessions \
    && chown -R honeypot:honeypot /app

# Only expose required ports
# 5760 = Honeypot MAVLink TCP
# 5000 = Defender Dashboard HTTP
# 9090 = Attacker Dashboard HTTP
EXPOSE 5760 5000 9090

# Switch to non-root user
USER honeypot

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/api/health')" || exit 1

# Default: run the honeypot orchestrator
CMD ["python3", "honeypot/mavlink_honeypot.py"]
