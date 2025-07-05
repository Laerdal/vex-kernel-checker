# Multi-stage build for VEX Kernel Checker
FROM python:3.11-slim as builder

# Set working directory
WORKDIR /app

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.11-slim

# Create non-root user
RUN groupadd -r vexchecker && useradd -r -g vexchecker vexchecker

# Set working directory
WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /root/.local /home/vexchecker/.local

# Copy application files
COPY vex-kernel-checker.py .
COPY examples/ examples/
COPY docs/ docs/
COPY README.md LICENSE ./

# Create directories for user data
RUN mkdir -p /app/data /app/cache /app/output && \
    chown -R vexchecker:vexchecker /app

# Switch to non-root user
USER vexchecker

# Add user's local bin to PATH
ENV PATH=/home/vexchecker/.local/bin:$PATH

# Create volume mount points
VOLUME ["/app/data", "/app/cache", "/app/output"]

# Set default environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 vex-kernel-checker.py --help > /dev/null || exit 1

# Default command
ENTRYPOINT ["python3", "vex-kernel-checker.py"]
CMD ["--help"]

# Labels for metadata
LABEL maintainer="Laerdal Medical <support@laerdal.com>"
LABEL version="1.0.0"
LABEL description="VEX Kernel Checker - CVE vulnerability analysis for Linux kernels"
LABEL org.opencontainers.image.title="VEX Kernel Checker"
LABEL org.opencontainers.image.description="A sophisticated tool for analyzing CVE vulnerabilities against Linux kernel configurations"
LABEL org.opencontainers.image.url="https://github.com/laerdal/vex-kernel-checker"
LABEL org.opencontainers.image.source="https://github.com/laerdal/vex-kernel-checker"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.licenses="MIT"
