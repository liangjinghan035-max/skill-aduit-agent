FROM python:3.11-slim

# Install git (required for cloning repos at runtime)
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Enable unbuffered logging
ENV PYTHONUNBUFFERED=1

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create runtime directories
RUN mkdir -p audit_results cloned_repos

# Expose port
EXPOSE 10000

# Run with gunicorn (production WSGI server)
# --worker-class=gthread enables SSE streaming support
# --timeout 300 allows long-running audit requests
CMD ["gunicorn", "web_server:app", \
     "--bind", "0.0.0.0:10000", \
     "--workers", "2", \
     "--threads", "4", \
     "--worker-class", "gthread", \
     "--timeout", "300"]
