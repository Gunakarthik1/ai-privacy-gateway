FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY gateway/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY gateway/ ./gateway/

# Create data directory for SQLite
RUN mkdir -p /app/data

# Expose port
EXPOSE 8000

# Run the gateway
CMD ["uvicorn", "gateway.main:app", "--host", "0.0.0.0", "--port", "8000"]
