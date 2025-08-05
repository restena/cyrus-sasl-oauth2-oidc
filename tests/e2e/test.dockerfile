FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    netcat-traditional \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy test files
COPY test_e2e.py .

# Run tests
CMD ["python", "test_e2e.py"]
