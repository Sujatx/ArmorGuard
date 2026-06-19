FROM python:3.11-slim

# Install system dependencies including Nmap, Nuclei, Sqlmap, and Httpx
RUN apt-get update && apt-get install -y \
    nmap \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install tool binaries if needed, e.g. Nuclei, Sqlmap, Httpx (stubs/mocking can cover these, but having dependencies is nice)
# For scaffolding, we just keep the base system tools installed.

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
