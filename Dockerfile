FROM python:3.10-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1 libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY domain/ domain/
COPY services/ services/
COPY usecases/ usecases/
COPY adapters/ adapters/
COPY interfaces/ interfaces/
COPY defense/ defense/
COPY model/ model/

RUN mkdir -p /srv/logs /srv/results

# [VULN-06] Container runs as root.

EXPOSE 8000
CMD ["uvicorn", "interfaces.api_main:app", "--host", "0.0.0.0", "--port", "8000"]
