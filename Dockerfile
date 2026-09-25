FROM python:3.10-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1 libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv

# ---------------------------------------------------------------
# Step 1: Install CPU-only PyTorch.
# Using --extra-index-url (not --index-url) so pip can still find
# small dependencies like typing-extensions and flit_core on PyPI.
# The +cpu suffix forces the CPU-only build of torch itself.
# ---------------------------------------------------------------
RUN pip install --no-cache-dir --timeout 1200 \
    torch==2.1.2+cpu torchvision==0.16.2+cpu \
    --extra-index-url https://download.pytorch.org/whl/cpu

# ---------------------------------------------------------------
# Step 2: Install remaining dependencies.
# ---------------------------------------------------------------
COPY requirements.txt .
RUN pip install --no-cache-dir --timeout 1200 -r requirements.txt

# COPY domain/ domain/
# COPY services/ services/
# COPY usecases/ usecases/
# COPY adapters/ adapters/
# COPY interfaces/ interfaces/
# COPY defense/ defense/
# COPY model/ model/

# RUN mkdir -p /srv/logs /srv/results

# # [VULN-06] Container runs as root.
# # ATLAS: AML.T0000

# EXPOSE 8000
# CMD ["uvicorn", "interfaces.api_main:app", "--host", "0.0.0.0", "--port", "8000"]

COPY domain/ domain/
COPY services/ services/
COPY usecases/ usecases/
COPY adapters/ adapters/
COPY interfaces/ interfaces/
COPY defense/ defense/
COPY model/ model/

# [VULN-06] FIXED: run as non-privileged user
RUN useradd -m -u 1000 appuser \
    && mkdir -p /srv/logs /srv/results \
    && chown -R appuser:appuser /srv

USER appuser

EXPOSE 8000
CMD ["uvicorn", "interfaces.api_main:app", "--host", "0.0.0.0", "--port", "8000"]