FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 10001 certwatch \
 && useradd -u 10001 -g certwatch -M -d /app -s /usr/sbin/nologin certwatch

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY certwatch ./certwatch

USER 10001:10001
CMD ["python", "-m", "certwatch.worker"]
