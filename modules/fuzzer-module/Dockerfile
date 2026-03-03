FROM python:3.11-slim

WORKDIR /app

# install system deps for playwright
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
    libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxrandr2 \
    libgbm1 libpango-1.0-0 libcairo2 libasound2 libxshmfence1 \
    && rm -rf /var/lib/apt/lists/*

# when build context is ./modules, copy requirements from subdirectory
COPY fuzzer-module/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# install playwright chromium browser
RUN playwright install chromium

# copy module source
COPY fuzzer-module/ .

# copy shared schemas (sibling directory in build context)
COPY shared/ /app/shared/

# training data directory is mounted as volume at /app/training_data
ENV TRAINING_DATA_DIR=/app/training_data

EXPOSE 5003

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5003"]
