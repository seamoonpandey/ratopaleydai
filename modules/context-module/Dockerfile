FROM python:3.11-slim

WORKDIR /app

# when build context is ./modules, copy requirements from subdirectory
COPY context-module/requirements.txt .
# retry up to 3 times to handle transient PyPI CDN hash mismatches
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt || \
    (sleep 15 && pip install --no-cache-dir -r requirements.txt) || \
    (sleep 15 && pip install --no-cache-dir -r requirements.txt)

# copy module source
COPY context-module/ .

# copy shared schemas (sibling directory in build context)
COPY shared/ /app/shared/

EXPOSE 5001

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5001"]
