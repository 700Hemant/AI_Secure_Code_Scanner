FROM python:3.12-slim

WORKDIR /app

# Node.js install
RUN apt-get update \
    && apt-get install -y curl \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Backend dependencies
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# Frontend
COPY frontend/package*.json /app/frontend/
WORKDIR /app/frontend
RUN npm install

COPY frontend /app/frontend
RUN npm run build

# Backend
COPY backend /app/backend

WORKDIR /app/backend

# Copy React production build into backend
RUN rm -rf /app/backend/static \
    && mkdir -p /app/backend/static \
    && cp -r /app/frontend/dist/* /app/backend/static/

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]