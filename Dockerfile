# Single-service deploy: build the React UI, then serve it + the API from FastAPI.

# ---- stage 1: build the web UI ----
FROM node:20-slim AS ui
WORKDIR /ui
COPY desktop/package.json ./
RUN npm install
COPY desktop/ ./
# Hosted build: same-origin API, and hide the local-only Live Agent tab.
ENV VITE_API_BASE=""
ENV VITE_HOSTED="1"
RUN npm run build

# ---- stage 2: python runtime serving API + UI ----
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
COPY --from=ui /ui/dist ./desktop/dist
ENV PORT=8008
EXPOSE 8008
CMD ["sh", "-c", "uvicorn server.app:app --host 0.0.0.0 --port ${PORT}"]
