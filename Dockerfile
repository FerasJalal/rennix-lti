# Build stage: better-sqlite3 (optional, only used by the one-time SQLite ->
# Postgres migration script) has no prebuilt Alpine binary for every Node
# version, and npm silently skips an optional dependency that fails to build --
# so compile it here, where the toolchain is available.
FROM node:20-alpine AS deps
WORKDIR /app
RUN apk add --no-cache python3 make g++
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && node -e "require('better-sqlite3')"

FROM node:20-alpine
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY package.json package-lock.json ./
COPY server.js ./
COPY src ./src
COPY scripts ./scripts

RUN mkdir -p /data
VOLUME /data
# Only read by scripts/migrate-sqlite-to-postgres.js (the data itself lives in Postgres).
ENV DB_PATH=/data/lti.db

EXPOSE 3002
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3002/health || exit 1
CMD ["node", "server.js"]
