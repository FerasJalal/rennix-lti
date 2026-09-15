FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY server.js ./
COPY src ./src

RUN mkdir -p /data
VOLUME /data
ENV DB_PATH=/data/lti.db

EXPOSE 3002
CMD ["node", "server.js"]
