FROM node:20-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY server.js ./

RUN mkdir -p /data
VOLUME /data
ENV DB_PATH=/data/lti.db

EXPOSE 3002
CMD ["node", "server.js"]
