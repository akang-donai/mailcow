# deploy/Dockerfile
#
# Pin by digest at deploy time: replace the tag below with
# node:24-alpine@sha256:<digest> (`docker pull node:24-alpine` then
# `docker inspect --format='{{index .RepoDigests 0}}' node:24-alpine`).
# See deploy/README.md for why this matters here specifically: it also
# fixes the experimental `node:sqlite` API to one known runtime.
FROM node:24-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY src ./src
USER node
ENV NODE_ENV=production
EXPOSE 8787
CMD ["node", "src/remote/main.ts"]
