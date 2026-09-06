# deploy/Dockerfile
#
# Built with the repo root as context (see deploy/docker-compose.yml), which
# is why the COPY paths below are repo-relative and not deploy-relative.
# Nothing here copies the AES key or the database, and the repo-root
# .dockerignore keeps them out of the build context entirely so a future
# `COPY . .` cannot bake them into a layer either.
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

# The stock `node` user in this image is uid 1000, gid 1000. The two bind
# mounts declared in docker-compose.yml (the key file and the data
# directory) must be owned by 1000:1000 ON THE HOST -- a bind mount carries
# host ownership straight through and Docker does not adjust it. If they are
# left owned by root with the modes the runbook sets (0400 key, 0700 data),
# this process cannot read the key or write SQLite's WAL files and the
# container restart-loops. See deploy/README.md step 1.
USER node
ENV NODE_ENV=production
EXPOSE 8787
CMD ["node", "src/remote/main.ts"]
