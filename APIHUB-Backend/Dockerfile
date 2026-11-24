FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
# Zero runtime dependencies: nothing to npm install.
COPY package.json ./
COPY src ./src
COPY migrations ./migrations
COPY backup.sh restore.sh ./
RUN addgroup -S apihub && adduser -S apihub -G apihub && mkdir -p /app/data && chown -R apihub:apihub /app
USER apihub
EXPOSE 8080
VOLUME ["/app/data"]
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD wget -qO- http://127.0.0.1:${PORT:-8080}/health || exit 1
CMD ["node", "--disable-warning=ExperimentalWarning", "src/server.js"]
