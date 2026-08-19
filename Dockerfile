FROM node:20-alpine AS base
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY cli.js server.js rules.cjs ./

FROM node:20-alpine
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
WORKDIR /app
COPY --from=base /app /app
RUN chown -R appuser:appgroup /app
USER appuser
RUN ln -s /app/cli.js /usr/local/bin/ai-firewall && \
    ln -s /app/cli.js /usr/local/bin/ai-fw
ENTRYPOINT ["node", "/app/cli.js"]
CMD ["--help"]
