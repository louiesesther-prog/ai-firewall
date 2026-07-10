FROM node:20-alpine AS base
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY cli.js ./
RUN chmod +x cli.js

FROM node:20-alpine
WORKDIR /app
COPY --from=base /app /app
RUN ln -s /app/cli.js /usr/local/bin/ai-firewall && \
    ln -s /app/cli.js /usr/local/bin/ai-fw
ENTRYPOINT ["node", "/app/cli.js"]
CMD ["--help"]
