# Production image for the Next.js web client.
#
# Uses the standalone output (next.config.js sets output: 'standalone') to
# produce a minimal server bundle containing only the node_modules the server
# actually needs. The /api/* proxy target is read from API_ORIGIN at runtime
# (next.config.js) and must point at the API service — http://api:3001 in the
# compose network, or the public API URL on single-container platforms.
#
# Build context must be apps/web (see docker-compose.prod.yml).

FROM node:20-bookworm-slim AS build
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
# The rewrite target is runtime config; a placeholder keeps next build happy.
ENV API_ORIGIN=http://api:3001
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

# ---- runtime ---------------------------------------------------------------
FROM node:20-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0

# Non-root runtime user.
RUN useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin nextjs
COPY --from=build --chown=nextjs:nextjs /app/.next/standalone ./
COPY --from=build --chown=nextjs:nextjs /app/.next/static ./.next/static
COPY --from=build --chown=nextjs:nextjs /app/public ./public

USER nextjs
EXPOSE 3000

# Liveness: the Next.js server responds (DB readiness is the API's /ready).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/?_health=1').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
