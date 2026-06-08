# ─── Build Stage ───────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev

# ─── Production Stage ──────────────────────────────────────────────
FROM node:20-alpine

WORKDIR /app

# Copia dependências do builder
COPY --from=builder /app/node_modules ./node_modules

# Copia código fonte
COPY package*.json ./
COPY server.js ./
COPY public/ ./public/

# Cria diretório de dados (volume será montado aqui)
RUN mkdir -p /app/data

# Usuário não-root por segurança
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
RUN chown -R appuser:appgroup /app
USER appuser

# Porta padrão
EXPOSE 3131

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:${PORT:-3131}/api/auth/check || exit 1

CMD ["node", "server.js"]
