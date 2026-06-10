# ═══════════════════════════════════════════════════════════════
# VaultZero Backend — Multi-stage Dockerfile
# Build context: REPO ROOT (Railway sets this automatically when
# dockerfilePath = "backend/Dockerfile" is set in railway.toml)
#
# Why multi-stage?
#   Stage 1 (builder): installs devDeps, compiles core + backend TypeScript
#   Stage 2 (runner):  prod deps only, no source, no tsc, smaller image
#
# Why copy both core/ and backend/?
#   @vaultzero/core is a local workspace dep. At runtime, Node resolves
#   it to core/dist/index.js via the npm workspace symlink. So core must
#   be compiled (core/dist/) before backend can run in production.
# ═══════════════════════════════════════════════════════════════

# ── Stage 1: Builder ──────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

# Copy workspace + package manifests first (layer cache: only reinstalls
# node_modules when package.json files change, not on every source change)
COPY package*.json ./
COPY core/package*.json    ./core/
COPY backend/package*.json ./backend/

# Install ALL dependencies (devDeps needed for tsc)
# --workspace flags limit install to only the packages we need
RUN npm ci --workspace=core --workspace=backend --include-workspace-root

# Copy source files for both packages
COPY core/src/         ./core/src/
COPY core/tsconfig.json ./core/tsconfig.json
COPY backend/src/         ./backend/src/
COPY backend/tsconfig.json ./backend/tsconfig.json
COPY backend/prisma/       ./backend/prisma/

# Step 1: Build @vaultzero/core → core/dist/
# Backend's compiled JS requires('@vaultzero/core') at runtime,
# which Node resolves via the workspace symlink to core/dist/index.js
RUN npm run build --workspace=core

# Step 2: Generate Prisma client (must happen before compiling backend)
RUN cd backend && npx prisma generate

# Step 3: Compile backend TypeScript → backend/dist/
# tsconfig.json paths alias (@vaultzero/core → ../core/src/index.ts)
# is used only during type-checking. The compiled JS uses the workspace import.
RUN npm run build --workspace=backend

# ── Stage 2: Runner ───────────────────────────────────────────
FROM node:20-alpine AS runner

ENV NODE_ENV=production

WORKDIR /app

# Copy package manifests for prod install
COPY package*.json ./
COPY core/package*.json    ./core/
COPY backend/package*.json ./backend/

# Production dependencies only (no tsc, no jest, no eslint)
RUN npm ci --workspace=core --workspace=backend --include-workspace-root --omit=dev

# Copy compiled core (needed at runtime by backend's require('@vaultzero/core'))
COPY --from=builder /app/core/dist/ ./core/dist/

# Copy Prisma schema + generate client for production
COPY backend/prisma/ ./backend/prisma/
RUN cd backend && npx prisma generate

# Copy compiled backend
COPY --from=builder /app/backend/dist/ ./backend/dist/

# Non-root user (built into node:alpine)
USER node

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3000/health || exit 1

CMD ["node", "backend/dist/server.js"]
