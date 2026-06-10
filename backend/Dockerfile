# ═══════════════════════════════════════════════════════════════
# VaultZero Backend — Multi-stage Dockerfile
# Build context: REPO ROOT
#
# WHY node:20-slim (not node:20-alpine)?
#   The `argon2` npm package uses native C bindings. Alpine uses musl
#   libc; Debian uses glibc. Prebuilt `argon2` binaries on npm are
#   compiled for glibc (linux/amd64). On Alpine (musl), there are no
#   prebuilt binaries, so npm tries to compile from source — which
#   requires python3 + make + g++ that aren't in the base image.
#   node:20-slim (Debian) resolves this: prebuilt binaries load fine.
#
# WHY Node.js healthcheck (not wget)?
#   node:20-slim doesn't include wget or curl by default.
#   A Node.js one-liner is lighter than installing an extra package.
# ═══════════════════════════════════════════════════════════════

# ── Stage 1: Builder ──────────────────────────────────────────
FROM node:20-slim AS builder

WORKDIR /app

# Copy workspace + package manifests (layer cache: only reinstalls
# when package.json files change, not on every source change)
COPY package*.json ./
COPY core/package*.json    ./core/
COPY backend/package*.json ./backend/

# Install ALL dependencies (devDeps needed for tsc + prisma generate)
RUN npm ci --workspace=core --workspace=backend --include-workspace-root

# Copy source files
COPY core/src/          ./core/src/
COPY core/tsconfig.json ./core/tsconfig.json
COPY backend/src/          ./backend/src/
COPY backend/tsconfig.json ./backend/tsconfig.json
COPY backend/prisma/       ./backend/prisma/

# 1. Build @vaultzero/core → core/dist/
#    backend's compiled JS requires('@vaultzero/core') which resolves
#    via npm workspace symlink to core/dist/index.js at runtime
RUN npm run build --workspace=core

# 2. Generate Prisma client (required before compiling backend TS)
RUN cd backend && npx prisma generate

# 3. Compile backend TypeScript → backend/dist/
RUN npm run build --workspace=backend

# ── Stage 2: Runner ───────────────────────────────────────────
FROM node:20-slim AS runner

ENV NODE_ENV=production

WORKDIR /app

# Copy package manifests for prod install
COPY package*.json ./
COPY core/package*.json    ./core/
COPY backend/package*.json ./backend/

# Production dependencies only
# node:20-slim has glibc so argon2's prebuilt binary loads correctly
RUN npm ci --workspace=core --workspace=backend --include-workspace-root --omit=dev

# Copy compiled core (required at runtime: require('@vaultzero/core') → core/dist/)
COPY --from=builder /app/core/dist/ ./core/dist/

# Copy Prisma schema and generate client for production runtime
COPY backend/prisma/ ./backend/prisma/
RUN cd backend && npx prisma generate

# Copy compiled backend
COPY --from=builder /app/backend/dist/ ./backend/dist/

# Non-root user for security (built into node images)
USER node

EXPOSE 3000

# Node.js healthcheck — no wget/curl needed in slim image
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"

CMD ["node", "backend/dist/server.js"]
