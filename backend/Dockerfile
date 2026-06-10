# ═══════════════════════════════════════════════════════════════
# VaultZero Backend — Multi-stage Dockerfile
# Build context: REPO ROOT
#
# WHY node:20-slim (not node:20-alpine)?
#   The `argon2` npm package uses native C bindings compiled against
#   glibc (Debian). Alpine uses musl libc — no prebuilt binaries, and
#   compilation requires python3 + make + g++. node:20-slim (Debian)
#   has glibc so prebuilt argon2 binaries load without compilation.
#
# WHY copy Prisma client from builder?
#   We generate the Prisma client once in the builder stage (as root,
#   with all dev tools present). In the runner stage we COPY it instead
#   of regenerating — avoids needing the Prisma CLI in the runner and
#   eliminates the file-permission mismatch between root-generated files
#   and the non-root `node` user.
#
# WHY Node.js healthcheck (not wget)?
#   node:20-slim doesn't include wget or curl. Node.js is always present.
# ═══════════════════════════════════════════════════════════════

# ── Stage 1: Builder ──────────────────────────────────────────
FROM node:20-slim AS builder

WORKDIR /app

# Copy workspace + package manifests first (layer cache optimisation)
COPY package*.json ./
COPY core/package*.json    ./core/
COPY backend/package*.json ./backend/

# Install ALL dependencies (devDeps needed for tsc)
RUN npm ci --workspace=core --workspace=backend --include-workspace-root

# Copy source files
COPY core/src/          ./core/src/
COPY core/tsconfig.json ./core/tsconfig.json
COPY backend/src/          ./backend/src/
COPY backend/tsconfig.json ./backend/tsconfig.json
COPY backend/prisma/       ./backend/prisma/

# 1. Build @vaultzero/core → core/dist/
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

# Production dependencies only (prisma CLI is now in dependencies, not devDeps)
RUN npm ci --workspace=core --workspace=backend --include-workspace-root --omit=dev

# Copy compiled core (required at runtime via workspace symlink: @vaultzero/core → core/dist/)
COPY --from=builder /app/core/dist/ ./core/dist/

# Copy Prisma schema (needed for db push at startup)
COPY backend/prisma/ ./backend/prisma/

# Copy the already-generated Prisma client from builder — do NOT regenerate.
# Generated in builder as root with full dev tools; copying preserves the binary.
# The node user has READ access to these files.
COPY --from=builder /app/node_modules/.prisma/ ./node_modules/.prisma/

# Copy compiled backend
COPY --from=builder /app/backend/dist/ ./backend/dist/

# Non-root user for security
USER node

EXPOSE 3000

# Node.js healthcheck — no wget/curl needed
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"

CMD ["node", "backend/dist/server.js"]
