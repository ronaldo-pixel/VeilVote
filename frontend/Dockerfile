# ---------- Stage 1: Build ----------
FROM node:22-bookworm AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
 && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm ci
# Copy the rest of the source (public/circuits/*.wasm, *.zkey are already present)
COPY . .

# Vite bakes VITE_* variables into the bundle at BUILD time, not at
# container start time. Pass them in as --build-arg so they end up in
# the compiled JS. Provide sensible fallbacks so the build doesn't fail
# if an arg is omitted (override them for real deployments!).
ARG VITE_CONTRACT_ID
ARG VITE_SOROBAN_RPC_URL=https://soroban-testnet.stellar.org
ARG VITE_NETWORK_PASSPHRASE="Test SDF Network ; September 2015"
ARG VITE_KEYHOLDERS

ENV VITE_CONTRACT_ID=$VITE_CONTRACT_ID \
    VITE_SOROBAN_RPC_URL=$VITE_SOROBAN_RPC_URL \
    VITE_NETWORK_PASSPHRASE=$VITE_NETWORK_PASSPHRASE \
    VITE_KEYHOLDERS=$VITE_KEYHOLDERS

RUN npm run build

# ---------- Stage 2: Serve ----------
FROM nginx:1.27-alpine AS runtime

# SPA-aware nginx config (client-side routing + correct wasm mime type)
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Static build output, including public/circuits/{vote.wasm,circuit_final.zkey}
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD wget -qO- http://127.0.0.1/ || exit 1

CMD ["nginx", "-g", "daemon off;"]