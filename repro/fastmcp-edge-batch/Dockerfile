# Benign, bounded Docker repro for the unbounded JSON-RPC batch dispatch in
# punkpeye/fastmcp's edge transport (src/edge/index.ts #handleMcpRequest).
#
#   docker build -t fastmcp-edge-batch repro/fastmcp-edge-batch
#   docker run --rm --memory=512m fastmcp-edge-batch
#
# The build clones fastmcp at the audited commit, installs and builds it, then
# runs probe.mjs against a REAL in-process EdgeFastMCP server. Pin/raise MAX_N
# with `-e MAX_N=...`. Nothing leaves the container; no network at run time.
FROM node:22-slim

# audited at this commit — see docs/variant-hunt-ssrf-unbounded.md
ARG FASTMCP_REF=febd9b4
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN git clone https://github.com/punkpeye/fastmcp.git \
    && cd fastmcp && git checkout ${FASTMCP_REF}
WORKDIR /app/fastmcp
RUN npm install --no-audit --no-fund && npm run build

# the probe imports `fastmcp` (edge export) from the built package
RUN npm link && cd /app && npm link fastmcp
WORKDIR /app
COPY probe.mjs /app/probe.mjs
ENV MAX_N=50000
CMD ["node", "probe.mjs"]
