FROM node:20-slim
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY server.cjs keccak.cjs ./
COPY circuits/verification_key.json ./circuits/
COPY scripts/download-artifacts.sh ./scripts/
RUN bash scripts/download-artifacts.sh
ENV PORT=8787 DATA_DIR=/app/data
RUN mkdir -p /app/data
EXPOSE 8787
CMD ["node", "server.cjs"]
