FROM oven/bun:1.3-alpine AS base
WORKDIR /app

COPY package.json bun.lock* ./
RUN bun install --frozen-lockfile || bun install

COPY . .
RUN bun run build

EXPOSE 3400
ENV PORT=3400
ENV NODE_ENV=production

CMD ["bun", "run", "start"]
