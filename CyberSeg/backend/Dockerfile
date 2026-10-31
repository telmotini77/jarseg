FROM node:20-alpine
RUN apk add --no-cache openssl
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npx prisma generate && npm run build
ENV NODE_ENV=production
EXPOSE 8780
# exec: node becomes PID 1 and receives SIGTERM for a clean shutdown.
CMD ["sh", "-c", "npx prisma db push --skip-generate && exec node dist/main"]
