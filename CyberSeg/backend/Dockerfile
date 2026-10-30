FROM node:20-alpine
RUN apk add --no-cache openssl
WORKDIR /app
COPY package.json ./
RUN npm install
COPY . .
RUN npx prisma generate && npm run build
EXPOSE 8780
CMD ["sh", "-c", "npx prisma db push && node dist/main"]
