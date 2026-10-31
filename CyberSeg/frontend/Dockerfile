FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
RUN apk add --no-cache openssl && touch /etc/nginx/cyberseg-auth.conf
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY docker-entrypoint.d/40-cyberseg-auth.sh /docker-entrypoint.d/40-cyberseg-auth.sh
# Strip CR in case the repository was checked out on Windows.
RUN sed -i 's/\r$//' /docker-entrypoint.d/40-cyberseg-auth.sh /etc/nginx/conf.d/default.conf \
  && chmod +x /docker-entrypoint.d/40-cyberseg-auth.sh
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
