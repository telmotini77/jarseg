FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
RUN apk add --no-cache openssl && mkdir -p /usr/share/nginx/downloads /etc/cyberseg/public
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY security-headers.conf /etc/nginx/security-headers.conf
COPY docker-entrypoint.d/40-cyberseg-tls.sh /docker-entrypoint.d/40-cyberseg-tls.sh
# Strip CR in case the repository was checked out on Windows.
RUN sed -i 's/\r$//' /docker-entrypoint.d/40-cyberseg-tls.sh /etc/nginx/conf.d/default.conf /etc/nginx/security-headers.conf \
  && chmod +x /docker-entrypoint.d/40-cyberseg-tls.sh
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80 443
