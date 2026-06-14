# VULN: Outdated Node base image
FROM node:26-alpine AS builder

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install

COPY . .
RUN npm run build

# VULN: Using nginx:latest mutable tag, running as root
FROM nginx:latest

# VULN: Secrets in build args / env
ENV API_URL=http://backend:5000
ENV INTERNAL_API_KEY=sk_live_cloudcart_nginx_secret_key

COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

# VULN: No HEALTHCHECK
EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
