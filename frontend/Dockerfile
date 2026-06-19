# VULN: Outdated Node base image
FROM node:14-alpine AS builder

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install

COPY . .
RUN npm run build

# VULN: Mutable tag
FROM nginx:latest

# Default for Docker Compose
ENV BACKEND_HOST=backend

COPY --from=builder /app/dist /usr/share/nginx/html

COPY nginx.conf.template \
/etc/nginx/templates/default.conf.template

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]