# ---- build stage: compile the CRA static bundle ----
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
# CRA bakes REACT_APP_* env in at build time. The CARTO basemap key is the only
# one the browser needs; everything else is same-origin/relative now.
ARG REACT_APP_CARTO_KEY=""
ENV REACT_APP_CARTO_KEY=$REACT_APP_CARTO_KEY
RUN npm run build

# ---- runtime stage: nginx serves the SPA and proxies /api, /ws, /pcap ----
FROM nginx:alpine
COPY --from=build /app/build /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
