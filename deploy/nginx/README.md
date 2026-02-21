# Nginx Reverse Proxy (HTTPS)

This directory contains an Nginx reverse proxy config for `pwa_client` with:

- HTTPS termination (`443`)
- HTTP to HTTPS redirect (`80 -> 443`)
- WebSocket proxy for `/ws`

## Files

- `nginx.conf`: base Nginx config
- `conf.d/incomudon-pwa.conf`: reverse proxy config
- `certs/`: place `fullchain.pem` and `privkey.pem` here

## Required certificate files

Place these files before starting Nginx:

- `deploy/nginx/certs/fullchain.pem`
- `deploy/nginx/certs/privkey.pem`

## Notes

- Current config assumes `pwa_client` serves at root path (`-base-path /`).
- If you use a non-root base path, adjust `location` and startup flags accordingly.
