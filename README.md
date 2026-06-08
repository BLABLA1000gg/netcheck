# netcheck

Network diagnostics tool — check DNS records, SSL certificates, HTTP status, open ports, and IP geolocation from the browser.

**Live:** [netcheck on Railway](https://netcheck.up.railway.app) 

![netcheck screenshot](docs/screenshot.png)

## Features

| Tool | Description |
|---|---|
| **DNS Lookup** | A, AAAA, MX, NS, TXT, CNAME records |
| **SSL Check** | Certificate validity, issuer, expiry, days remaining |
| **HTTP Check** | Status code, response time, redirect chain, server header |
| **Port Scan** | 13 common ports (SSH, HTTP, HTTPS, MySQL, Redis, ...) |
| **IP Info** | Geolocation, ASN, timezone, coordinates |

## Stack

- **Backend:** Python, FastAPI, dnspython, httpx
- **Frontend:** Vanilla JS, Tailwind CSS (CDN)
- **Deployment:** Railway (Docker)

## Run locally

```bash
pip install -r requirements.txt
uvicorn main:app --reload
# → http://localhost:8000
```

## Deploy to Railway

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/new/template)

1. Connect this repo on [railway.app](https://railway.app)
2. Railway auto-detects the `Dockerfile` and deploys
3. Done — get your public URL

## API

All endpoints return JSON and are publicly accessible.

```
GET /api/dns/{domain}       DNS records
GET /api/ssl/{host}         SSL certificate info
GET /api/http?url={url}     HTTP check
GET /api/ports/{host}       Port scan (common ports)
GET /api/ip/{ip}            IP geolocation
```
