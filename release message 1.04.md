# 🚀 Nexo Share v.1.04

**Nexo Share v.1.04** is a major update introducing a complete branding overhaul, official PWA support, and significant enhancements to the upload engine for better performance and reliability.

## ⚠️ Beta
**Please note**, that Nexo Share is still in beta! Always keep a copy of the data that you're sending to others.
**Also note**, that this is always a best practice, as a share can expire if you set an expiry date or leave the default expiry date. In that case, the share along with its data will be deleted upon that expiry date!

## 📦 How to Install (Docker)

You don't need to download source code. You can pull the pre-built Docker image directly from this repository.

### 1. Pull the Image

`docker pull ghcr.io/minemap-nl/nexoshare:v.1.04`

### 2. Quick Start (docker-compose.yml)

Create a `docker-compose.yml` file and paste the following configuration:

```yaml
services:
  nexoshare:
    image: ghcr.io/minemap-nl/nexoshare:v.1.04 # or latest depending on what you pulled
    container_name: nexoshare
    restart: unless-stopped
    ports:
      - "3000:3000"
    environment:
      - PORT=3000
      - DB_HOST=postgres
      - DB_USER=nexoshare
      - DB_PASSWORD=your_secure_db_password # generate: openssl rand -base64 32
      - DB_NAME=nexoshare
      - UPLOAD_DIR=/app/backend/uploads
      - JWT_SECRET=change_this_to_a_long_random_string # generate: openssl rand -hex 32
      - APP_URL= #like https://share.yourdomain.com
      
      - CLAMAV_HOST=clamav
      - CLAMAV_PORT=3310
      - NODE_ENV=production
      - TZ=UTC
      - APP_LOCALE=en-GB
    volumes:
      - ./uploads:/app/backend/uploads
    depends_on:
      postgres:
        condition: service_healthy
      clamav: 
        condition: service_healthy
  postgres:
    image: postgres:17-alpine
    container_name: nexoshare_db
    restart: unless-stopped
    environment:
      - POSTGRES_USER=nexoshare
      - POSTGRES_PASSWORD=your_secure_db_password
      - POSTGRES_DB=nexoshare
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U nexoshare -d nexoshare"]
      interval: 5s
      timeout: 5s
      retries: 10
    volumes:
      - ./data:/var/lib/postgresql/data
  clamav:
    image: clamav/clamav:latest
    container_name: nexoshare_clamav
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "nc", "-z", "localhost", "3310"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 120s
    volumes:
      - ./clamav:/var/lib/clamav:rw
```

## 🎯 Key Changes in this Release (v.1.04)

### 🎨 Branding Overhaul & UX
*   **New Icon Set:** Introduced a complete set of custom icons (SVG, ICO, Apple Touch, and multi-size PWA icons) for a consistent brand identity across all platforms.
*   **Official Logo Integration:** The new logo is now correctly integrated as the default branding fallback in the Login and Dashboard views.
*   **Refactored Views:** Core pages (`LoginPage`, `Dashboard`, `GuestUploadPage`, and `DownloadPage`) have been refactored for better responsiveness and visual alignment.

### 📲 Progressive Web App (PWA) Support
*   **Web Manifest:** Added `site.webmanifest` providing full PWA integration, allowing users to "install" Nexo Share on mobile and desktop with high-quality icons and a standalone experience.

### ⚡ Enhanced Upload Engine
*   **Parallel Chunking:** Massive performance boost by allowing multiple file chunks to upload in parallel.
*   **Hashing Verification:** Added client-side file hashing to ensure data integrity during transmission.
*   **Improved Finalization:** Refined the chunk-merging process on the backend to handle large files (6GB+) more reliably and efficiently.

### 🔒 Security & Performance
*   **Auth Refactor:** Improved token expiration logic and refined the authentication flow for a smoother user experience.
*   **Core Cleanup:** Removed legacy Vite placeholders and redundant assets to reduce bundle size and improve load times.
*   **Dependency Updates:** Minor security patches for backend and frontend libraries.

---

**Maintained by [Minemap-NL](https://github.com/minemap-nl)**.
