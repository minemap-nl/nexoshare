# 🚀 Nexo Share v.1.03.7

**Nexo Share v.1.03.7** is a maintenance release focused on addressing known security vulnerabilities in third-party dependencies.

## ⚠️ Beta
**Please note**, that Nexo Share is still in beta! Always keep a copy of the data that you're sending to others.
**Also note**, that this is always a best practice, as a share can expire if you set an expiry date or leave the default expiry date. In that case, the share along with its data will be deleted upon that expiry date!

## 📦 How to Install (Docker)

You don't need to download source code. You can pull the pre-built Docker image directly from this repository.

### 1. Pull the Image

`docker pull ghcr.io/minemap-nl/nexoshare:v.1.03.7`

### 2. Quick Start (docker-compose.yml)

Create a `docker-compose.yml` file and paste the following configuration:

```yaml
services:
  nexoshare:
    image: ghcr.io/minemap-nl/nexoshare:v.1.03.7 # or latest depending on what you pulled
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

## 🎯 Key Changes in this Release (v.1.03.7)

### 🔒 Security: Dependency Updates
Multiple dependencies have been updated to address known security vulnerabilities identified by Snyk.

*   **axios** updated from `1.13.2` → `1.13.5` — Fixes potential request handling vulnerabilities.
*   **multer** updated from `2.0.2` → `2.1.1` — Addresses file upload security improvements.
*   **qs** updated from `6.14.1` → `6.14.2` — Fixes prototype pollution vulnerability.
*   **minimatch** override added at `^10.2.3` — Mitigates ReDoS (Regular Expression Denial of Service) vulnerability.
*   **lodash** override added at `^4.17.23` — Addresses known prototype pollution vulnerabilities.
*   **fast-xml-parser** override added at `^5.3.8` — Fixes XML parsing security issues.
*   **@isaacs/brace-expansion** override added at `^5.0.1` — Mitigates ReDoS vulnerability.

### 🛠️ Minor Improvements
*   **Improved error logging:** Enhanced error log formatting for file finalization to prevent potential log injection.
*   **Frontend dependencies:** Minor dependency updates for frontend packages.

---

**Important Note:** This release addresses multiple known vulnerabilities in third-party dependencies. We recommend upgrading to v.1.03.7 to keep your instance secure.

**Maintained by [Minemap-NL](https://github.com/minemap-nl)**.