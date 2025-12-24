<a id="readme-top"></a>

[][contributors-url]
[][forks-url]
[][stars-url]
[][issues-url]
[][license-url]

<br />
<div align="center">
<a href="[https://nexoshare.famretera.nl](https://nexoshare.famretera.nl)">
<svg xmlns="[http://www.w3.org/2000/svg](http://www.w3.org/2000/svg)" width="80" height="80" viewBox="0 0 24 24" fill="none" stroke="#7c3aed" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
</a>

<h3 align="center">Nexo Share</h3>

<p align="center">
A powerful, self-hosted, and secure file-sharing platform. Share large files securely with password protection, expiration dates, and 2FA support.
<br />
<br />
<a href="[https://nexoshare.famretera.nl](https://nexoshare.famretera.nl)"><strong>View Demo & More Info »</strong></a>
<br />
<br />
<a href="[https://github.com/minemap-nl/nexoshare/issues/new?labels=bug&template=bug-report---.md](https://www.google.com/search?q=https://github.com/minemap-nl/nexoshare/issues/new%3Flabels%3Dbug%26template%3Dbug-report---.md)">Report Bug</a>
&middot;
<a href="[https://github.com/minemap-nl/nexoshare/issues/new?labels=enhancement&template=feature-request---.md](https://www.google.com/search?q=https://github.com/minemap-nl/nexoshare/issues/new%3Flabels%3Denhancement%26template%3Dfeature-request---.md)">Request Feature</a>
</p>
</div>

<details>
<summary>Table of Contents</summary>
<ol>
<li>
<a href="#about-the-project">About The Project</a>
<ul>
<li><a href="#built-with">Built With</a></li>
</ul>
</li>
<li><a href="#key-features">Key Features</a></li>
<li>
<a href="#getting-started">Getting Started</a>
<ul>
<li><a href="#prerequisites">Prerequisites</a></li>
<li><a href="#installation">Installation (Docker)</a></li>
</ul>
</li>
<li><a href="#usage">Usage</a></li>
<li><a href="#license">License</a></li>
<li><a href="#contact">Contact</a></li>
</ol>
</details>

## About The Project

Nexo Share is designed to be a secure alternative to public file transfer services. It allows you to host your own sharing platform where you are in full control of your data.

Unlike standard open-source solutions, Nexo Share focuses heavily on security features like Mandatory 2FA, Passkey support, and ClamAV virus scanning integration, while offering user-friendly features like "Reverse Shares" to let clients send files to you without needing an account.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Built With

* [][React-url]
* [][TypeScript-url]
* [][Node-url]
* [][Express-url]
* [][PostgreSQL-url]
* [][Docker-url]

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Key Features

* **🔒 Secure Sharing:** Share files with password protection and auto-expiration logic.
* **📂 Chunked Uploads:** Supports huge files (limited only by server storage) via robust chunked uploading.
* **arrows_counter_clockwise Reverse Shares:** Create public drop-off links where guests can upload files to you via a secure link.
* **🛡️ Advanced Security:**
* Two-Factor Authentication (TOTP).
* Passkey support (FaceID / TouchID / Windows Hello).
* ClamAV Virus Scanning integration.


* **🔑 SSO Support:** OpenID Connect (OIDC) integration for Single Sign-On.
* **⚙️ Admin Dashboard:** Manage users, global settings, SMTP configuration, and view audit logs.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Getting Started

The recommended way to install Nexo Share is via **Docker**.

### Prerequisites

* **Docker** & **Docker Compose** installed on your server.

### Installation

1. Create a directory for your project and navigate into it.
2. Create a file named `docker-compose.yml`.
3. Paste the following configuration into the file:

```yaml
services:
  secureshare:
    image: ghcr.io/minemap-nl/nexoshare:latest
    container_name: secureshare
    restart: unless-stopped
    ports:
      - "3000:3000"
    environment:
      - PORT=3000
      - DB_HOST=postgres
      - DB_PORT=5432
      - DB_NAME=secureshare
      - DB_USER=secureshare
      - DB_PASSWORD=CHANGE_THIS_PASSWORD  # Must match POSTGRES_PASSWORD below
      - JWT_SECRET=CHANGE_THIS_SECRET     # Generate a long random string
      - UPLOAD_DIR=/app/backend/uploads
      - ALLOWED_ORIGINS=http://localhost:3000 # Or your domain (e.g., https://share.yourdomain.com)
      - NODE_ENV=production
      - TZ=UTC
      - APP_LOCALE=en-GB
      - CLAMAV_HOST=clamav
      - CLAMAV_PORT=3310
      # - RP_ID=yourdomain.com # Required for Passkeys! Use only the domain (no http/https/port).
    volumes:
      - ./uploads:/app/backend/uploads
    depends_on:
      postgres:
        condition: service_healthy
      clamav:
        condition: service_healthy

  postgres:
    image: postgres:17-alpine
    container_name: secureshare_db
    restart: unless-stopped
    environment:
      - POSTGRES_USER=secureshare
      - POSTGRES_PASSWORD=CHANGE_THIS_PASSWORD
      - POSTGRES_DB=secureshare
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U secureshare -d secureshare"]
      interval: 10s
      timeout: 5s
      retries: 5
    volumes:
      - ./data:/var/lib/postgresql/data

  clamav:
    image: clamav/clamav:latest
    container_name: secureshare_clamav
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "nc", "-z", "localhost", "3310"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 120s
    volumes:
      - ./clamav:/var/lib/clamav

```

4. Start the container stack:
```sh
docker compose up -d

```



<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Usage

After the containers are running, navigate to `http://localhost:3000` (or your configured domain).

**First Time Setup:**
On the first run, the database tables are created automatically. A default admin user is created if no users exist:

* **Email:** `admin@nexoshare.com`
* **Password:** `admin123`

> ⚠️ **IMPORTANT:** Log in immediately and change these credentials in your profile settings!

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## License

**Source Available / Commons Clause**

This project is licensed under the **MIT License** with the **Commons Clause** condition.

* ✅ **You may:** Use, copy, modify, and distribute this software for personal or internal business use.
* ✅ **You may:** Use this software to send files to partners or clients as part of your normal business operations.
* ❌ **You may NOT:** Sell this software or provide it as a commercial service (SaaS) where the value of the service is derived primarily from the software itself.

See `LICENSE` file for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Contact

Minemap / Famretera - [https://nexoshare.famretera.nl](https://nexoshare.famretera.nl)

Project Link: [https://github.com/minemap-nl/nexoshare](https://www.google.com/search?q=https://github.com/minemap-nl/nexoshare)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

[]: #
[contributors-url]: https://www.google.com/search?q=%5Bhttps://github.com/minemap-nl/nexoshare/graphs/contributors%5D
[]: #
[forks-url]: https://www.google.com/search?q=%5Bhttps://github.com/minemap-nl/nexoshare/network/members%5D
[]: #
[stars-url]: https://www.google.com/search?q=%5Bhttps://github.com/minemap-nl/nexoshare/stargazers%5D
[]: #
[issues-url]: https://www.google.com/search?q=%5Bhttps://github.com/minemap-nl/nexoshare/issues%5D
[]: #
[license-url]: https://www.google.com/search?q=%5Bhttps://github.com/minemap-nl/nexoshare/blob/main/LICENSE%5D
[]: #
[react-url]: https://www.google.com/search?q=%5Bhttps://reactjs.org/%5D
[]: #
[typescript-url]: https://www.google.com/search?q=%5Bhttps://www.typescriptlang.org/%5D
[]: #
[node-url]: https://www.google.com/search?q=%5Bhttps://nodejs.org/%5D
[]: #
[express-url]: https://www.google.com/search?q=%5Bhttps://expressjs.com/%5D
[]: #
[postgresql-url]: https://www.google.com/search?q=%5Bhttps://www.postgresql.org/%5D
[]: #
[docker-url]: https://www.google.com/search?q=%5Bhttps://www.docker.com/%5D
