# Fasmo Deployment Guide

This guide explains how to deploy the **Fasmo** project on a single Linux VPS with full security and automation.

---

## 1. DNS & Cloudflare Setup

Before setting up the server, configure your domain in Cloudflare:

1.  **Add Site**: Add your domain (e.g., `fasmo.com`) to Cloudflare.
2.  **DNS Records**: Add **A Records** pointing to your VPS IP for these 2 hostnames:
    - `fasmo.com` (Main App/Frontend)
    - `api.fasmo.com` (Backend API)
3.  **Proxy Status**: Ensure the cloud icon is **Orange** (Proxied) for all records.
4.  **SSL/TLS**: Set mode to **Full (Strict)**.

---

## 2. Server Preparation

Connect to your VPS via SSH and run the following commands:

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install UFW (Firewall)
sudo apt install ufw -y

# ALLOW SSH (Crucial!)
sudo ufw allow ssh

# ALLOW Traffic ONLY from Cloudflare
# List found at: https://www.cloudflare.com/ips/
for ip in $(curl -s https://www.cloudflare.com/ips-v4); do sudo ufw allow from $ip to any port 80; done
for ip in $(curl -s https://www.cloudflare.com/ips-v4); do sudo ufw allow from $ip to any port 443; done

# Enable Firewall
sudo ufw enable
```

### 2.1 Memory Management (Recommended)
If your VPS has less than 4GB RAM, the frontend build process might crash. It is highly recommended to create a **Swap File**:

```bash
# Create a 2GB swap file
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# Make it permanent
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

---

## 3. Application Setup

1.  **Clone Repo**: `git clone <repo-url> && cd fasmo`
2.  **Create Folders & Permissions**:
    ```bash
    mkdir -p logs/backend logs/nginx certbot/conf certbot/www
    sudo chown -R $USER:$USER logs/
    ```
3.  **Setup Environment**:
    ```bash
    cp .env.production.example .env
    nano .env
    ```
    *Fill in all the secrets, passwords, and your actual domain name.*
4.  **Using Makefile**:
    This project includes a `Makefile` to simplify common commands.
    ```bash
    # Build and launch production containers
    make docker-prod
    ```
    Or manually:
    ```bash
    docker compose -f docker-compose.prod.yml up -d
    ```

---

## 4. SSL Certificates (Cloudflare Origin CA)

We are using Cloudflare Proxy, so we use **Cloudflare Origin Certificates** for 15 years of valid SSL.

1.  **Generate Certificate**:
    - Go to Cloudflare Dashboard -> **SSL/TLS** -> **Origin Server**.
    - Click **Create Certificate**.
    - Keep defaults (RSA 2048, 15 years) and click **Create**.
2.  **Save to VPS**:
    - Copy the **Origin Certificate** and save it to: `certbot/conf/live/fasmo.com/fullchain.pem`
    - Copy the **Private Key** and save it to: `certbot/conf/live/fasmo.com/privkey.pem`
3.  **Active SSL Mode**:
    - In Cloudflare, set SSL/TLS mode to **Full (Strict)**.
4.  **Reload Nginx**:
    ```bash
    docker exec fasmo-nginx nginx -s reload
    ```

---

## 5. Secure Database Access (MongoDB Compass)

To view your data safely from your local machine:

1.  Open **MongoDB Compass**.
2.  Set Connection String: `mongodb://admin:password@localhost:27017`
3.  Go to **More Options** -> **SSH Tunnel**.
4.  SSH Host: `Your Server IP`
5.  SSH Username: `Your VPS Username`
6.  SSH Key: `Path to your .pem or .id_rsa file`

---

## 6. Maintenance

1.  **Logs**: Check logs in `./logs/` if anything goes wrong.
2.  **Update App**:
    ```bash
    git pull
    make docker-prod
    ```
    Or manually:
    ```bash
    docker compose -f docker-compose.prod.yml up -d --build
    ```
3.  **Cleanup**: Use the Makefile to clean up dev artifacts.
    ```bash
    make clean
    ```

---

## 7. Troubleshooting

### 7.1 Nginx 502 Bad Gateway
If Nginx logs show `upstream sent too big header`:
- **Cause**: SvelteKit is sending large headers/cookies.
- **Fix**: Increase `proxy_buffer_size` in `nginx/default.conf` to `512k`.

### 7.2 Backend Unhealthy
- **Log Check**: `docker logs fasmo-backend`
- **MongoDB**: Ensure `fasmo-mongodb` is running and credentials in `.env` match.
- **Index Creator**: Ensure `fasmo-index-creator` has finished successfully (*Exited with code 0*).

---

## 8. CI/CD (Auto-Deployment)

Every time you `git push origin main`, your server will update automatically if you set up GitHub Actions.

1.  Generate an SSH Key on the server.
2.  Add the Public Key to `~/.ssh/authorized_keys`.
3.  Add the Private Key to **GitHub Secrets** as `SSH_PRIVATE_KEY`.
4.  Add other required secrets: `REMOTE_HOST`, `REMOTE_USER`, and `REMOTE_TARGET`.
