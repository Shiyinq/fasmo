#!/bin/bash

# =================================================================
# FASMO - AUTOMATED SERVER SETUP SCRIPT (Ubuntu/Debian)
# =================================================================
# This script prepares a fresh VPS for Fasmo deployment.
# It is idempotent (safe to run multiple times).

set -e

# --- CONFIGURATION ---
REPO_URL="https://github.com/Shiyinq/fasmo.git"
PROJECT_DIR="$HOME/fasmo"
SWAP_SIZE="2G"

echo "🚀 Starting Fasmo Server Setup..."

# 1. Update System
echo "🔄 Updating system packages..."
sudo apt update && sudo apt upgrade -y

# 2. Check & Install Dependencies
echo "📦 Checking basic dependencies..."
sudo apt install -y git curl ufw

# 3. Check & Install Docker
if ! [ -x "$(command -v docker)" ]; then
    echo "🐳 Docker not found. Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
    echo "✅ Docker installed successfully."
else
    echo "✅ Docker is already installed."
fi

# 4. Memory Management (Swap File)
if [ ! -f /swapfile ]; then
    echo "🧠 Creating ${SWAP_SIZE} swap file for build stability..."
    sudo fallocate -l $SWAP_SIZE /swapfile
    sudo chmod 600 /swapfile
    sudo mkswap /swapfile
    sudo swapon /swapfile
    echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
    echo "✅ Swap file created."
else
    echo "✅ Swap file already exists."
fi

# 5. Firewall Configuration (UFW)
echo "🛡️ Configuring Firewall (UFW)..."
sudo ufw allow ssh
# Allow Cloudflare IPs
echo "☁️ Allowing Cloudflare IP ranges..."
for ip in $(curl -s https://www.cloudflare.com/ips-v4); do sudo ufw allow from $ip to any port 80; done
for ip in $(curl -s https://www.cloudflare.com/ips-v4); do sudo ufw allow from $ip to any port 443; done
sudo ufw --force enable
echo "✅ Firewall configured."

# 6. Project Directory Setup
if [ ! -d "$PROJECT_DIR" ]; then
    echo "📂 Cloning repository to $PROJECT_DIR..."
    git clone $REPO_URL "$PROJECT_DIR"
else
    echo "📂 Project directory already exists at $PROJECT_DIR."
fi

cd "$PROJECT_DIR"

# 7. Directory Structure
echo "📁 Creating necessary directories..."
mkdir -p logs/backend logs/nginx certbot/conf certbot/www
sudo chown -R $USER:$USER logs/

# 8. Interactive .env Setup
ENV_FILE=".env"
SHOULD_SETUP_ENV=true

if [ -f "$ENV_FILE" ]; then
    read -p "⚠️  File .env already exists. Update it? (y/n): " confirm_env
    if [[ $confirm_env != "y" ]]; then
        SHOULD_SETUP_ENV=false
        echo "⏭️  Skipping .env setup."
    fi
fi

if [ "$SHOULD_SETUP_ENV" = true ]; then
    echo "📝 Setting up environment variables (.env)..."
    
    # Use production template as base
    cp .env.production.example .env.tmp
    
    # Prompt for critical inputs
    read -p "🌐 Enter your main domain (e.g., fasmo.app): " DOMAIN
    DOMAIN=${DOMAIN:-fasmo.app}

    read -p "🔐 Enter MongoDB Root User (default: admin): " MONGO_ROOT_USER
    MONGO_ROOT_USER=${MONGO_ROOT_USER:-admin}

    read -p "🔑 Enter MongoDB Root Password: " MONGO_ROOT_PASSWORD
    
    read -p "📧 Enter Resend API Key: " RESEND_KEY
    read -p "✉️  Enter Email From (default: noreply@$DOMAIN): " EMAIL_FROM
    EMAIL_FROM=${EMAIL_FROM:-noreply@$DOMAIN}

    # Generate random secret key
    SECRET_KEY=$(openssl rand -hex 32)

    # Replace values in .env.tmp
    sed -i "s|FRONTEND_URL=.*|FRONTEND_URL=https://$DOMAIN|g" .env.tmp
    sed -i "s|PUBLIC_CLIENT_SIDE_API_BASE_URL=.*|PUBLIC_CLIENT_SIDE_API_BASE_URL=https://api.$DOMAIN|g" .env.tmp
    sed -i "s|API_BASE_URL=.*|API_BASE_URL=https://api.$DOMAIN/api|g" .env.tmp
    sed -i "s|ORIGINS=.*|ORIGINS=https://$DOMAIN,https://api.$DOMAIN|g" .env.tmp
    sed -i "s|COOKIE_DOMAIN=.*|COOKIE_DOMAIN=$DOMAIN|g" .env.tmp
    
    sed -i "s|SECRET_KEY=.*|SECRET_KEY=$SECRET_KEY|g" .env.tmp
    
    sed -i "s|MONGO_ROOT_USER=.*|MONGO_ROOT_USER=$MONGO_ROOT_USER|g" .env.tmp
    sed -i "s|MONGO_ROOT_PASSWORD=.*|MONGO_ROOT_PASSWORD=$MONGO_ROOT_PASSWORD|g" .env.tmp
    
    sed -i "s|RESEND_API_KEY=.*|RESEND_API_KEY=$RESEND_KEY|g" .env.tmp
    sed -i "s|EMAIL_FROM=.*|EMAIL_FROM=$EMAIL_FROM|g" .env.tmp

    # Automate Redirect URIs
    sed -i "s|GITHUB_REDIRECT_URI=.*|GITHUB_REDIRECT_URI=https://api.$DOMAIN/auth/github/callback|g" .env.tmp
    sed -i "s|GOOGLE_REDIRECT_URI=.*|GOOGLE_REDIRECT_URI=https://api.$DOMAIN/auth/google/callback|g" .env.tmp
    
    # Github/Google placeholders
    echo "ℹ️  OAuth Client IDs and Secrets must still be filled manually in .env"

    mv .env.tmp .env
    echo "✅ .env file generated successfully."
fi

# 9. SSL Directory Setup
echo "🔑 Preparing SSL certificate directory structure..."
CERT_DIR="certbot/conf/live/$DOMAIN"
mkdir -p "$CERT_DIR"
touch "$CERT_DIR/fullchain.pem"
touch "$CERT_DIR/privkey.pem"
echo "✅ SSL directory and empty files created."

echo "--------------------------------------------------------"
echo "🎉 SETUP COMPLETE!"
echo "--------------------------------------------------------"
echo "Next steps:"
echo "1. Verify .env file: nano .env"
echo "2. Setup SSL (Cloudflare Origin CA):"
echo "   - Paste Origin Certificate to: certbot/conf/live/$DOMAIN/fullchain.pem"
echo "   - Paste Private Key to:        certbot/conf/live/$DOMAIN/privkey.pem"
echo "3. Run deployment:"
echo "   make docker-prod"
echo "--------------------------------------------------------"
