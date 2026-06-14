#!/usr/bin/env bash

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
cat << "EOF"
            ('-.      .-')   _   .-')                
           ( OO ).-. ( OO ).( '.( OO )_              
   ,------./ . --. /(_)---\_),--.   ,--.).-'),-----. 
('-| _.---'| \-.  \ /    _ | |   `.'   |( OO'  .-.  '
(OO|(_\  .-'-'  |  |\  :` `. |         |/   |  | |  |
/  |  '--.\| |_.'  | '..`''.)|  |'.'|  |\_) |  |\|  |
\_)|  .--' |  .-.  |.-._)   \|  |   |  |  \ |  | |  |
  \|  |_)  |  | |  |\       /|  |   |  |   `'  '-'  '
   `--'    `--' `--' `-----' `--'   `--'     `-----' 
EOF
echo -e "${NC}"
echo -e "${GREEN}Welcome to the FASMO setup script!${NC}\n"

# Read from /dev/tty so it works when piped from curl
echo -n "Enter project name (leave blank to install in current directory): "
read PROJECT_NAME < /dev/tty || true

if [ -z "$PROJECT_NAME" ] || [ "$PROJECT_NAME" = "." ]; then
    # Install in current directory
    if [ "$(ls -A)" ]; then
        echo -e "${RED}Error: Current directory is not empty. Please run this in an empty directory or provide a project name.${NC}"
        exit 1
    fi
    echo -e "\n${GREEN}➤ Cloning FASMO repository into current directory...${NC}"
    git clone -q https://github.com/Shiyinq/fasmo.git .
else
    # Install in new directory
    if [ -d "$PROJECT_NAME" ]; then
        echo -e "${RED}Error: Directory '$PROJECT_NAME' already exists. Aborting.${NC}"
        exit 1
    fi
    echo -e "\n${GREEN}➤ Cloning FASMO repository into '$PROJECT_NAME'...${NC}"
    git clone -q https://github.com/Shiyinq/fasmo.git "$PROJECT_NAME"
    cd "$PROJECT_NAME"
fi

echo -e "${GREEN}➤ Cleaning up git history...${NC}"
rm -rf .git
rm -f install.sh
git init -q
git branch -m main 2>/dev/null || true

# Check if there are files to commit before committing
if [ -n "$(git status --porcelain)" ]; then
    git add .
    git commit -q -m "Initial commit" || true
fi

echo -e "${GREEN}➤ Setting up environment files...${NC}"
if [ -f .env.example ]; then cp .env.example .env; fi
if [ -f frontend/.env.example ]; then cp frontend/.env.example frontend/.env; fi

echo ""
echo -e "${BLUE}=======================================${NC}"
echo -e "${GREEN}Setup completed successfully!${NC}"
echo -e "${BLUE}=======================================${NC}"
echo ""
echo -e "Next steps:"
if [ -n "$PROJECT_NAME" ] && [ "$PROJECT_NAME" != "." ]; then
    echo -e "  1. ${YELLOW}cd ${PROJECT_NAME}${NC}"
    echo -e "  2. Update the .env files if necessary"
    echo -e "  3. ${YELLOW}make install${NC}"
    echo -e "  4. ${YELLOW}make dev${NC}"
else
    echo -e "  1. Update the .env files if necessary"
    echo -e "  2. ${YELLOW}make install${NC}"
    echo -e "  3. ${YELLOW}make dev${NC}"
fi
echo ""
echo -e "Happy Coding!"
