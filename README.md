# FASMO

<div align="center">
<!-- https://patorjk.com/software/taag/#p=display&f=Ghost&t=FASMO -->
<pre>
            ('-.      .-')   _   .-')                
           ( OO ).-. ( OO ).( '.( OO )_              
   ,------./ . --. /(_)---\_),--.   ,--.).-'),-----. 
('-| _.---'| \-.  \ /    _ | |   `.'   |( OO'  .-.  '
(OO|(_\  .-'-'  |  |\  :` `. |         |/   |  | |  |
/  |  '--.\| |_.'  | '..`''.)|  |'.'|  |\_) |  |\|  |
\_)|  .--' |  .-.  |.-._)   \|  |   |  |  \ |  | |  |
  \|  |_)  |  | |  |\       /|  |   |  |   `'  '-'  '
   `--'    `--' `--' `-----' `--'   `--'     `-----' 
</pre>
</div>
                         


FASMO - FastAPI SvelteKit MongoDB

The project structure for the backend is inspired by [this repository](https://github.com/zhanymkanov/fastapi-best-practices?tab=readme-ov-file#project-structure).

The frontend of the project is built using SvelteKit, initialized with the command: <br /> `npm create svelte@latest fasmo`

# Table of Contents
- [FASMO](#fasmo)
- [Table of Contents](#table-of-contents)
  - [Quick Start](#quick-start)
  - [Development](#development)
    - [Backend](#backend)
    - [Frontend](#frontend)
  - [Quality Control](#quality-control)
  - [Docker Quick Start (Local)](#docker-quick-start-local)
  - [Deployment](#deployment)


## Quick Start

### ⚡ One-Line Installation (Recommended)

The easiest way to get started is by using our installation script. Run the following command in your terminal:

```bash
curl -fsSL https://raw.githubusercontent.com/Shiyinq/fasmo/main/install.sh | bash
```

The script will ask for your project name, clone the repository, clean up the git history, and set up your `.env` files automatically.

---

### Manual Installation

If you prefer to set it up manually and have `make` installed, follow these steps:

**1. Create and edit environment files**
```bash
cp .env.example .env
cp frontend/.env.example frontend/.env
```
Update the values in both `.env` files as needed.

**2. Install and Run**
```bash
# Install all dependencies (Backend & Frontend)
make install

# Run both Backend and Frontend
make dev

# Run quality checks (Linting & Tests)
make check
```

### Backend

**1. Create the .env File**

Create and update `.env` file based on `.env.example`:

```bash
cp .env.example .env
```
Update the values in the `.env` file as needed.

**2. Setup Environment**

Using Makefile:

```bash
make install-be
```

Alternatively, manual steps:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements/base.txt -r requirements/dev.txt
```

**3. Run the backend**

Run the server using Makefile:

```bash
make dev-be
```

Or manually:

```bash
sh scripts/start-dev.sh
```

**4. Open the API Documentation**

The API documentation can be opened in a browser at the following address:

```
http://localhost:8000/docs
```

### Frontend

**1. Create the .env File**

Create and update `.env` file based on `.env.example`:

```bash
cp frontend/.env.example frontend/.env
```
Update the values in the `.env` file as needed.

**2. Install dependencies**

Using Makefile:
```bash
make install-fe
```

Or manually:
```bash
cd frontend
npm install
```

**3. Run the frontend**

Using Makefile:
```bash
make dev-fe
```

Or manually:
```bash
cd frontend
npm run dev
```

## Quality Control
To ensure code quality and consistency.

Using Makefile:
```bash
# Run all checks
make check

# Run only backend checks
make check-be

# Run only frontend checks
make check-fe
```

Or manually:

Backend:
```bash
sh scripts/lint-format.sh
pytest
```
Frontend:
```bash
cd frontend
npm run check
npm run format
npm run lint
```

## Docker Quick Start (Local)

If you have [Docker](https://docs.docker.com/engine/install/) installed and want to run the project locally using containers:

**1. Create and edit environment files**
```bash
cp .env.example .env
cp frontend/.env.example frontend/.env
```
Update the values in both `.env` files as needed.

**2. Run with Makefile**
```bash
# Start in development mode
make docker-dev

# Start in production mode
make docker-prod
```

**3. Access the app**
- Frontend: http://localhost:5050
- Backend: http://localhost:8000

## Deployment

For detailed production deployment instructions, including VPS setup and CI/CD, please refer to [DEPLOYMENT.md](docs/DEPLOYMENT.md).
