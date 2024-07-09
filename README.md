# FASMO

<div style="text-align: center;">
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
                         


# Table of Contents
- [FASMO](#fasmo)
- [Table of Contents](#table-of-contents)
  - [Development](#development)
    - [Backend](#backend)
    - [Frontend](#frontend)
  - [Formatting](#formatting)
  - [Deployment](#deployment)


## Development

### Backend

**1. Create a Virtual Environment (venv)**

Create a virtual environment (venv) using conda with the following command:

```
conda create -n [venv-name] python=3.10
```

Activate the venv with the following command:

```
conda activate [venv-name]
```

**2. Create the .env File**

Create and update `.env` file based on `.env.example`

```
cp .env.example .env
```

**3. Run the backend**

Run the server with the following command:

```
sh script/start-dev.sh
```

**4. Open the API Documentation**

The API documentation can be opened in a browser at the following address:

```
http://localhost:8000/docs
```

### Frontend
**1. Go to frontend folder**
Go to frontend folder and install dependencies:
```
cd frontend
npm install
```

**2. Create the .env File**

Create and update `.env` file based on `.env.example`

```
cp .env.example .env
```

**3. Run the frontend**
Run development server
```bash
npm run dev

# or start the server and open the app in a new browser tab
npm run dev -- --open
```

## Formatting
To make the code cleaner and more structured

Backend:
```
sh scripts/lint-fromat.sh
```
Frontend:
```
npm run lint
npm run format
```

## Deployment

Before you begin, ensure you have [Docker](https://docs.docker.com/engine/install/) installed.

**1. Create environment files**

For the backend:
```bash
cp .env.example .env
```

For the frontend:
```bash
cd frontend
cp .env.example .env
cd ..
```

Open each `.env` file you have created and update the values as needed.

**2. Build and run the Docker containers**
```bash
docker compose up --build -d
```
Wait a few minutes for the setup to complete. You can then access:
- Frontend at http://localhost:5000
- Backend at http://localhost:8000