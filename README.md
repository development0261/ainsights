# Ainsights

## Project setup

Follow the given steps to setup the project

clone the project

```
git clone git@github.com:masifrao/ainsights
```

cd into the project

```
cd ainsights/
```

create a python virtual environment in src/python/backend

```
python3 -m venv .venv
```

activate the virtual environment

```
source .venv/bin/activate
```

for fish shell use this

```
source .venv/bin/activate.fish
```

install the dependencies

```
pip install -r requirements.txt
```

run the server for local development

```
uvicorn --reload --proxy-headers src.app:app
```

To run the frontend web app, cd into webapp

```
cd src/js/webapp
```

start the local development server

```
npm run dev
```

This will serve the webapp at localhost:3000

## Deployment guidelines

### Ubuntu EC2 instance

In order to deploy the project run the below commands

cd into the project directory

```
cd ainsights/
```

pull the latest code from github using the **main** branch

```
git pull origin main
```

build, create and update the containers

```
sudo docker compose up -d --build
```
