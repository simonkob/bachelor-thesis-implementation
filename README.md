# bachelor-thesis-implementation

Implementation of bachelor's thesis on topic of Gathering Information from Community Threat Intelligence Platform

## Before running

Replace api_key in [main.py](https://gitlab.fi.muni.cz/xbezek2/bachelor-thesis-implementation/-/blob/master/main.py) and [users_algo.py](https://gitlab.fi.muni.cz/xbezek2/bachelor-thesis-implementation/-/blob/master/users_algo.py) with your own OTX api key. You can get it [here](https://otx.alienvault.com/api) after logging in or signing up.

## Run locally

Install the dependencies for the app with pip:

```
pip install -r requirements.txt
```

Start your local Neo4j Server (APOC plugin is required), then modify login credentials in **main.py** if needed. <br />
Finally, start up the application: 

```
python main.py
```

## Run with docker-compose

Download [Docker desktop](https://www.docker.com/products/docker-desktop). Docker Compose will be installed automatically on Windows and Mac. On Linux, you will have to install it [manually](https://docs.docker.com/compose/install/#install-compose). <br />

To run use: 
```
docker-compose up
```

