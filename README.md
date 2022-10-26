# bachelor-thesis-implementation

Implementation of bachelor's thesis on the topic of Gathering Information from Community Threat Intelligence Platform. 
This implementation creates a program, that obtains data from the community threat intelligence platform [Open Threat Exchange (OTX)](https://otx.alienvault.com/) 
and [MITRE ATT&CK](https://attack.mitre.org/) knowledge base, and  stores it in a graph database [Neo4j](https://neo4j.com/).

## Before running

Replace api_key in [main.py](https://gitlab.fi.muni.cz/xbezek2/bachelor-thesis-implementation/-/blob/master/main.py) and [users_algo.py](https://gitlab.fi.muni.cz/xbezek2/bachelor-thesis-implementation/-/blob/master/users_algo.py) with your own OTX api key. You can get it [here](https://otx.alienvault.com/api) after logging in or signing up.

## Run locally

Install the dependencies for the app with pip:

```
pip install -r requirements.txt
```

Start your local Neo4j Server (APOC plugin is required), then modify the Neo4j login credentials in [main.py](https://gitlab.fi.muni.cz/xbezek2/bachelor-thesis-implementation/-/blob/master/main.py) if needed. <br />
Finally, start up the application: 

```
python main.py
```

## Run with docker-compose

Download [Docker desktop](https://www.docker.com/products/docker-desktop). Docker Compose will be installed automatically on Windows and Mac. On Linux, you will have to install it [manually](https://docs.docker.com/compose/install/#install-compose). <br />

To execute the program, use: 
```
docker-compose run --rm app
```
while Docker desktop is running. <br />
After the execution finishes, the container with the Neo4j database will continue to be running. Rerun the same command to update the data again. The Neo4j database container can be stopped manually in the Docker desktop application, or by running:
```
docker-compose stop
```

