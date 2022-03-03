from OTXv2 import OTXv2
from app import App
import datetime
import configparser
import json
import os

otx = OTXv2(api_key)  # Replace with your own OTX api key
is_in_docker = os.getenv('IS_IN_DOCKER', False)


def create_pulses(app_, since=None):
    for pulse in otx.getall_iter(modified_since=since):
        app_.create_pulse(pulse)


def import_attack_json(app_):
    with open("enterprise-attack-10.1.json") as file:
        data = json.load(file)
    for item in data["objects"]:
        app_.create_attack_item(item)


def load_timestamp(config_):
    config_.read('config.ini')
    return config_.get('Info', 'Date', fallback=None)


def save_timestamp(config_):
    config_['Info'] = {'Date': datetime.datetime.now()}
    with open('config.ini', 'w') as config_file:
        config_.write(config_file)


if __name__ == '__main__':
    config = configparser.ConfigParser()
    if is_in_docker:
        bolt_url = "bolt://neo4j_db:7687"
    else:
        bolt_url = "bolt://localhost:7687"
    user = "neo4j"
    password = "1234"
    app = App(bolt_url, user, password)
    create_pulses(app, load_timestamp(config))
    app.close()
    save_timestamp(config)
