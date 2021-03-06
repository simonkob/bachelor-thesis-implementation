from OTXv2 import OTXv2, NotFound, BadRequest, InvalidAPIKey
from app import App
import datetime
import configparser
from enum import Enum

otx = OTXv2("65c4b1a25b5896043ef4dfd0b38ea42a5910abac8f4fd19e79f83fda68965eeb")


class InfoOptions(Enum):
    following = 1
    subscribing = 2


def create_pulses(app_, since=None):
    for pulse in otx.getall_iter(modified_since=since):
        app_.create_pulse(pulse)


def load_timestamp(config_):
    config_.read('config.ini')
    return config_.get('Info', 'Date', fallback=None)


def save_timestamp(config_):
    config_['Info'] = {'Date': datetime.datetime.now()}
    with open('config.ini', 'w') as config_file:
        config_.write(config_file)


def get_watched_users(options: InfoOptions = InfoOptions.following):
    """Gets list of users that AlienVault follows/subscribes to.

    :param options: Whether returned users should be following or subscribing
    :return: list of users that AlienVault follows/subscribes to
    """
    users = []
    try:
        api_call = otx.get(f"https://otx.alienvault.com/otxapi/users/AlienVault/{options.name}/?limit=20")
    except (NotFound, BadRequest, InvalidAPIKey):
        return None
    while True:
        results = api_call['results']
        for result in results:
            users.append(result['username'])
        if not api_call['next']:
            break
        api_call = otx.get(api_call['next'])
    return users


if __name__ == '__main__':
    config = configparser.ConfigParser()
    bolt_url = "bolt://localhost:7687"
    user = "neo4j"
    password = "1234"
    app = App(bolt_url, user, password)
    create_pulses(app, load_timestamp(config))
    app.close()
    save_timestamp(config)
