from OTXv2 import OTXv2
from app import App
import datetime
import configparser

otx = OTXv2("65c4b1a25b5896043ef4dfd0b38ea42a5910abac8f4fd19e79f83fda68965eeb")


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


if __name__ == '__main__':
    config = configparser.ConfigParser()
    bolt_url = "bolt://localhost:7687"
    user = "neo4j"
    password = "1234"
    app = App(bolt_url, user, password)
    create_pulses(app, load_timestamp(config))
    app.close()
    save_timestamp(config)
