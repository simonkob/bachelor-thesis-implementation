import configparser
import datetime
import json
import os
import urllib.request

from OTXv2 import OTXv2

from app import App

otx = OTXv2(api_key)  # Replace with your own OTX api key
is_in_docker = os.getenv('IS_IN_DOCKER', False)
config = configparser.ConfigParser()


def create_pulses(app_, since=None):
    """Creates a pulse record in the database for every pulse that has been modified since 'since' argument.

    :param app_: A database connection
    :param since: Date of last modification
    """
    for pulse in otx.getall_iter(modified_since=since):
        app_.create_pulse(pulse)
    save_timestamp(config)


def import_attack_json(app_, config_):
    """Imports data from MITRE ATT&CK json

    :param app_: A database connection
    :param config_: Configuration file
    """
    url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack" \
          ".json "
    data = json.loads(urllib.request.urlopen(url).read())
    data_version = data["objects"][0]["x_mitre_version"]
    if data_version != load_attack_ver(config_):
        json_objects_dict = {}
        for item in data["objects"]:
            app_.create_attack_item(item, json_objects_dict)
        save_attack_ver(config_, data_version)
    else:
        print("Latest MITRE ATT&CK already imported.")


def load_attack_ver(config_):
    """Loads the last imported attack version from the configuration file

    :param config_: Configuration file
    :return: String of the last attack version
    """
    config_.read('config.ini')
    return config_.get('Info', 'Attack_ver', fallback=None)


def save_attack_ver(config_, version):
    """Saves the last imported attack version to the configuration file

    :param config_: Configuration file
    :param version: Attack version to be saved
    """
    config_.set('Info', 'Attack_ver', version)
    with open('config.ini', 'w') as config_file:
        config_.write(config_file)


def load_timestamp(config_):
    """Loads the date when pulses from OTX were last updated from configuration file

    :param config_: Configuration file
    :return: String of the date when pulses were last updated
    """
    config_.read('config.ini')
    return config_.get('Info', 'Date', fallback=None)


def save_timestamp(config_):
    """Saves the date when pulses from OTX were last updated to configuration file

    :param config_: Configuration file
    """
    config_.set('Info', 'Date', str(datetime.datetime.now()))
    with open('config.ini', 'w') as config_file:
        config_.write(config_file)


def get_option_input(prompt):
    """Gets an input from the user to choose which data will be updated

    :param prompt: Message displayed to the user
    :return: True = update pulses from OTX, False = update MITRE ATT&CK json
    """
    while True:
        value = input(prompt)
        if value in ("1", "1.", "a"):
            return True
        if value in ("2", "2.", "b"):
            return False
        print("Invalid selection, try again.")


def choose_source(app_, config_):
    """Asks user to select which data source should updated and runs the corresponding function

    :param app_: A database connection
    :param config_: Configuration file
    """
    print("Choose which data should be updated:\n1. The Open Threat Exchange (OTX)\n2. MITRE ATT&CK")
    if get_option_input("Select an option (1 or 2): "):
        create_pulses(app_, load_timestamp(config_))
    else:
        import_attack_json(app_, config_)


if __name__ == '__main__':
    if is_in_docker:
        bolt_url = "bolt://neo4j_db:7687"
    else:
        bolt_url = "bolt://localhost:7687"
    user = "neo4j"
    password = "1234"
    app = App(bolt_url, user, password)
    choose_source(app, config)
    app.close()
