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


def get_watched_users(options: InfoOptions = InfoOptions.following, user_="AlienVault"):
    """Gets list of users that specified user follows/subscribes to. Defaults user_ to AlienVault

    :param options: Whether returned users should be following or subscribing
    :param user_:  User whose following/subscribing users we want to get
    :return: list of users that AlienVault follows/subscribes to
    """
    users = []
    try:
        api_call = otx.get(f"https://otx.alienvault.com/otxapi/users/{user_}/{options.name}/?limit=20")
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


def get_trusted_users(user_, threshold, is_follower=False, subscribe=None, follow=None):
    """Gets users that should be trusted to follow and subscribe based on threshold.

    :param user_: Current user
    :param threshold: Threshold
    :param is_follower: Whether the user is followed or not
    :param subscribe: Set of users that are safe to subscribe
    :param follow: Set of users that are safe to follow
    :return: Sets of users that are safe to follow and subscribe
    """
    if follow is None:
        follow = set()
    if subscribe is None:
        subscribe = set()
    if is_follower:
        follow.add(user_)
    else:
        subscribe.add(user_)
    if threshold >= 1:
        subscribers = get_watched_users(InfoOptions.subscribing, user_)
        for subscriber in subscribers:
            if subscriber not in subscribe:
                if not is_follower:
                    subscribe.update(get_trusted_users(subscriber, threshold, is_follower, subscribe, follow)[1])
                else:
                    follow.update(get_trusted_users(subscriber, threshold, is_follower, subscribe, follow)[0])
        followers = get_watched_users(InfoOptions.following, user_)
        for follower in followers:
            if follower not in follow and follower not in subscribe:
                follow.update(get_trusted_users(follower, threshold-1, True, subscribe, follow)[0])
    return [follow, subscribe]


if __name__ == '__main__':
    config = configparser.ConfigParser()
    bolt_url = "bolt://localhost:7687"
    user = "neo4j"
    password = "1234"
    app = App(bolt_url, user, password)
    create_pulses(app, load_timestamp(config))
    app.close()
    save_timestamp(config)
