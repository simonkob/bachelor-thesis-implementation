from OTXv2 import OTXv2, NotFound, BadRequest, InvalidAPIKey, RetryError
from enum import Enum
import datetime
from time import sleep
from collections import deque

otx = OTXv2(api_key)


class InfoOptions(Enum):
    following = 1
    subscribing = 2


class QueueItem:
    def __init__(self, name, trust_lvl):
        self.name = name
        self.trust_lvl = trust_lvl


def _watched_users(options: InfoOptions, user_):
    """Gets list of users that specified user follows/subscribes to.

    :param options: Whether returned users should be following or subscribing
    :param user_:  User whose following/subscribing users we want to get
    :return: list of users that AlienVault follows/subscribes to
    """
    users = []
    api_call = otx.get(f"https://otx.alienvault.com/otxapi/users/{user_}/{options.name}/?limit=20")
    while True:
        results = api_call['results']
        for result in results:
            users.append(result['username'])
        if not api_call['next']:
            break
        api_call = otx.get(api_call['next'])
    return users


def get_watched_users(options: InfoOptions, user_):
    """Tries to get list of users that specified user follows/subscribes to. If a request limit on the OTX platform is
    reached, waits for one hour and then tries again.

    :param options: Whether returned users should be following or subscribing
    :param user_: User whose following/subscribing users we want to get
    :return:
    """
    try:
        return _watched_users(options, user_)
    except RetryError:
        print("Sleep started: ", datetime.datetime.now())
        sleep(3690)
        print("Continuing...: ", datetime.datetime.now())
        return _watched_users(options, user_)
    except (NotFound, BadRequest, InvalidAPIKey) as e:
        raise Exception("Unexpected error: " + e)


def get_trusted_users(threshold, starting_username="AlienVault"):
    """Gets users that should be trusted to follow and subscribe based on threshold.

    :param threshold: Threshold
    :param starting_username: Username of the user from which we start the algorithm
    :return: Sets of users that are safe to follow and subscribe
    """
    subscribe_set = set()
    follow_set = set()
    sub_queue = deque()
    sub_queue.append(QueueItem(starting_username, 0))
    fol_queue = deque()

    while current_user := sub_queue.popleft():
        subscribe_set.add(current_user.name)
        subscribers_list = get_watched_users(InfoOptions.subscribing, current_user.name)
        for subscriber_name in subscribers_list:
            if subscriber_name not in subscribe_set:
                sub_queue.append(QueueItem(subscriber_name, current_user.trust_lvl))

        followers_list = get_watched_users(InfoOptions.following, current_user.name)
        for follower_name in followers_list:
            if follower_name not in subscribe_set:
                fol_queue.append(QueueItem(follower_name, current_user.trust_lvl + 1))

        if not sub_queue:
            break

    if fol_queue:
        while current_user := fol_queue.popleft():
            if current_user.trust_lvl > threshold:
                break

            if current_user.name not in subscribe_set and current_user.name not in follow_set:
                follow_set.add(current_user.name)
                subscribers_list = get_watched_users(InfoOptions.subscribing, current_user.name)
                for subscriber_name in subscribers_list:
                    if subscriber_name not in subscribe_set and subscriber_name not in follow_set:
                        fol_queue.appendleft(QueueItem(subscriber_name, current_user.trust_lvl))

                followers_list = get_watched_users(InfoOptions.following, current_user.name)
                for follower_name in followers_list:
                    if follower_name not in subscribe_set and follower_name not in follow_set:
                        fol_queue.append(QueueItem(follower_name, current_user.trust_lvl + 1))

            if not fol_queue:
                break

    return [follow_set, subscribe_set]
