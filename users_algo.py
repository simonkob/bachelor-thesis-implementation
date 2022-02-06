from OTXv2 import OTXv2, NotFound, BadRequest, InvalidAPIKey, RetryError
from enum import Enum
import datetime
from time import sleep

otx = OTXv2("65c4b1a25b5896043ef4dfd0b38ea42a5910abac8f4fd19e79f83fda68965eeb")


class InfoOptions(Enum):
    following = 1
    subscribing = 2


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


def get_trusted_users(current_user, threshold, current=0, is_follower=False, subscribe_dict=None, follow_dict=None):
    """Gets users that should be trusted to follow and subscribe based on threshold.

    :param current_user: Current user
    :param threshold: Threshold
    :param current: current level of trustability
    :param is_follower: Whether the user is followed or not
    :param subscribe_dict: Set of users that are safe to subscribe
    :param follow_dict: Set of users that are safe to follow
    :return: Sets of users that are safe to follow and subscribe
    """
    if follow_dict is None:
        follow_dict = {}
    if subscribe_dict is None:
        subscribe_dict = {}

    if is_follower:
        # In the following statement this will not harm but could be useless: follow_dict.get(current_user) > current
        if current_user not in follow_dict or follow_dict.get(current_user) > current:
            follow_dict.update({current_user: current})
    else:
        # In the following statement this will not harm but could be useless: subscribe_dict.get(current_user) > current
        if current_user not in subscribe_dict or subscribe_dict.get(current_user) > current:
            subscribe_dict.update({current_user: current})

    if current <= threshold:
        try:
            subscribers_list = get_watched_users(InfoOptions.subscribing, current_user)
        except RetryError:
            # Requests limit reached
            print("Sleep started: ", datetime.datetime.now())
            sleep(3690)
            print("Continuing...: ", datetime.datetime.now())
            subscribers_list = get_watched_users(InfoOptions.subscribing, current_user)

        for subscriber_item in subscribers_list:
            if not is_follower and subscriber_item in follow_dict:
                follow_dict.pop(subscriber_item)

            if (subscriber_item not in subscribe_dict and subscriber_item not in follow_dict) or \
                    (is_follower and follow_dict.get(subscriber_item, 0) > current):
                if not is_follower:
                    subscribe_dict.update({subscriber_item: current})
                else:
                    follow_dict.update({subscriber_item: current})

                get_trusted_users(subscriber_item, threshold, current, is_follower, subscribe_dict, follow_dict)

        if current < threshold:
            try:
                followers_list = get_watched_users(InfoOptions.following, current_user)
            except RetryError:
                print("Sleep started: ", datetime.datetime.now())
                sleep(3690)
                print("Continuing...: ", datetime.datetime.now())
                followers_list = get_watched_users(InfoOptions.following, current_user)

            for follower_item in followers_list:
                if (follower_item not in follow_dict and follower_item not in subscribe_dict) or \
                        follow_dict.get(follower_item, 0) > current:

                    follow_dict.update({follower_item: current})
                    get_trusted_users(follower_item, threshold, current + 1, True, subscribe_dict, follow_dict)

    return [follow_dict.keys(), subscribe_dict.keys()]
