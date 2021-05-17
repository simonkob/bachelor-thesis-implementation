import unittest
from unittest import mock
from main import get_trusted_users, InfoOptions


def mock_empty(*args):
    if args[0] == InfoOptions.following:
        return {
        }.get(args[1], [])
    else:
        return {
        }.get(args[1], [])


def mock_basic(*args):
    if args[0] == InfoOptions.following:
        return {
            "AlienVault": ["user1"],
            "user1": ["user2"]
        }.get(args[1], [])
    else:
        return {
            "AlienVault": ["user3"],
            "user3": ["user4"]
        }.get(args[1], [])


def mock_case1(*args):
    if args[0] == InfoOptions.following:
        return {
            "AlienVault": ["user1"],
            "user1": ["user2"],
            "user3": ["user4"]
        }.get(args[1], [])
    else:
        return {
            "user2": ["user3"]
        }.get(args[1], [])


def mock_repeat(*args):
    if args[0] == InfoOptions.following:
        return {
            "AlienVault": ["u2", "u3", "u4"],
            "u4": ["AlienVault", "u1", "u2"]
        }.get(args[1], [])
    else:
        return {
            "AlienVault": ["u1"],
            "u1": ["u3", "u4"],
            "u3": ["u4"]
        }.get(args[1], [])


class GetTrustedUsersTestCase(unittest.TestCase):
    @mock.patch("main.get_watched_users", side_effect=mock_empty)
    def test_empty(self, mock_get):
        result = get_trusted_users("AlienVault", 7)
        self.assertEqual(result[0], set())
        self.assertEqual(result[1], {'AlienVault'})

    @mock.patch("main.get_watched_users", side_effect=mock_basic)
    def test_basic(self, mock_get):
        result = get_trusted_users("AlienVault", 7)
        self.assertEqual(result[0], {'user1', 'user2'})
        self.assertEqual(result[1], {'AlienVault', 'user3', 'user4'})

    @mock.patch("main.get_watched_users", side_effect=mock_case1)
    def test_case1(self, mock_get):
        result = get_trusted_users("AlienVault", 7)
        self.assertEqual(result[0], {'user1', 'user2', 'user3', 'user4'})
        self.assertEqual(result[1], {'AlienVault'})

    @mock.patch("main.get_watched_users", side_effect=mock_repeat)
    def test_repeat(self, mock_get):
        result = get_trusted_users("AlienVault", 7)
        self.assertEqual(result[0], {'u2'})
        self.assertEqual(result[1], {'AlienVault', 'u1', 'u3', 'u4'})


if __name__ == "__main__":
    unittest.main()
