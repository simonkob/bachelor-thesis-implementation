import unittest
from unittest import mock
from users_algo import get_trusted_users, InfoOptions


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


def mock_threshold(*args):
    if args[0] == InfoOptions.following:
        return {
            "AlienVault": ["f1"],
            "f1": ["f2"],
            "f2": ["f3"],
            "f3": ["f4"],
            "f4": ["f5"],
            "f5": ["f6"],
            "f6": ["f7"]
        }.get(args[1], [])
    else:
        return {
            "AlienVault": ["s1"],
            "s1": ["s2"],
            "s2": ["s3"],
            "s3": ["s4"],
            "s4": ["s5"],
            "s5": ["s6"],
            "s6": ["s7"]
        }.get(args[1], [])


def mock_case2(*args):
    if args[0] == InfoOptions.following:
        return {
            "AlienVault": ["f1"]
        }.get(args[1], [])
    else:
        return {
            "f1": ["f2"],
            "f2": ["f3"],
            "f3": ["f4"],
            "f4": ["f5"],
            "f5": ["f6"],
            "f6": ["f7", "AlienVault"],
            "f7": ["f8"],
            "f8": ["f9"],
            "f9": ["f10"],
            "f10": ["f11"],
            "f11": ["f12"],
            "f12": ["target", "AlienVault"],
            "target": ["f12", "AlienVault"]
        }.get(args[1], [])


def mock_case3(*args):
    if args[0] == InfoOptions.following:
        return {
            "AlienVault": ["f3"],
            "f2": ["f7", "f10"],
            "f3": ["f5", "f6", "f7"],
            "f4": ["AlienVault", "f11"]
        }.get(args[1], [])
    else:
        return {
            "AlienVault": ["f2", "f3", "f4"],
            "f2": ["f5", "f6"],
            "f3": ["f7"],
            "f4": ["f6", "f8", "f9"]
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

    @mock.patch("main.get_watched_users", side_effect=mock_threshold)
    def test_threshold(self, mock_get):
        result = get_trusted_users("AlienVault", 1)
        self.assertEqual(result[0], {'f1'})
        self.assertEqual(result[1], {'AlienVault', 's1', 's2', 's3', 's4', 's5', 's6', 's7'})
        result = get_trusted_users("AlienVault", 2)
        self.assertEqual(result[0], {'f1', "f2"})
        self.assertEqual(result[1], {'AlienVault', 's1', 's2', 's3', 's4', 's5', 's6', 's7'})
        result = get_trusted_users("AlienVault", 3)
        self.assertEqual(result[0], {'f1', "f2", "f3"})
        self.assertEqual(result[1], {'AlienVault', 's1', 's2', 's3', 's4', 's5', 's6', 's7'})
        result = get_trusted_users("AlienVault", 6)
        self.assertEqual(result[0], {'f1', "f2", "f3", "f4", "f5", "f6"})
        self.assertEqual(result[1], {'AlienVault', 's1', 's2', 's3', 's4', 's5', 's6', 's7'})
        result = get_trusted_users("AlienVault", 7)
        self.assertEqual(result[0], {'f1', "f2", "f3", "f4", "f5", "f6", "f7"})
        self.assertEqual(result[1], {'AlienVault', 's1', 's2', 's3', 's4', 's5', 's6', 's7'})

    @mock.patch("main.get_watched_users", side_effect=mock_case2)
    def test_case2(self, mock_get):
        result = get_trusted_users("AlienVault", 0)
        self.assertEqual(result[0], set())
        self.assertEqual(result[1], {"AlienVault"})
        result = get_trusted_users("AlienVault", 1)
        self.assertEqual(result[0],
                         {'f1', "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "f10", "f11", "f12", "target"})
        self.assertEqual(result[1], {"AlienVault"})
        result = get_trusted_users("AlienVault", 2)
        self.assertEqual(result[0],
                         {'f1', "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "f10", "f11", "f12", "target"})
        self.assertEqual(result[1], {"AlienVault"})

    @mock.patch("main.get_watched_users", side_effect=mock_case3)
    def test_case3(self, mock_get):
        result = get_trusted_users("AlienVault", 7)
        self.assertEqual(result[0], {"f10", "f11"})
        self.assertEqual(result[1], {'AlienVault', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9'})


if __name__ == "__main__":
    unittest.main()
