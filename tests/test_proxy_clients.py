import copy
import unittest

from app import proxy_auth, proxy_clients


class ProxyClientSettingsTest(unittest.TestCase):
    def setUp(self):
        self.state = {"upstreams": [{"id": "u1"}, {"id": "u2"}]}
        self.input = {"username": "anton", "password": "long-test-password", "port": 3128,
                      "upstream": "u1"}

    def test_password_hidden_and_disable_independent(self):
        a = proxy_clients.save(self.state, self.input)
        b = proxy_clients.save(self.state, {**self.input, "username": "two", "port": 3129})
        self.assertNotIn("password", a)
        changed = proxy_clients.save(self.state, {"enabled": False}, a["id"])
        self.assertFalse(changed["enabled"])
        self.assertTrue(self.state["proxy_clients"][1]["enabled"])
        self.assertEqual(self.state["proxy_clients"][1]["id"], b["id"])

    def test_uniqueness_and_missing_exit(self):
        proxy_clients.save(self.state, self.input)
        for changes in ({"username": "two"}, {"port": 3129}, {"port": 3130, "username": "z", "upstream": "missing"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                proxy_clients.save(self.state, {**self.input, **changes})

    def test_update_keeps_hash_until_password_changed(self):
        entry = proxy_clients.save(self.state, self.input)
        before = self.state["proxy_clients"][0]["password"]
        proxy_clients.save(self.state, {"port": 3129}, entry["id"])
        self.assertEqual(self.state["proxy_clients"][0]["password"], before)
        proxy_clients.save(self.state, {"password": "another-test-password"}, entry["id"])
        self.assertNotEqual(self.state["proxy_clients"][0]["password"], before)

    def test_backup_preserves_clients_and_rejects_corruption(self):
        proxy_clients.save(self.state, self.input)
        saved = copy.deepcopy(self.state["proxy_clients"])
        restored = {"upstreams": [{"id": "u1"}]}
        proxy_clients.restore(restored, saved)
        self.assertEqual(restored["proxy_clients"], saved)
        saved[0]["password"]["hash"] = "invalid"
        with self.assertRaises(ValueError):
            proxy_clients.restore(restored, saved)
        self.assertNotEqual(restored["proxy_clients"], saved)


if __name__ == "__main__":
    unittest.main()
