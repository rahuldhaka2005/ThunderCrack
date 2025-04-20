import unittest
from thundercrack import ThunderCrack

class TestThunderCrack(unittest.TestCase):
    def setUp(self):
        self.cracker = ThunderCrack(hash_type="md5")

    def test_hash_password(self):
        self.assertEqual(
            self.cracker.hash_password("password"),
            "5f4dcc3b5aa765d61d8327deb882cf99"
        )

    def test_dictionary_attack(self):
        wordlist = ["password", "admin"]
        result = self.cracker.dictionary_attack(
            "5f4dcc3b5aa765d61d8327deb882cf99", wordlist
        )
        self.assertEqual(result, "password")

if __name__ == "__main__":
    unittest.main()
