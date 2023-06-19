import unittest
import os
from Crypto.PublicKey import RSA
import xmlchain

class TestXmlchain(unittest.TestCase):

    def test_key_generation(self):
        key = xmlchain.generate_keypair()
        self.assertIsInstance(key, RSA.RsaKey, "Key is not an instance of RSA.RsaKey")

    def test_sign_and_verify(self):
        key = xmlchain.generate_keypair()
        data = "Test data"
        signature = xmlchain.sign_data(key, data)
        self.assertTrue(xmlchain.verify_signature(key.publickey(), signature, data), "Signature verification failed")

    def test_hash_data(self):
        data = "Test data"
        prev_hash = "0"
        result_hash = xmlchain.hash_data(data, prev_hash)
        self.assertEqual(len(result_hash), 64, "SHA-256 hash length should be 64")

    def test_create_block(self):
        print(dir(xmlchain))
        
        data = "Test data"
        prev_hash = "0"
        key = xmlchain.generate_keypair()
        signature = xmlchain.sign_data(key, data)
        block = xmlchain.create_block(data, prev_hash, signature, key.publickey())
        self.assertEqual(block.tag, "block", "Element tag should be 'block'")
        self.assertEqual(block.get("data"), data, "Block data does not match input data")


if __name__ == '__main__':
    unittest.main()
