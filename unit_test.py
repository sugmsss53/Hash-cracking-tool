import unittest
import threading
import tempfile
import hashlib
from crack_hash import (
    identify_hash,
    compute_hash,
    dictionary_attack,
    brute_force_attack,
    generate_file_hash
)

class TestHashCracker(unittest.TestCase):
    def test_identify_hash(self):
        self.assertEqual(identify_hash("d41d8cd98f00b204e9800998ecf8427e"), ["MD5", "NTLM"])
        self.assertEqual(identify_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709"), ["SHA-1"])
        self.assertEqual(identify_hash("a"*64), ["SHA-256"])
        self.assertEqual(identify_hash("a"*128), ["SHA-512"])
        self.assertEqual(identify_hash("abc"), ["Unknown"])

    def test_compute_hash(self):
        # Test MD5
        self.assertEqual(compute_hash("hello", "MD5"), "5d41402abc4b2a76b9719d911017c592")
        
        # Test SHA-1
        self.assertEqual(compute_hash("hello", "SHA-1"), "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
        
        # Test SHA-256
        expected_sha256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        self.assertEqual(compute_hash("hello", "SHA-256"), expected_sha256)
        
        # Test NTLM (with MD4 availability check)
        try:
            hashlib.new("md4", b"test")
        except ValueError:
            self.skipTest("MD4 not available in this environment")
        else:
            self.assertEqual(compute_hash("password", "NTLM"), "8846f7eaee8fb117ad06bdd830b7586c")
        
        # Test invalid algorithm
        self.assertIsNone(compute_hash("test", "INVALID"))

    def test_dictionary_attack(self):
        # Test successful crack
        captured = []
        def success_callback(result):
            captured.append(result)
        
        hash_value = "5f4dcc3b5aa765d61d8327deb882cf99"  # MD5 of "password"
        dictionary_attack(hash_value, ["password", "123456"], success_callback)
        self.assertIn("Hash Cracked: password", captured[0])

        # Test unknown hash type
        captured = []
        dictionary_attack("abc", ["test"], lambda res: captured.append(res))
        self.assertEqual(captured[0], "Unsupported Hash Type")

    def test_brute_force_attack(self):
        # Test short password crack
        captured = []
        stop_event = threading.Event()
        hash_value = compute_hash("a", "MD5")
        
        brute_force_attack(
            hash_value,
            lambda res: captured.append(res),
            stop_event,
            max_length=1
        )
        self.assertIn("Hash Cracked: a", captured[-1])

        # Test stop event with VALID hash
        captured = []
        stop_event = threading.Event()
        stop_event.set()  # Set immediately
        valid_hash = "d41d8cd98f00b204e9800998ecf8427e"  # MD5 of ""
        brute_force_attack(
            valid_hash,
            lambda res: captured.append(res),
            stop_event
        )
        self.assertEqual(captured[0], "Brute Force Stopped")

    def test_file_hash_generation(self):
        # Test valid file hash
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test")
            f.close()
            expected = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
            self.assertEqual(generate_file_hash(f.name, "sha256"), expected)

        # Test invalid file
        result = generate_file_hash("nonexistent_file.txt")
        self.assertIn("Error:", result)

if __name__ == "__main__":
    unittest.main()