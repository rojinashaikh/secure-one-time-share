import unittest
from cryptography.fernet import Fernet
import os

class TestEncryption(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """Set up the Fernet key before running any tests."""
        # In a real app, this would be set via an environment variable or config file
        cls.key = Fernet.generate_key()  # Generate a new key
        cls.fernet = Fernet(cls.key)  # Create a Fernet object with the key

    def test_encryption_decryption(self):
        """Test that encryption and decryption work correctly."""
        # Original data
        original_data = "my_sensitive_data"

        # Encrypt the data
        encrypted_data = self.fernet.encrypt(original_data.encode())
        self.assertNotEqual(original_data, encrypted_data.decode(), "Data was not encrypted properly.")

        # Decrypt the data
        decrypted_data = self.fernet.decrypt(encrypted_data).decode()
        
        # Assert that the decrypted data matches the original
        self.assertEqual(original_data, decrypted_data, "Decrypted data does not match original.")

    def test_invalid_decryption(self):
        """Test that an incorrect key causes decryption to fail."""
        invalid_key = Fernet.generate_key()  # Generate a new invalid key
        invalid_fernet = Fernet(invalid_key)

        # Encrypt the data with the valid key
        encrypted_data = self.fernet.encrypt("my_sensitive_data".encode())

        # Try to decrypt using the invalid key and expect an exception
        with self.assertRaises(Exception):
            invalid_fernet.decrypt(encrypted_data)

if __name__ == '__main__':
    unittest.main()
